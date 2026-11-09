//   Copyright 2026 BoxBuild Inc DBA CodeCargo
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

//go:build linux

package tc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// skipUnlessStrict skips t for what the environment lacks, or fails it
// where CARGOWALL_TEST_STRICT=1 (CI's privileged lanes) says it must not.
func skipUnlessStrict(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CARGOWALL_TEST_STRICT") == "1" {
		t.Fatalf(format+" (CARGOWALL_TEST_STRICT=1)", args...)
	}
	t.Skipf(format, args...)
}

// scratchIndex is the interface index the scratch device takes, so a
// device recreated behind it takes the same one.
const scratchIndex = 77

// scratchNetns makes a scratch network namespace holding a dummy device d0
// at scratchIndex, and moves the test's goroutine into it, on a thread
// locked to it for good: the thread exits with the test rather than carry
// the namespace back into the scheduler's pool. It returns the
// namespace's name, for ip and tc.
func scratchNetns(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN) to manage namespaces, qdiscs and filters")
	}
	for _, bin := range []string{"ip", "tc"} {
		if _, err := exec.LookPath(bin); err != nil {
			skipUnlessStrict(t, "needs iproute2's %s", bin)
		}
	}
	// One a run that died left behind, its process gone, is no one's.
	stale, _ := filepath.Glob("/run/netns/cwtc-*")
	for _, path := range stale {
		pid := strings.TrimPrefix(filepath.Base(path), "cwtc-")
		if _, err := os.Stat("/proc/" + pid); errors.Is(err, os.ErrNotExist) {
			_ = exec.Command("ip", "netns", "del", filepath.Base(path)).Run()
		}
	}
	name := fmt.Sprintf("cwtc-%d", os.Getpid())
	run(t, "ip", "netns", "add", name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	addScratchDevice(t, name)

	f, err := os.Open("/run/netns/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	runtime.LockOSThread()
	if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
		t.Fatalf("setns: %v", err)
	}
	return name
}

func addScratchDevice(t *testing.T, netns string) {
	t.Helper()
	run(t, "ip", "-n", netns, "link", "add", "d0", "index", fmt.Sprint(scratchIndex), "type", "dummy")
	run(t, "ip", "-n", netns, "link", "set", "d0", "up")
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// hasClsact reports whether d0 has a clsact qdisc.
func hasClsact(t *testing.T, netns string) bool {
	t.Helper()
	return strings.Contains(run(t, "tc", "-n", netns, "qdisc", "show", "dev", "d0"), "clsact")
}

// passProg is a SCHED_CLS program that lets every packet on.
func passProg(t *testing.T) *ebpf.Program {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, -1), // TC_ACT_UNSPEC
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("load SCHED_CLS program: %v", err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// An ingress attachment is attached until its interface goes, and says so
// after, whichever way it attached.
func TestAttachIngress_AttachedUntilTheInterfaceGoes(t *testing.T) {
	netns := scratchNetns(t)
	prog := passProg(t)

	a, err := AttachIngress(scratchIndex, "d0", prog, discard())
	if err != nil {
		t.Fatalf("AttachIngress: %v", err)
	}
	defer a.Close()
	if !a.Attached() {
		t.Fatal("not attached")
	}
	if _, ok := a.(tcxAttachment); !ok {
		t.Log("TCX unsupported: attached by clsact")
	}
	run(t, "ip", "-n", netns, "link", "del", "d0")
	addScratchDevice(t, netns)
	if a.Attached() {
		t.Fatal("attached to a later interface at the same index")
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// An egress and an ingress filter of ours on one clsact qdisc we created:
// the qdisc goes with the second, not the first.
func TestAttachClsact_SharedQdisc(t *testing.T) {
	netns := scratchNetns(t)
	prog := passProg(t)

	eg, err := attachClsact(scratchIndex, prog, egress, discard())
	if err != nil {
		t.Fatalf("attach egress: %v", err)
	}
	defer eg.Close()
	in, err := attachClsact(scratchIndex, prog, ingress, discard())
	if err != nil {
		t.Fatalf("attach ingress: %v", err)
	}
	defer in.Close()
	if !eg.Attached() || !in.Attached() {
		t.Fatal("both filters must be attached")
	}
	out := run(t, "tc", "-n", netns, "filter", "show", "dev", "d0", "ingress")
	if !strings.Contains(out, "cargowall_ingress") || !strings.Contains(out, "direct-action") {
		t.Fatalf("ingress filter must be ours and direct-action:\n%s", out)
	}

	if err := eg.Close(); err != nil {
		t.Fatalf("Close egress: %v", err)
	}
	if !in.Attached() || !hasClsact(t, netns) {
		t.Fatal("the ingress filter and its qdisc must outlive the egress filter")
	}
	if err := in.Close(); err != nil {
		t.Fatalf("Close ingress: %v", err)
	}
	if hasClsact(t, netns) {
		t.Fatal("the qdisc we created must go with our last filter")
	}
}

// A clsact qdisc we did not create stays, with our filter gone from it.
func TestAttachClsact_LeavesAQdiscItDidNotCreate(t *testing.T) {
	netns := scratchNetns(t)
	prog := passProg(t)
	run(t, "tc", "-n", netns, "qdisc", "add", "dev", "d0", "clsact")

	in, err := attachClsact(scratchIndex, prog, ingress, discard())
	if err != nil {
		t.Fatalf("attach ingress: %v", err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if in.Attached() {
		t.Fatal("our filter must be gone")
	}
	if !hasClsact(t, netns) {
		t.Fatal("a qdisc we did not create must stay")
	}
}

// A filter of ours whose interface went, closed after a later interface
// took its index and got a clsact qdisc of someone else's, leaves that
// qdisc be, and so does a filter of ours attached there since.
func TestAttachClsact_RecreatedInterface(t *testing.T) {
	netns := scratchNetns(t)
	prog := passProg(t)

	stale, err := attachClsact(scratchIndex, prog, ingress, discard())
	if err != nil {
		t.Fatalf("attach ingress: %v", err)
	}
	run(t, "ip", "-n", netns, "link", "del", "d0")
	addScratchDevice(t, netns)
	run(t, "tc", "-n", netns, "qdisc", "add", "dev", "d0", "clsact")
	if stale.Attached() {
		t.Fatal("attached to a later interface at the same index")
	}
	if err := stale.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !hasClsact(t, netns) {
		t.Fatal("a filter of a dead interface's removed the qdisc of the interface after it")
	}

	fresh, err := attachClsact(scratchIndex, prog, ingress, discard())
	if err != nil {
		t.Fatalf("attach ingress again: %v", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !hasClsact(t, netns) {
		t.Fatal("a qdisc we did not create must stay")
	}
}

// A qdisc we create counts our filters on it afresh: a count left from an
// interface that went, its filter never closed, doesn't keep the qdisc
// once our last filter on it closes.
func TestAttachClsact_FreshQdiscCountsAfresh(t *testing.T) {
	netns := scratchNetns(t)
	prog := passProg(t)

	if _, err := attachClsact(scratchIndex, prog, ingress, discard()); err != nil {
		t.Fatalf("attach ingress: %v", err)
	}
	run(t, "ip", "-n", netns, "link", "del", "d0")
	addScratchDevice(t, netns)
	fresh, err := attachClsact(scratchIndex, prog, ingress, discard())
	if err != nil {
		t.Fatalf("attach ingress again: %v", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if hasClsact(t, netns) {
		t.Fatal("the qdisc we created must go with our last filter on it")
	}
}
