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

package cmd

import (
	"log/slog"
	"net"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
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

// stampedPorts is the indexes of the ports b is attached to, sorted, each
// attached still.
func stampedPorts(b *bridgeStamp) []int {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []int
	for index, a := range b.ports {
		if a.Attached() {
			out = append(out, index)
		}
	}
	slices.Sort(out)
	return out
}

// The stamp with the kernel's own interfaces and TC hooks: a veth put on a
// Docker bridge is attached to, and detached from as it leaves the bridge
// and as it goes; a veth on another bridge never is.
func TestBridgeStampPortsNetns(t *testing.T) {
	newNetns(t)
	if _, err := exec.LookPath("ip"); err != nil {
		skipUnlessStrict(t, "needs iproute2's ip")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	load := func(stepRules bool) *bpf.TcBpfObjects {
		spec, err := bpf.LoadTcBpf()
		require.NoError(t, err)
		require.NoError(t, bpf.SetStepRules(spec, stepRules))
		var objs bpf.TcBpfObjects
		require.NoError(t, spec.LoadAndAssign(&objs, nil))
		t.Cleanup(func() { objs.Close() })
		return &objs
	}
	require.Nil(t, newBridgeStamp(load(false), slog.New(slog.DiscardHandler)),
		"step rules off: no stamp, so no watch and no bridge callbacks")
	objs := *load(true)

	ip := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "ip %v: %s", args, out)
	}
	if out, err := exec.Command("ip", "link", "add", "br-0123456789ab", "type", "bridge").CombinedOutput(); err != nil {
		skipUnlessStrict(t, "no bridge support: %v: %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "add", "p0h", "type", "veth", "peer", "name", "p0").CombinedOutput(); err != nil {
		skipUnlessStrict(t, "no veth support: %v: %s", err, out)
	}
	ip("link", "add", "virbr9", "type", "bridge")
	ip("link", "add", "p1h", "type", "veth", "peer", "name", "p1")
	for _, dev := range []string{"br-0123456789ab", "virbr9", "p0h", "p0", "p1h", "p1"} {
		ip("link", "set", dev, "up")
	}
	index := func(name string) int {
		ifi, err := net.InterfaceByName(name)
		require.NoError(t, err)
		return ifi.Index
	}
	p0h, p1h := index("p0h"), index("p1h")

	logs := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stamp's log:\n%s", logs.String())
		}
	})
	b := newBridgeStamp(&objs, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	require.NotNil(t, b)
	b.start()
	t.Cleanup(b.Close)
	ports := func(want ...int) func() bool {
		return func() bool { return slices.Equal(stampedPorts(b), want) }
	}

	ip("link", "set", "p0h", "master", "br-0123456789ab")
	require.Eventually(t, ports(p0h), 5*time.Second, 10*time.Millisecond, "a Docker bridge's port is attached to")
	// On the port itself, in this namespace: the watch's reports are made
	// from it, though they come on a goroutine of their own.
	if progs, err := link.QueryPrograms(link.QueryOptions{Target: p0h, Attach: ebpf.AttachTCXIngress}); err == nil {
		info, err := objs.CwTcBrStamp.Info()
		require.NoError(t, err)
		id, _ := info.ID()
		require.True(t, slices.ContainsFunc(progs.Programs, func(p link.AttachedProgram) bool { return p.ID == id }),
			"cw_tc_br_stamp on p0h's ingress")
	}
	ip("link", "set", "p1h", "master", "virbr9")
	require.Never(t, func() bool { return slices.Contains(stampedPorts(b), p1h) },
		300*time.Millisecond, 10*time.Millisecond, "another bridge's port is not attached to")

	ip("link", "set", "p0h", "nomaster")
	require.Eventually(t, ports(), 5*time.Second, 10*time.Millisecond, "a port that leaves the bridge is detached from")
	ip("link", "set", "p0h", "master", "br-0123456789ab")
	require.Eventually(t, ports(p0h), 5*time.Second, 10*time.Millisecond)
	ip("link", "del", "p0h")
	require.Eventually(t, ports(), 5*time.Second, 10*time.Millisecond, "a port that goes is detached from")
	b.mu.Lock()
	require.Empty(t, b.ports)
	b.mu.Unlock()
}
