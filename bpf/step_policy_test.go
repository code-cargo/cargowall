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

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/tc"
)

// loadBPFObjectsStepRules loads the tcbpf collection with the step-rules
// gate set as asked.
func loadBPFObjectsStepRules(t *testing.T, on bool) *TcBpfObjects {
	t.Helper()
	requireBPF(t)
	spec, err := LoadTcBpf()
	require.NoError(t, err)
	require.NoError(t, SetStepRules(spec, on))
	var objs TcBpfObjects
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// Step policies and ordinals of TestStepPolicyVerdicts.
const (
	stepPolicyA uint32 = 3
	stepPolicyB uint32 = 5

	ordinalA       uint32 = 11 // bound to stepPolicyA
	ordinalB       uint32 = 12 // bound to stepPolicyB
	ordinalUnbound uint32 = 13 // a step not identified (yet)
	ordinalJob     uint32 = 14 // a step identified, with no rules of its own
	ordinalRunner  uint32 = 0xFFFFFFFF
)

// TestStepPolicyVerdicts drives real sockets, each tagged with a step
// ordinal by its SO_COOKIE, past both hooks, and checks every verdict
// against the rule a step's own rules follow: the job's rules decide first,
// and only where they decide nothing may the socket's step's rules allow.
//
// In both families (10.99.0.x and fd99::x) the job allows .10 on all ports
// and .12 on TCP 443, and denies .11. Step policy A allows .11 (the job's
// deny must win), .12 on all ports (filling the job's port miss), .20 and
// TCP 9000 anywhere, and .40 on TCP 443 alone, whose port miss falls to A's
// wildcard; and it denies .31, which must deny nothing: a step's rules only
// ever add to the job's. B allows .21 alone. Every destination is checked under every tag and
// under both default actions, so a lookup that ignored its policy, or asked
// the wrong one, or let a step's rules deny, fails some row: A's entries
// are not B's, nor the job's.
//
// TC sees each SYN on a dummy device in a scratch network namespace, where
// it is dropped or passed into nowhere, and reports it with the socket's
// tag. The cgroup hook is attached at the root in shadow mode, so it
// computes and records every verdict and drops nothing on the host.
func TestStepPolicyVerdicts(t *testing.T) {
	requireBPF(t)
	tcObjs := loadBPFObjectsStepRules(t, true)
	originObjs := loadOriginObjectsSharing(t, tcObjs)
	setOriginMode(t, originObjs, originModeShadow)

	require.NoError(t, tcObjs.MapAuditMode.Put(uint32(0), uint8(0)))
	host := func(ip string) uint32 { return ipToU32(ip) }
	allow, deny := TcBpfLpmVal{Action: 1}, TcBpfLpmVal{Action: 0}
	portAllow := TcBpfPortVal{Action: 1}
	put := func(m *ebpf.Map, k, v any) { require.NoError(t, m.Put(k, v)) }

	host6 := func(ip string) [16]byte { return netip.MustParseAddr(ip).As16() }
	portSpecific := TcBpfLpmVal{Action: 1, PortSpecific: 1}

	put(tcObjs.MapCidrs, RuleKey(PolicyJob, 32, host("10.99.0.10")), allow)
	put(tcObjs.MapCidrs, RuleKey(PolicyJob, 32, host("10.99.0.11")), deny)
	put(tcObjs.MapCidrs, RuleKey(PolicyJob, 32, host("10.99.0.12")), portSpecific)
	put(tcObjs.MapPorts, RulePortKey(PolicyJob, host("10.99.0.12"), 443, ipprotoTCP, 0), portAllow)
	put(tcObjs.MapCidrsV6, RuleKeyV6(PolicyJob, 128, host6("fd99::10")), allow)
	put(tcObjs.MapCidrsV6, RuleKeyV6(PolicyJob, 128, host6("fd99::11")), deny)
	put(tcObjs.MapCidrsV6, RuleKeyV6(PolicyJob, 128, host6("fd99::12")), portSpecific)
	put(tcObjs.MapPortsV6, RulePortKeyV6(PolicyJob, host6("fd99::12"), 443, ipprotoTCP, 0), portAllow)

	put(tcObjs.MapCidrs, RuleKey(stepPolicyA, 32, host("10.99.0.11")), allow)
	put(tcObjs.MapCidrs, RuleKey(stepPolicyA, 32, host("10.99.0.12")), allow)
	put(tcObjs.MapCidrs, RuleKey(stepPolicyA, 32, host("10.99.0.20")), allow)
	put(tcObjs.MapPorts, RulePortKey(stepPolicyA, 0, 9000, ipprotoTCP, 0), portAllow)
	put(tcObjs.MapCidrs, RuleKey(stepPolicyA, 32, host("10.99.0.31")), deny)
	put(tcObjs.MapCidrs, RuleKey(stepPolicyA, 32, host("10.99.0.40")), portSpecific)
	put(tcObjs.MapPorts, RulePortKey(stepPolicyA, host("10.99.0.40"), 443, ipprotoTCP, 0), portAllow)
	put(tcObjs.MapCidrsV6, RuleKeyV6(stepPolicyA, 128, host6("fd99::11")), allow)
	put(tcObjs.MapCidrsV6, RuleKeyV6(stepPolicyA, 128, host6("fd99::12")), allow)
	put(tcObjs.MapCidrsV6, RuleKeyV6(stepPolicyA, 128, host6("fd99::20")), allow)
	put(tcObjs.MapPortsV6, RulePortKeyV6(stepPolicyA, [16]byte{}, 9000, ipprotoTCP, 0), portAllow)
	put(tcObjs.MapCidrsV6, RuleKeyV6(stepPolicyA, 128, host6("fd99::31")), deny)
	put(tcObjs.MapCidrsV6, RuleKeyV6(stepPolicyA, 128, host6("fd99::40")), portSpecific)
	put(tcObjs.MapPortsV6, RulePortKeyV6(stepPolicyA, host6("fd99::40"), 443, ipprotoTCP, 0), portAllow)

	put(tcObjs.MapCidrs, RuleKey(stepPolicyB, 32, host("10.99.0.21")), allow)
	put(tcObjs.MapCidrsV6, RuleKeyV6(stepPolicyB, 128, host6("fd99::21")), allow)

	put(tcObjs.MapStepPolicy, ordinalA, stepPolicyA)
	put(tcObjs.MapStepPolicy, ordinalB, stepPolicyB)
	put(tcObjs.MapStepPolicy, ordinalJob, PolicyJob)

	ns := newStepNetns(t)

	cgLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: originObjs.CwCgEgress,
	})
	if err != nil {
		t.Skipf("cannot attach cgroup_skb/egress at root cgroup: %v", err)
	}
	t.Cleanup(func() { cgLink.Close() })
	tcEvents, err := ringbuf.NewReader(tcObjs.MapEvents)
	require.NoError(t, err)
	t.Cleanup(func() { tcEvents.Close() })
	cgRecords, err := ringbuf.NewReader(originObjs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { cgRecords.Close() })

	// From here this goroutine's thread is the namespace's, for good.
	enterStepNetns(t, ns)
	tcLink, err := tc.AttachEgress("d0", tcObjs.CwTcEgress, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(func() { tcLink.Close() })

	tags := []struct {
		name    string
		tagged  bool
		ordinal uint32
		policy  uint32 // the step policy the tag resolves to
	}{
		{"untagged", false, 0, PolicyJob},
		{"step A", true, ordinalA, stepPolicyA},
		{"step B", true, ordinalB, stepPolicyB},
		{"unbound step", true, ordinalUnbound, PolicyJob},
		{"step bound to the job", true, ordinalJob, PolicyJob},
		{"runner", true, ordinalRunner, PolicyJob},
	}
	dsts := []struct {
		addr   string
		port   uint16
		job    int    // RULE_ALLOW, RULE_DENY or RULE_NONE under the job's rules
		allows uint32 // the step policy whose rules allow it, if any
	}{
		{"10.99.0.10", 443, ruleAllow, 0},
		{"10.99.0.11", 443, ruleDeny, stepPolicyA},
		{"10.99.0.12", 443, ruleAllow, stepPolicyA},
		{"10.99.0.12", 8443, ruleNone, stepPolicyA},
		{"10.99.0.20", 80, ruleNone, stepPolicyA},
		{"10.99.0.21", 80, ruleNone, stepPolicyB},
		{"10.99.0.30", 9000, ruleNone, stepPolicyA},
		{"10.99.0.30", 80, ruleNone, 0},
		{"10.99.0.31", 80, ruleNone, 0}, // A denies it
		{"10.99.0.40", 443, ruleNone, stepPolicyA},
		{"10.99.0.40", 9000, ruleNone, stepPolicyA}, // A's port miss, then A's wildcard
		{"10.99.0.40", 80, ruleNone, 0},
		{"fd99::10", 443, ruleAllow, 0},
		{"fd99::11", 443, ruleDeny, stepPolicyA},
		{"fd99::12", 443, ruleAllow, stepPolicyA},
		{"fd99::12", 8443, ruleNone, stepPolicyA},
		{"fd99::20", 80, ruleNone, stepPolicyA},
		{"fd99::21", 80, ruleNone, stepPolicyB},
		{"fd99::30", 9000, ruleNone, stepPolicyA},
		{"fd99::30", 80, ruleNone, 0},
		{"fd99::31", 80, ruleNone, 0}, // A denies it
		{"fd99::40", 443, ruleNone, stepPolicyA},
		{"fd99::40", 9000, ruleNone, stepPolicyA},
		{"fd99::40", 80, ruleNone, 0},
	}

	for _, defaultAllow := range []bool{false, true} {
		def := uint8(0)
		if defaultAllow {
			def = 1
		}
		require.NoError(t, tcObjs.MapDefaultAction.Put(uint32(0), def))
		for _, tag := range tags {
			for _, dst := range dsts {
				checkStepVerdict(t, tcObjs, tcEvents, cgRecords, defaultAllow,
					tag.name, tag.tagged, tag.ordinal, tag.policy, dst.addr, dst.port, dst.job, dst.allows)
			}
		}
	}
}

// checkStepVerdict connects one tagged socket and checks both hooks' verdict
// on its SYN against the rule: the job's rules decide; where they decide
// nothing, the step's own may allow, and the default action decides the
// rest.
func checkStepVerdict(t *testing.T, tcObjs *TcBpfObjects, tcEvents, cgRecords *ringbuf.Reader, defaultAllow bool,
	tagName string, tagged bool, ordinal, policy uint32, addr string, port uint16, job int, allows uint32,
) {
	t.Helper()
	name := fmt.Sprintf("default allow %v, %s to %s:%d", defaultAllow, tagName, addr, port)
	stepAsked := job == ruleNone && policy != PolicyJob
	want := job == ruleAllow || (job == ruleNone && ((stepAsked && allows == policy) || defaultAllow))

	cookie, sport := connectTagged(t, tcObjs, addr, port, tagged, ordinal)
	ev := readTcEventFor(t, tcEvents, netip.MustParseAddr(addr), port, sport)
	require.Equal(t, want, ev.Allowed == 1, "%s: cw_tc_egress verdict", name)
	require.Equal(t, stepAsked, ev.Flags&0x2 != 0, "%s: cw_tc_egress EVENT_FLAG_STEP_TIER", name)
	require.Equal(t, ordinal, ev.StepOrdinal, "%s: cw_tc_egress step tag", name)

	rec := readOriginRecordFor(t, cgRecords, cookie)
	wantVerdict := uint8(originVerdictWouldBlock)
	if want {
		wantVerdict = originVerdictAllow
	}
	require.Equal(t, wantVerdict, rec.Verdict, "%s: cw_cg_egress verdict", name)
	require.Equal(t, stepAsked, rec.Flags&OriginFlagStepTier != 0, "%s: cw_cg_egress ORIGIN_FLAG_STEP_TIER", name)
}

// newStepNetns makes a scratch network namespace with loopback up and a
// dummy device, d0, carrying 10.99.0.1/24 and fd99::1/64: a packet to any
// other address in them leaves by d0, past whatever TC program is attached
// there, and goes nowhere.
func newStepNetns(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2's ip")
	}
	ip := func(args ...string) {
		out, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "ip %v: %s", args, out)
	}
	// One a run that died left behind, its process gone, is no one's.
	stale, _ := filepath.Glob("/run/netns/cwstep-*")
	for _, path := range stale {
		pid := strings.TrimPrefix(filepath.Base(path), "cwstep-")
		if _, err := os.Stat("/proc/" + pid); errors.Is(err, os.ErrNotExist) {
			_ = exec.Command("ip", "netns", "del", filepath.Base(path)).Run()
		}
	}
	name := fmt.Sprintf("cwstep-%d", os.Getpid())
	ip("netns", "add", name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	ip("-n", name, "link", "set", "lo", "up")
	ip("-n", name, "link", "add", "d0", "type", "dummy")
	ip("-n", name, "addr", "add", "10.99.0.1/24", "dev", "d0")
	ip("-n", name, "addr", "add", "fd99::1/64", "dev", "d0", "nodad")
	ip("-n", name, "link", "set", "d0", "up")
	return name
}

// enterStepNetns moves the test's goroutine into the namespace, on a thread
// locked to it for good: the thread exits with the test rather than carry
// the namespace back into the scheduler's pool. Subtests would run on other
// goroutines, outside it, so the caller checks its cases inline.
func enterStepNetns(t *testing.T, name string) {
	t.Helper()
	f, err := os.Open("/run/netns/" + name)
	require.NoError(t, err)
	defer f.Close()
	runtime.LockOSThread()
	require.NoError(t, unix.Setns(int(f.Fd()), unix.CLONE_NEWNET))
}

// connectTagged opens a non-blocking TCP socket, tags its cookie with
// ordinal in map_sock_step unless tagged is false, and starts a connect to
// addr:port, which sends the SYN. It returns the cookie and source port.
func connectTagged(t *testing.T, objs *TcBpfObjects, addr string, port uint16, tagged bool, ordinal uint32) (uint64, uint16) {
	t.Helper()
	dst := netip.MustParseAddr(addr)
	family := unix.AF_INET
	if dst.Is6() {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)
	if tagged {
		require.NoError(t, objs.MapSockStep.Put(cookie, ordinal))
	}
	var sa unix.Sockaddr
	if dst.Is6() {
		sa = &unix.SockaddrInet6{Port: int(port), Addr: dst.As16()}
	} else {
		sa = &unix.SockaddrInet4{Port: int(port), Addr: dst.As4()}
	}
	err = unix.Connect(fd, sa)
	require.True(t, errors.Is(err, unix.EINPROGRESS), "connect to %s: %v", addr, err)
	local, err := unix.Getsockname(fd)
	require.NoError(t, err)
	switch l := local.(type) {
	case *unix.SockaddrInet4:
		return cookie, uint16(l.Port)
	case *unix.SockaddrInet6:
		return cookie, uint16(l.Port)
	}
	t.Fatalf("unexpected local address %T", local)
	return 0, 0
}

// readTcEventFor reads cw_tc_egress events until the one for the SYN to
// dst:port from sport.
func readTcEventFor(t *testing.T, rd *ringbuf.Reader, dst netip.Addr, port, sport uint16) bpfBlockedEvent {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		require.NoError(t, err)
		var ev bpfBlockedEvent
		require.NoError(t, binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev))
		if ev.DstPort != port || ev.SrcPort != sport {
			continue
		}
		if dst.Is4() && ev.IpVersion == 4 && ev.DstIp == binary.BigEndian.Uint32(dst.AsSlice()) {
			return ev
		}
		if dst.Is6() && ev.IpVersion == 6 && ev.DstIp6 == dst.As16() {
			return ev
		}
	}
	t.Fatalf("no cw_tc_egress event for the SYN to %s:%d from port %d", dst, port, sport)
	return bpfBlockedEvent{}
}

// readOriginRecordFor reads cw_cg_egress records until one for cookie: the
// root attachment records the whole host's flows.
func readOriginRecordFor(t *testing.T, rd *ringbuf.Reader, cookie uint64) OriginEvent {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(rec.RawSample), int(unsafe.Sizeof(OriginEvent{})))
		if ev := *(*OriginEvent)(unsafe.Pointer(&rec.RawSample[0])); ev.Cookie == cookie {
			return ev
		}
	}
	t.Fatalf("no cw_cg_egress record for socket cookie %d", cookie)
	return OriginEvent{}
}

// The RULE_* results of verdict.h, as the test's expectations name them.
const (
	ruleNone  = 0
	ruleDeny  = 1
	ruleAllow = 2
)
