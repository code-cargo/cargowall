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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/internal/testenv"
	"github.com/code-cargo/cargowall/pkg/tc"
)

// The Go mirrors of verdict.h's stamp constants are its values.
func TestStepStampMatchesVerdictH(t *testing.T) {
	src, err := os.ReadFile("verdict.h")
	require.NoError(t, err)
	for name, want := range map[string]uint32{
		"STEP_STAMP_MAGIC":      StepStampMagic,
		"STEP_STAMP_MASK":       StepStampMask,
		"STEP_STAMP_POLICY_MAX": StepStampPolicyMax,
	} {
		m := regexp.MustCompile(`#define ` + name + `\s+0x([0-9A-Fa-f]+)u`).FindSubmatch(src)
		require.NotNil(t, m, "verdict.h defines %s", name)
		got, err := strconv.ParseUint(string(m[1]), 16, 32)
		require.NoError(t, err)
		require.Equal(t, want, uint32(got), name)
	}
	require.Equal(t, StepStampMagic, StepStampMagic&StepStampMask)
	require.Equal(t, StepStampPolicyMax, ^StepStampMask)
}

const tcActUnspec = 0xFFFFFFFF // TC_ACT_UNSPEC, -1, as a run's return

// Run on a test packet, whose socket (the kernel's dummy) has no step
// tag, cw_tc_br_stamp clears a stamp it finds and leaves every other mark
// as it is; with the gate off it touches nothing. It never ends the
// bridge's chain.
func TestBridgeStampTestRun(t *testing.T) {
	for _, gate := range []bool{true, false} {
		objs := loadBPFObjectsStepRules(t, gate)
		for _, c := range []struct {
			mark, want uint32
		}{
			{StepStampMagic | 7, 0},
			{StepStampMagic | StepStampPolicyMax, 0},
			{StepStampMagic, 0},
			{0, 0},
			{0x42, 0x42},
			{0xCA1A0007, 0xCA1A0007},
			{0xCA1C0007, 0xCA1C0007},
			{0x00010007, 0x00010007},
		} {
			want := c.want
			if !gate {
				want = c.mark
			}
			out := skBuffCtx{}
			ret, err := objs.CwTcBrStamp.Run(&ebpf.RunOptions{
				Data:       craftIPv4TCP(t, "10.99.0.20", 80),
				Context:    skBuffCtx{Mark: c.mark},
				ContextOut: &out,
			})
			require.NoError(t, err)
			require.Equal(t, uint32(tcActUnspec), ret, "gate %v, mark %#x", gate, c.mark)
			require.Equal(t, want, out.Mark, "gate %v, mark %#x", gate, c.mark)
		}
	}
}

// Policies and ordinals of TestBridgeStamp.
const (
	brPolicy        uint32 = 7
	brPolicyTooWide uint32 = 0x000A0000 | brPolicy // fits no stamp; stamped anyway, it would read as brPolicy
	brOrdinal       uint32 = 41                    // bound to brPolicy
	brOrdinalUnb    uint32 = 42                    // bound to nothing
	brOrdinalWide   uint32 = 43                    // bound to brPolicyTooWide
	brPolicyNone    uint32 = 9                     // allows nothing
	brOrdinalNone   uint32 = 44                    // bound to brPolicyNone
	brForeignMark   uint32 = 0x00010000 | brPolicy // a mark no stamp: its low bits read as brPolicy
)

// TestBridgeStamp drives a container's sockets through the shape Docker
// gives it: the container's namespace, a veth into the host's, a bridge
// there with br_netfilter on it, forwarding (masquerading, where iptables
// is there) and an uplink with cw_tc_egress on it, cw_tc_br_stamp on the
// veth's host end, the bridge's port. The job's rules allow nothing, the
// default denies, and step policy brPolicy allows 10.99.0.20 and fd99::20:
// a SYN to it gets through only with a stamp of brPolicy, which only a
// socket tagged with a step bound to it may get. Nothing else gets one:
// not an untagged or unbound socket, nor a mark the container set (cleared
// as the packet leaves its namespace), or a stamp set on the host's side
// ahead of the program (cleared, or rewritten to the packet's own
// socket's), or a packet another mark is on (left as it is, unstamped).
// A host socket's mark in the stamp's range is never read as one, nor is
// an AF_PACKET frame a tagged thread sends: packet sockets get no tag. And
// every one of the container's packets reaches the port with its socket:
// BridgeSocketless stays 0.
//
// ci-kernels have no bridge or veth: there it skips, and CI's runner
// kernels run it. On a host without br_netfilter loaded it loads the
// module, a change to the whole host while it runs (every namespace's
// bridges are filtered by default then), and unloads it after only if it
// loaded it and nothing else uses it. The switches it sets are its own
// namespace's, never the host's.
func TestBridgeStamp(t *testing.T) {
	runBridgeStamp(t, true)
}

// TestBridgeStampWithoutBrNetfilter is TestBridgeStamp on a bridge
// br_netfilter leaves alone, as one where the module is not loaded is.
func TestBridgeStampWithoutBrNetfilter(t *testing.T) {
	runBridgeStamp(t, false)
}

func runBridgeStamp(t *testing.T, brNetfilter bool) {
	requireBPF(t)
	objs := loadBPFObjectsStepRules(t, true)
	put := func(m *ebpf.Map, k, v any) { require.NoError(t, m.Put(k, v)) }
	put(objs.MapAuditMode, uint32(0), uint8(0))
	put(objs.MapDefaultAction, uint32(0), uint8(0))
	put(objs.MapCidrs, RuleKey(brPolicy, 32, ipToU32("10.99.0.20")), TcBpfLpmVal{Action: 1})
	put(objs.MapCidrsV6, RuleKeyV6(brPolicy, 128, netip.MustParseAddr("fd99::20").As16()), TcBpfLpmVal{Action: 1})
	put(objs.MapStepPolicy, brOrdinal, brPolicy)
	put(objs.MapStepPolicy, brOrdinalWide, brPolicyTooWide)
	put(objs.MapStepPolicy, brOrdinalNone, brPolicyNone)
	events, err := ringbuf.NewReader(objs.MapEvents)
	require.NoError(t, err)
	t.Cleanup(func() { events.Close() })

	topo := newBridgeTopology(t, brNetfilter)
	topo.enter(t, topo.rtr)
	logger := slog.New(slog.DiscardHandler)
	c0h := interfaceIndex(t, "c0h")
	stamp, err := tc.AttachIngress(c0h, "c0h", objs.CwTcBrStamp, logger)
	require.NoError(t, err)
	t.Cleanup(func() { stamp.Close() })
	uplink, err := tc.AttachEgress("d0", objs.CwTcEgress, logger)
	require.NoError(t, err)
	t.Cleanup(func() { uplink.Close() })
	brMAC := interfaceMAC(t, "br0")
	probe, pastPort := stampedPastPort(t)
	probeLink, err := tc.AttachIngress(interfaceIndex(t, "br0"), "br0", probe, logger)
	require.NoError(t, err)
	t.Cleanup(func() { probeLink.Close() })

	for _, dst := range []netip.Addr{netip.MustParseAddr("10.99.0.20"), netip.MustParseAddr("fd99::20")} {
		// From the container.
		checkAsked := func(name string, ordinal, mark uint32, want, asked bool) {
			t.Helper()
			topo.enter(t, topo.ctr)
			_, sport := dialSYN(t, objs, dst, ordinal, mark)
			topo.enter(t, topo.rtr)
			checkUplinkAsked(t, events, fmt.Sprintf("%s to %s", name, dst), dst, sport, want, asked)
		}
		check := func(name string, ordinal, mark uint32, want bool) {
			t.Helper()
			checkAsked(name, ordinal, mark, want, want)
		}
		check("bound step", brOrdinal, 0, true)
		check("untagged", 0, 0, false)
		check("unbound step", brOrdinalUnb, 0, false)
		check("step bound past the stamp's range", brOrdinalWide, 0, false)
		check("forged stamp, set in the container", 0, StepStampMagic|brPolicy, false)

		if m := markAhead(t, c0h, StepStampMagic|brPolicy); m != nil {
			check("forged stamp, set on the host's side", 0, 0, false)
			// A stamp found is rewritten to the packet's own socket's, so
			// one step's can't stand for another's, in either direction.
			checkAsked("a step allowed nothing, another step's stamp on its packets", brOrdinalNone, 0, false, true)
			require.NoError(t, m.Close())
			m = markAhead(t, c0h, StepStampMagic|brPolicyNone)
			check("bound step, another step's stamp on its packets", brOrdinal, 0, true)
			require.NoError(t, m.Close())
			m = markAhead(t, c0h, brForeignMark)
			check("bound step, another mark on its packets", brOrdinal, 0, false)
			require.NoError(t, m.Close())
			check("bound step, the marks gone", brOrdinal, 0, true)
		}

		// From a host socket: its own mark is no stamp.
		_, sport := dialSYN(t, objs, dst, 0, StepStampMagic|brPolicy)
		checkUplink(t, events, fmt.Sprintf("host socket with a stamp's mark to %s", dst), dst, sport, false)
	}
	requireSocketless(t, objs, 0)
	if brNetfilter {
		require.NotZero(t, pastPort(), "stamps land at the port, and reach the bridge after br_netfilter took the socket")
	} else {
		require.Zero(t, pastPort(), "without br_netfilter, packets reach the bridge with their socket")
	}

	// A tagged thread's TCP socket is tagged by the connect hook, and
	// stamped; its AF_PACKET frame is not.
	connect4, err := link.AttachCgroup(link.CgroupOptions{
		Path: "/sys/fs/cgroup", Attach: ebpf.AttachCGroupInet4Connect, Program: objs.CwCgConnect4,
	})
	if err != nil {
		t.Skipf("cannot attach cgroup/connect4 at the root cgroup: %v", err)
	}
	t.Cleanup(func() { connect4.Close() })
	connect6, err := link.AttachCgroup(link.CgroupOptions{
		Path: "/sys/fs/cgroup", Attach: ebpf.AttachCGroupInet6Connect, Program: objs.CwCgConnect6,
	})
	require.NoError(t, err)
	t.Cleanup(func() { connect6.Close() })
	put(objs.MapStepState, uint32(0), TcBpfStepState{Enabled: 1})
	tid := uint32(unix.Gettid())
	put(objs.MapTaskStep, tid, brOrdinal)
	t.Cleanup(func() { _ = objs.MapTaskStep.Delete(tid) })

	topo.enter(t, topo.ctr)
	c0MAC := interfaceMAC(t, "c0")
	c0, err := net.InterfaceByName("c0")
	require.NoError(t, err)
	for i, c := range []struct{ src, dst netip.Addr }{
		{netip.MustParseAddr("10.98.0.2"), netip.MustParseAddr("10.99.0.20")},
		{netip.MustParseAddr("fd98::2"), netip.MustParseAddr("fd99::20")},
	} {
		topo.enter(t, topo.ctr)
		cookie, sport := dialSYN(t, objs, c.dst, 0, 0)
		var got uint32
		require.NoError(t, objs.MapSockStep.Lookup(cookie, &got), "the connect hook tags the socket")
		require.Equal(t, brOrdinal, got)
		topo.enter(t, topo.rtr)
		checkUplink(t, events, fmt.Sprintf("tagged thread's TCP socket to %s", c.dst), c.dst, sport, true)

		topo.enter(t, topo.ctr)
		sport = uint16(41000 + i)
		cookie = sendFrame(t, c0.Index, synFrame(brMAC, c0MAC, c.src, c.dst, sport, 80))
		require.ErrorIs(t, objs.MapSockStep.Lookup(cookie, &got), ebpf.ErrKeyNotExist, "a packet socket gets no tag")
		topo.enter(t, topo.rtr)
		checkUplink(t, events, fmt.Sprintf("tagged thread's AF_PACKET frame to %s", c.dst), c.dst, sport, false)
	}
	topo.enter(t, topo.rtr)
	requireSocketless(t, objs, 0)
}

// requireSocketless checks how many IP packets have reached a bridge port's
// ingress with no socket.
func requireSocketless(t *testing.T, objs *TcBpfObjects, want uint64) {
	t.Helper()
	n, err := objs.BridgeSocketless()
	require.NoError(t, err)
	require.Equal(t, want, n, "IP packets at a bridge port's ingress with no socket")
}

// sendUntilCounted calls send, and again each second it is not yet
// counted, until the count passes after, and returns the count. One packet
// alone can be dropped on the way (an IPv6 route not yet there, as a
// namespace an earlier test made is torn down), and a resend is the same
// packet.
func sendUntilCounted(t *testing.T, objs *TcBpfObjects, after uint64, what string, send func()) uint64 {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
		send()
		for again := time.Now().Add(time.Second); time.Now().Before(again); time.Sleep(20 * time.Millisecond) {
			if n, err := objs.BridgeSocketless(); err == nil && n > after {
				return n
			}
		}
	}
	t.Fatalf("%s never reached the port with no socket and counted", what)
	return 0
}

// A packet that reaches a bridge port's ingress with no socket is counted,
// as two do by nature: one the container forwards from a namespace behind
// it, which its own IP layer took the socket from, and an IGMP report,
// which the kernel builds without one, sent as the container joins a
// group.
func TestBridgeStampCountsSocketless(t *testing.T) {
	requireBPF(t)
	objs := loadBPFObjectsStepRules(t, true)
	topo := newBridgeTopology(t, true)
	nested := topo.addNested(t)
	topo.enter(t, topo.rtr)
	stamp, err := tc.AttachIngress(interfaceIndex(t, "c0h"), "c0h", objs.CwTcBrStamp, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(func() { stamp.Close() })
	requireSocketless(t, objs, 0)

	n := uint64(0)
	for _, dst := range []unix.Sockaddr{
		&unix.SockaddrInet4{Port: 9, Addr: netip.MustParseAddr("10.99.0.20").As4()},
		&unix.SockaddrInet6{Port: 9, Addr: netip.MustParseAddr("fd99::20").As16()},
	} {
		family := unix.AF_INET
		if _, v6 := dst.(*unix.SockaddrInet6); v6 {
			family = unix.AF_INET6
		}
		topo.enter(t, nested)
		udp, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		require.NoError(t, err)
		t.Cleanup(func() { unix.Close(udp) })
		n = sendUntilCounted(t, objs, n, fmt.Sprintf("a datagram (family %d) the container forwards", family), func() {
			require.NoError(t, unix.Sendto(udp, []byte("x"), 0, dst))
		})
	}

	topo.enter(t, topo.ctr)
	c0, err := net.InterfaceByName("c0")
	require.NoError(t, err)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	group := &unix.IPMreqn{Multiaddr: [4]byte{239, 1, 2, 3}, Ifindex: int32(c0.Index)}
	joined := false
	// Each join, after a leave, sends a report.
	sendUntilCounted(t, objs, n, "the IGMP report", func() {
		if joined {
			require.NoError(t, unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_DROP_MEMBERSHIP, group))
		}
		require.NoError(t, unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, group))
		joined = true
	})
	topo.enter(t, topo.rtr)
}

// markAhead attaches a program that sets mark on every packet at the head
// of the ingress of the interface at ifindex, ahead of any other, as a
// host's own program might be. Nil where the kernel has no TCX to put it
// there with.
func markAhead(t *testing.T, ifindex int, mark uint32) io.Closer {
	t.Helper()
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   markerProg(t, mark),
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})
	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Log("no TCX: the cases with a mark set ahead of the program are not run")
		return nil
	}
	require.NoError(t, err)
	return l
}

func interfaceIndex(t *testing.T, name string) int {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	require.NoError(t, err)
	return iface.Index
}

// checkUplink reads cw_tc_egress's event for the SYN to dst:80 from sport
// at the uplink: allowed by the step's rules when want, and denied by the
// job's, its step not asked, when not.
func checkUplink(t *testing.T, events *ringbuf.Reader, name string, dst netip.Addr, sport uint16, want bool) {
	t.Helper()
	checkUplinkAsked(t, events, name, dst, sport, want, want)
}

// checkUplinkAsked is checkUplink for a verdict and a step tier apart: a
// step whose rules allow nothing there is asked and denies.
func checkUplinkAsked(t *testing.T, events *ringbuf.Reader, name string, dst netip.Addr, sport uint16, want, asked bool) {
	t.Helper()
	ev := readTcEventFor(t, events, dst, 80, sport)
	require.Equal(t, want, ev.Allowed == 1, "%s: verdict", name)
	require.Equal(t, asked, ev.Flags&0x2 != 0, "%s: EVENT_FLAG_STEP_TIER", name)
}

// bridgeTopology is two scratch namespaces: ctr, a container's, whose c0
// has 10.98.0.2/24 and fd98::2/64 and its default routes by the bridge,
// and rtr, the host's, with c0's peer c0h on the bridge br0 (10.98.0.1/24,
// fd98::1/64), forwarding to the dummy uplink d0 (10.99.0.1/24, fd99::1/64),
// past which packets go nowhere. br_netfilter filters the bridge's
// traffic, as on a Docker host, or leaves it alone.
type bridgeTopology struct {
	ctr, rtr *os.File
	ip       func(args ...string)
}

func newBridgeTopology(t *testing.T, brNetfilter bool) *bridgeTopology {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		testenv.SkipUnlessStrict(t, "needs iproute2's ip")
	}
	// Ahead of the namespaces, so its cleanup runs after theirs.
	brNetfilterLoaded := brNetfilter && loadBrNetfilter(t)
	if !brNetfilter {
		_, err := os.Stat("/sys/module/br_netfilter")
		brNetfilterLoaded = err == nil
	}
	ip := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "ip %v: %s", args, out)
	}
	// One a run that died left behind, its process gone, is no one's.
	stale, _ := filepath.Glob("/run/netns/cwbr-*")
	for _, path := range stale {
		pid, _, _ := strings.Cut(strings.TrimPrefix(filepath.Base(path), "cwbr-"), "-")
		if _, err := os.Stat("/proc/" + pid); errors.Is(err, os.ErrNotExist) {
			_ = exec.Command("ip", "netns", "del", filepath.Base(path)).Run()
		}
	}
	ctr, rtr := fmt.Sprintf("cwbr-%d-c", os.Getpid()), fmt.Sprintf("cwbr-%d-r", os.Getpid())
	for _, ns := range []string{ctr, rtr} {
		ip("netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		ip("-n", ns, "link", "set", "lo", "up")
	}
	if out, err := exec.Command("ip", "-n", rtr, "link", "add", "br0", "type", "bridge").CombinedOutput(); err != nil {
		testenv.SkipUnlessStrict(t, "no bridge support: %v: %s", err, out)
	}
	if out, err := exec.Command("ip", "-n", rtr, "link", "add", "c0h", "type", "veth", "peer", "name", "c0", "netns", ctr).CombinedOutput(); err != nil {
		testenv.SkipUnlessStrict(t, "no veth support: %v: %s", err, out)
	}
	// A namespace's own br_netfilter switches, which in a new one start
	// on once the module is loaded; the host's are never touched.
	if brNetfilterLoaded {
		on := "0"
		if brNetfilter {
			on = "1"
		}
		ip("netns", "exec", rtr, "sysctl", "-qw", "net.bridge.bridge-nf-call-iptables="+on,
			"net.bridge.bridge-nf-call-ip6tables="+on)
	}
	ip("-n", rtr, "link", "set", "c0h", "master", "br0")
	ip("-n", rtr, "addr", "add", "10.98.0.1/24", "dev", "br0")
	ip("-n", rtr, "addr", "add", "fd98::1/64", "dev", "br0", "nodad")
	ip("-n", rtr, "link", "set", "br0", "up")
	ip("-n", rtr, "link", "set", "c0h", "up")
	ip("-n", rtr, "link", "add", "d0", "type", "dummy")
	ip("-n", rtr, "addr", "add", "10.99.0.1/24", "dev", "d0")
	ip("-n", rtr, "addr", "add", "fd99::1/64", "dev", "d0", "nodad")
	ip("-n", rtr, "link", "set", "d0", "up")
	ip("netns", "exec", rtr, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
	ip("-n", ctr, "addr", "add", "10.98.0.2/24", "dev", "c0")
	ip("-n", ctr, "addr", "add", "fd98::2/64", "dev", "c0", "nodad")
	ip("-n", ctr, "link", "set", "c0", "up")
	ip("-n", ctr, "route", "add", "default", "via", "10.98.0.1")
	ip("-n", ctr, "-6", "route", "add", "default", "via", "fd98::1")
	for _, ipt := range []string{"iptables", "ip6tables"} {
		if out, err := exec.Command("ip", "netns", "exec", rtr, ipt, "-t", "nat", "-A", "POSTROUTING", "-o", "d0", "-j", "MASQUERADE").CombinedOutput(); err != nil {
			t.Logf("no %s masquerade, forwarding without: %v: %s", ipt, err, out)
		}
	}

	topo := &bridgeTopology{ip: ip}
	for _, ns := range []struct {
		f    **os.File
		name string
	}{{&topo.ctr, ctr}, {&topo.rtr, rtr}} {
		f, err := os.Open("/run/netns/" + ns.name)
		require.NoError(t, err)
		t.Cleanup(func() { f.Close() })
		*ns.f = f
	}
	// The thread is the namespaces' for good, and exits with the test
	// rather than carry one back into the scheduler's pool. Subtests would
	// run on other goroutines, so the caller checks its cases inline.
	runtime.LockOSThread()
	return topo
}

// loadBrNetfilter loads br_netfilter where it is not loaded, and reports
// whether it is. One this loaded is unloaded at the end, unless something
// has come to use it since, and nothing else is: rmmod, not modprobe -r,
// which would take the bridge module with it from under another test.
func loadBrNetfilter(t *testing.T) bool {
	t.Helper()
	if _, err := os.Stat("/sys/module/br_netfilter"); err == nil {
		return true
	}
	if out, err := exec.Command("modprobe", "br_netfilter").CombinedOutput(); err != nil {
		testenv.SkipUnlessStrict(t, "cannot load br_netfilter: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if refs, err := os.ReadFile("/sys/module/br_netfilter/refcnt"); err == nil && strings.TrimSpace(string(refs)) == "0" {
			_ = exec.Command("rmmod", "br_netfilter").Run()
		}
	})
	return true
}

// addNested adds a namespace behind the container's, with n0 at
// 10.97.0.2/24 and fd97::2/64, whose default routes are the container,
// which forwards.
func (b *bridgeTopology) addNested(t *testing.T) *os.File {
	t.Helper()
	ctr, nst := fmt.Sprintf("cwbr-%d-c", os.Getpid()), fmt.Sprintf("cwbr-%d-n", os.Getpid())
	b.ip("netns", "add", nst)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", nst).Run() })
	b.ip("-n", ctr, "link", "add", "n0c", "type", "veth", "peer", "name", "n0", "netns", nst)
	b.ip("-n", ctr, "addr", "add", "10.97.0.1/24", "dev", "n0c")
	b.ip("-n", ctr, "addr", "add", "fd97::1/64", "dev", "n0c", "nodad")
	b.ip("-n", ctr, "link", "set", "n0c", "up")
	b.ip("-n", nst, "addr", "add", "10.97.0.2/24", "dev", "n0")
	b.ip("-n", nst, "addr", "add", "fd97::2/64", "dev", "n0", "nodad")
	b.ip("-n", nst, "link", "set", "n0", "up")
	b.ip("-n", nst, "route", "add", "default", "via", "10.97.0.1")
	b.ip("-n", nst, "-6", "route", "add", "default", "via", "fd97::1")
	b.ip("netns", "exec", ctr, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
	f, err := os.Open("/run/netns/" + nst)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// enter moves the test's thread into ns.
func (b *bridgeTopology) enter(t *testing.T, ns *os.File) {
	t.Helper()
	require.NoError(t, unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET))
}

func interfaceMAC(t *testing.T, name string) net.HardwareAddr {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	require.NoError(t, err)
	return iface.HardwareAddr
}

// dialSYN opens a non-blocking TCP socket in the thread's namespace, tags
// its cookie with ordinal unless that is 0, sets mark on it as SO_MARK
// unless that is 0, and starts a connect to dst:80, which sends the SYN.
// It returns the cookie and source port.
func dialSYN(t *testing.T, objs *TcBpfObjects, dst netip.Addr, ordinal, mark uint32) (uint64, uint16) {
	t.Helper()
	family := unix.AF_INET
	if dst.Is6() {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)
	if ordinal != 0 {
		require.NoError(t, objs.MapSockStep.Put(cookie, ordinal))
	}
	if mark != 0 {
		require.NoError(t, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)))
	}
	var sa unix.Sockaddr
	if dst.Is6() {
		sa = &unix.SockaddrInet6{Port: 80, Addr: dst.As16()}
	} else {
		sa = &unix.SockaddrInet4{Port: 80, Addr: dst.As4()}
	}
	err = unix.Connect(fd, sa)
	require.ErrorIs(t, err, unix.EINPROGRESS, "connect to %s", dst)
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

// stampedPastPort is a program for the bridge's own ingress, and the count
// it keeps of the packets that reach it with no socket and a stamp on
// them: stamped at the port, before br_netfilter took the socket.
func stampedPastPort(t *testing.T) (*ebpf.Program, func() uint64) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	mask, magic := StepStampMask, StepStampMagic
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.FnGetSocketCookie.Call(),
			asm.JNE.Imm(asm.R0, 0, "out"),
			asm.LoadMem(asm.R2, asm.R6, int16(unsafe.Offsetof(skBuffCtx{}.Mark)), asm.Word),
			asm.And.Imm32(asm.R2, int32(mask)),
			asm.JNE.Imm32(asm.R2, int32(magic), "out"),
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "out"),
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R0, -1).WithSymbol("out"), // TC_ACT_UNSPEC
			asm.Return(),
		},
		License: "GPL",
	})
	require.NoError(t, err)
	t.Cleanup(func() { prog.Close() })
	return prog, func() uint64 {
		var n uint64
		require.NoError(t, m.Lookup(uint32(0), &n))
		return n
	}
}

// markerProg sets mark on every packet and lets it on, as a host's own TC
// program before the bridge might.
func markerProg(t *testing.T, mark uint32) *ebpf.Program {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm32(asm.R2, int32(mark)),
			asm.StoreMem(asm.R1, int16(unsafe.Offsetof(skBuffCtx{}.Mark)), asm.R2, asm.Word),
			asm.Mov.Imm(asm.R0, -1), // TC_ACT_UNSPEC
			asm.Return(),
		},
		License: "GPL",
	})
	require.NoError(t, err)
	t.Cleanup(func() { prog.Close() })
	return prog
}

// sendFrame sends frame out the interface at ifindex from an AF_PACKET
// socket, and returns the socket's cookie.
func sendFrame(t *testing.T, ifindex int, frame []byte) uint64 {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)
	proto := binary.BigEndian.Uint16(frame[12:14])
	sll := &unix.SockaddrLinklayer{
		Protocol: binary.NativeEndian.Uint16(binary.BigEndian.AppendUint16(nil, proto)), // network order
		Ifindex:  ifindex,
	}
	require.NoError(t, unix.Sendto(fd, frame, 0, sll))
	return cookie
}

// synFrame is an Ethernet frame holding a TCP SYN from src:sport to
// dst:dport, its checksums right.
func synFrame(dstMAC, srcMAC net.HardwareAddr, src, dst netip.Addr, sport, dport uint16) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 0x01020304)
	tcp[12] = 5 << 4
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	var ip, pseudo []byte
	proto := uint16(0x0800)
	if src.Is4() {
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(tcp)))
		binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF
		ip[8] = 64
		ip[9] = ipprotoTCP
		copy(ip[12:16], src.AsSlice())
		copy(ip[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(ip[10:12], inetChecksum(0, ip))
		pseudo = append(append(append([]byte{}, ip[12:20]...), 0, ipprotoTCP), 0, byte(len(tcp)))
	} else {
		proto = 0x86DD
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(tcp)))
		ip[6] = ipprotoTCP
		ip[7] = 64
		copy(ip[8:24], src.AsSlice())
		copy(ip[24:40], dst.AsSlice())
		pseudo = append(append([]byte{}, ip[8:40]...), 0, 0, 0, byte(len(tcp)), 0, 0, 0, ipprotoTCP)
	}
	binary.BigEndian.PutUint16(tcp[16:18], inetChecksum(inetSum(0, pseudo), tcp))

	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], srcMAC)
	binary.BigEndian.PutUint16(eth[12:14], proto)
	return append(append(eth, ip...), tcp...)
}

// inetSum adds b to the ones'-complement sum, as 16-bit big-endian words.
func inetSum(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// inetChecksum is the Internet checksum of b, sum carried in.
func inetChecksum(sum uint32, b []byte) uint16 {
	sum = inetSum(sum, b)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
