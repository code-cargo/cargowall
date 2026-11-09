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
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

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
	brForeignMark   uint32 = 0x00010000 | brPolicy // a mark no stamp: its low bits read as brPolicy
)

// TestBridgeStamp drives a container's sockets through the shape Docker
// gives it: the container's namespace, a veth into the host's, a bridge
// there, forwarding (masquerading, where iptables is there) and an uplink
// with cw_tc_egress on it, cw_tc_br_stamp on the bridge's ingress. The
// job's rules allow nothing, the default denies, and step policy brPolicy
// allows 10.99.0.20 and fd99::20: a SYN to it gets through only with a
// stamp of brPolicy, which only a socket tagged with a step bound to it
// may get. Nothing else gets one: not an untagged or unbound socket, nor a
// mark the container set (cleared as the packet leaves its namespace), or
// a stamp set on the host's side before the bridge (cleared there), or a
// packet another mark is on (left as it is, unstamped). A host socket's
// mark in the stamp's range is never read as one, nor is an AF_PACKET
// frame a tagged thread sends: packet sockets get no tag.
//
// ci-kernels have no bridge or veth: there it skips, and CI's runner
// kernels run it.
func TestBridgeStamp(t *testing.T) {
	requireBPF(t)
	objs := loadBPFObjectsStepRules(t, true)
	put := func(m *ebpf.Map, k, v any) { require.NoError(t, m.Put(k, v)) }
	put(objs.MapAuditMode, uint32(0), uint8(0))
	put(objs.MapDefaultAction, uint32(0), uint8(0))
	put(objs.MapCidrs, RuleKey(brPolicy, 32, ipToU32("10.99.0.20")), TcBpfLpmVal{Action: 1})
	put(objs.MapCidrsV6, RuleKeyV6(brPolicy, 128, netip.MustParseAddr("fd99::20").As16()), TcBpfLpmVal{Action: 1})
	put(objs.MapStepPolicy, brOrdinal, brPolicy)
	put(objs.MapStepPolicy, brOrdinalWide, brPolicyTooWide)
	events, err := ringbuf.NewReader(objs.MapEvents)
	require.NoError(t, err)
	t.Cleanup(func() { events.Close() })

	topo := newBridgeTopology(t)
	topo.enter(t, topo.rtr)
	logger := slog.New(slog.DiscardHandler)
	stamp, err := tc.AttachIngress("br0", objs.CwTcBrStamp, logger)
	require.NoError(t, err)
	t.Cleanup(func() { stamp.Close() })
	uplink, err := tc.AttachEgress("d0", objs.CwTcEgress, logger)
	require.NoError(t, err)
	t.Cleanup(func() { uplink.Close() })
	brMAC := interfaceMAC(t, "br0")

	for _, dst := range []netip.Addr{netip.MustParseAddr("10.99.0.20"), netip.MustParseAddr("fd99::20")} {
		// From the container.
		check := func(name string, ordinal, mark uint32, want bool) {
			t.Helper()
			topo.enter(t, topo.ctr)
			_, sport := dialSYN(t, objs, dst, ordinal, mark)
			topo.enter(t, topo.rtr)
			checkUplink(t, events, fmt.Sprintf("%s to %s", name, dst), dst, sport, want)
		}
		check("bound step", brOrdinal, 0, true)
		check("untagged", 0, 0, false)
		check("unbound step", brOrdinalUnb, 0, false)
		check("step bound past the stamp's range", brOrdinalWide, 0, false)
		check("forged stamp, set in the container", 0, StepStampMagic|brPolicy, false)

		marker := markerProg(t, StepStampMagic|brPolicy)
		m, err := tc.AttachIngress("c0h", marker, logger)
		require.NoError(t, err)
		check("forged stamp, set on the host's side", 0, 0, false)
		require.NoError(t, m.Close())
		m, err = tc.AttachIngress("c0h", markerProg(t, brForeignMark), logger)
		require.NoError(t, err)
		check("bound step, another mark on its packets", brOrdinal, 0, false)
		require.NoError(t, m.Close())
		check("bound step, the marks gone", brOrdinal, 0, true)

		// From a host socket: its own mark is no stamp.
		_, sport := dialSYN(t, objs, dst, 0, StepStampMagic|brPolicy)
		checkUplink(t, events, fmt.Sprintf("host socket with a stamp's mark to %s", dst), dst, sport, false)
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
}

// checkUplink reads cw_tc_egress's event for the SYN to dst:80 from sport
// at the uplink: allowed by the step's rules when want, and denied by the
// job's, its step not asked, when not.
func checkUplink(t *testing.T, events *ringbuf.Reader, name string, dst netip.Addr, sport uint16, want bool) {
	t.Helper()
	ev := readTcEventFor(t, events, dst, 80, sport)
	require.Equal(t, want, ev.Allowed == 1, "%s: verdict", name)
	require.Equal(t, want, ev.Flags&0x2 != 0, "%s: EVENT_FLAG_STEP_TIER", name)
}

// bridgeTopology is two scratch namespaces: ctr, a container's, whose c0
// has 10.98.0.2/24 and fd98::2/64 and its default routes by the bridge,
// and rtr, the host's, with c0's peer c0h on the bridge br0 (10.98.0.1/24,
// fd98::1/64), forwarding to the dummy uplink d0 (10.99.0.1/24, fd99::1/64),
// past which packets go nowhere.
type bridgeTopology struct {
	ctr, rtr *os.File
}

func newBridgeTopology(t *testing.T) *bridgeTopology {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2's ip")
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
		t.Skipf("no bridge support: %v: %s", err, out)
	}
	if out, err := exec.Command("ip", "-n", rtr, "link", "add", "c0h", "type", "veth", "peer", "name", "c0", "netns", ctr).CombinedOutput(); err != nil {
		t.Skipf("no veth support: %v: %s", err, out)
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

	topo := &bridgeTopology{}
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
