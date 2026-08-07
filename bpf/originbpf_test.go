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
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// originEventT mirrors struct origin_event in originbpf.c (72 bytes packed;
// 8-byte fields first so the packed C layout equals Go's natural layout).
type originEventT struct {
	Cookie    uint64
	CgroupID  uint64
	Timestamp uint64
	SrcIp     uint32
	DstIp     uint32
	SrcIp6    [16]byte
	DstIp6    [16]byte
	SrcPort   uint16
	DstPort   uint16
	IpVersion uint8
	IpProto   uint8
	Flags     uint8
	Pad       uint8
}

// originFlagTCPSyn mirrors ORIGIN_FLAG_TCP_SYN in originbpf.c.
const originFlagTCPSyn = 0x1

func loadOriginObjects(t *testing.T) *OriginBpfObjects {
	t.Helper()
	requireBPF(t)
	var objs OriginBpfObjects
	if err := LoadOriginBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loading origin objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// Note on PROG_TEST_RUN inputs: for non-L2 program types like cgroup_skb the
// kernel consumes the first 14 bytes of the test payload as a pseudo-Ethernet
// header (eth_type_trans), so the program's data starts at the IP header —
// exactly like a live cgroup_skb invocation. The existing tcbpf crafters
// therefore work unchanged, and every input must be at least 14 bytes.

// TestOriginEgressAlwaysAllows pins the observer's zero-enforcement-risk
// property: whatever the packet — valid, truncated, malformed, fragmented,
// garbage — cg_origin_egress must return 1 (pass). This is the safety
// contract phase 3a rests on; if this test fails, the program is no longer
// an observer.
func TestOriginEgressAlwaysAllows(t *testing.T) {
	objs := loadOriginObjects(t)

	tests := []struct {
		name   string
		packet []byte
	}{
		{"IPv4 TCP SYN", craftIPv4TCP(t, "140.82.114.3", 443)},
		{"IPv4 TCP ACK only", craftIPv4TCPWithFlags(t, "140.82.114.3", 443, 0x10)},
		{"IPv4 TCP with IP options", craftIPv4WithOptionsTCP(t, "140.82.114.3", 443)},
		{"IPv4 UDP", craftIPv4UDP(t, "8.8.8.8", 53)},
		{"IPv4 first fragment", craftIPv4FirstFragment(t, "140.82.114.3", 443)},
		{"IPv4 non-first fragment", craftIPv4NonFirstFragment(t, "140.82.114.3")},
		// craftTruncatedIPv4 is absent by necessity, not oversight: the
		// kernel EINVALs a cgroup_skb test run whose ethertype says IPv4 but
		// whose payload is shorter than a full IP header, so that input
		// never reaches the program. The equivalent program path (version
		// nibble 4, truncated header, load_bytes fails) is exercised by
		// "garbage nibble 4 truncated" below via a non-IP ethertype.
		{"IPv4 invalid IHL", craftInvalidIHLIPv4(t)},
		{"IPv4 truncated TCP", craftTruncatedTCP(t)},
		{"IPv6 TCP SYN", craftIPv6TCP(t, "2606:4700::1", 443)},
		{"IPv6 TCP behind ext header", craftIPv6ExtHdrTCP(t, "2606:4700::1", 443, ipprotoHopOpts)},
		{"IPv6 multicast", craftIPv6Multicast(t)},
		{"IPv6 ICMPv6 NDP", craftICMPv6NDP(t)},
		{"IPv6 fragmented ICMPv6 non-first", craftIPv6FragmentedICMPv6(t, false)},
		{"ARP (non-IP nibble)", craftARP(t)},
		{"empty L3 (14-byte input)", make([]byte, 14)},
		{"one garbage byte", append(make([]byte, 14), 0xFF)},
		{"garbage nibble 4 truncated", append(make([]byte, 14), 0x45, 0xDE, 0xAD)},
		{"garbage nibble 6 truncated", append(make([]byte, 14), 0x60, 0xDE, 0xAD)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.CgOriginEgress.Test(tt.packet)
			require.NoError(t, err)
			require.Equal(t, uint32(1), ret, "observer must pass every packet")
		})
	}
}

// drainOriginRecords reads every already-buffered origin record and returns
// those a previous subtest hasn't consumed, filtered out. It uses a short
// deadline poll so "no record emitted" cases don't hang.
func collectOriginRecords(t *testing.T, rd *ringbuf.Reader, wait time.Duration) []originEventT {
	t.Helper()
	var out []originEventT
	rd.SetDeadline(time.Now().Add(wait))
	for {
		record, err := rd.Read()
		if err != nil {
			return out // deadline: nothing more buffered
		}
		require.GreaterOrEqual(t, len(record.RawSample), int(unsafe.Sizeof(originEventT{})))
		out = append(out, *(*originEventT)(unsafe.Pointer(&record.RawSample[0])))
	}
}

// TestOriginEmission verifies what the observer records and — just as
// important — what it deliberately does not: one record per flow origin with
// correct tuple/flags, dedup inside the re-emit interval, and silence for
// established-flow segments, fragments, multicast, and ICMPv6.
//
// Each PROG_TEST_RUN invocation allocates a fresh dummy socket, so records
// across invocations carry distinct cookies; dedup is only observable via
// Repeat within one invocation.
func TestOriginEmission(t *testing.T) {
	objs := loadOriginObjects(t)

	rd, err := ringbuf.NewReader(objs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	run := func(t *testing.T, pkt []byte, repeat int) {
		t.Helper()
		ret, err := objs.CgOriginEgress.Run(&ebpf.RunOptions{
			Data:   pkt,
			Repeat: uint32(repeat),
		})
		require.NoError(t, err)
		require.Equal(t, uint32(1), ret)
	}

	t.Run("IPv4 TCP SYN emits one record", func(t *testing.T) {
		run(t, craftIPv4TCP(t, "140.82.114.3", 443), 1)
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 1)
		r := recs[0]
		require.Equal(t, uint8(4), r.IpVersion)
		require.Equal(t, uint8(ipprotoTCP), r.IpProto)
		require.Equal(t, uint8(originFlagTCPSyn), r.Flags)
		require.Equal(t, uint32(0x8C527203), r.DstIp) // 140.82.114.3 host order
		require.Equal(t, uint32(0xC0A80164), r.SrcIp) // 192.168.1.100 (crafter src)
		require.Equal(t, uint16(443), r.DstPort)
		require.Equal(t, uint16(12345), r.SrcPort)
		require.NotZero(t, r.Cookie, "test-run skb carries a real socket")
		require.NotZero(t, r.Timestamp)
	})

	t.Run("repeat within interval dedups", func(t *testing.T) {
		run(t, craftIPv4TCP(t, "140.82.114.4", 443), 8)
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 1, "same socket+tuple must emit once per interval")
	})

	t.Run("IPv4 TCP ACK-only is silent", func(t *testing.T) {
		run(t, craftIPv4TCPWithFlags(t, "140.82.114.5", 443, 0x10), 1)
		// Marker packet proves the pipeline is live and orders the assertion.
		run(t, craftIPv4TCP(t, "10.99.0.1", 999), 1)
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 1)
		require.Equal(t, uint16(999), recs[0].DstPort, "only the marker may emit")
	})

	t.Run("IPv4 UDP emits", func(t *testing.T) {
		run(t, craftIPv4UDP(t, "8.8.8.8", 53), 1)
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 1)
		require.Equal(t, uint8(ipprotoUDP), recs[0].IpProto)
		require.Equal(t, uint16(53), recs[0].DstPort)
		require.Zero(t, recs[0].Flags)
	})

	t.Run("IPv4 ICMP emits with ports zero", func(t *testing.T) {
		eth := craftEthHeader(ethPIP)
		icmp := make([]byte, 8)
		icmp[0] = 8 // echo request
		ip := craftIPv4Header("1.1.1.1", ipprotoICMP, len(icmp))
		pkt := append(append(eth, ip...), icmp...)
		run(t, pkt, 1)
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 1)
		require.Equal(t, uint8(ipprotoICMP), recs[0].IpProto)
		require.Zero(t, recs[0].SrcPort)
		require.Zero(t, recs[0].DstPort)
	})

	t.Run("IPv6 TCP SYN emits, also behind ext header", func(t *testing.T) {
		run(t, craftIPv6TCP(t, "2606:4700::1", 443), 1)
		run(t, craftIPv6ExtHdrTCP(t, "2606:4700::2", 8443, ipprotoHopOpts), 1)
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 2)
		require.Equal(t, uint8(6), recs[0].IpVersion)
		require.Equal(t, net.ParseIP("2606:4700::1").To16(), net.IP(recs[0].DstIp6[:]))
		require.Equal(t, net.ParseIP("fe80::1").To16(), net.IP(recs[0].SrcIp6[:]))
		require.Equal(t, uint16(443), recs[0].DstPort)
		require.Equal(t, uint8(originFlagTCPSyn), recs[0].Flags)
		require.Equal(t, uint16(8443), recs[1].DstPort, "ext-header walk must reach TCP")
	})

	t.Run("fragments, multicast, ICMPv6 are silent", func(t *testing.T) {
		run(t, craftIPv4NonFirstFragment(t, "140.82.114.3"), 1)
		run(t, craftIPv6Multicast(t), 1)
		run(t, craftICMPv6NDP(t), 1)
		run(t, craftIPv6FragmentedICMPv6(t, false), 1)
		run(t, craftIPv4TCP(t, "10.99.0.2", 998), 1) // marker
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 1)
		require.Equal(t, uint16(998), recs[0].DstPort, "only the marker may emit")
	})
}

// TestOriginEventLayoutMatchesBTF pins the kernel↔userspace record layout the
// same way TestBlockedEventLayoutMatchesBTF does for the TC event: every C
// member must sit at its Go mirror offset, and a C member without a mirror
// field fails loudly.
func TestOriginEventLayoutMatchesBTF(t *testing.T) {
	spec, err := LoadOriginBpf()
	require.NoError(t, err)

	typ, err := spec.Types.AnyTypeByName("origin_event")
	require.NoError(t, err)
	st, ok := typ.(*btf.Struct)
	require.True(t, ok, "origin_event must be a struct, got %T", typ)

	var evt originEventT
	require.Equal(t, uint32(unsafe.Sizeof(evt)), st.Size, "struct size")

	goOffsets := map[string]uintptr{
		"cookie":     unsafe.Offsetof(evt.Cookie),
		"cgroup_id":  unsafe.Offsetof(evt.CgroupID),
		"timestamp":  unsafe.Offsetof(evt.Timestamp),
		"src_ip":     unsafe.Offsetof(evt.SrcIp),
		"dst_ip":     unsafe.Offsetof(evt.DstIp),
		"src_ip6":    unsafe.Offsetof(evt.SrcIp6),
		"dst_ip6":    unsafe.Offsetof(evt.DstIp6),
		"src_port":   unsafe.Offsetof(evt.SrcPort),
		"dst_port":   unsafe.Offsetof(evt.DstPort),
		"ip_version": unsafe.Offsetof(evt.IpVersion),
		"ip_proto":   unsafe.Offsetof(evt.IpProto),
		"flags":      unsafe.Offsetof(evt.Flags),
		"pad":        unsafe.Offsetof(evt.Pad),
	}

	seen := make(map[string]bool)
	for _, m := range st.Members {
		want, known := goOffsets[m.Name]
		require.True(t, known, "C member %q has no Go mirror field", m.Name)
		require.Equal(t, want, uintptr(m.Offset.Bytes()), "offset of %q", m.Name)
		seen[m.Name] = true
	}
	require.Len(t, seen, len(goOffsets), "Go mirror has fields the C struct lacks")
}

// TestOriginRealSocket closes the gap PROG_TEST_RUN can't cover (its socket
// cookies are unknowable): attach at the real root cgroup, dial through a
// real socket, and assert the record's cookie equals the socket's SO_COOKIE
// and that the cookie resolves to our pid via the tcbpf map — an end-to-end
// rehearsal of exactly the read-time join pkg/origin performs.
func TestOriginRealSocket(t *testing.T) {
	objs := loadOriginObjects(t)
	tcObjs := loadBPFObjects(t)

	originLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgOriginEgress,
	})
	if err != nil {
		t.Skipf("cannot attach cgroup_skb/egress at root cgroup: %v", err)
	}
	t.Cleanup(func() { originLink.Close() })

	connectLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: tcObjs.CgConnect4,
	})
	require.NoError(t, err, "attach cgroup connect4")
	t.Cleanup(func() { connectLink.Close() })

	rd, err := ringbuf.NewReader(objs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	conn, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	var wantCookie uint64
	raw, err := conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	require.NoError(t, raw.Control(func(fd uintptr) {
		wantCookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}))
	require.NoError(t, err)
	require.NotZero(t, wantCookie)

	// The root-cgroup attachment observes every flow on the host; scan for
	// ours by cookie+tuple.
	rd.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		record, err := rd.Read()
		require.NoError(t, err, "origin record for the dialed connection must arrive")
		require.GreaterOrEqual(t, len(record.RawSample), int(unsafe.Sizeof(originEventT{})))
		r := *(*originEventT)(unsafe.Pointer(&record.RawSample[0]))
		if r.Cookie != wantCookie {
			continue
		}
		require.Equal(t, uint8(4), r.IpVersion)
		require.Equal(t, uint8(ipprotoTCP), r.IpProto)
		require.Equal(t, uint8(originFlagTCPSyn), r.Flags)
		require.Equal(t, uint32(0x7F000001), r.DstIp, "dst must be 127.0.0.1")
		require.Equal(t, port, r.DstPort)
		require.NotZero(t, r.CgroupID, "real socket must carry its cgroup id")

		// The read-time join pkg/origin performs: cookie → pid via the tcbpf
		// map the connect4 hook populates.
		var pid uint32
		require.NoError(t, tcObjs.MapSockPid.Lookup(r.Cookie, &pid))
		require.Equal(t, uint32(os.Getpid()), pid)
		break
	}
}
