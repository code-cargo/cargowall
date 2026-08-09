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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	cargowallNet "github.com/code-cargo/cargowall/pkg/network"
)

// Mode and verdict constants, mirroring ORIGIN_MODE_* / ORIGIN_VERDICT_* in
// originbpf.c (the numeric values are pinned to the C source by
// TestOriginConstantsMatchBpfSource in pkg/origin). The event struct itself
// is NOT mirrored here: these tests use OriginEvent from origin_event.go —
// the same struct pkg/origin casts ringbuf bytes to in production — so the
// layout test below validates the layout the reader actually uses.
const (
	originModeObserve = 0
	originModeShadow  = 1
	originModeEnforce = 2

	originVerdictNone       = 0
	originVerdictAllow      = 1
	originVerdictWouldBlock = 2
	originVerdictBlock      = 3

	// originCfgKeyLoCarveout mirrors ORIGIN_CFG_KEY_LO_CARVEOUT in
	// originbpf.c (pinned by TestOriginConstantsMatchBpfSource in
	// pkg/origin).
	originCfgKeyLoCarveout = 1

	// dnsProxyFWMark mirrors DNS_PROXY_FW_MARK in verdict.h (and
	// pkg/network.DNSProxyFWMark); pinned by
	// TestDNSProxyFWMarkMatchesGoConstant.
	dnsProxyFWMark = 0xCA12
)

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

// setOriginMode raises the hook's posture for the rest of the test.
func setOriginMode(t *testing.T, objs *OriginBpfObjects, mode uint8) {
	t.Helper()
	require.NoError(t, objs.MapOriginConfig.Put(uint32(0), mode))
}

// seedOriginRules programs a deny-by-default policy with one allowed /24
// into the maps the cgroup hook reads, so verdict tests exercise the real
// lookup path rather than only the default action.
func seedOriginRules(t *testing.T, objs *OriginBpfObjects) {
	t.Helper()
	require.NoError(t, objs.MapDefaultAction.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapCidrs.Put(
		OriginBpfLpmKey{Prefixlen: 24, Ip: ipToU32("140.82.114.0")},
		OriginBpfLpmVal{Action: 1},
	))
	require.NoError(t, objs.MapCidrsV6.Put(
		originV6Key(t, 32, "2606:4700::"),
		OriginBpfLpmVal{Action: 1},
	))
}

func originV6Key(t *testing.T, prefixlen uint32, addr string) OriginBpfLpmKeyV6 {
	t.Helper()
	key := OriginBpfLpmKeyV6{Prefixlen: prefixlen}
	ip := net.ParseIP(addr).To16()
	require.NotNil(t, ip, "bad v6 addr %q", addr)
	copy(key.Ip[:], ip)
	return key
}

// Note on PROG_TEST_RUN inputs: for non-L2 program types like cgroup_skb the
// kernel consumes the first 14 bytes of the test payload as a pseudo-Ethernet
// header (eth_type_trans), so the program's data starts at the IP header —
// exactly like a live cgroup_skb invocation. The existing tcbpf crafters
// therefore work unchanged, and every input must be at least 14 bytes.

// TestOriginEgressPassesInNonEnforcingModes pins the safety property the
// mode ladder rests on: in observe (phase 3a) and shadow, whatever the
// packet — valid, truncated, malformed, fragmented, garbage — and whatever
// the policy, cg_origin_egress must return 1 (pass). Only enforce mode may
// ever drop. If this fails, turning container attribution on has silently
// started blocking traffic.
func TestOriginEgressPassesInNonEnforcingModes(t *testing.T) {
	objs := loadOriginObjects(t)
	// Deny-all policy: in an enforcing mode nearly every packet below would
	// drop, so passing proves the mode gate holds rather than the policy.
	seedOriginRules(t, objs)

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

	for _, mode := range []uint8{originModeObserve, originModeShadow} {
		setOriginMode(t, objs, mode)
		for _, tt := range tests {
			t.Run(fmt.Sprintf("mode%d/%s", mode, tt.name), func(t *testing.T) {
				ret, _, err := objs.CgOriginEgress.Test(tt.packet)
				require.NoError(t, err)
				require.Equal(t, uint32(1), ret, "non-enforcing modes must pass every packet")
			})
		}
	}
}

// drainOriginRecords reads every already-buffered origin record and returns
// those a previous subtest hasn't consumed, filtered out. It uses a short
// deadline poll so "no record emitted" cases don't hang.
func collectOriginRecords(t *testing.T, rd *ringbuf.Reader, wait time.Duration) []OriginEvent {
	t.Helper()
	var out []OriginEvent
	rd.SetDeadline(time.Now().Add(wait))
	for {
		record, err := rd.Read()
		if err != nil {
			return out // deadline: nothing more buffered
		}
		require.GreaterOrEqual(t, len(record.RawSample), int(unsafe.Sizeof(OriginEvent{})))
		out = append(out, *(*OriginEvent)(unsafe.Pointer(&record.RawSample[0])))
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
		require.Equal(t, uint8(OriginFlagTCPSyn), r.Flags)
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
		require.Equal(t, uint8(OriginFlagTCPSyn), recs[0].Flags)
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

// TestOriginEgressEnforceVerdicts is the phase-3b enforcement contract: in
// enforce mode the hook drops denied destinations (0) and passes allowed
// ones (1), and malformed packets fail closed exactly as tc_egress does.
func TestOriginEgressEnforceVerdicts(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	tests := []struct {
		name    string
		packet  []byte
		wantRet uint32
	}{
		{"allowed v4 dst", craftIPv4TCP(t, "140.82.114.3", 443), 1},
		{"denied v4 dst (default deny)", craftIPv4TCP(t, "93.184.216.34", 443), 0},
		{"denied v4 UDP", craftIPv4UDP(t, "93.184.216.34", 9999), 0},
		{"allowed v6 dst", craftIPv6TCP(t, "2606:4700::1", 443), 1},
		{"denied v6 dst", craftIPv6TCP(t, "2001:db8::1", 443), 0},
		// Established segments are adjudicated too — an allowlist change
		// must be able to kill a live flow, as it does at TC.
		{"denied v4 established ACK", craftIPv4TCPWithFlags(t, "93.184.216.34", 443, 0x10), 0},
		{"allowed v4 established ACK", craftIPv4TCPWithFlags(t, "140.82.114.3", 443, 0x10), 1},
		// Fail-closed on malformed, matching check_audit_or_block.
		{"invalid IHL fails closed", craftInvalidIHLIPv4(t), 0},
		{"truncated TCP fails closed", craftTruncatedTCP(t), 0},
		// Carve-outs survive enforcement.
		{"loopback dst", craftIPv4TCP(t, "127.0.0.1", 8080), 1},
		{"IPv6 loopback dst", craftIPv6TCP(t, "::1", 8080), 1},
		{"ICMPv4", craftIPv4ICMP(t, "93.184.216.34"), 1},
		{"IPv6 multicast", craftIPv6Multicast(t), 1},
		{"IPv6 ICMPv6 NDP", craftICMPv6NDP(t), 1},
		// Non-IP is passed, as at TC.
		{"ARP", craftARP(t), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.CgOriginEgress.Test(tt.packet)
			require.NoError(t, err)
			require.Equal(t, tt.wantRet, ret)
		})
	}
}

// The verdict label on each emitted record is what userspace turns into an
// audit event, so it must say exactly what happened: nothing was evaluated
// (observe), denied-but-passed (shadow), or denied-and-dropped (enforce).
// Getting this wrong would either overstate what the firewall blocked or
// hide a real drop.
func TestOriginEgressVerdictLabels(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)

	rd, err := ringbuf.NewReader(objs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	// Distinct destinations per case: the emit dedup is keyed by
	// cookie+destination, and PROG_TEST_RUN reuses a socket within a run.
	tests := []struct {
		name        string
		mode        uint8
		dst         string
		auditMode   uint8
		wantVerdict uint8
	}{
		{"observe records no verdict", originModeObserve, "203.0.113.10", 0, originVerdictNone},
		{"shadow denies without blocking", originModeShadow, "203.0.113.11", 0, originVerdictWouldBlock},
		{"shadow allows", originModeShadow, "140.82.114.9", 0, originVerdictAllow},
		{"enforce blocks", originModeEnforce, "203.0.113.12", 0, originVerdictBlock},
		{"enforce allows", originModeEnforce, "140.82.114.10", 0, originVerdictAllow},
		// Audit posture downgrades a drop to a would-block: the record must
		// not claim the packet was dropped, because it wasn't.
		{"enforce under audit downgrades to would-block", originModeEnforce, "203.0.113.13", 1, originVerdictWouldBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOriginMode(t, objs, tt.mode)
			require.NoError(t, objs.MapAuditMode.Put(uint32(0), tt.auditMode))

			_, _, err := objs.CgOriginEgress.Test(craftIPv4TCP(t, tt.dst, 443))
			require.NoError(t, err)

			recs := collectOriginRecords(t, rd, 500*time.Millisecond)
			require.Len(t, recs, 1, "exactly one record for this flow")
			require.Equal(t, tt.wantVerdict, recs[0].Verdict)
		})
	}
}

// The loopback-DEVICE carve-out (origin_lo_carveout): traffic egressing lo
// never leaves the host — including flows to the host's OWN non-loopback
// address — and was never policed by TC, so the armed hook must not
// adjudicate it. Every PROG_TEST_RUN skb rides the netns loopback device,
// which is exactly why the carve-out is a config byte: armed (as pkg/origin
// always arms it in production) even a denied destination passes here;
// unarmed — the default for a fresh collection, and how every other test in
// this file runs — the same packet drops, proving the verdict path is
// reachable at all.
func TestOriginEgressLoopbackDeviceCarveOut(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	pkt4 := craftIPv4TCP(t, "93.184.216.34", 443) // denied dst
	pkt6 := craftIPv6TCP(t, "2001:db8::1", 443)   // denied dst

	ret, _, err := objs.CgOriginEgress.Test(pkt4)
	require.NoError(t, err)
	require.Equal(t, uint32(0), ret, "unarmed: denied v4 dst must drop")
	ret, _, err = objs.CgOriginEgress.Test(pkt6)
	require.NoError(t, err)
	require.Equal(t, uint32(0), ret, "unarmed: denied v6 dst must drop")

	require.NoError(t, objs.MapOriginConfig.Put(uint32(originCfgKeyLoCarveout), uint8(1)))
	ret, _, err = objs.CgOriginEgress.Test(pkt4)
	require.NoError(t, err)
	require.Equal(t, uint32(1), ret, "armed: test skbs ride lo, local-only v4 traffic must pass")
	ret, _, err = objs.CgOriginEgress.Test(pkt6)
	require.NoError(t, err)
	require.Equal(t, uint32(1), ret, "armed: test skbs ride lo, local-only v6 traffic must pass")
}

// Denial reporting must mirror tc_egress's policy, not just its verdict: a
// killed established flow is emitted (flagged mid-stream), while kernel RST
// replies to inbound port scans and SYN-ACK replies to inbound handshakes
// stay silent — on a public CI runner those arrive constantly and would
// otherwise flood the audit stream as killed egress connections.
func TestOriginDenialEmissionMirrorsTC(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeShadow)

	rd, err := ringbuf.NewReader(objs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	t.Run("denied established ACK emits mid-stream", func(t *testing.T) {
		_, _, err := objs.CgOriginEgress.Test(craftIPv4TCPWithFlags(t, "203.0.113.20", 443, 0x10))
		require.NoError(t, err)
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 1)
		require.Equal(t, uint8(OriginFlagTCPMidstream), recs[0].Flags)
		require.Equal(t, uint8(originVerdictWouldBlock), recs[0].Verdict)
	})

	t.Run("denied RST and SYN-ACK replies are silent", func(t *testing.T) {
		_, _, err := objs.CgOriginEgress.Test(craftIPv4TCPWithFlags(t, "203.0.113.21", 443, 0x14)) // ACK|RST
		require.NoError(t, err)
		_, _, err = objs.CgOriginEgress.Test(craftIPv4TCPWithFlags(t, "203.0.113.22", 443, 0x12)) // SYN|ACK
		require.NoError(t, err)
		// Marker packet proves the pipeline is live and orders the assertion.
		_, _, err = objs.CgOriginEgress.Test(craftIPv4TCP(t, "10.99.0.3", 997))
		require.NoError(t, err)
		recs := collectOriginRecords(t, rd, 500*time.Millisecond)
		require.Len(t, recs, 1)
		require.Equal(t, uint16(997), recs[0].DstPort, "only the marker may emit")
	})
}

// A verdict CHANGE must re-emit within the dedup interval. Otherwise a tuple
// that emitted verdict-NONE just before enableMode raised the hook (startup
// traffic, a long-lived runner connection) has its first enforced drop
// suppressed for up to 10s — a drop with no record, no audit event, and no
// late-allow reconciliation, on the very packet that dies before TC can see
// it. PROG_TEST_RUN can't reach this (each invocation mints a fresh socket
// cookie), so this test attaches to a private cgroup, moves itself in, and
// reuses one real socket across the mode raise; the deny-all enforce policy
// can therefore never affect anything but this test process.
func TestOriginVerdictChangeReemitsWithinInterval(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeObserve)

	cgRoot := "/sys/fs/cgroup"
	cgPath := filepath.Join(cgRoot, fmt.Sprintf("cargowall-origin-test-%d", os.Getpid()))
	if err := os.Mkdir(cgPath, 0o755); err != nil {
		t.Skipf("cannot create test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cgPath) })
	self := []byte(strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"), self, 0); err != nil {
		t.Skipf("cannot enter test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(cgRoot, "cgroup.procs"), self, 0) })

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgOriginEgress,
	})
	if err != nil {
		t.Skipf("cannot attach cgroup_skb/egress at test cgroup: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	rd, err := ringbuf.NewReader(objs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	// TEST-NET-3 (RFC 5737): reserved and unroutable — deliverability is
	// irrelevant, only adjudication by THIS test's hook is. Expected side
	// effect when a production cargowall polices the same machine (CI
	// runners): the observe-phase datagram below legitimately leaves this
	// test's cgroup and is then blocked and audited by the runner's TC as
	// "Connection blocked ... dst=203.0.113.9 process=bpf.test" — one line
	// per run, noise, not a leak. If the runner's cargowall is itself
	// cgroup-enforcing, the first write fails with EPERM and this test
	// skips instead.
	conn, err := net.Dial("udp4", "203.0.113.9:9999")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	findRecord := func(wantVerdict uint8) bool {
		for _, r := range collectOriginRecords(t, rd, time.Second) {
			if r.IpVersion == 4 && r.DstIp == 0xCB007109 && r.DstPort == 9999 && r.Verdict == wantVerdict {
				return true
			}
		}
		return false
	}

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Skipf("no route for test egress: %v", err)
	}
	require.True(t, findRecord(originVerdictNone), "observe-mode record for the flow must arrive")

	// Same socket, same tuple, well inside the dedup interval — only the
	// verdict differs. The enforced drop must still produce a record.
	setOriginMode(t, objs, originModeEnforce)
	_, werr := conn.Write([]byte("x"))
	require.Error(t, werr, "enforce mode must drop the denied datagram")
	require.True(t, findRecord(originVerdictBlock),
		"the first enforced drop after a verdict change must emit despite the dedup interval")
}

// Audit posture is the run's single source of truth for "log, never block".
// It must hold at this hook exactly as it does at TC, even in enforce mode.
func TestOriginEgressAuditModeNeverDrops(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)
	require.NoError(t, objs.MapAuditMode.Put(uint32(0), uint8(1)))

	ret, _, err := objs.CgOriginEgress.Test(craftIPv4TCP(t, "93.184.216.34", 443))
	require.NoError(t, err)
	require.Equal(t, uint32(1), ret, "audit mode must pass traffic enforce mode would drop")
}

// skBuffCtx mirrors struct __sk_buff for PROG_TEST_RUN's ctx_in. The kernel
// validates the size exactly and copies a subset of fields (mark among
// them) onto the test skb, so the whole struct must be present even though
// only Mark is set here.
type skBuffCtx struct {
	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VlanPresent    uint32
	VlanTci        uint32
	VlanProto      uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
	TcIndex        uint32
	Cb             [5]uint32
	Hash           uint32
	TcClassid      uint32
	Data           uint32
	DataEnd        uint32
	NapiID         uint32
	Family         uint32
	RemoteIP4      uint32
	LocalIP4       uint32
	RemoteIP6      [4]uint32
	LocalIP6       [4]uint32
	RemotePort     uint32
	LocalPort      uint32
	DataMeta       uint32
	FlowKeys       uint64
	Tstamp         uint64
	WireLen        uint32
	GsoSegs        uint32
	Sk             uint64
	GsoSize        uint32
	TstampType     uint32
	_              [2]uint32
	Hwtstamp       uint64
}

// The DNS proxy's own upstream queries carry SO_MARK 0xCA12. They must never
// be adjudicated, so a policy race can't let the proxy self-block the very
// lookups that populate the allowlist.
func TestOriginEgressSkipsDNSProxyMark(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	pkt := craftIPv4UDP(t, "93.184.216.34", 53) // denied dst

	// Without the mark the same packet is dropped — so a pass below can only
	// be the mark carve-out, not a lenient policy.
	ret, _, err := objs.CgOriginEgress.Test(pkt)
	require.NoError(t, err)
	require.Equal(t, uint32(0), ret, "unmarked traffic to a denied dst must drop")

	in := skBuffCtx{Mark: dnsProxyFWMark}
	out := skBuffCtx{}
	ret, err = objs.CgOriginEgress.Run(&ebpf.RunOptions{
		Data:       pkt,
		Context:    in,
		ContextOut: &out,
	})
	if err != nil {
		t.Skipf("kernel rejected __sk_buff ctx_in for cgroup_skb test run: %v", err)
	}
	require.Equal(t, uint32(1), ret, "marked proxy traffic must bypass the verdict")
}

// dnsProxyFWMark must equal the Go constant the DNS proxy actually sets on
// its upstream socket; the BPF side mirrors it in verdict.h, and a drift
// would silently un-exempt the proxy.
func TestDNSProxyFWMarkMatchesGoConstant(t *testing.T) {
	src, err := os.ReadFile("verdict.h")
	require.NoError(t, err)
	require.Contains(t, string(src), fmt.Sprintf("#define DNS_PROXY_FW_MARK 0x%X", cargowallNet.DNSProxyFWMark),
		"verdict.h DNS_PROXY_FW_MARK must match pkg/network.DNSProxyFWMark")
	require.Equal(t, uint32(cargowallNet.DNSProxyFWMark), uint32(dnsProxyFWMark))
}

// TestVerdictParityWithTcEgress is the anti-drift guard for phase 3b: the
// enforcing cgroup hook and the TC backstop share verdict.h, and this proves
// they actually agree. A divergence between the primary hook and its
// backstop is a security bug, so every tuple must produce the same
// allow/deny from both — despite different parse paths (TC starts at the
// Ethernet header, cgroup at L3) and inverted action constants.
func TestVerdictParityWithTcEgress(t *testing.T) {
	requireBPF(t)
	tcObjs := loadBPFObjects(t)
	originObjs := loadOriginObjectsSharing(t, tcObjs)

	// One policy, written once, read by both programs through the shared maps.
	require.NoError(t, tcObjs.MapDefaultAction.Put(uint32(0), uint8(0)))
	require.NoError(t, tcObjs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, tcObjs.MapCidrs.Put(
		TcBpfLpmKey{Prefixlen: 24, Ip: ipToU32("140.82.114.0")},
		TcBpfLpmVal{Action: 1},
	))
	require.NoError(t, tcObjs.MapCidrs.Put(
		TcBpfLpmKey{Prefixlen: 32, Ip: ipToU32("10.1.2.3")},
		TcBpfLpmVal{Action: 1, PortSpecific: 1},
	))
	require.NoError(t, tcObjs.MapPorts.Put(
		TcBpfPortKey{Ip: ipToU32("10.1.2.3"), Port: 8443, Proto: ipprotoTCP},
		TcBpfPortVal{Action: 1},
	))
	require.NoError(t, originObjs.MapOriginConfig.Put(uint32(0), uint8(originModeEnforce)))

	cases := []struct {
		name   string
		packet []byte
	}{
		// Decision coverage: the rule lookup itself.
		{"allowed /24 member", craftIPv4TCP(t, "140.82.114.3", 443)},
		{"outside the /24", craftIPv4TCP(t, "140.82.115.3", 443)},
		{"port-specific allowed port", craftIPv4TCP(t, "10.1.2.3", 8443)},
		{"port-specific other port", craftIPv4TCP(t, "10.1.2.3", 443)},
		{"unmatched, default deny", craftIPv4TCP(t, "93.184.216.34", 80)},

		// Parse coverage: the two hooks keep SEPARATE parsers (TC starts at
		// the Ethernet header, the cgroup hook at L3), and the shared
		// verdict helper only guarantees the decision. Parse drift is
		// therefore the likelier split, and comments claiming "same
		// discipline as tcbpf" are not a contract — these are. Each case is
		// an edge where a parser could disagree about the tuple it feeds
		// into the decision.
		{"IPv4 header with options", craftIPv4WithOptionsTCP(t, "140.82.114.3", 443)},
		{"IPv4 first fragment", craftIPv4FirstFragment(t, "140.82.114.3", 443)},
		{"IPv4 non-first fragment (no L4 header)", craftIPv4NonFirstFragment(t, "140.82.114.3")},
		{"IPv4 non-first fragment, denied dst", craftIPv4NonFirstFragment(t, "93.184.216.34")},
		{"IPv4 invalid IHL", craftInvalidIHLIPv4(t)},
		{"IPv4 truncated TCP", craftTruncatedTCP(t)},
		{"IPv4 UDP allowed", craftIPv4UDP(t, "140.82.114.3", 443)},
		{"IPv4 UDP denied", craftIPv4UDP(t, "93.184.216.34", 53)},
		{"IPv4 established ACK, denied dst", craftIPv4TCPWithFlags(t, "93.184.216.34", 443, 0x10)},
		{"IPv6 allowed", craftIPv6TCP(t, "2606:4700::1", 443)},
		{"IPv6 denied", craftIPv6TCP(t, "2001:db8::1", 443)},
		{"IPv6 behind hop-by-hop ext header", craftIPv6ExtHdrTCP(t, "2606:4700::1", 443, ipprotoHopOpts)},
		{"IPv6 behind routing ext header", craftIPv6ExtHdrTCP(t, "2001:db8::1", 443, ipprotoRouting)},
		{"IPv6 UDP denied", craftIPv6UDP(t, "2001:db8::1", 9999)},
		{"IPv6 multicast", craftIPv6Multicast(t)},
		{"IPv6 ICMPv6 NDP", craftICMPv6NDP(t)},
		{"IPv6 fragmented ICMPv6 non-first", craftIPv6FragmentedICMPv6(t, false)},
		{"ARP (non-IP)", craftARP(t)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tcRet, _, err := tcObjs.TcEgress.Test(tc.packet)
			require.NoError(t, err)
			cgRet, _, err := originObjs.CgOriginEgress.Test(tc.packet)
			require.NoError(t, err)

			// TC: 0 = pass, 2 = drop. cgroup: 1 = pass, 0 = drop.
			tcAllowed := tcRet == tcActOK
			cgAllowed := cgRet == 1
			require.Equal(t, tcAllowed, cgAllowed,
				"tc_egress and cg_origin_egress disagree (tc=%d cgroup=%d)", tcRet, cgRet)
		})
	}
}

// loadOriginObjectsSharing loads the origin collection against the tcbpf
// collection's rule maps — the same MapReplacements wiring pkg/origin uses
// in production, which also pins that the two collections' map specs stay
// compatible (a shape or size drift fails the load here).
func loadOriginObjectsSharing(t *testing.T, tcObjs *TcBpfObjects) *OriginBpfObjects {
	t.Helper()
	var objs OriginBpfObjects
	require.NoError(t, LoadOriginBpfObjects(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"map_cidrs":          tcObjs.MapCidrs,
			"map_ports":          tcObjs.MapPorts,
			"map_cidrs_v6":       tcObjs.MapCidrsV6,
			"map_ports_v6":       tcObjs.MapPortsV6,
			"map_default_action": tcObjs.MapDefaultAction,
			"map_audit_mode":     tcObjs.MapAuditMode,
		},
	}), "origin collection must load against the tcbpf rule maps")
	t.Cleanup(func() { objs.Close() })
	return &objs
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

	var evt OriginEvent
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
		"verdict":    unsafe.Offsetof(evt.Verdict),
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
		require.GreaterOrEqual(t, len(record.RawSample), int(unsafe.Sizeof(OriginEvent{})))
		r := *(*OriginEvent)(unsafe.Pointer(&record.RawSample[0]))
		if r.Cookie != wantCookie {
			continue
		}
		require.Equal(t, uint8(4), r.IpVersion)
		require.Equal(t, uint8(ipprotoTCP), r.IpProto)
		require.Equal(t, uint8(OriginFlagTCPSyn), r.Flags)
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
