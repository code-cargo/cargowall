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
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// L7 constants mirrored from sni.h for the tests.
const (
	l7CfgKeyMode  = 2
	l7ModeObserve = 1
	l7ModeEnforce = 2
	tcpFlagSYN    = 0x02
	tcpFlagPSHACK = 0x18

	l7StateNeedHello = 0
	l7StatePending   = 1
	l7StateAllowed   = 2
	l7StateDenied    = 3

	l7PuntFlagNoState = 0x01
	l7PuntFlagObserve = 0x02
	l7PuntFlagQUIC    = 0x08
	l7PuntFlagRepin   = 0x10
	l7PuntFlagRefused = 0x20
)

// craftIPv4TLSData builds an eth+IPv4+TCP data segment (PSH|ACK) carrying a
// ClientHello for sni, to dstIP:443.
func craftIPv4TLSData(dstIP, sni string) []byte {
	eth := craftEthHeader(ethPIP)
	payload := snitest.BuildClientHello(sni)
	tcp := craftTCPHeaderWithFlags(443, tcpFlagPSHACK)
	ip := craftIPv4Header(dstIP, ipprotoTCP, len(tcp)+len(payload))
	out := append(append(eth, ip...), tcp...)
	return append(out, payload...)
}

// TestOriginL7NoInlineAdmit pins the kernel's role: it decides WHETHER a
// segment needs adjudication, never WHO is allowed. With L7 enforce on and a
// scoped edge IP, EVERY ClientHello — plausible name, attacker name, or a
// duplicate-SNI smuggle — is punted and dropped pending the oracle, which is
// the ONLY name matcher (the allowed-vs-attacker discrimination is proved at
// the oracle level and on real sockets in the writeback tests). No in-kernel
// name map exists for a stale or ambiguous entry to admit through.
func TestOriginL7NoInlineAdmit(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	// The shared edge IP: L4-allowed (inside the seeded /24), SNI-scoped.
	const edgeIP = "140.82.114.10"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	// SYN opens the flow (no payload) — must pass, and never punt.
	require.Equal(t, 1, run(craftIPv4TCPWithFlags(t, edgeIP, 443, tcpFlagSYN)),
		"SYN to a scoped IP must pass")
	requireNoL7Sample(t, rd)

	// Every hello punts, whatever name it carries.
	for _, sni := range []string{"auth.docker.io", "evil.attacker.example"} {
		require.Equal(t, 0, run(craftIPv4TLSData(edgeIP, sni)),
			"a ClientHello must always be adjudicated (dropped pending), name %q", sni)
		ev := readL7Sample(t, rd)
		require.Equal(t, snitest.BuildClientHello(sni), append([]byte(nil), ev.Payload[:ev.PayloadLen]...),
			"the oracle must receive the hello verbatim")
	}

	// A hello smuggling TWO server_name extensions is punted like any other —
	// nothing inline can admit on "the first name" while the oracle would
	// judge another; its parser rejects the ambiguity as malformed
	// (pkg/sni TestParseTLSClientHelloRejectsDuplicateSNI).
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 443,
		snitest.BuildClientHello("auth.docker.io", "evil.attacker.example"))),
		"a duplicate-SNI hello must be punted, never admitted inline")
	_ = readL7Sample(t, rd)
}

// craftIPv4TCPData builds an eth+IPv4+TCP data segment (PSH|ACK) with an
// arbitrary destination port and payload.
func craftIPv4TCPData(dstIP string, dstPort uint16, payload []byte) []byte {
	eth := craftEthHeader(ethPIP)
	tcp := craftTCPHeaderWithFlags(dstPort, tcpFlagPSHACK)
	ip := craftIPv4Header(dstIP, ipprotoTCP, len(tcp)+len(payload))
	out := append(append(eth, ip...), tcp...)
	return append(out, payload...)
}

// craftIPv4UDPData builds an eth+IPv4+UDP datagram with an arbitrary
// destination port and payload.
func craftIPv4UDPData(dstIP string, dstPort uint16, payload []byte) []byte {
	eth := craftEthHeader(ethPIP)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	ip := craftIPv4Header(dstIP, ipprotoUDP, len(udp)+len(payload))
	out := append(append(eth, ip...), udp...)
	return append(out, payload...)
}

// TestOriginL7EstablishedFlowPasses proves the identity gate: once a flow is
// past its handshake, its continuation bytes carry no SNI, so L7 must pass
// them — even with no ALLOWED map_l7_flow entry (the flow predates L7, or its
// entry was LRU-evicted). Without the gate these mid-stream segments would be
// punted and the oracle would terminally DENY a live allowed connection.
func TestOriginL7EstablishedFlowPasses(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.14"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	// TLS application_data (0x17) as the first byte of the segment we see: an
	// established TLS session mid-stream, no flow entry. Must pass.
	appData := append([]byte{0x17, 0x03, 0x03, 0x00, 0x05}, []byte("hello")...)
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 443, appData)),
		"established TLS app-data on a scoped IP must pass, not be denied")

	// A TLS alert (0x15) — e.g. close_notify — must also pass.
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 443, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00})),
		"a TLS alert record must pass")

	// A genuine non-TLS byte on 443 still fails closed (SSH-on-443).
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 443, []byte("SSH-2.0-OpenSSH\r\n"))),
		"non-TLS bytes on 443 must still fail closed")
}

// quicNonInitialV1 builds a minimal v1 0-RTT long header (type 0b01) with
// dcid/scid length 0, a 1-byte Length varint, and bodyLen filler bytes — a
// coalesced packet the walk skips by its Length. bodyLen must be < 64.
func quicNonInitialV1(bodyLen int) []byte {
	pkt := []byte{0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, byte(bodyLen)}
	return append(pkt, make([]byte, bodyLen)...)
}

// TestOriginL7HandshakeMsgTypeDiscrimination proves the NO_STATE identity gate
// distinguishes a ClientHello from any other TLS handshake record by its
// message type, in a SINGLE PROG_TEST_RUN call (each call gets a fresh socket
// cookie, so a multi-segment same-flow scenario — a split hello — rides a real
// socket instead: see TestOriginL7RealSocketSplitHello). Both frames are
// stateless 0x16 handshake records to a scoped TLS IP; only the ClientHello
// opens adjudication (punt → drop pending), while a KeyUpdate is
// established-session traffic and passes.
func TestOriginL7HandshakeMsgTypeDiscrimination(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.18"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	// A ClientHello (msg type 1) on a stateless flow OPENS adjudication:
	// it punts and drops pending.
	require.Equal(t, 0, run(craftIPv4TLSData(edgeIP, "auth.docker.io")),
		"a stateless ClientHello must be adjudicated (dropped pending)")

	// A KeyUpdate (record type 0x16, msg type 24) on a stateless flow is
	// established-session traffic — it carries no SNI and must pass, not be
	// mis-parsed as a bad hello and denied.
	keyUpdate := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 24, 0x00, 0x00, 0x01, 0x00}
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 443, keyUpdate)),
		"a stateless KeyUpdate must pass, not be denied as a malformed hello")
}

// TestL7EventAddrs pins SrcAddr/DstAddr — the ONE decode of the punt event's
// byte-order convention (v4 host order, v6 raw bytes), consumed by both the
// pin-ip binding (NameResolvedToIP) and the audit sink. A wrong conversion
// here silently turns --tls-sni=enforce-pinned into a blanket deny (every binding
// lookup misses) while audit keeps printing plausible-looking addresses.
func TestL7EventAddrs(t *testing.T) {
	var ev L7Event
	ev.IpVersion = 4
	ev.DstIp = binary.BigEndian.Uint32(net.ParseIP("140.82.114.20").To4()) // host-order value
	ev.SrcIp = binary.BigEndian.Uint32(net.ParseIP("10.0.0.9").To4())
	require.Equal(t, "140.82.114.20", ev.DstAddr().String())
	require.Equal(t, "10.0.0.9", ev.SrcAddr().String())

	var ev6 L7Event
	ev6.IpVersion = 6
	copy(ev6.DstIp6[:], net.ParseIP("2606:4700::1").To16())
	copy(ev6.SrcIp6[:], net.ParseIP("fd00::2").To16())
	require.Equal(t, "2606:4700::1", ev6.DstAddr().String())
	require.Equal(t, "fd00::2", ev6.SrcAddr().String())
}

// readL7Sample reads the next punt sample. PROG_TEST_RUN commits the ringbuf
// sample before Test() returns, so a sample the program emitted is already
// readable; the deadline only bounds a genuine failure.
func readL7Sample(t *testing.T, rd *ringbuf.Reader) *L7Event {
	t.Helper()
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	rec, err := rd.Read()
	require.NoError(t, err, "expected a punt sample")
	ev, ok := L7EventFromBytes(rec.RawSample)
	require.True(t, ok, "punt sample must parse as an L7Event")
	return ev
}

// requireNoL7Sample asserts the punt ring is empty. Safe to keep short for the
// same reason readL7Sample's deadline is: a PROG_TEST_RUN punt would already
// be committed by the time this reads.
func requireNoL7Sample(t *testing.T, rd *ringbuf.Reader) {
	t.Helper()
	rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := rd.Read()
	require.ErrorIs(t, err, os.ErrDeadlineExceeded, "the punt ring must be empty")
}

// dumpL7Flows snapshots map_l7_flow.
func dumpL7Flows(t *testing.T, objs *OriginBpfObjects) map[OriginBpfL7FlowKey]OriginBpfL7FlowVal {
	t.Helper()
	out := make(map[OriginBpfL7FlowKey]OriginBpfL7FlowVal)
	var (
		k OriginBpfL7FlowKey
		v OriginBpfL7FlowVal
	)
	it := objs.MapL7Flow.Iterate()
	for it.Next(&k, &v) {
		out[k] = v
	}
	require.NoError(t, it.Err())
	return out
}

// l7StatSum totals a per-CPU L7 stats slot (indices mirror L7_STAT_* in sni.h).
func l7StatSum(t *testing.T, objs *OriginBpfObjects, slot uint32) uint64 {
	t.Helper()
	var per []uint64
	require.NoError(t, objs.MapL7Stats.Lookup(slot, &per))
	var total uint64
	for _, v := range per {
		total += v
	}
	return total
}

// TestOriginL7GateRefusedCounted pins the identity gate's refusal counters and
// their record policy. A fresh refusal (SYN seen) counts GATE_REFUSED and
// emits an audit record — the trace the counter-only refusal lacked, so an
// operator debugging a hung ssh-on-443 sees more than an L4 ALLOW. A no-state
// refusal (no SYN — an evicted flow's mid-record ciphertext, or a
// pre-existing connection at attach) counts in the SEPARATE GATE_NO_STATE slot
// and is counter-only: those are high-volume eviction noise, and folding them
// into GATE_REFUSED made the enforce-rollout measurement unreadable.
//
// Each Test() call mints a fresh cookie, so the SSH segment here rides a
// no-state flow — the GATE_NO_STATE arm. The FRESH arm (record + GATE_REFUSED)
// needs the SYN and the data on ONE cookie, so it is proved on a real socket
// in TestOriginL7RealSocketFreshRefusalRecorded.
func TestOriginL7GateRefusedCounted(t *testing.T) {
	const (
		statGateRefused = 6
		statPendingNoID = 7
		statGateNoState = 8
	)

	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.19"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	beforeRefused := l7StatSum(t, objs, statGateRefused)
	beforeNoState := l7StatSum(t, objs, statGateNoState)

	// Non-TLS bytes on a scoped 443, on a NO-STATE flow (fresh cookie, no SYN):
	// dropped, counted in GATE_NO_STATE, and NOT recorded — it must leave the
	// punt ring empty and must not touch GATE_REFUSED.
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 443, []byte("SSH-2.0-OpenSSH\r\n"))),
		"non-TLS on 443 fails closed")
	requireNoL7Sample(t, rd)
	require.Equal(t, beforeNoState+1, l7StatSum(t, objs, statGateNoState),
		"a no-state non-protocol refusal must count in GATE_NO_STATE")
	require.Equal(t, beforeRefused, l7StatSum(t, objs, statGateRefused),
		"a no-state refusal must not inflate GATE_REFUSED (the rollout measure)")

	// A ClientHello on the same scoped IP is adjudicated normally: it punts,
	// so it must NOT inflate either refusal counter.
	require.Equal(t, 0, run(craftIPv4TLSData(edgeIP, "auth.docker.io")),
		"a hello is dropped pending adjudication")
	punt := readL7Sample(t, rd)
	require.Zero(t, punt.Flags&l7PuntFlagRefused, "an adjudication punt is not a refusal")
	require.Equal(t, beforeRefused, l7StatSum(t, objs, statGateRefused),
		"an adjudicated hello must not count as a gate refusal")
	require.Zero(t, l7StatSum(t, objs, statPendingNoID),
		"no QUIC pending-flow drop occurred in this test")
}

// quicNonInitialV1DCID builds a minimal v1 0-RTT long header (type 0b01)
// carrying the given Destination CID, a zero-length SCID, a 1-byte Length
// varint and bodyLen filler. bodyLen must be < 64.
func quicNonInitialV1DCID(dcid []byte, bodyLen int) []byte {
	pkt := []byte{0xd0, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	pkt = append(pkt, dcid...)
	pkt = append(pkt, 0x00, byte(bodyLen)) // scid len, Length varint
	return append(pkt, make([]byte, bodyLen)...)
}

// TestOriginL7RejectsSubMinimumTCPDataOffset closes a fail-open in the L7
// hook's payload arithmetic: payload_off = ip_hlen + doff*4 was computed from
// a data offset the caller had parsed but never range-checked, so a segment
// declaring doff below the 5-word minimum put payload_off INSIDE the TCP
// header and the identity gate read header bytes as L7 payload.
//
// The crafted header below is what that costs: source port 0x1601 puts a TLS
// handshake record type where the gate looks for one, and a sequence number of
// 0x00010000 puts ClientHello's message type at the byte it checks next — so
// the buggy offset finds a "ClientHello" made entirely of TCP header fields,
// punts it, and drops a flow pending adjudication of bytes that are not a
// handshake at all. The fix declines to guess a payload offset for a header
// that has none and leaves the packet to its L4 verdict, so the assertion is
// BOTH that it passes and that nothing was punted.
func TestOriginL7RejectsSubMinimumTCPDataOffset(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.33"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	frame := craftIPv4TCPDataRaw(edgeIP, 443, 0x1601, 0x00010000, 0,
		[]byte("SSH-2.0-OpenSSH_9.7\r\n"))
	ret, _, err := objs.CgOriginEgress.Test(frame)
	require.NoError(t, err)
	require.Equal(t, 1, int(ret),
		"a sub-minimum data offset must fall through to the L4 verdict, not be adjudicated")
	requireNoL7Sample(t, rd)
}

// craftIPv4TCPDataRaw builds an eth+IPv4+TCP data segment with an explicit
// source port, sequence, and data offset (in 32-bit words; 0 selects the
// wire-illegal value the bounds check exists to reject). The header stays 20
// bytes on the wire whatever doff claims — that mismatch is the whole point.
func craftIPv4TCPDataRaw(dstIP string, dstPort, srcPort uint16, seq uint32, doff uint8, payload []byte) []byte {
	eth := craftEthHeader(ethPIP)
	tcp := craftTCPHeaderWithFlags(dstPort, tcpFlagPSHACK)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = doff << 4
	ip := craftIPv4Header(dstIP, ipprotoTCP, len(tcp)+len(payload))
	out := append(append(eth, ip...), tcp...)
	return append(out, payload...)
}
