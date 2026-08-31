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
	"testing"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/sni"
)

// QUIC connection-attempt identity: the coalesced walk's verdict on a
// datagram, and the DCID that pins which attempt a verdict belongs to. The
// walk's contract against the userspace decoder lives in
// originsni_quicwalk_test.go; these drive it through the datapath.

// TestOriginL7QUICNonIdentityPasses proves the QUIC arm of the identity gate
// on stateless flows: a datagram the walk clears of any Initial — a 1-RTT
// short header or a lone skippable non-Initial long header (0-RTT/Handshake) —
// is established traffic that must pass without a punt (under enforce a punt
// would park the flow PENDING and return a drop, so ret==1 pins both). An
// UNSKIPPABLE leading packet (unknown version, Retry) is a separate case: it
// could hide an Initial, so it fails closed — see TestOriginL7QUICUnknownVersionFailsClosed.
func TestOriginL7QUICNonIdentityPasses(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.15"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(0x04))) // QUIC scope

	run := func(payload []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(craftIPv4UDPData(edgeIP, 443, payload))
		require.NoError(t, err)
		return int(ret)
	}

	// Short-header QUIC (first byte high bit clear).
	require.Equal(t, 1, run(append([]byte{0x40, 0x01, 0x02, 0x03}, make([]byte, 40)...)),
		"an established QUIC 1-RTT packet must pass, not be denied")

	// A lone v1 0-RTT long header (type 0b01), skippable to a clean end: the
	// walk finds no Initial, so it passes and spends no punt budget.
	require.Equal(t, 1, run(quicNonInitialV1(4)), "a lone non-Initial long header must pass, not punt")
}

// TestOriginL7QUICUnknownVersionFailsClosed: a long header whose version is not
// in the table cannot be sized to skip past, so the walk cannot rule out an
// Initial hiding behind it (the [unknown-version][Initial] coalescing variant).
// It is UNCERTAIN, so it is dropped and refused — matching design.md's "an
// unknown QUIC version fails closed". It must NOT open an adjudication cycle:
// no PENDING flow state (a punt would park the flow on a sample the oracle may
// resolve to "no Initial", stranding the socket). The refusal DOES emit a
// report-only L7_PUNT_F_REFUSED record so an operator sees which process spoke
// the unknown version — the old long-header punt produced one.
func TestOriginL7QUICUnknownVersionFailsClosed(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.17"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeQUIC)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	unknown := append([]byte{0xc0, 0xde, 0xad, 0xbe, 0xef, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00}, make([]byte, 32)...)
	ret, _, err := objs.CgOriginEgress.Test(craftIPv4UDPData(edgeIP, 443, unknown))
	require.NoError(t, err)
	require.Equal(t, 0, int(ret), "an unknown-version long header must fail closed, not pass")
	refusal := readL7Sample(t, rd)
	require.NotZero(t, refusal.Flags&l7PuntFlagRefused, "an uncertain QUIC drop must emit a refusal record")
	require.Zero(t, refusal.Flags&l7PuntFlagQUIC, "a refusal record is not an adjudication punt")
	require.Empty(t, dumpL7Flows(t, objs), "an uncertain refusal must not park flow state")
}

// TestOriginL7QUICCoalescedInitial proves the coalesced-datagram walk closes
// the fail-open where a leading 0-RTT/Handshake long header hides the Initial
// (and its SNI) from a naive first-packet check: a real receiver processes the
// trailing Initial, so the datapath must too. On a scoped UDP/443 flow with no
// state, a datagram that coalesces a skippable non-Initial before a v1 Initial
// must be PUNTED (found → drop pending under enforce), carrying the BURIED
// Initial's DCID; and a datagram padded with more leading non-Initials than the
// walk examines is UNCERTAIN and dropped outright — no punt, no flow state — so
// padding cannot smuggle the Initial past the walk, nor park the flow PENDING
// on a sample the oracle might resolve to "no Initial".
func TestOriginL7QUICCoalescedInitial(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.16"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeQUIC)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(payload []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(craftIPv4UDPData(edgeIP, 443, payload))
		require.NoError(t, err)
		return int(ret)
	}

	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// One leading 0-RTT, then the Initial: the walk skips the 0-RTT, finds the
	// Initial, punts it (drop pending), and the sample carries the buried DCID.
	// The 0-RTT carries the SAME connection ID, which is what a real client
	// sends — RFC 9000 §12.2 forbids coalescing across connection IDs, and
	// TestOriginL7QUICMixedConnectionIDs covers the shape that violates it.
	coalesced := append(quicNonInitialV1DCID(dcid, 4), quicInitialDatagram(0x00000001, dcid)...)
	require.Equal(t, 0, run(coalesced), "a coalesced [0-RTT][Initial] must be adjudicated, not passed")
	ev := readL7Sample(t, rd)
	require.NotZero(t, ev.Flags&l7PuntFlagQUIC)
	require.Equal(t, dcid, append([]byte(nil), ev.Dcid[:ev.DcidLen]...),
		"the walk must punt the BURIED Initial's exact DCID")

	// As many leading non-Initials as the walk can reach, so the Initial sits
	// one packet BEYOND it and the datagram is UNCERTAIN — dropped and refused
	// (report-only, no flow state) rather than passing the hidden Initial. The
	// legitimate coalesced punt above left a PENDING entry, so assert the
	// uncertain drop adds NO new flow state, not that the map is empty. The
	// count comes from the cap itself (pinned to L7_QUIC_MAX_COALESCED by
	// TestKernelCoalescedCapMatchesParser) so raising the cap cannot quietly
	// turn this into a test of a datagram the walk still finishes.
	before := dumpL7Flows(t, objs)
	var padded []byte
	for i := 0; i < sni.MaxCoalescedPackets; i++ {
		padded = append(padded, quicNonInitialV1DCID(dcid, 2)...)
	}
	padded = append(padded, quicInitialDatagram(0x00000001, dcid)...)
	require.Equal(t, 0, run(padded), "an Initial padded past the walk must fail closed, not pass")
	refusal := readL7Sample(t, rd)
	require.NotZero(t, refusal.Flags&l7PuntFlagRefused, "a padded-past-walk drop must refuse")
	require.Equal(t, before, dumpL7Flows(t, objs), "an uncertain refusal must not park flow state")
}

// TestOriginL7QUICSecondInitialDifferentDCID closes the coalesced-second-
// Initial fail-open: a datagram = [Initial DCID=A][Initial DCID=B] must be
// refused, not adjudicated on A alone with B riding unseen. The walk does not
// stop at the first Initial — it keeps going and, finding a second Initial
// under a DIFFERENT DCID, marks the datagram uncertain and drops it. (Two
// Initials with the SAME DCID are one attempt's ClientHello spanning packets
// and are punted normally.)
func TestOriginL7QUICSecondInitialDifferentDCID(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.24"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeQUIC)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(payload []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(craftIPv4UDPData(edgeIP, 443, payload))
		require.NoError(t, err)
		return int(ret)
	}

	dcidA := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	dcidB := []byte{9, 9, 9, 9, 8, 8, 8, 8}

	// [Initial A][Initial B]: two attempts smuggled in one datagram.
	twoInitials := append(quicInitialDatagram(0x00000001, dcidA), quicInitialDatagram(0x00000001, dcidB)...)
	require.Equal(t, 0, run(twoInitials),
		"a datagram carrying two different-DCID Initials must fail closed")
	refusal := readL7Sample(t, rd)
	require.NotZero(t, refusal.Flags&l7PuntFlagRefused,
		"a second different-DCID Initial must refuse, not punt one and hide the other")
	require.Empty(t, dumpL7Flows(t, objs), "the uncertain refusal must not park flow state")

	// [Initial A][Initial A]: one attempt's ClientHello across two packets —
	// same DCID, so it is punted normally (the buried copy rides the identity).
	sameDCID := append(quicInitialDatagram(0x00000001, dcidA), quicInitialDatagram(0x00000001, dcidA)...)
	require.Equal(t, 0, run(sameDCID), "coalesced same-DCID Initials are one attempt: adjudicated")
	punt := readL7Sample(t, rd)
	require.Zero(t, punt.Flags&l7PuntFlagRefused, "same-DCID coalesced Initials must punt, not refuse")
	require.Equal(t, dcidA, append([]byte(nil), punt.Dcid[:punt.DcidLen]...))
}

// TestOriginL7QUICMixedConnectionIDs: RFC 9000 §12.2 forbids coalescing
// packets with different connection IDs into one datagram, so the walk holds
// every long header to a single identity. Without that it adjudicated the
// Initial and passed whatever else rode along — a 0-RTT/Handshake for a
// DIFFERENT connection would inherit the Initial's verdict without ever
// presenting its own. A conformant client never sends this shape.
func TestOriginL7QUICMixedConnectionIDs(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.25"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeQUIC)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(payload []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(craftIPv4UDPData(edgeIP, 443, payload))
		require.NoError(t, err)
		return int(ret)
	}

	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	other := []byte{7, 7, 7, 7, 6, 6, 6, 6}

	// [0-RTT for connection A][Initial for connection B]: refused, no state.
	before := dumpL7Flows(t, objs)
	require.Equal(t, 0, run(append(quicNonInitialV1DCID(other, 4), quicInitialDatagram(0x00000001, dcid)...)),
		"a datagram mixing connection IDs must fail closed")
	refusal := readL7Sample(t, rd)
	require.NotZero(t, refusal.Flags&l7PuntFlagRefused, "the mixed-CID drop must refuse")
	require.Equal(t, before, dumpL7Flows(t, objs), "an uncertain refusal must not park flow state")

	// The same shape with ONE connection ID is the conformant coalescing a
	// real client sends: the Initial is found behind the 0-RTT and punted.
	require.Equal(t, 0, run(append(quicNonInitialV1DCID(dcid, 4), quicInitialDatagram(0x00000001, dcid)...)),
		"same-CID coalescing must be adjudicated, not refused")
	punt := readL7Sample(t, rd)
	require.Zero(t, punt.Flags&l7PuntFlagRefused, "same-CID coalescing is not a refusal")
	require.Equal(t, dcid, append([]byte(nil), punt.Dcid[:punt.DcidLen]...),
		"the punt carries the buried Initial's DCID")
}
