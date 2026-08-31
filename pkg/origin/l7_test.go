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

package origin

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/sni"
	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

func requireBPFOrigin(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("BPF tests require root/CAP_BPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock: %v", err)
	}
}

func loadL7Objects(t *testing.T) *bpf.OriginBpfObjects {
	t.Helper()
	requireBPFOrigin(t)
	var objs bpf.OriginBpfObjects
	require.NoError(t, bpf.LoadOriginBpfObjects(&objs, nil))
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// craftIPv4TLS builds an eth+IPv4+TCP data segment carrying a ClientHello.
func craftIPv4TLS(dstIP string, serverName string, syn bool) []byte {
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	var payload []byte
	if !syn {
		payload = snitest.BuildClientHello(serverName)
	}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 1000) // seq
	tcp[12] = 5 << 4
	if syn {
		tcp[13] = 0x02
	} else {
		tcp[13] = 0x18
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:], []byte{10, 0, 0, 9})
	copy(ip[16:], net.ParseIP(dstIP).To4())
	out := append(append(eth, ip...), tcp...)
	return append(out, payload...)
}

// TestL7OracleEndToEnd proves the whole slow-path loop against the real kernel
// program: a scoped TLS flow with NO pre-seeded allow entry punts on its
// ClientHello (dropped in enforce), the oracle reassembles from the ringbuf,
// adjudicates, and writes the flow verdict back — asserted on the punted
// flow's exact map_l7_flow entry (ALLOWED / DENIED), since that entry is what
// admits or keeps dropping the client's retransmit. The retransmit itself
// rides a real socket in bpf.TestOriginL7RealSocketWriteback; here a re-run
// of the frame is a NEW flow (fresh Test cookie) and punts again.
func TestL7OracleEndToEnd(t *testing.T) {
	objs := loadL7Objects(t)

	// Deny-by-default L4 with the edge /24 allowed; enforce; lo carve-out off
	// (PROG_TEST_RUN rides lo). L7 enforce, TLS-scope the edge IP.
	require.NoError(t, objs.MapDefaultAction.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapCidrs.Put(
		bpf.OriginBpfLpmKey{Prefixlen: 24, Ip: binary.NativeEndian.Uint32(net.ParseIP("140.82.114.0").To4())},
		bpf.OriginBpfLpmVal{Action: 1},
	))
	require.NoError(t, objs.MapOriginConfig.Put(uint32(0), uint8(ModeEnforce)))
	const edgeIP = "140.82.114.20"
	const evilIP = "140.82.114.21" // a second scoped IP, so the evil flow has a distinct key
	require.NoError(t, objs.MapL7Scope.Put(binary.NativeEndian.Uint32(net.ParseIP(edgeIP).To4()), bpf.L7ScopeTLS))
	require.NoError(t, objs.MapL7Scope.Put(binary.NativeEndian.Uint32(net.ParseIP(evilIP).To4()), bpf.L7ScopeTLS))

	l := newL7(objs, L7Options{Matcher: allowSet{"auth.docker.io": true}}, nil)
	require.NoError(t, l.SetMode(L7ModeEnforce))

	reader, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer reader.Close()

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}
	// Drain exactly one punt sample, feed it to the oracle, and return it —
	// its FlowKey() is the only handle on the flow the kernel actually
	// punted (every Test() call mints a fresh socket cookie).
	pump := func() *bpf.L7Event {
		reader.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := reader.Read()
		require.NoError(t, err, "expected a punt sample")
		ev, ok := bpf.L7EventFromBytes(rec.RawSample)
		require.True(t, ok)
		l.onSample(ev)
		return ev
	}

	// --- allowed name ---
	require.Equal(t, 1, run(craftIPv4TLS(edgeIP, "", true)), "SYN passes")
	require.Equal(t, 0, run(craftIPv4TLS(edgeIP, "auth.docker.io", false)),
		"first ClientHello: punted, dropped pending")
	ev := pump()
	// The writeback assertion, pinned to the punted flow's exact key: the
	// client's retransmit is admitted by THIS entry flipping to ALLOWED. (A
	// re-run of the frame cannot prove it — a fresh Test cookie is a fresh
	// flow. The same-flow retransmit is proved on a real socket in
	// bpf.TestOriginL7RealSocketWriteback.) A TCP verdict carries no DCID and
	// no anchor: last_punt_seq is the kernel's PENDING dedup field, never read
	// on a terminal state.
	var fv bpf.OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &fv))
	require.Equal(t, l7StateAllowed, fv.State,
		"the oracle's ALLOWED verdict must land on the punted flow's key")
	require.Zero(t, fv.DcidLen, "a TCP verdict carries no QUIC identity")

	// A NEW flow with the same name is adjudicated again — the kernel has no
	// name state, so nothing an admit did can short-circuit the next flow.
	require.Equal(t, 0, run(craftIPv4TLS(edgeIP, "auth.docker.io", false)),
		"a new flow (fresh cookie) must punt and drop pending")
	ev2 := pump() // adjudicate it too, so the ring stays in lockstep
	require.NoError(t, objs.MapL7Flow.Lookup(ev2.FlowKey(), &fv))
	require.Equal(t, l7StateAllowed, fv.State)

	// --- attacker name on a second scoped IP (distinct flow key) ---
	require.Equal(t, 0, run(craftIPv4TLS(evilIP, "evil.attacker.example", false)),
		"evil ClientHello: punted, dropped pending")
	evilEv := pump()
	require.NoError(t, objs.MapL7Flow.Lookup(evilEv.FlowKey(), &fv))
	require.Equal(t, l7StateDenied, fv.State,
		"the oracle's DENIED verdict must land on the punted flow's key — "+
			"this entry, not a re-punt, is what keeps dropping the retransmit")
}

// makeL7Event builds a punt event for the oracle's onSample: a TCP TLS segment
// (or a QUIC datagram when quic=true) to dst:port with the given seq bytes. The
// Scope byte mirrors what the kernel stamps (the single narrowed dimension) —
// protocolForEvent reads it to select the parser.
func makeL7Event(dstPort uint16, seq uint32, payload []byte, quic bool) *bpf.L7Event {
	ev := &bpf.L7Event{IpVersion: 4, IpProto: 6, DstPort: dstPort, Seq: seq, Scope: bpf.L7ScopeTLS}
	if dstPort == 80 {
		ev.Scope = bpf.L7ScopeHTTP
	}
	if quic {
		ev.IpProto = 17
		ev.Flags |= 0x08 // l7PuntQUIC
		ev.Scope = bpf.L7ScopeQUIC
	}
	ev.DstIp = binary.BigEndian.Uint32(net.ParseIP("140.82.114.30").To4())
	n := copy(ev.Payload[:], payload)
	ev.PayloadLen = uint16(n)
	return ev
}

// accumulateDrive calls accumulate under the flow mutex, as onSample does.
func accumulateDrive(l *L7, st *l7flow, ev *bpf.L7Event, payload []byte) (bool, L7Outcome) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.accumulate(st, ev, payload)
}

// TestL7AccumulateSplitTLS covers the multi-segment reassembly path: a
// ClientHello split across two TCP segments must yield needMore on the first
// and a decision on the second, using the seq-relative offset.
func TestL7AccumulateSplitTLS(t *testing.T) {
	full := snitest.BuildClientHello("split.example.com")
	mid := len(full) / 2

	l := &L7{matcher: allowSet{"split.example.com": true}, flows: map[bpf.OriginBpfL7FlowKey]*l7flow{}}

	ev1 := makeL7Event(443, 5000, full[:mid], false)
	st := &l7flow{proto: sni.ProtoTLS}
	l.flows[ev1.FlowKey()] = st
	needMore, _ := accumulateDrive(l, st, ev1, full[:mid])
	if !needMore {
		t.Fatal("first segment: want needMore")
	}

	ev2 := makeL7Event(443, 5000+uint32(mid), full[mid:], false)
	needMore, out := accumulateDrive(l, st, ev2, full[mid:])
	if needMore || !out.Allowed || out.Name != "split.example.com" || out.Reason != L7Allowed {
		t.Fatalf("reassembled: needMore=%v allowed=%v name=%q why=%q, want allow/split.example.com",
			needMore, out.Allowed, out.Name, out.Reason)
	}
}

// TestL7AccumulateReassemblyConflict covers the overlap-conflict deny: a second
// segment that rewrites already-seen bytes with different content is an attack
// signature and must deny, not resolve.
func TestL7AccumulateReassemblyConflict(t *testing.T) {
	l := &L7{matcher: allowSet{}, flows: map[bpf.OriginBpfL7FlowKey]*l7flow{}}
	st := &l7flow{proto: sni.ProtoTLS}
	_, _ = accumulateDrive(l, st, makeL7Event(443, 100, []byte("aaaa"), false), []byte("aaaa"))
	_, out := accumulateDrive(l, st, makeL7Event(443, 100, []byte("bbbb"), false), []byte("bbbb"))
	if out.Allowed || out.Reason != L7Reassembly {
		t.Errorf("conflict: allowed=%v why=%q, want deny/reassembly", out.Allowed, out.Reason)
	}
}

// TestL7AccumulateQUICUnknownVersion covers the QUIC error branch: a long-header
// Initial with an unregistered version denies with quic_version.
func TestL7AccumulateQUICUnknownVersion(t *testing.T) {
	l := &L7{matcher: allowSet{}, flows: map[bpf.OriginBpfL7FlowKey]*l7flow{}}
	st := &l7flow{proto: sni.ProtoQUIC}
	// Long header (0xc0) + unknown version 0x0a0a0a0a + a dcid len byte.
	pkt := []byte{0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}
	_, out := accumulateDrive(l, st, makeL7Event(443, 0, pkt, true), pkt)
	if out.Allowed || out.Reason != L7QUICVersion {
		t.Errorf("unknown QUIC version: allowed=%v why=%q, want deny/quic_version", out.Allowed, out.Reason)
	}
}

// TestProtocolForEvent covers the parser-selection branches AND pins the
// audit labels: the outcome carries the flow's classified protocol and the
// sink reports its String(), so the protocol audit names is by construction
// the one the matcher parsed. Selection is on ev.Scope — the kernel's own
// narrowed classification — not a userspace re-derivation from flags+port.
func TestProtocolForEvent(t *testing.T) {
	quic := protocolForEvent(&bpf.L7Event{Scope: bpf.L7ScopeQUIC})
	if quic != sni.ProtoQUIC || quic.String() != "quic" {
		t.Errorf("QUIC scope = %v/%q, want QUIC/quic", quic, quic.String())
	}
	http := protocolForEvent(&bpf.L7Event{Scope: bpf.L7ScopeHTTP})
	if http != sni.ProtoHTTP || http.String() != "http" {
		t.Errorf("HTTP scope = %v/%q, want HTTP/http", http, http.String())
	}
	tls := protocolForEvent(&bpf.L7Event{Scope: bpf.L7ScopeTLS})
	if tls != sni.ProtoTLS || tls.String() != "tls" {
		t.Errorf("TLS scope = %v/%q, want TLS/tls", tls, tls.String())
	}
	unknown := protocolForEvent(&bpf.L7Event{Scope: 0})
	if unknown != sni.ProtoUnknown {
		t.Errorf("unscoped = %v, want Unknown", unknown)
	}
}

// TestL7ReaderGoroutine exercises the real punt-reader path (start → run →
// onSample → verdict writeback → close), rather than driving onSample directly:
// it starts the reader, makes the kernel punt via PROG_TEST_RUN, and polls the
// flow map until the oracle's verdict lands.
func TestL7ReaderGoroutine(t *testing.T) {
	objs := loadL7Objects(t)
	require.NoError(t, objs.MapDefaultAction.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapCidrs.Put(
		bpf.OriginBpfLpmKey{Prefixlen: 24, Ip: binary.NativeEndian.Uint32(net.ParseIP("140.82.114.0").To4())},
		bpf.OriginBpfLpmVal{Action: 1},
	))
	require.NoError(t, objs.MapOriginConfig.Put(uint32(0), uint8(ModeEnforce)))
	const edgeIP = "140.82.114.40"
	require.NoError(t, objs.MapL7Scope.Put(binary.NativeEndian.Uint32(net.ParseIP(edgeIP).To4()), bpf.L7ScopeTLS))

	l := newL7(objs, L7Options{Matcher: allowSet{"auth.docker.io": true}}, nil)
	require.NoError(t, l.SetMode(L7ModeEnforce))
	require.NoError(t, l.start()) // starts the run() goroutine
	defer l.close()

	// SYN + ClientHello: the hello punts (every hello does).
	_, _, err := objs.CgOriginEgress.Test(craftIPv4TLS(edgeIP, "", true))
	require.NoError(t, err)
	_, _, err = objs.CgOriginEgress.Test(craftIPv4TLS(edgeIP, "auth.docker.io", false))
	require.NoError(t, err)

	// The reader goroutine adjudicates asynchronously; its verdict writeback
	// is the observable. The reader consumed the sample (its cookie is
	// unknowable here), so poll the flow map for an ALLOWED entry: it holds
	// exactly the SYN's NEED_HELLO entry and the hello's entry.
	require.Eventually(t, func() bool {
		allowedEntries := 0
		var (
			fk bpf.OriginBpfL7FlowKey
			fv bpf.OriginBpfL7FlowVal
		)
		it := objs.MapL7Flow.Iterate()
		for it.Next(&fk, &fv) {
			if fv.State == l7StateAllowed {
				allowedEntries++
			}
		}
		return it.Err() == nil && allowedEntries == 1
	}, 3*time.Second, 10*time.Millisecond,
		"the reader's adjudication must write ALLOWED onto the punted flow's entry")
}

// captureSink installs a synchronous outcome recorder. In-package so it can
// set the field directly; production wiring goes through L7Options.Sink, which
// is the only way to configure a started oracle.
func captureSink(l *L7) *[]L7Outcome {
	var outcomes []L7Outcome
	l.sink = func(o L7Outcome) { outcomes = append(outcomes, o) }
	return &outcomes
}

// TestL7TruncatedPuntTerminalDeny: a sample cut at the kernel's punt window
// can never complete — the missing bytes were never captured — so it must
// become a terminal deny with an audit outcome, not park as needs-more (which
// would black-hole the flow under enforce with no record).
func TestL7TruncatedPuntTerminalDeny(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{"auth.docker.io": true}}, nil)
	outcomes := captureSink(l)

	ev := makeL7Event(443, 1000, snitest.BuildClientHello("auth.docker.io")[:8], false)
	ev.Flags |= l7PuntTruncated
	l.onSample(ev)

	require.Len(t, *outcomes, 1, "a truncated incomplete sample must produce a terminal outcome")
	require.False(t, (*outcomes)[0].Allowed)
	require.Equal(t, L7ParseError, (*outcomes)[0].Reason)

	var v bpf.OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &v))
	require.Equal(t, l7StateDenied, v.State, "the deny must reach the kernel flow map")
}

// TestL7StalePuntAfterVerdictRepairs: punts already queued in the ringbuf
// when the verdict landed (retransmits past the kernel's single-seq dedup)
// must be dropped by the tombstone — not restart accumulation from a
// mid-stream segment and overwrite the verdict just written. AND the tombstone
// must RE-ASSERT the verdict: the kernel-side write that queued the stale
// sample can itself have clobbered the entry back to PENDING (the snapshot
// race), after which the retransmit dedup swallows every further sample and
// the flow strands under enforce with nothing left to repair it.
func TestL7StalePuntAfterVerdictRepairs(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{"auth.docker.io": true}}, nil)
	outcomes := captureSink(l)

	ev := makeL7Event(443, 1000, snitest.BuildClientHello("auth.docker.io"), false)
	l.onSample(ev)
	require.Len(t, *outcomes, 1)
	require.True(t, (*outcomes)[0].Allowed)

	// Simulate the racing kernel write that accompanied the stale punt: the
	// snapshot (taken before our verdict landed) stamped PENDING over it.
	require.NoError(t, objs.MapL7Flow.Put(ev.FlowKey(),
		bpf.OriginBpfL7FlowVal{State: 1 /* PENDING */, Punts: 3, LastPuntSeq: 2000}))

	// Same flow key, later seq, hostile payload, NO no-state flag: stale.
	stale := makeL7Event(443, 2000, snitest.BuildClientHello("evil.example"), false)
	l.onSample(stale)

	require.Len(t, *outcomes, 1, "a stale punt after the verdict must not re-adjudicate")
	var v bpf.OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &v))
	require.Equal(t, l7StateAllowed, v.State,
		"the tombstone must repair the clobbered kernel entry, not merely drop the sample")
}

// TestL7NoStatePuntReAdjudicates: a NO_STATE punt on a decided flow means the
// kernel LRU evicted the entry (the verdict is gone and the kernel will punt
// until a new one lands) — the oracle must adjudicate afresh instead of
// dropping the punt and letting the flow exhaust its budget unaudited.
func TestL7NoStatePuntReAdjudicates(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{"auth.docker.io": true}}, nil)
	outcomes := captureSink(l)

	first := makeL7Event(443, 1000, snitest.BuildClientHello("auth.docker.io"), false)
	l.onSample(first)
	require.Len(t, *outcomes, 1)

	evicted := makeL7Event(443, 5000, snitest.BuildClientHello("evil.example"), false)
	evicted.Flags |= l7PuntNoState
	l.onSample(evicted)

	require.Len(t, *outcomes, 2, "a NO_STATE punt must re-adjudicate")
	require.False(t, (*outcomes)[1].Allowed)
	require.Equal(t, L7Mismatch, (*outcomes)[1].Reason)
	var v bpf.OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(first.FlowKey(), &v))
	require.Equal(t, l7StateDenied, v.State, "the fresh verdict must be re-written")
}

// TestL7FlowBounds: the flows map must hold the l7MaxFlows cap under a
// parked-flow flood and the TTL sweep must collect idle entries — without
// either, every never-completed handshake leaks its Assembler for the
// daemon's lifetime.
func TestL7FlowBounds(t *testing.T) {
	l := &L7{matcher: allowSet{}, flows: map[bpf.OriginBpfL7FlowKey]*l7flow{}}
	partial := snitest.BuildClientHello("x.example")[:8] // parses to needs-more forever

	for i := 0; i < l7MaxFlows+50; i++ {
		ev := makeL7Event(443, 1000, partial, false)
		ev.Cookie = uint64(i + 1) // distinct flow keys
		l.onSample(ev)
	}
	require.LessOrEqual(t, len(l.flows), l7MaxFlows, "the cap must hold under a flood")

	// Age everything out and force the next sample to sweep.
	past := time.Now().Add(-2 * l7FlowTTL)
	l.mu.Lock()
	for _, st := range l.flows {
		st.lastSeen = past
	}
	l.lastSweep = time.Now().Add(-2 * l7SweepInterval)
	l.mu.Unlock()

	fresh := makeL7Event(443, 1000, partial, false)
	fresh.Cookie = 999999
	l.onSample(fresh)
	require.Equal(t, 1, len(l.flows), "the sweep must collect idle flows, keeping only the fresh one")
}

// TestL7AccumulateQUICMalformedLength: a QUIC Initial whose Length claims
// more bytes than the datagram holds is the crafted park-the-flow shape — it
// must terminally deny with parse_error, never return needs-more (a datagram
// is atomic; QUIC punts are never deduped, so needs-more would re-punt until
// the budget black-holes the flow).
func TestL7AccumulateQUICMalformedLength(t *testing.T) {
	l := &L7{matcher: allowSet{}, flows: map[bpf.OriginBpfL7FlowKey]*l7flow{}}
	st := &l7flow{proto: sni.ProtoQUIC}
	pkt := []byte{
		0xc0,                   // long header, fixed bit, type Initial (v1)
		0x00, 0x00, 0x00, 0x01, // version 1
		0x08, 1, 2, 3, 4, 5, 6, 7, 8, // dcid
		0x00,       // scid len 0
		0x00,       // token length 0
		0x7f, 0xff, // Length = 16383, beyond the datagram
	}
	_, out := accumulateDrive(l, st, makeL7Event(443, 0, pkt, true), pkt)
	require.False(t, out.Allowed)
	require.Equal(t, L7ParseError, out.Reason)
}

// TestL7ObservePreservesReason: in observe mode (or enforce under audit
// posture) the sink must carry the ACTUAL parse/policy reason, not a generic
// "would_block" — observe mode exists to measure that breakdown before
// enforcement. The posture rides Enforce/EventType, never the reason field.
func TestL7ObservePreservesReason(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{}}, nil)
	outcomes := captureSink(l)

	// A no-SNI ClientHello, punted with the OBSERVE flag set.
	ev := makeL7Event(443, 1000, snitest.BuildClientHello(""), false)
	ev.Flags |= l7PuntObserve
	l.onSample(ev)

	require.Len(t, *outcomes, 1)
	require.False(t, (*outcomes)[0].Allowed)
	require.False(t, (*outcomes)[0].Enforce, "observe posture")
	require.Equal(t, L7NoName, (*outcomes)[0].Reason,
		"observe mode must preserve the real reason, not flatten to would_block")

	// A name_mismatch in observe mode likewise keeps its reason.
	outcomes2 := captureSink(l)
	ev2 := makeL7Event(443, 2000, snitest.BuildClientHello("evil.example"), false)
	ev2.Cookie = 2
	ev2.Flags |= l7PuntObserve
	l.onSample(ev2)
	require.Len(t, *outcomes2, 1)
	require.Equal(t, L7Mismatch, (*outcomes2)[0].Reason)
}

// kernelL7Source returns the L7 kernel headers concatenated. Both are read so
// a constant moving between sni.h and sni_quic.h cannot silently un-pin these
// tests — the pins are on the source of truth, not on a file name.
func kernelL7Source(t *testing.T) string {
	t.Helper()
	var all []byte
	for _, f := range []string{"../../bpf/sni.h", "../../bpf/sni_quic.h"} {
		b, err := os.ReadFile(f)
		require.NoError(t, err, "reading %s", f)
		all = append(all, b...)
	}
	return string(all)
}

// TestL7RepinReAdjudicatesQUIC drives the production REPIN protocol: a new
// QUIC connection attempt (a different Initial DCID) superseding an ALLOWED
// flow. The fixture is RFC 9001's real protected client Initial (SNI
// "example.com"), so the oracle's full decrypt+parse runs. The re-pinned
// sample must reset the tombstone and consult CURRENT policy afresh — proved
// by flipping the matcher between the two attempts, the oracle-side analogue
// of a second connection to a different tenant — and BOTH verdicts must
// record the attempt's DCID: the deny too, because an identity-less DENIED
// entry (no TTL) would sentence every later connection on the socket.
func TestL7RepinReAdjudicatesQUIC(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{"example.com": true}}, nil)
	outcomes := captureSink(l)

	initial := snitest.RFC9001ClientInitial()
	// The RFC 9001 vector's DCID. The verdict identity comes from the EVENT's
	// dcid field (kernel-extracted), never re-parsed from the payload.
	dcid1 := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	ev1 := makeL7Event(443, 0, initial, true)
	ev1.DcidLen = uint8(copy(ev1.Dcid[:], dcid1))
	l.onSample(ev1)
	require.Len(t, *outcomes, 1)
	require.True(t, (*outcomes)[0].Allowed, "connection 1's Initial is admitted")
	var v bpf.OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(ev1.FlowKey(), &v))
	require.Equal(t, l7StateAllowed, v.State)
	// The ALLOWED verdict must carry the attempt's EXACT DCID — the kernel
	// compares it byte-for-byte, so a forged fold cannot ride this verdict.
	require.Equal(t, uint8(len(dcid1)), v.DcidLen, "the verdict must record the DCID length")
	require.Equal(t, dcid1, v.Dcid[:v.DcidLen], "the verdict must record the exact DCID bytes")

	// A second connection attempt: the kernel saw a different DCID and
	// re-pinned. Policy no longer allows the name — the fresh adjudication
	// must consult it, not ride the tombstoned verdict.
	l.matcher = allowSet{}
	dcid2 := []byte{9, 9, 9, 9, 8, 8, 8, 8}
	ev2 := makeL7Event(443, 0, initial, true)
	ev2.DcidLen = uint8(copy(ev2.Dcid[:], dcid2))
	ev2.Flags |= l7PuntRepin
	l.onSample(ev2)

	require.Len(t, *outcomes, 2, "a REPIN punt must re-adjudicate, not drop as stale")
	require.False(t, (*outcomes)[1].Allowed, "the second attempt meets current policy")
	require.Equal(t, L7Mismatch, (*outcomes)[1].Reason)
	require.NoError(t, objs.MapL7Flow.Lookup(ev1.FlowKey(), &v))
	require.Equal(t, l7StateDenied, v.State, "the fresh deny must reach the kernel flow map")
	require.Equal(t, uint8(len(dcid2)), v.DcidLen, "the DENIED verdict must pin the attempt's DCID")
	require.Equal(t, dcid2, v.Dcid[:v.DcidLen], "the deny is scoped to THIS attempt, not the socket")
}

// TestL7ReassemblyLowerSeqReanchors: a segment whose sequence is LOWER than
// the latched base (its uint32 delta wraps ~2^32) must re-anchor the assembler
// rather than compute an out-of-range offset and deny the flow as
// ErrAssemblyOverflow. Belt-and-suspenders — the kernel's stamp-on-successful-
// punt keeps segments in order at the oracle in the common case — but a lost
// punt must degrade to a re-drive, never a false deny of a legitimate flow.
func TestL7ReassemblyLowerSeqReanchors(t *testing.T) {
	full := snitest.BuildClientHello("split.example.com")

	l := &L7{matcher: allowSet{"split.example.com": true}, flows: map[bpf.OriginBpfL7FlowKey]*l7flow{}}
	st := &l7flow{proto: sni.ProtoTLS}

	// Base latches HIGH on a partial record prefix → incomplete.
	high := makeL7Event(443, 10000, full[:5], false)
	l.flows[high.FlowKey()] = st
	needMore, _ := accumulateDrive(l, st, high, full[:5])
	require.True(t, needMore, "a record prefix alone is incomplete")

	// A LOWER-seq segment: delta = 5000-10000 wraps to ~2^32. It must
	// re-anchor (Reset + rebase) and adjudicate the full hello it carries —
	// NOT deny with ErrAssemblyOverflow.
	low := makeL7Event(443, 5000, full, false)
	_, out := accumulateDrive(l, st, low, full)
	require.True(t, out.Allowed, "the re-anchored full hello must adjudicate, not overflow (why=%q)", out.Reason)
	require.Equal(t, "split.example.com", out.Name)
}

// TestL7AccumulateQUICNoInitialFailsClosed: the kernel punts a QUIC datagram
// ONLY when its walk found a known-version Initial — a datagram it cannot
// classify is dropped there, never punted. So a SAMPLE the decoder finds no
// Initial in is drift or a malformed Initial-shaped packet, and it must fail
// closed WITH a record: the kernel has already parked the flow PENDING, so
// returning "nothing to adjudicate" would strand every later datagram on the
// socket with no audit trail.
func TestL7AccumulateQUICNoInitialFailsClosed(t *testing.T) {
	l := &L7{matcher: allowSet{}, flows: map[bpf.OriginBpfL7FlowKey]*l7flow{}}
	st := &l7flow{proto: sni.ProtoQUIC}
	// Long header (0x80 set), type bits = 0b01 (NOT Initial for v1), version 1.
	pkt := []byte{0xd0, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00}
	_, out := accumulateDrive(l, st, makeL7Event(443, 0, pkt, true), pkt)
	require.False(t, out.Allowed, "a punted sample with no Initial must fail closed, not park the flow")
	require.Equal(t, L7NotProtocol, out.Reason)
}

// TestL7UndecidedNewDCIDResetsOnNoState: the DCID is the connection-attempt
// identity in EVERY state, userspace included. The kernel raises REPIN only
// when ITS entry held a disagreeing DCID — so when that entry is LRU-evicted
// mid-handshake, the next attempt arrives NO_STATE with nothing there to
// compare, and the oracle must notice the identity changed on its own.
// Without that, the new attempt's CRYPTO merges into the superseded
// assembler and a legitimate handshake is denied as an overlap conflict.
func TestL7UndecidedNewDCIDResetsOnNoState(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{"example.com": true}}, nil)
	outcomes := captureSink(l)

	dcid1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	dcid2 := []byte{9, 9, 9, 9, 8, 8, 8, 8}

	// Attempt 1: an undecided cycle whose assembler already holds CRYPTO (a
	// ClientHello spanning several Initials, still incomplete).
	fresh := makeL7Event(443, 0, snitest.RFC9001ClientInitial(), true)
	fresh.DcidLen = uint8(copy(fresh.Dcid[:], dcid2))
	fresh.Flags |= l7PuntNoState // its kernel entry was evicted: no DCID to REPIN from

	l.mu.Lock()
	// lastSeen/lastSweep are set so the TTL sweep on the next punt does not
	// collect the entry out from under the case being tested.
	st := &l7flow{proto: sni.ProtoQUIC, dcid: append([]byte(nil), dcid1...), lastSeen: time.Now()}
	require.NoError(t, st.asm.Add(0, []byte{0xde, 0xad, 0xbe, 0xef}))
	l.flows[fresh.FlowKey()] = st
	l.lastSweep = time.Now()
	l.mu.Unlock()

	// Attempt 2 arrives NO_STATE under a DIFFERENT DCID.
	l.onSample(fresh)

	require.Len(t, *outcomes, 1, "the new attempt must adjudicate")
	require.True(t, (*outcomes)[0].Allowed,
		"the new attempt's own CRYPTO must decide it, not a merge with the superseded "+
			"attempt's bytes (reason=%q)", (*outcomes)[0].Reason)
	require.Equal(t, L7Allowed, (*outcomes)[0].Reason)

	var v bpf.OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(fresh.FlowKey(), &v))
	require.Equal(t, dcid2, v.Dcid[:v.DcidLen], "the verdict pins the NEW attempt's identity")
}

// TestL7TombstoneSweepIsNotHeldOpenByStalePunts: a decided flow is kept as a
// tombstone until the TTL sweep collects it, and its TTL has to run from the
// DECISION. onSample used to stamp lastSeen before the decided check, so every
// stale punt re-armed the tombstone: a flow whose kernel entry keeps getting
// clobbered back to PENDING (the re-assert cycle) or LRU-evicted and re-punted
// never aged out, and with enough of them l.flows saturated at l7MaxFlows and
// evictOneLocked began dropping LIVE parked flows, forcing each to
// re-accumulate from a mid-stream segment.
func TestL7TombstoneSweepIsNotHeldOpenByStalePunts(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{"auth.docker.io": true}}, nil)
	captureSink(l)

	first := makeL7Event(443, 1000, snitest.BuildClientHello("auth.docker.io"), false)
	l.onSample(first)
	require.Len(t, l.flows, 1, "the decided flow is kept as a tombstone")

	// Age the tombstone past the TTL, then deliver a stale punt. It re-asserts
	// the verdict, and must NOT push the tombstone's expiry out.
	l.mu.Lock()
	l.flows[first.FlowKey()].lastSeen = time.Now().Add(-2 * l7FlowTTL)
	l.mu.Unlock()

	stale := makeL7Event(443, 2000, snitest.BuildClientHello("evil.example"), false)
	l.onSample(stale)

	l.mu.Lock()
	aged := time.Since(l.flows[first.FlowKey()].lastSeen)
	l.lastSweep = time.Now().Add(-2 * l7SweepInterval)
	l.mu.Unlock()
	require.Greater(t, aged, l7FlowTTL, "a stale punt must not refresh the tombstone's TTL")

	// The next sample on any flow runs the sweep, which must now collect it.
	other := makeL7Event(443, 1000, snitest.BuildClientHello("auth.docker.io"), false)
	other.Cookie = first.Cookie + 1
	l.onSample(other)
	require.NotContains(t, l.flows, first.FlowKey(), "the sweep must collect the aged tombstone")
}

// TestL7OutcomeReportsTheParsedProtocol: accumulate parses with the flow's
// first-seen protocol (st.proto) while finish used to stamp the outcome from
// THIS sample's scope byte. When the two disagree — kernel/userspace drift, or
// a flow key reused across a scope change — the operator got a
// not_protocol/parse_error denial labelled with a decoder that never ran.
func TestL7OutcomeReportsTheParsedProtocol(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{}}, nil)
	outcomes := captureSink(l)

	// The flow is created as TLS...
	first := makeL7Event(443, 1000, snitest.BuildClientHello("evil.example")[:8], false)
	l.onSample(first)
	require.Empty(t, *outcomes, "a partial hello parks the flow")

	// ...and a later sample on the same key arrives stamped QUIC. The parse
	// still runs as TLS, so the report must say TLS.
	second := makeL7Event(443, 1000, snitest.BuildClientHello("evil.example"), false)
	second.Scope = bpf.L7ScopeQUIC
	l.onSample(second)

	require.Len(t, *outcomes, 1)
	require.Equal(t, sni.ProtoTLS, (*outcomes)[0].Protocol,
		"the outcome must name the protocol the handshake was parsed with")
}
