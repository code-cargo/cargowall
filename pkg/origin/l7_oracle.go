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

// The verdict oracle: the ONLY name matcher. The kernel decides WHETHER a
// segment needs adjudication and punts it here; this reassembles the punted
// handshake, parses it with pkg/sni, matches the recovered name against
// policy, and writes the verdict back into map_l7_flow so the client's
// retransmit is admitted or dropped in the kernel. It never carries traffic.

package origin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/sni"
)

// Bounds on per-flow reassembly state. Without them every flow that ends
// undecided (a split hello never completed, a client dead mid-handshake) leaks
// its entry and Assembler for the daemon's lifetime — free for an attacker to
// trigger in observe mode, where an incomplete handshake passes at L4 yet
// parks state here.
const (
	// l7MaxFlows caps userspace flow state at the kernel map_l7_flow LRU size:
	// past that the kernel evicts its own entries anyway.
	l7MaxFlows = 16384
	// l7FlowTTL expires idle flows and decided tombstones. A decision normally
	// lands in milliseconds; a flow idle this long re-punts if it speaks again.
	l7FlowTTL = 30 * time.Second
	// l7SweepInterval bounds how often the expiry sweep walks the map. It runs
	// on the punt path under l.mu, so it must stay rare.
	l7SweepInterval = 10 * time.Second
)

// L7Reason is why the oracle decided a flow the way it did — the verdict
// layer's vocabulary, deliberately not pkg/sni's (which is parse-only).
type L7Reason string

const (
	L7Allowed     L7Reason = "allowed"
	L7Mismatch    L7Reason = "name_mismatch" // a name was recovered but no rule allows it
	L7NoName      L7Reason = "no_name"       // TLS with no SNI / HTTP with no Host
	L7ECH         L7Reason = "ech"           // ECH present, no usable cleartext SNI
	L7NotProtocol L7Reason = "not_protocol"  // not TLS/HTTP/QUIC on a scoped port
	L7QUICVersion L7Reason = "quic_version"  // unknown QUIC version
	L7ParseError  L7Reason = "parse_error"   // malformed handshake
	L7Reassembly  L7Reason = "reassembly"    // overlap conflict / overflow
	// L7NameNotAtIP: the name IS allowed by policy on this port, but this
	// daemon never saw it resolve to THIS destination. Distinct from
	// L7Mismatch because observe-mode telemetry has to separate "name not
	// allowed at all" from "name allowed, but not here" to decide whether the
	// binding is safe to enforce.
	L7NameNotAtIP L7Reason = "name_not_at_ip"
)

// L7Matcher is the name authority. Its vocabulary is pkg/config's, not a
// parallel copy: the port is load-bearing (a name allowed only on :22 must not
// validate as an SNI on a shared edge IP some 443 rule scoped) and so is the
// destination (without it an allowed name is a passphrase that opens every
// scoped IP), and both dimensions are decided by the policy plane. Injected so
// the oracle can be tested without a config.Manager; config.L7Policy is the
// production implementation.
type L7Matcher interface {
	MatchName(q config.L7Request) config.L7Match
}

// L7Outcome is one adjudicated flow. A small VALUE type, deliberately not the
// 16KB ringbuf sample: the sink never reads the punted payload, the async sink
// queue must not hold megabytes of dead handshake bytes, and the oracle's
// public API should not leak the BPF wire layout.
//
// adjudicate fills the policy half (Name, Reason, Allowed, WouldNarrow);
// finish adds the flow identity while the sample is in hand.
type L7Outcome struct {
	Cookie   uint64
	CgroupID uint64
	SrcIP    netip.Addr
	DstIP    netip.Addr
	DstPort  uint16
	IPProto  uint8        // L4 protocol number
	Protocol sni.Protocol // the identity the oracle parsed; audit label via String()
	Name     string
	Reason   L7Reason
	Allowed  bool
	Enforce  bool // false in observe mode (the packet was passed regardless)
	// WouldNarrow marks a flow the per-IP binding WOULD have denied while that
	// dimension is only measured (Allowed stays true). This is the number that
	// decides whether pinning is safe to turn on.
	WouldNarrow bool
}

// l7flow is the per-flow reassembly state kept between punts.
type l7flow struct {
	proto    sni.Protocol
	asm      sni.Assembler
	baseSeq  uint32
	haveBase bool
	// decided marks a flow whose terminal verdict reached the kernel. The
	// entry is kept as a tombstone (assembler freed) until the TTL sweep
	// collects it, so punts already queued when the verdict landed are dropped
	// here instead of restarting accumulation from a mid-stream segment and
	// racing a second, contradictory verdict against the one just written.
	decided bool
	// verdict and dcid are what writeFlowState stamped, kept so a stale punt
	// that clobbered the kernel entry back to PENDING can re-assert instead of
	// stranding the flow (see l7_commit_pending for the race the kernel
	// narrows but cannot close).
	verdict  uint8
	dcid     []byte
	lastSeen time.Time
}

// onSample accumulates one punt into its flow's reassembly buffer and, once
// the handshake is complete, adjudicates it and writes the verdict back. The
// QUIC decrypt runs under l.mu, in accumulate, so a stale punt is dropped
// before paying for it; this goroutine is the mutex's only contended locker.
func (l *L7) onSample(ev *bpf.L7Event) {
	// An identity-gate refusal record: report-only. The kernel already
	// answered the packet and parked nothing, so there is no cycle to open.
	if ev.Flags&l7PuntRefused != 0 {
		l.reportRefusal(ev)
		return
	}

	fk := ev.FlowKey()
	payload := ev.Payload[:ev.PayloadLen]

	now := time.Now()
	l.mu.Lock()
	l.maybeSweepLocked(now)
	st := l.flows[fk]
	if st == nil {
		if len(l.flows) >= l7MaxFlows {
			l.evictOneLocked(fk)
		}
		st = &l7flow{proto: protocolForEvent(ev)}
		l.flows[fk] = st
	}
	if st.decided && ev.Flags&(l7PuntNoState|l7PuntRepin) == 0 {
		// A punt queued before our verdict landed: stale. Its kernel-side
		// write may have clobbered the entry back to PENDING, which would
		// strand the flow under enforce — re-assert rather than only
		// dropping the sample.
		//
		// lastSeen is deliberately NOT refreshed here: a tombstone's TTL runs
		// from the DECISION, and refreshing it on stale punts kept the entry
		// alive for as long as they kept arriving — the sweep could never
		// collect it, and l.flows saturating at l7MaxFlows made evictOneLocked
		// start dropping live parked flows instead.
		verdict, dcid := st.verdict, st.dcid
		l.mu.Unlock()
		if err := l.reassertVerdict(fk, verdict, dcid); err != nil && l.logger != nil {
			l.logger.Warn("L7 verdict re-assert failed", "err", err)
		}
		return
	}
	st.lastSeen = now
	if st.decided {
		// NO_STATE: the kernel LRU evicted the entry after we adjudicated, so
		// the verdict is gone and the kernel punts until a new one is written.
		// REPIN: a new QUIC attempt superseded the adjudicated one. Either
		// way, start over from this sample.
		*st = l7flow{proto: st.proto, lastSeen: now}
	} else if ev.Flags&l7PuntRepin != 0 || supersededDCID(st, ev) {
		// A new attempt superseded a still-undecided cycle: its CRYPTO must
		// not mix with the superseded assembler's.
		*st = l7flow{proto: st.proto, lastSeen: now}
	}
	// Record the cycle's identity. REPIN only fires when the KERNEL had a
	// stored DCID to disagree with; if its entry was LRU-evicted mid-handshake
	// the next attempt arrives NO_STATE with nothing to compare there, so this
	// is what lets supersededDCID catch it above.
	if len(st.dcid) == 0 {
		st.dcid = append([]byte(nil), eventDCID(ev)...)
	}

	needMore, out := l.accumulate(st, ev, payload)
	if needMore && ev.Flags&l7PuntTruncated != 0 {
		// The sample was cut at the kernel's punt window: the missing bytes
		// were never captured and a retransmit reproduces the same cut, so
		// "need more" can never be satisfied. A terminal deny with a record,
		// not a parked flow that black-holes under enforce.
		needMore, out = false, L7Outcome{Reason: L7ParseError}
	}
	if needMore {
		l.mu.Unlock()
		return
	}
	// Tombstone rather than delete — see l7flow.decided. Reset frees the
	// assembler; the TTL sweep collects the entry.
	st.decided = true
	st.verdict = l7FlowState(out.Allowed)
	// The QUIC connection-attempt identity the verdict pins, taken from the
	// kernel-extracted event field so there is exactly ONE decoder of the
	// Initial's long header. Stamped with BOTH verdicts: on ALLOWED so the
	// adjudicated attempt's Initials pass, on DENIED so only THAT attempt
	// stays denied while a new DCID re-enters adjudication (the kernel entry
	// has no TTL — an identity-less deny would sentence the whole socket).
	st.dcid = append([]byte(nil), eventDCID(ev)...)
	dcid := st.dcid
	// The protocol the flow was PARSED with, not this sample's scope byte:
	// accumulate ran st.proto, so reporting protocolForEvent(ev) would label a
	// not_protocol/parse_error denial with a decoder that never ran if the two
	// ever disagreed (kernel/userspace drift, a flow key reused across a scope
	// change). One value, one place it is read.
	flowProto := st.proto
	st.asm.Reset()
	l.mu.Unlock()

	l.finish(ev, flowProto, out, dcid)
}

// eventDCID returns the sample's QUIC connection-attempt identity, or nil for
// TCP and for a length the sample cannot carry.
func eventDCID(ev *bpf.L7Event) []byte {
	n := int(ev.DcidLen)
	if n <= 0 || n > len(ev.Dcid) {
		return nil
	}
	return ev.Dcid[:n]
}

// supersededDCID reports whether this sample belongs to a DIFFERENT connection
// attempt than the one st is assembling. The DCID is the attempt identity in
// every state, and userspace has to check it too: the kernel raises REPIN only
// when ITS entry held a disagreeing DCID, so an attempt that arrives after its
// kernel entry was LRU-evicted comes in as NO_STATE with nothing there to
// compare — and without this its CRYPTO would merge into the previous
// attempt's assembler and deny a legitimate handshake as an overlap conflict.
func supersededDCID(st *l7flow, ev *bpf.L7Event) bool {
	cur := eventDCID(ev)
	return len(st.dcid) > 0 && len(cur) > 0 && !bytes.Equal(st.dcid, cur)
}

// l7FlowState maps an outcome onto the kernel flow state. THE one derivation:
// onSample stores it on the tombstone and finish writes it to the map, and a
// second copy would let those two write different verdicts for one flow.
func l7FlowState(allowed bool) uint8 {
	if allowed {
		return l7StateAllowed
	}
	return l7StateDenied
}

// maybeSweepLocked expires flows idle past l7FlowTTL — parked reassembly that
// will never complete, and decided tombstones whose dedup window has passed.
// Called with l.mu held, rate-limited by l7SweepInterval.
func (l *L7) maybeSweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < l7SweepInterval {
		return
	}
	l.lastSweep = now
	for k, st := range l.flows {
		if now.Sub(st.lastSeen) > l7FlowTTL {
			delete(l.flows, k)
		}
	}
}

// evictOneLocked drops one arbitrary entry (never the one being inserted) to
// hold the cap when the sweep alone cannot: under a deliberate parked-flow
// flood every entry is fresh, and evicting a random parked flow — which
// re-accumulates from its next punt — beats unbounded growth or refusing state
// for new legitimate flows.
func (l *L7) evictOneLocked(keep bpf.OriginBpfL7FlowKey) {
	for k := range l.flows {
		if k != keep {
			delete(l.flows, k)
			return
		}
	}
}

// accumulate adds this sample's bytes to the flow and re-attempts a decision.
// Must be called with l.mu held (it mutates the flow's assembler).
func (l *L7) accumulate(st *l7flow, ev *bpf.L7Event, payload []byte) (bool, L7Outcome) {
	if st.proto == sni.ProtoQUIC {
		chunks, err := sni.DecodeInitialCrypto(payload)
		if err != nil {
			switch {
			case errors.Is(err, sni.ErrNotQUIC):
				// The kernel punts a QUIC datagram ONLY when its walk found a
				// known-version Initial, so a sample this decoder finds no
				// Initial in is drift or a malformed Initial-shaped packet.
				// Fail closed WITH a record: the flow is already PENDING, so
				// returning "nothing to do" would strand the socket.
				return false, L7Outcome{Reason: L7NotProtocol}
			case errors.Is(err, sni.ErrQUICVersion):
				return false, L7Outcome{Reason: L7QUICVersion}
			default:
				// No ErrIncomplete arm: DecodeInitialCrypto never returns it (a
				// datagram is atomic). CRYPTO-stream incompleteness surfaces
				// from the parser below.
				return false, L7Outcome{Reason: L7ParseError}
			}
		}
		for _, c := range chunks {
			if err := st.asm.Add(c.Offset, c.Data); err != nil {
				return false, L7Outcome{Reason: L7Reassembly}
			}
		}
	} else {
		if !st.haveBase {
			st.baseSeq = ev.Seq
			st.haveBase = true
		}
		delta := ev.Seq - st.baseSeq
		if delta >= 1<<31 {
			// This segment PRECEDES the anchor: the base was latched to
			// whichever punt arrived first, and that was not the lowest-seq
			// segment (a sibling's punt was lost to a full ring, or a reset
			// re-anchored mid-stream). Treating the wrapped delta as an offset
			// would overflow MaxAssembly and deny a legitimate flow under
			// nothing worse than ring pressure. Re-anchor instead; the
			// discarded later bytes are re-delivered by the retransmit.
			st.asm.Reset()
			st.baseSeq = ev.Seq
			delta = 0
		}
		if err := st.asm.Add(uint64(delta), payload); err != nil {
			return false, L7Outcome{Reason: L7Reassembly}
		}
	}
	// ev.DstAddr owns the wire->address conversion (shared with the audit
	// sink), so the string the matcher sees is the spelling the DNS layer
	// recorded.
	q := config.L7Request{DstIP: ev.DstAddr().String(), DstPort: ev.DstPort, Proto: ev.IpProto}
	return adjudicate(st.proto, st.asm.Bytes(), q, l.matcher, l.pinIP)
}

// adjudicate parses the reassembled handshake and maps it onto an outcome.
// Pure: no maps, no I/O — the unit-testable core. It fills the policy half of
// the outcome; needMore means the handshake is not complete yet.
func adjudicate(proto sni.Protocol, buf []byte, q config.L7Request, m L7Matcher, pinIP bool) (bool, L7Outcome) {
	var (
		hello sni.Hello
		err   error
	)
	switch proto {
	case sni.ProtoTLS:
		hello, err = sni.ParseTLSClientHello(buf)
	case sni.ProtoHTTP:
		hello, err = sni.ParseHTTPRequestHost(buf)
	case sni.ProtoQUIC:
		hello, err = sni.ParseQUICClientHello(buf)
	default:
		return false, L7Outcome{Reason: L7NotProtocol}
	}

	if err != nil {
		switch {
		case errors.Is(err, sni.ErrIncomplete):
			return true, L7Outcome{}
		case errors.Is(err, sni.ErrNotTLS), errors.Is(err, sni.ErrNotHTTP):
			return false, L7Outcome{Reason: L7NotProtocol}
		default:
			return false, L7Outcome{Reason: L7ParseError}
		}
	}

	if !hello.HasName() {
		if hello.ECHPresent {
			return false, L7Outcome{Reason: L7ECH}
		}
		return false, L7Outcome{Reason: L7NoName}
	}
	q.Name = hello.ServerName
	switch m.MatchName(q) {
	case config.L7MatchOK:
		return false, L7Outcome{Name: hello.ServerName, Reason: L7Allowed, Allowed: true}
	case config.L7MatchElsewhere:
		// Allowed by name and port, but this daemon never saw the name resolve
		// to this destination. Under pinning that is a deny; otherwise the
		// packet passes and the would-have-denied is reported, which is the
		// measurement deciding whether pinning is safe to enable.
		return false, L7Outcome{
			Name:        hello.ServerName,
			Reason:      L7NameNotAtIP,
			Allowed:     !pinIP,
			WouldNarrow: !pinIP,
		}
	default:
		return false, L7Outcome{Name: hello.ServerName, Reason: L7Mismatch}
	}
}

// finish completes the outcome with the flow's identity, writes the verdict
// (with the QUIC connection-attempt identity when there is one), and reports.
func (l *L7) finish(ev *bpf.L7Event, proto sni.Protocol, out L7Outcome, dcid []byte) {
	out.Cookie = ev.Cookie
	out.CgroupID = ev.CgroupID
	out.SrcIP = ev.SrcAddr()
	out.DstIP = ev.DstAddr()
	out.DstPort = ev.DstPort
	out.IPProto = ev.IpProto
	out.Protocol = proto
	out.Enforce = ev.Flags&l7PuntObserve == 0

	if err := l.writeFlowState(ev.FlowKey(), l7FlowState(out.Allowed), dcid); err != nil && l.logger != nil {
		// Warn, not Debug: under enforce a lost verdict write leaves the flow
		// PENDING, so the kernel drops every retransmit until the punt budget
		// black-holes it — this line is the only operator-visible signal.
		l.logger.Warn("L7 flow verdict write failed — flow will be dropped until re-adjudicated",
			"allowed", out.Allowed, "err", err)
	}

	// Reason is the actual parse/policy verdict in EVERY posture — observe
	// mode exists to MEASURE that breakdown, so it must not be flattened to a
	// generic "would_block". The posture rides Enforce, and the sink maps it
	// to the l7_blocked / l7_would_block event type.
	l.report(out)
}

// report delivers one outcome to the sink — inline when the oracle is driven
// synchronously (tests calling onSample directly), else via sinkCh so the
// reader never blocks on the sink's I/O. A dropped outcome loses only its
// report; the verdict was already written.
func (l *L7) report(o L7Outcome) {
	if l.sink == nil {
		return
	}
	if l.sinkCh == nil {
		l.sink(o)
		return
	}
	select {
	case l.sinkCh <- o:
	default:
		l.sinkDropped.Add(1)
	}
}

// reportRefusal turns an identity-gate refusal record into an audit outcome.
// The kernel already answered the packet (drop under enforce, pass under
// observe) and parked nothing; this is the per-flow trace a counter-only
// refusal lacked, so an operator debugging a hung QUIC or ssh-on-443
// connection sees more than an L4 ALLOW.
func (l *L7) reportRefusal(ev *bpf.L7Event) {
	l.report(L7Outcome{
		Cookie:   ev.Cookie,
		CgroupID: ev.CgroupID,
		SrcIP:    ev.SrcAddr(),
		DstIP:    ev.DstAddr(),
		DstPort:  ev.DstPort,
		IPProto:  ev.IpProto,
		Protocol: protocolForEvent(ev),
		Reason:   refusalReason(ev),
		Enforce:  ev.Flags&l7PuntObserve == 0,
	})
}

// refusalReason classifies a refusal from its snippet. A QUIC long header in a
// version outside the decryptor's table gets its own reason because its remedy
// is extending that table, not fixing a workload.
func refusalReason(ev *bpf.L7Event) L7Reason {
	if ev.Scope == bpf.L7ScopeQUIC {
		s := ev.Payload[:ev.PayloadLen]
		if len(s) >= 5 && s[0]&0x80 != 0 {
			if _, _, known := sni.InitialTypeBits(binary.BigEndian.Uint32(s[1:5])); !known {
				return L7QUICVersion
			}
		}
	}
	return L7NotProtocol
}

// reassertVerdict re-writes a decided flow's terminal verdict over a kernel
// entry that a stale punt's commit clobbered back to PENDING — UNLESS the
// entry now belongs to a DIFFERENT QUIC attempt (its stored DCID disagrees):
// overwriting a newer attempt's PENDING would discard the CRYPTO it has
// already assembled and stall its handshake until the client retransmits. The
// lookup narrows the race the same way the kernel's commit re-lookup does;
// neither closes it, and the converging repin/re-assert cycle repairs the
// remainder. TCP verdicts carry no DCID and always re-assert.
func (l *L7) reassertVerdict(key bpf.OriginBpfL7FlowKey, state uint8, dcid []byte) error {
	if len(dcid) > 0 {
		var cur bpf.OriginBpfL7FlowVal
		if err := l.flow.Lookup(&key, &cur); err == nil {
			if n := int(cur.DcidLen); n > 0 && n <= len(cur.Dcid) && !bytes.Equal(cur.Dcid[:n], dcid) {
				return nil // a newer attempt owns the entry
			}
		}
	}
	return l.writeFlowState(key, state, dcid)
}

// writeFlowState stamps the kernel flow-state map so the client's retransmit
// is admitted or dropped without another punt. dcid is the QUIC
// connection-attempt identity the kernel compares in every state; empty for
// TCP. last_punt_seq is deliberately left zero: it is the kernel's PENDING
// dedup field, never read on a terminal state.
func (l *L7) writeFlowState(key bpf.OriginBpfL7FlowKey, state uint8, dcid []byte) error {
	val := bpf.OriginBpfL7FlowVal{State: state}
	if n := copy(val.Dcid[:], dcid); n > 0 {
		val.DcidLen = uint8(n)
	}
	return l.flow.Update(key, val, ebpf.UpdateAny)
}

// protocolForEvent classifies which L7 identity a punt carries, from the
// kernel's own narrowed scope stamped into every sample — l7_adjudicate
// reduces the scope bits to exactly the dimension the packet's proto+port
// selected before punting, so reading it here means the oracle adjudicates
// under precisely the classification the kernel punted with. Called once, at
// flow creation. An unrecognized scope is drift and maps to ProtoUnknown,
// which adjudicate fails closed with a not_protocol record.
func protocolForEvent(ev *bpf.L7Event) sni.Protocol {
	switch ev.Scope {
	case bpf.L7ScopeQUIC:
		return sni.ProtoQUIC
	case bpf.L7ScopeHTTP:
		return sni.ProtoHTTP
	case bpf.L7ScopeTLS:
		return sni.ProtoTLS
	default:
		return sni.ProtoUnknown
	}
}
