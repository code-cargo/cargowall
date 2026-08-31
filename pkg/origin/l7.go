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

// L7 map ownership and lifecycle: the scope maps the DNS path populates, the
// punt-ringbuf reader, the sink worker, and the kernel stat counters. The
// adjudication itself lives in l7_oracle.go.

package origin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// L7 mode, mirroring sni.h. Independent of the origin Mode so L7 can be
// dark-launched while origin enforcement is already on.
const (
	L7ModeOff     uint8 = 0
	L7ModeObserve uint8 = 1
	L7ModeEnforce uint8 = 2
)

// map_origin_config key owned by sni.h (0 and 1 belong to origin).
const l7CfgKeyMode = uint32(2)

// Flow-state values written back to map_l7_flow (sni.h L7_STATE_*).
const (
	l7StateAllowed uint8 = 2
	l7StateDenied  uint8 = 3
)

// Punt flags (sni.h L7_PUNT_F_*).
const (
	l7PuntNoState   uint8 = 0x01
	l7PuntObserve   uint8 = 0x02
	l7PuntTruncated uint8 = 0x04
	l7PuntQUIC      uint8 = 0x08
	l7PuntRepin     uint8 = 0x10 // a new QUIC Initial DCID superseded the flow's identity
	l7PuntRefused   uint8 = 0x20 // an identity-gate refusal record, not an adjudication punt
)

// Stats slots (sni.h L7_STAT_*), read by logStats and pinned against the C
// source by TestL7KernelConstantsMatchSniSource.
const (
	l7StatPunt        uint32 = 0
	l7StatPuntDropped uint32 = 1
	l7StatQUIC        uint32 = 2
	l7StatBudget      uint32 = 3
	l7StatAllowed     uint32 = 4
	l7StatDenied      uint32 = 5
	l7StatGateRefused uint32 = 6
	l7StatPendingNoID uint32 = 7
	l7StatGateNoState uint32 = 8
	l7StatAltUngated  uint32 = 9
)

// L7Options configures the oracle. Everything the reader goroutines read is
// supplied here, at construction, so a half-configured oracle is
// unrepresentable — a half-configured PinIP was exactly the bypass the flag
// exists to prevent.
type L7Options struct {
	// Matcher is the only name authority. Required.
	Matcher L7Matcher
	// PinIP additionally requires a name to be bound to the destination it is
	// presented at (L7MatchElsewhere denies instead of reporting would-narrow).
	PinIP bool
	// Sink receives adjudicated outcomes for audit/telemetry. Optional; when
	// nil the oracle still enforces, it just reports nothing.
	Sink func(L7Outcome)
}

// L7 owns the L7 maps, the punt-ringbuf reader, and the reassembly state.
type L7 struct {
	scope   *ebpf.Map
	scopeV6 *ebpf.Map
	flow    *ebpf.Map
	events  *ebpf.Map
	cfg     *ebpf.Map
	stats   *ebpf.Map
	reader  *ringbuf.Reader
	logger  *slog.Logger

	matcher L7Matcher
	pinIP   bool
	sink    func(L7Outcome)

	// scopeMu serializes ScopeIP's read-modify-write of the scope maps:
	// concurrent DNS resolutions for hostnames sharing an edge IP would
	// otherwise each read the old bits and the last Put would drop the other's
	// dimension (fail-open on that protocol). It also guards scopeFullWarned.
	scopeMu         sync.Mutex
	scopeFullWarned bool
	// scopeFullDrops counts destinations that could not be scoped because the
	// map was full — each one is an IP L7 no longer covers.
	scopeFullDrops atomic.Uint64

	mu        sync.Mutex
	flows     map[bpf.OriginBpfL7FlowKey]*l7flow
	lastSweep time.Time

	// sinkCh decouples sink invocations (audit encode+fsync, procfs reads)
	// from the ringbuf reader: a burst of denials must never stall the reader
	// while the kernel ring overflows. Nil when the oracle is driven
	// synchronously (tests calling onSample directly). Overflow drops the
	// REPORT only — the verdict was already written — and is counted.
	sinkCh      chan L7Outcome
	sinkDone    chan struct{}
	sinkDropped atomic.Uint64

	done chan struct{}
}

// newL7 wires the oracle to the loaded collection's L7 maps. Call start to run
// it; EnableL7 does both.
func newL7(objs *bpf.OriginBpfObjects, opts L7Options, logger *slog.Logger) *L7 {
	return &L7{
		scope:   objs.MapL7Scope,
		scopeV6: objs.MapL7ScopeV6,
		flow:    objs.MapL7Flow,
		events:  objs.MapL7Events,
		cfg:     objs.MapOriginConfig,
		stats:   objs.MapL7Stats,
		logger:  logger,
		matcher: opts.Matcher,
		pinIP:   opts.PinIP,
		sink:    opts.Sink,
		flows:   make(map[bpf.OriginBpfL7FlowKey]*l7flow),
		done:    make(chan struct{}),
	}
}

// start launches the punt-ringbuf reader and the sink worker. Separate from
// the origin-event reader so a punt backlog never queues behind origin-record
// dedup traffic.
func (l *L7) start() error {
	rd, err := ringbuf.NewReader(l.events)
	if err != nil {
		return fmt.Errorf("l7: creating punt reader: %w", err)
	}
	l.reader = rd
	l.sinkCh = make(chan L7Outcome, 512)
	l.sinkDone = make(chan struct{})
	go l.sinkLoop()
	go l.run()
	return nil
}

// SetMode writes the L7 rollout gate. Deliberately NOT part of L7Options: the
// gate is raised only after the scope maps have warmed, so a flow is never
// adjudicated against empty maps. The kernel's ENFORCE drop still defers to
// audit_mode_active().
func (l *L7) SetMode(mode uint8) error {
	return l.cfg.Put(l7CfgKeyMode, mode)
}

// l7ScopeFromPorts maps a rule's allowed ports onto the L7 dimensions to pin.
// An empty port list is an all-ports allow, which includes 443 and 80, so all
// three dimensions apply; a specific list scopes only the ports it names.
//
// It lives HERE, not in pkg/dns, because L7_SCOPE_* is the value layout of
// map_l7_scope — an implementation detail of the map this package owns. The
// callers upstream (the DNS proxy, the late-allow path) speak in a rule's
// ports and must never have to know the bitmask.
//
// TLS and Host cover the CDN alternate ports too: an all-ports hostname allow
// opens the edge /32 on every port, so scoping only 443/80 would govern the
// identity there while leaving the same shared edge L4-only everywhere else it
// terminates TLS. The kernel's l7_narrow_scope reads the same two tables.
func l7ScopeFromPorts(ports []config.Port) uint8 {
	if len(ports) == 0 {
		return bpf.L7ScopeTLS | bpf.L7ScopeHTTP | bpf.L7ScopeQUIC
	}
	var flags uint8
	for _, p := range ports {
		tcp := p.Protocol == config.ProtocolTCP || p.Protocol == config.ProtocolAll
		udp := p.Protocol == config.ProtocolUDP || p.Protocol == config.ProtocolAll
		switch {
		case p.Port == 443:
			if tcp {
				flags |= bpf.L7ScopeTLS
			}
			if udp {
				flags |= bpf.L7ScopeQUIC
			}
		case p.Port == 80:
			if tcp {
				flags |= bpf.L7ScopeHTTP
			}
		case tcp && bpf.IsAltHTTPSPort(p.Port):
			flags |= bpf.L7ScopeTLS
		case tcp && bpf.IsAltHTTPPort(p.Port):
			flags |= bpf.L7ScopeHTTP
		}
	}
	return flags
}

// ScopeIP marks a destination IP L7-scoped for the dimensions its rule's ports
// open, unioning with any already present. Called by the DNS registrar as
// names resolve, concurrently from per-query goroutines. A rule that opens no
// L7-governed port leaves the IP at L4.
func (l *L7) ScopeIP(ip net.IP, ports []config.Port) error {
	flags := l7ScopeFromPorts(ports)
	if flags == 0 {
		return nil
	}
	l.scopeMu.Lock()
	defer l.scopeMu.Unlock()
	if ip4 := ip.To4(); ip4 != nil {
		key := binary.NativeEndian.Uint32(ip4) // network-order bytes, per pkg/firewall
		var cur uint8
		if err := l.scope.Lookup(key, &cur); err == nil {
			flags |= cur
		}
		return l.scopeFull(l.scope.Put(key, flags), ip, l.scope)
	}
	ip6 := ip.To16()
	if ip6 == nil {
		return fmt.Errorf("l7: not an IP: %v", ip)
	}
	var key [16]byte
	copy(key[:], ip6)
	var cur uint8
	if err := l.scopeV6.Lookup(key, &cur); err == nil {
		flags |= cur
	}
	return l.scopeFull(l.scopeV6.Put(key, flags), ip, l.scopeV6)
}

// FlushScopes empties both scope maps. Called on policy reload, immediately
// before the tracked-hostname replay re-warms them — the two are one step:
// scope entries have no expiry and no per-name reverse index, so a dropped
// rule's IPs would otherwise stay L7-governed forever, and dead entries would
// eventually fill the fixed-size maps and silently FAIL-OPEN every newly
// resolved destination (see scopeFull). The unscoped window between flush and
// re-warm fails toward the pre-L7 posture.
func (l *L7) FlushScopes() error {
	l.scopeMu.Lock()
	defer l.scopeMu.Unlock()
	// Reload made room again: re-arm the one-shot fail-open warning so a
	// post-reload fill is as loud as the first. The cumulative drop counter is
	// left intact for a run-wide total at close.
	l.scopeFullWarned = false
	// BOTH maps, always. Returning on the v4 error left every v6 entry in
	// place while the caller logged a warning and re-warmed on top of it, so a
	// dropped rule's v6 IPs stayed L7-governed forever and the dead entries
	// accumulated until the fixed-size map filled — where scopeFull's
	// documented fail-OPEN takes over.
	err4 := drainScopeMap[uint32](l.scope)
	err6 := drainScopeMap[[16]byte](l.scopeV6)
	return errors.Join(err4, err6)
}

// drainScopeMap empties one scope map. Batch ops first — a full map drains in
// a handful of syscalls where the per-entry walk costs two each, all spent
// under scopeMu with concurrent DNS-resolution ScopeIP calls stalled behind
// it. The walk stays as the fallback: batch support is per-map-type, not just
// per-kernel-version.
func drainScopeMap[K uint32 | [16]byte](m *ebpf.Map) error {
	keys := make([]K, 1024)
	vals := make([]uint8, 1024)
	var cursor ebpf.MapBatchCursor
	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, vals, nil)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // drained
		}
		if err != nil {
			break // fall back to the per-entry walk
		}
		if n == 0 {
			// Success with no elements: not the documented end-of-map signal,
			// so nothing here proves the next call makes progress either. The
			// loop holds scopeMu, and spinning under it would block every
			// ScopeIP and hang the reload that called us. Fall back instead.
			break
		}
	}
	var k K
	for {
		if err := m.NextKey(nil, &k); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil // drained
			}
			return err
		}
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
}

// scopeFull escalates a scope-map write failure. The map is fixed-size with no
// eviction, so a full map means every newly resolved destination stays
// L4-allowed but never L7-scoped while the daemon still reports L7 active.
// That is a fail-OPEN, so it gets a loud one-shot warning rather than the
// Debug line callers give ordinary registration errors. Called with scopeMu
// held. `m` is the map the failing Put targeted — the warning is what an
// operator sizes the fix from, and reporting the v4 capacity for a v6 overflow
// sent them to resize the wrong map.
func (l *L7) scopeFull(err error, ip net.IP, m *ebpf.Map) error {
	if err == nil || l.logger == nil {
		return err
	}
	if errors.Is(err, unix.E2BIG) || errors.Is(err, unix.ENOSPC) {
		if !l.scopeFullWarned {
			l.scopeFullWarned = true
			l.logger.Warn("L7 scope map is FULL — newly resolved destinations are no longer "+
				"SNI-enforced (they stay L4-allowed); L7 coverage is now partial for this run",
				"ip", ip.String(), "map", m.String(), "capacity", m.MaxEntries(), "error", err)
		}
		l.scopeFullDrops.Add(1)
	}
	return err
}

func (l *L7) close() {
	if l.reader != nil {
		_ = l.reader.Close()
		<-l.done // run() was sinkCh's only sender and has exited
	}
	if l.sinkCh != nil {
		close(l.sinkCh)
		<-l.sinkDone
	}
	if n := l.sinkDropped.Load(); n > 0 && l.logger != nil {
		l.logger.Warn("L7 outcome reports dropped by a saturated sink", "dropped", n)
	}
	if n := l.scopeFullDrops.Load(); n > 0 && l.logger != nil {
		l.logger.Warn("L7 scope map was full — destinations left un-enforced this run",
			"unscoped_destinations", n)
	}
	l.logStats()
}

// sinkLoop delivers outcomes off the ringbuf reader, which must stay free to
// drain the kernel ring even while the sink pays for audit and procfs I/O.
func (l *L7) sinkLoop() {
	defer close(l.sinkDone)
	for o := range l.sinkCh {
		if l.sink != nil {
			l.sink(o)
		}
	}
}

// logStats surfaces the kernel counters at teardown. Load-bearing for punts
// that never produced an oracle record: a sample lost to a full ring or a flow
// that exhausted its budget was DROPPED under enforce with no event anywhere,
// so a silent close would leave an unexplained hang looking like an allowed
// flow (its SYN's origin record said ALLOW).
func (l *L7) logStats() {
	if l.stats == nil || l.logger == nil {
		return
	}
	sum := func(slot uint32) uint64 {
		var per []uint64
		if err := l.stats.Lookup(slot, &per); err != nil {
			return 0
		}
		var t uint64
		for _, v := range per {
			t += v
		}
		return t
	}
	puntDropped, budget := sum(l7StatPuntDropped), sum(l7StatBudget)
	gateRefused, pendingNoID := sum(l7StatGateRefused), sum(l7StatPendingNoID)
	gateNoState := sum(l7StatGateNoState)
	l.logger.Info("L7 oracle closed",
		"punts", sum(l7StatPunt), "punts_dropped_ring_full", puntDropped,
		"quic_punts", sum(l7StatQUIC), "budget_exhausted", budget,
		"allowed", sum(l7StatAllowed), "denied", sum(l7StatDenied),
		"identity_gate_refused", gateRefused, "pending_no_identity", pendingNoID,
		"no_state_refused", gateNoState,
		// Packets on an alternate HTTPS/HTTP port that carried no TLS/HTTP
		// identity and were PASSED rather than refused. Reported so the
		// widened scope's residual is visible next to the refusals.
		"alt_port_ungated", sum(l7StatAltUngated))
	if puntDropped > 0 || budget > 0 {
		l.logger.Warn("L7 flows were dropped without an audit record "+
			"(full punt ring or exhausted punt budget fails closed in enforce)",
			"punts_dropped_ring_full", puntDropped, "budget_exhausted", budget)
	}
	if gateRefused > 0 {
		// Posture-neutral wording: under enforce these were dropped, under
		// observe passed, and the count is the incidence to weigh before
		// turning enforcement on. Each also emitted a per-flow record unless
		// the ring was full. no_state_refused is kept OUT of this number —
		// those are mostly evicted flows' mid-record ciphertext.
		l.logger.Warn("L7 identity gate refused first flights carrying no usable "+
			"identity (non-TLS on 443, no HTTP request line on 80, or an "+
			"unclassifiable QUIC datagram) — dropped under enforce, passed "+
			"under observe; see the per-flow refusal audit records",
			"identity_gate_refused", gateRefused)
	}
}

func (l *L7) run() {
	defer close(l.done)
	// Consecutive unexpected read errors. A deadline tick is the normal case
	// and is not one; anything else may be sticky (a failed epoll or fd), and
	// treating it as "retry immediately" would spin at 100% CPU with no log
	// while the punt path silently stopped delivering.
	readErrs := 0
	// One Record reused across reads: an l7_event is ~16.5KB, so a fresh
	// RawSample per punt would put N x 16.5KB/s of garbage on this goroutine
	// at N punts/s — GC pressure exactly when the ring is busiest, and a
	// stalled reader means fail-closed drops under enforce. Safe because
	// onSample copies out everything it keeps before the next read.
	var rec ringbuf.Record
	for {
		// Poll on a coarse deadline rather than blocking indefinitely: the
		// kernel's adaptive ringbuf notification is best-effort, and a punt
		// whose wakeup is missed generates no further wakeups on a quiet host
		// (retransmits are deduped, so no new sample). Blocking forever left
		// the flow PENDING with every retransmit dropped under enforce — an
		// unaudited black hole. A deadline tick still drains pending records,
		// bounding the stall at one tick.
		l.reader.SetDeadline(time.Now().Add(time.Second))
		err := l.reader.ReadInto(&rec)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				readErrs = 0
				continue // the poll tick: no samples this second
			}
			readErrs++
			if readErrs == 1 && l.logger != nil {
				l.logger.Warn("L7 punt reader read failed — retrying; while this "+
					"persists no verdict is written and enforce drops every "+
					"punted flow", "err", err)
			}
			time.Sleep(100 * time.Millisecond) // a sticky error must not spin
			continue
		}
		readErrs = 0
		ev, ok := bpf.L7EventFromBytes(rec.RawSample)
		if !ok {
			continue
		}
		l.onSample(ev)
	}
}
