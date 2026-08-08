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

// Package origin owns the cgroup_skb/egress hook (issue #106): the
// flow-origin recorder and, from phase 3b, the primary egress verdict. It
// records every flow's pre-NAT origin — socket cookie, cgroup id, addresses
// — from inside the originating netns, where container sockets are still
// visible. This package loads and attaches the program, resolves each
// record's cookie against the tcbpf pid/step maps at read time, keeps a
// bounded join store that pkg/containers consults to attribute post-NAT TC
// events, and hands verdict-bearing records to a sink that reports them as
// connection outcomes.
//
// What the hook DOES is set at runtime by SetMode:
//   - ModeObserve: passes every packet, records origins only (phase 3a).
//   - ModeShadow: computes the verdict, records would-blocks, still passes.
//   - ModeEnforce: drops denied traffic. The hook is then the primary
//     enforcement point for traffic with a local socket.
//
// The rule maps are shared with the tcbpf collection (MapReplacements) so
// the two hooks can never disagree about policy. A Start error is still
// survivable — TC egress remains attached and enforcing, so the failure
// degrades enforcement to TC-only rather than leaving traffic unpoliced —
// but it is no longer merely "attribution disabled".
package origin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/code-cargo/cargowall/bpf"
)

// The ringbuf wire layout is bpf.OriginEvent (bpf/origin_event.go) — the one
// Go mirror of struct origin_event, shared with the BTF layout test so the
// struct this reader casts bytes to is the struct the test validates.

// map_origin_config keys, mirroring ORIGIN_CFG_KEY_* in originbpf.c.
const (
	cfgKeyMode       = uint32(0)
	cfgKeyLoCarveout = uint32(1)
)

// Mode is the cgroup hook's enforcement posture, mirroring ORIGIN_MODE_* in
// originbpf.c. The program is attached early (the observer and the join
// store need it) but stays inert until userspace raises the mode — after the
// allowlist, auto-allows, and existing-connection gating are programmed.
type Mode uint8

const (
	// ModeObserve is phase-3a behavior: always pass, emit origin records.
	ModeObserve Mode = 0
	// ModeShadow computes the verdict and reports would-blocks, but always
	// passes. Zero enforcement risk; measures the blast radius of the
	// surfaces this hook newly sees (loopback, bridge, container netns).
	ModeShadow Mode = 1
	// ModeEnforce drops denied traffic at this hook. TC egress remains
	// attached as the fail-closed backstop for traffic with no local socket.
	ModeEnforce Mode = 2
)

// Verdict is what the hook decided about a flow, mirroring ORIGIN_VERDICT_*.
type Verdict uint8

const (
	VerdictNone       Verdict = 0 // observe mode: no verdict computed
	VerdictAllow      Verdict = 1
	VerdictWouldBlock Verdict = 2 // denied by policy but passed (shadow, or audit posture)
	VerdictBlock      Verdict = 3 // denied by policy and dropped here
)

// Record is one resolved flow origin: the pre-NAT view of a flow plus the
// identities its socket cookie resolved to at ringbuf-read time. A zero
// PID/StepOrdinal means the socket was untagged when the record arrived —
// exactly the traffic the container-unattributed tier exists for.
type Record struct {
	Cookie      uint64
	CgroupID    uint64
	Timestamp   uint64 // bpf_ktime_get_ns, same clock domain as the TC event timestamp
	SrcIP       netip.Addr
	DstIP       netip.Addr
	DstPort     uint16
	SrcPort     uint16
	Proto       uint8
	PID         uint32
	StepOrdinal uint32
	TCPSyn      bool
	// Midstream marks a denial of an established flow (ACK set, no SYN/RST,
	// mirroring tc_egress's guard) rather than a connection attempt.
	Midstream bool
	// Verdict is what the hook decided. VerdictWouldBlock/VerdictBlock
	// records are handed to the verdict sink, but the two differ in what
	// else sees the flow:
	//   - VerdictBlock (enforce): the packet dies at ip_finish_output,
	//     before the TC qdisc — this record is the ONLY event source for
	//     the drop.
	//   - VerdictWouldBlock (shadow): the packet is PASSED and TC still
	//     adjudicates it, so the flow is dual-sourced — TC's own event needs
	//     this record in the join store for container enrichment. That is
	//     why the store is updated before the sink is notified.
	Verdict Verdict
}

// flowKey indexes the store by the fields NAT preserves: MASQUERADE rewrites
// the source, never the destination tuple.
type flowKey struct {
	dst       [16]byte // v4 address big-endian in bytes 0-3, rest zero
	port      uint16
	proto     uint8
	ipVersion uint8
}

const (
	// storeMaxKeys bounds the join store. Keys are destination tuples, so
	// this matches the rule/midstream map sizing rationale in tcbpf.c: one
	// per distinct destination. Eviction is second-chance (see insert): a
	// key refreshed since it was last considered gets rotated to the back
	// instead of evicted, so the hot destinations a build hammers aren't
	// evicted in insertion order while idle one-shot keys survive. The cost
	// of any eviction is a missed join, never anything worse.
	storeMaxKeys = 4096
	// perKeyMax bounds concurrent same-destination flows tracked per key
	// (distinct sockets to one dst:port — e.g. several containers hitting
	// the same registry). Overflow drops the oldest: a missed join, tiered
	// stricter.
	perKeyMax = 8
	// verdictQueueDepth bounds the buffer between the ringbuf reader and the
	// verdict-reporting worker. Reporting runs the full post-verdict
	// pipeline (up to a 500ms PTR lookup per cold destination), so it must
	// never run on the reader goroutine — a stalled reader overflows the
	// 128KB kernel ring and silently loses records. Overflow here drops the
	// REPORT only (counted and logged); enforcement and the join store are
	// unaffected.
	verdictQueueDepth = 1024
)

// Observer owns the loaded collection, its root-cgroup attachment, the
// ringbuf reader, the verdict-reporting worker, and the join store.
type Observer struct {
	objs     bpf.OriginBpfObjects
	link     link.Link
	reader   *ringbuf.Reader
	sockPid  *ebpf.Map
	sockStep *ebpf.Map
	logger   *slog.Logger
	done     chan struct{}
	// verdicts is the callback for records carrying a would-block/block
	// decision. Atomic because SetVerdictSink installs it from the main
	// goroutine after Start has already launched the goroutines that load it
	// — a plain field would be a data race with no happens-before edge.
	verdicts atomic.Pointer[func(Record)]
	// verdictCh feeds reportLoop, the worker that actually invokes the sink.
	// insert's send is non-blocking: the reader must never wait on the
	// reporting pipeline (see verdictQueueDepth).
	verdictCh  chan Record
	reportDone chan struct{}

	mu    sync.Mutex
	flows map[flowKey][]Record
	fifo  []flowKey
	// hot marks keys refreshed since eviction last considered them; such a
	// key gets one rotation to the back of fifo instead of eviction.
	hot map[flowKey]struct{}

	records         atomic.Uint64
	blocked         atomic.Uint64
	verdictsDropped atomic.Uint64
}

// Start loads the origin collection, attaches the observer at the root
// cgroup, and starts the reader. Nothing here can affect enforcement; any
// error means the caller runs without container attribution.
func Start(tcObjs *bpf.TcBpfObjects, logger *slog.Logger) (*Observer, error) {
	if tcObjs == nil {
		return nil, errors.New("nil TC BPF objects")
	}
	if logger == nil {
		return nil, errors.New("nil logger")
	}

	o := &Observer{
		sockPid:    tcObjs.MapSockPid,
		sockStep:   tcObjs.MapSockStep,
		logger:     logger,
		done:       make(chan struct{}),
		flows:      make(map[flowKey][]Record),
		hot:        make(map[flowKey]struct{}),
		verdictCh:  make(chan Record, verdictQueueDepth),
		reportDone: make(chan struct{}),
	}

	// The rule/config maps are owned by the tcbpf collection; replacing them
	// here makes both hooks read one set of kernel maps, so the enforcing
	// hook and its TC backstop can never disagree about policy. This is a
	// deliberate reversal of phase 3a's standalone-collection design: 3a
	// shared nothing so a verifier rejection could only cost attribution,
	// but 3b's whole purpose is to compute the verdict here. The blast
	// radius is bounded instead by the mode gate (the program is inert until
	// userspace raises it) and by TC remaining attached as the backstop.
	if err := bpf.LoadOriginBpfObjects(&o.objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"map_cidrs":          tcObjs.MapCidrs,
			"map_ports":          tcObjs.MapPorts,
			"map_cidrs_v6":       tcObjs.MapCidrsV6,
			"map_ports_v6":       tcObjs.MapPortsV6,
			"map_default_action": tcObjs.MapDefaultAction,
			"map_audit_mode":     tcObjs.MapAuditMode,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to load origin BPF objects: %w", err)
	}

	// Arm the loopback-device carve-out before attach: traffic egressing lo
	// never leaves the host and was never adjudicated by TC (that includes
	// flows to the host's OWN address, which Linux routes over lo), so the
	// hook must not police it. Always on in production; it is a config byte
	// rather than hardwired only because PROG_TEST_RUN pins every test skb
	// to the loopback device — see origin_lo_carveout in originbpf.c.
	if err := o.objs.MapOriginConfig.Put(cfgKeyLoCarveout, uint8(1)); err != nil {
		o.objs.Close()
		return nil, fmt.Errorf("failed to arm loopback carve-out: %w", err)
	}

	// Telemetry: what else is attached at the root cgroup (Docker's or
	// systemd's own programs), before and after ours joins them. Under
	// ALLOW_MULTI every program runs and the effective verdict is their AND:
	// a peer can never veto our drop, and we can never veto theirs — which
	// is why every drop we cause emits a record, so an unexplained drop is
	// always attributable to whoever caused it.
	o.logAttachedEgressPrograms("pre-attach")

	l, err := link.AttachCgroup(link.CgroupOptions{
		// Root cgroup, same rationale as the connect/sendmsg hooks: observe
		// every process on the machine, containers included.
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: o.objs.CgOriginEgress,
	})
	if err != nil {
		o.objs.Close()
		return nil, fmt.Errorf("failed to attach cgroup_skb/egress observer: %w", err)
	}
	o.link = l
	o.logAttachedEgressPrograms("post-attach")

	rd, err := ringbuf.NewReader(o.objs.MapOriginEvents)
	if err != nil {
		_ = l.Close()
		o.objs.Close()
		return nil, fmt.Errorf("failed to create origin event reader: %w", err)
	}
	o.reader = rd
	go o.run()
	go o.reportLoop()

	return o, nil
}

// Close stops the reader, drains the verdict-reporting worker, detaches the
// observer, and releases the collection, in that order so the reader never
// sees a closed map and no queued verdict report is lost at shutdown.
func (o *Observer) Close() {
	if o.reader != nil {
		_ = o.reader.Close()
		<-o.done // run() exits promptly on ringbuf.ErrClosed
	}
	if o.verdictCh != nil {
		close(o.verdictCh) // run() was the only sender and has exited
		<-o.reportDone
	}
	if o.link != nil {
		_ = o.link.Close()
	}
	o.objs.Close()
}

// Program exposes the observer program for BPF runtime-stats logging.
func (o *Observer) Program() *ebpf.Program { return o.objs.CgOriginEgress }

// SetVerdictSink installs the callback that receives would-block/block
// records. Must be called before the mode is raised above observe. The sink
// runs on the reporting worker, never on the ringbuf reader — it may do
// slow work (hostname resolution, firewall writes, audit I/O).
func (o *Observer) SetVerdictSink(fn func(Record)) { o.verdicts.Store(&fn) }

// SetMode raises (or lowers) the hook's enforcement posture. Callers MUST
// only raise it above ModeObserve once the allowlist, DNS/infra auto-allows,
// and existing-connection gating are programmed — otherwise the hook runs
// live against an empty allowlist and drops legitimate startup traffic (the
// attach-before-program race that cmd/start.go's TC ordering exists to
// avoid). Attaching early is safe precisely because the mode starts at
// observe.
func (o *Observer) SetMode(mode Mode) error {
	if err := o.objs.MapOriginConfig.Put(cfgKeyMode, uint8(mode)); err != nil {
		return fmt.Errorf("failed to set origin mode %d: %w", mode, err)
	}
	o.logger.Info("Container egress hook mode set", "mode", mode.String())
	return nil
}

// String renders a Mode for logs.
func (m Mode) String() string {
	switch m {
	case ModeObserve:
		return "observe"
	case ModeShadow:
		return "shadow"
	case ModeEnforce:
		return "enforce"
	default:
		return "unknown"
	}
}

// Blocked returns how many would-block/block records have been seen — the
// shadow-mode blast-radius counter and the enforce-mode drop count.
func (o *Observer) Blocked() uint64 { return o.blocked.Load() }

// Records returns how many origin records have been consumed — the
// denominator for the 3a correlation-accuracy telemetry.
func (o *Observer) Records() uint64 { return o.records.Load() }

func (o *Observer) logAttachedEgressPrograms(when string) {
	cg, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		o.logger.Debug("Cannot open root cgroup for program query", "error", err)
		return
	}
	defer cg.Close()
	res, err := link.QueryPrograms(link.QueryOptions{
		Target: int(cg.Fd()),
		Attach: ebpf.AttachCGroupInetEgress,
	})
	if err != nil {
		o.logger.Debug("Cannot query root-cgroup egress programs", "error", err)
		return
	}
	ids := make([]uint32, 0, len(res.Programs))
	for _, p := range res.Programs {
		ids = append(ids, uint32(p.ID))
	}
	o.logger.Info("Root-cgroup egress programs", "when", when, "count", len(ids), "ids", ids)
}

func (o *Observer) run() {
	defer close(o.done)
	for {
		record, err := o.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			o.logger.Error("Failed to read origin event", "error", err)
			continue
		}
		if len(record.RawSample) < int(unsafe.Sizeof(bpf.OriginEvent{})) {
			continue
		}
		ev := (*bpf.OriginEvent)(unsafe.Pointer(&record.RawSample[0]))
		o.records.Add(1)
		o.insert(ev)
	}
}

// reportLoop invokes the verdict sink for each queued record. Its own
// goroutine, so a slow sink (PTR lookups, audit writes) stalls reporting
// only — never the ringbuf reader, whose backlog is a 128KB kernel ring
// that overflows into silently lost records.
func (o *Observer) reportLoop() {
	defer close(o.reportDone)
	for rec := range o.verdictCh {
		if fn := o.verdicts.Load(); fn != nil {
			(*fn)(rec)
		}
	}
}

// insert resolves the record's cookie against the tcbpf identity maps and
// stores the result. Resolution happens here, at read time, rather than in
// the BPF program, at the cost of a µs-scale window in which a lookup can
// miss — a missed attribution, tiered stricter, never anything worse.
//
// Ordering is load-bearing: the join store is updated BEFORE the verdict
// sink is notified. In enforce mode a VerdictBlock record is the sole event
// source for the drop (the packet dies before the TC qdisc), but in shadow
// mode a VerdictWouldBlock packet is PASSED — TC adjudicates it too, and
// TC's enrichment reads this join store. Reporting first would race the TC
// event against its own join candidate and file container flows into the
// unattributed tier under the default posture.
func (o *Observer) insert(ev *bpf.OriginEvent) {
	var pid, ordinal uint32
	if o.sockPid != nil {
		_ = o.sockPid.Lookup(ev.Cookie, &pid)
	}
	if o.sockStep != nil {
		_ = o.sockStep.Lookup(ev.Cookie, &ordinal)
	}

	var srcIP, dstIP netip.Addr
	if ev.IpVersion == 4 {
		var s, d [4]byte
		binary.BigEndian.PutUint32(s[:], ev.SrcIp)
		binary.BigEndian.PutUint32(d[:], ev.DstIp)
		srcIP = netip.AddrFrom4(s)
		dstIP = netip.AddrFrom4(d)
	} else {
		srcIP = netip.AddrFrom16(ev.SrcIp6)
		dstIP = netip.AddrFrom16(ev.DstIp6)
	}

	rec := Record{
		Cookie:      ev.Cookie,
		CgroupID:    ev.CgroupID,
		Timestamp:   ev.Timestamp,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		DstPort:     ev.DstPort,
		SrcPort:     ev.SrcPort,
		Proto:       ev.IpProto,
		PID:         pid,
		StepOrdinal: ordinal,
		TCPSyn:      ev.Flags&bpf.OriginFlagTCPSyn != 0,
		Midstream:   ev.Flags&bpf.OriginFlagTCPMidstream != 0,
		Verdict:     Verdict(ev.Verdict),
	}

	key := flowKey{port: ev.DstPort, proto: ev.IpProto, ipVersion: ev.IpVersion}
	if ev.IpVersion == 4 {
		binary.BigEndian.PutUint32(key.dst[:4], ev.DstIp)
	} else {
		key.dst = ev.DstIp6
	}

	o.mu.Lock()
	entries, existed := o.flows[key]
	// A re-emit for a known socket (the 10s refresh interval in originbpf.c)
	// replaces its entry; a new socket prepends. Newest-first order is the
	// Lookup contract.
	for i, e := range entries {
		if e.Cookie == rec.Cookie {
			entries = append(entries[:i], entries[i+1:]...)
			break
		}
	}
	entries = append([]Record{rec}, entries...)
	if len(entries) > perKeyMax {
		entries = entries[:perKeyMax]
	}
	o.flows[key] = entries

	if existed {
		o.hot[key] = struct{}{}
	} else {
		o.fifo = append(o.fifo, key)
		// Second-chance eviction: a key refreshed since it was last
		// considered is rotated to the back (its hot bit cleared) instead of
		// evicted, so continuously re-emitted destinations outlive keys idle
		// since insertion. Terminates: each rotation clears one hot bit.
		for len(o.flows) > storeMaxKeys && len(o.fifo) > 0 {
			victim := o.fifo[0]
			o.fifo = o.fifo[1:]
			if _, isHot := o.hot[victim]; isHot {
				delete(o.hot, victim)
				o.fifo = append(o.fifo, victim)
				continue
			}
			delete(o.flows, victim)
		}
	}
	o.mu.Unlock()

	// Report AFTER the store write above — see the ordering note in the doc
	// comment. Non-blocking: a full queue costs the report, never the reader.
	if rec.Verdict == VerdictWouldBlock || rec.Verdict == VerdictBlock {
		o.blocked.Add(1)
		select {
		case o.verdictCh <- rec:
		default:
			if n := o.verdictsDropped.Add(1); n == 1 || n%1000 == 0 {
				o.logger.Warn("Verdict report queue full; dropping report (enforcement and join store unaffected)",
					"dropped_total", n)
			}
		}
	}
}

// LookupV4 returns origin candidates for a post-NAT IPv4 flow view (host
// byte order dst, as TC events carry it), newest first. See lookup.
func (o *Observer) LookupV4(dstIP uint32, dstPort uint16, proto uint8, srcPort uint16) []Record {
	key := flowKey{port: dstPort, proto: proto, ipVersion: 4}
	binary.BigEndian.PutUint32(key.dst[:4], dstIP)
	return o.lookup(key, srcPort)
}

// LookupV6 returns origin candidates for a post-NAT IPv6 flow view, newest
// first. See lookup.
func (o *Observer) LookupV6(dstIP [16]byte, dstPort uint16, proto uint8, srcPort uint16) []Record {
	return o.lookup(flowKey{dst: dstIP, port: dstPort, proto: proto, ipVersion: 6}, srcPort)
}

// lookup matches on what NAT preserves. An exact source-port match is
// authoritative (MASQUERADE keeps the source port unless it collides) and
// returned alone; otherwise all live candidates for the destination tuple
// are returned, newest first, so the caller can decide whether they agree —
// disagreement must degrade to the stricter tier, and that policy belongs
// to the caller, not the store. srcPort 0 skips the exact pass (protocol-
// block events carry no ports).
func (o *Observer) lookup(key flowKey, srcPort uint16) []Record {
	o.mu.Lock()
	defer o.mu.Unlock()
	entries := o.flows[key]
	if len(entries) == 0 {
		return nil
	}
	if srcPort != 0 {
		for _, r := range entries {
			if r.SrcPort == srcPort {
				return []Record{r}
			}
		}
	}
	out := make([]Record, len(entries))
	copy(out, entries)
	return out
}
