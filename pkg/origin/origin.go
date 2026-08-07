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

// Package origin owns the cgroup_skb/egress flow-origin observer (issue
// #106, phase 3a). The observer records every flow's pre-NAT origin — socket
// cookie, cgroup id, addresses — from inside the originating netns, where
// container sockets are still visible; this package loads and attaches it,
// resolves each record's cookie against the tcbpf pid/step maps at read
// time, and keeps a bounded join store that pkg/containers consults to put
// container attribution onto post-NAT TC verdict events.
//
// Attribution only, by construction: the BPF program passes every packet
// (see originbpf.c), the collection shares nothing with the enforcing
// tcbpf collection, and every failure here is survivable — callers treat a
// Start error as "container attribution disabled", never as a firewall
// fault.
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

// originEvent mirrors struct origin_event in originbpf.c (72 bytes packed;
// 8-byte fields first so the packed C layout equals Go's natural layout).
// Layout pinned by TestOriginEventLayoutMatchesBTF in bpf/originbpf_test.go.
type originEvent struct {
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

// flagTCPSyn mirrors ORIGIN_FLAG_TCP_SYN in originbpf.c.
const flagTCPSyn = 0x1

// Record is one resolved flow origin: the pre-NAT view of a flow plus the
// identities its socket cookie resolved to at ringbuf-read time. A zero
// PID/StepOrdinal means the socket was untagged when the record arrived —
// exactly the traffic the container-unattributed tier exists for.
type Record struct {
	Cookie      uint64
	CgroupID    uint64
	Timestamp   uint64 // bpf_ktime_get_ns, same clock domain as the TC event timestamp
	SrcIP       netip.Addr
	SrcPort     uint16
	PID         uint32
	StepOrdinal uint32
	TCPSyn      bool
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
	// per distinct destination, LRU-ish eviction costing a missed join,
	// never anything worse.
	storeMaxKeys = 4096
	// perKeyMax bounds concurrent same-destination flows tracked per key
	// (distinct sockets to one dst:port — e.g. several containers hitting
	// the same registry). Overflow drops the oldest: a missed join, tiered
	// stricter.
	perKeyMax = 8
)

// Observer owns the loaded collection, its root-cgroup attachment, the
// ringbuf reader, and the join store.
type Observer struct {
	objs     bpf.OriginBpfObjects
	link     link.Link
	reader   *ringbuf.Reader
	sockPid  *ebpf.Map
	sockStep *ebpf.Map
	logger   *slog.Logger
	done     chan struct{}

	mu    sync.Mutex
	flows map[flowKey][]Record
	fifo  []flowKey

	records atomic.Uint64
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
		sockPid:  tcObjs.MapSockPid,
		sockStep: tcObjs.MapSockStep,
		logger:   logger,
		done:     make(chan struct{}),
		flows:    make(map[flowKey][]Record),
	}

	if err := bpf.LoadOriginBpfObjects(&o.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load origin BPF objects: %w", err)
	}

	// 3a telemetry: what else is attached at the root cgroup (Docker's or
	// systemd's own programs), before and after ours joins them. Under
	// ALLOW_MULTI every program runs and the verdict is their AND; our
	// constant-pass observer is the identity element in that AND.
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

	return o, nil
}

// Close stops the reader, detaches the observer, and releases the
// collection, in that order so the reader never sees a closed map.
func (o *Observer) Close() {
	if o.reader != nil {
		_ = o.reader.Close()
		<-o.done // run() exits promptly on ringbuf.ErrClosed
	}
	if o.link != nil {
		_ = o.link.Close()
	}
	o.objs.Close()
}

// Program exposes the observer program for BPF runtime-stats logging.
func (o *Observer) Program() *ebpf.Program { return o.objs.CgOriginEgress }

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
		if len(record.RawSample) < int(unsafe.Sizeof(originEvent{})) {
			continue
		}
		ev := (*originEvent)(unsafe.Pointer(&record.RawSample[0]))
		o.records.Add(1)
		o.insert(ev)
	}
}

// insert resolves the record's cookie against the shared tcbpf maps and
// stores the result. Resolution happens here, at read time, rather than in
// the BPF program: it keeps the collection standalone (no MapReplacements,
// no coupling to the step-map shrink in cmd/start.go) at the cost of a
// µs-scale window in which a lookup can miss — a missed attribution, tiered
// stricter, never anything worse.
func (o *Observer) insert(ev *originEvent) {
	var pid, ordinal uint32
	if o.sockPid != nil {
		_ = o.sockPid.Lookup(ev.Cookie, &pid)
	}
	if o.sockStep != nil {
		_ = o.sockStep.Lookup(ev.Cookie, &ordinal)
	}

	var srcIP netip.Addr
	if ev.IpVersion == 4 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], ev.SrcIp)
		srcIP = netip.AddrFrom4(b)
	} else {
		srcIP = netip.AddrFrom16(ev.SrcIp6)
	}

	rec := Record{
		Cookie:      ev.Cookie,
		CgroupID:    ev.CgroupID,
		Timestamp:   ev.Timestamp,
		SrcIP:       srcIP,
		SrcPort:     ev.SrcPort,
		PID:         pid,
		StepOrdinal: ordinal,
		TCPSyn:      ev.Flags&flagTCPSyn != 0,
	}

	key := flowKey{port: ev.DstPort, proto: ev.IpProto, ipVersion: ev.IpVersion}
	if ev.IpVersion == 4 {
		binary.BigEndian.PutUint32(key.dst[:4], ev.DstIp)
	} else {
		key.dst = ev.DstIp6
	}

	o.mu.Lock()
	defer o.mu.Unlock()

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

	if !existed {
		o.fifo = append(o.fifo, key)
		for len(o.flows) > storeMaxKeys && len(o.fifo) > 0 {
			victim := o.fifo[0]
			o.fifo = o.fifo[1:]
			delete(o.flows, victim)
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
