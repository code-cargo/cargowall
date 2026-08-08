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

// The read side of container attribution: joining origin records onto TC
// verdict events (Enrich) and resolving DNS clients (LookupClient). The
// docker-event machinery that builds the identity indexes lives in
// tracker.go; this file only consumes them.

package containers

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/origin"
)

// joinKind is what a set of origin candidates supports claiming.
type joinKind int

const (
	joinNone                joinKind = iota
	joinResolved                     // candidates agree; rec/info are usable
	joinAmbiguousContainers          // candidates disagree, but every one is a container
	joinAmbiguousMixed               // candidates disagree and at least one is not a container
)

// joinResult is resolveJoin's decision. rec and info are meaningful only
// for joinResolved; info nil there means a host flow.
type joinResult struct {
	kind joinKind
	rec  origin.Record
	info *containerInfo
}

// resolveJoin is the join-agreement policy, pure so it is testable without
// a Tracker: given origin candidates (newest first — a single candidate is
// an exact or unambiguous match by the store's contract) and a classifier,
// decide what may be claimed. Disagreement about who owned a flow must
// degrade to the stricter tier: a container-origin claim survives only when
// EVERY candidate is a container, a step claim only when all candidates
// agree on identity and ordinal, and a process claim only when they also
// agree on PID — two processes in one container hitting the same
// destination agree on everything else, and naming either one would be a
// coin flip stamped into the audit stream as fact.
func resolveJoin(recs []origin.Record, classify func(origin.Record) *containerInfo) joinResult {
	if len(recs) == 0 {
		return joinResult{kind: joinNone}
	}
	first := classify(recs[0])
	pidsAgree := true
	for _, r := range recs[1:] {
		if classify(r) != first || r.StepOrdinal != recs[0].StepOrdinal {
			for _, rr := range recs {
				if classify(rr) == nil {
					return joinResult{kind: joinAmbiguousMixed}
				}
			}
			return joinResult{kind: joinAmbiguousContainers}
		}
		if r.PID != recs[0].PID {
			pidsAgree = false
		}
	}
	res := joinResult{kind: joinResolved, rec: recs[0], info: first}
	if !pidsAgree {
		res.rec.PID = 0 // container and step stand; the process claim does not
	}
	return res
}

// classifyLocked resolves an origin record to a known container, by the
// socket's cgroup first (exact) and source IP second (pre-NAT container
// address). Caller holds t.mu.
func (t *Tracker) classifyLocked(r origin.Record) *containerInfo {
	if r.CgroupID != 0 {
		if info := t.byCgroup[r.CgroupID]; info != nil {
			return info
		}
	}
	if r.SrcIP.IsValid() {
		return t.byIP[r.SrcIP]
	}
	return nil
}

// Enrich implements events.ContainerEnricher: called for TC events whose
// socket carried no identity (pid 0, ordinal 0 — the NATed-container
// signature), it consults the origin observer's pre-NAT records and adopts
// what the flow's socket actually carried.
//
// Invariant: only the origin record's socket-tag ordinal is ever copied —
// never OrdinalAt or any "current step" notion — so traffic from the window
// between container start and tagging can only land in the
// container-unattributed tier, never on a step.
func (t *Tracker) Enrich(audit *events.AuditEvent, ev *events.BpfBlockedEvent) {
	if t.observer == nil {
		return
	}

	dstPort, srcPort := ev.DstPort, ev.SrcPort
	if ev.IsProtocolBlock() {
		// dst_port carried the protocol number; origin records for
		// non-TCP/UDP protocols carry ports 0 to match.
		dstPort, srcPort = 0, 0
	}
	var recs []origin.Record
	if ev.IpVersion == 6 {
		recs = t.observer.LookupV6(ev.DstIp6, dstPort, ev.IpProto, srcPort)
	} else {
		recs = t.observer.LookupV4(ev.DstIp, dstPort, ev.IpProto, srcPort)
	}
	// A record cannot postdate the TC event it explains (the cgroup hook
	// runs before TC on the same packet, in the same clock domain).
	recs = slices.DeleteFunc(recs, func(r origin.Record) bool { return r.Timestamp > ev.Timestamp })
	if len(recs) == 0 {
		t.tcNoRecord.Add(1)
		return
	}

	t.mu.Lock()
	res := resolveJoin(recs, t.classifyLocked)
	t.mu.Unlock()

	switch res.kind {
	case joinAmbiguousMixed:
		t.tcAmbiguous.Add(1)
	case joinAmbiguousContainers:
		t.tcAmbiguous.Add(1)
		audit.ContainerOrigin = true
	case joinResolved:
		t.applyJoin(audit, res)
	}
}

// applyJoin copies a resolved join onto the audit record and counts it.
func (t *Tracker) applyJoin(audit *events.AuditEvent, res joinResult) {
	if res.rec.StepOrdinal != 0 {
		audit.StepOrdinal = res.rec.StepOrdinal
	}
	if res.rec.PID != 0 {
		audit.PID = res.rec.PID
		if audit.Process == "" {
			audit.Process = readComm(t.opts.ProcRoot, int(res.rec.PID))
		}
	}
	switch {
	case res.info != nil:
		audit.ContainerOrigin = true
		audit.ContainerID = shortID(res.info.id)
		if res.rec.StepOrdinal != 0 {
			t.tcEnriched.Add(1)
		} else {
			t.tcContainerOnly.Add(1)
		}
	case res.rec.StepOrdinal != 0 || res.rec.PID != 0:
		// Host flow the TC join missed (e.g. map_sock_pid eviction): the
		// origin record still knows its socket. Pure bonus attribution.
		t.tcEnriched.Add(1)
	}
}

// LookupClient resolves a DNS client address to container attribution: the
// container IP is the source of both direct bridge queries and the embedded
// resolver's external forwards. Wired into pkg/dns via SetContainerLookup.
//
// The returned ordinal is the container's EFFECTIVE ordinal — birth step,
// or the latest exec re-tag. Last-writer-wins per container: an
// approximation, unlike TC enrichment which reads each socket's own tag.
// See the Container Attribution section of design.md.
func (t *Tracker) LookupClient(addr net.Addr) (ordinal uint32, containerID string, ok bool) {
	var ip netip.Addr
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, ok = netip.AddrFromSlice(a.IP)
	case *net.TCPAddr:
		ip, ok = netip.AddrFromSlice(a.IP)
	}
	if !ok {
		return 0, "", false
	}
	ip = ip.Unmap()

	t.mu.Lock()
	info := t.byIP[ip]
	t.mu.Unlock()
	if info == nil {
		t.dnsMisses.Add(1)
		return 0, "", false
	}
	t.dnsHits.Add(1)
	return info.effectiveOrdinal, shortID(info.id), true
}

// DecorateVerdict adds container identity to a connection outcome the
// cgroup hook reported. Decoration only: this package supplies "which
// container did this come from", never the outcome itself — that belongs to
// the shared post-verdict pipeline in pkg/events, which owns hostname
// resolution, late-allow, notifications, and the audit record for BOTH
// hooks. Most cgroup verdicts are host processes with no container at all.
func (t *Tracker) DecorateVerdict(audit *events.AuditEvent, rec origin.Record) {
	t.mu.Lock()
	info := t.classifyLocked(rec)
	t.mu.Unlock()
	if info == nil {
		return
	}
	audit.ContainerOrigin = true
	audit.ContainerID = shortID(info.id)
}

func readComm(procRoot string, pid int) string {
	comm, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}
