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

package events

import (
	"sort"
	"sync"
	"time"

	"github.com/code-cargo/cargowall/pkg/config"
)

// DefaultRecentBlocksTTL bounds how long a blocked connection stays
// reconcilable as late-allowed. Long enough to cover a client whose cached
// DNS answer expires well after its first blocked attempt (~35s observed in
// #83), short enough that a re-labeled block is still plausibly the same
// traffic the firewall later opened for.
const DefaultRecentBlocksTTL = 5 * time.Minute

// maxRecentBlocks caps buffer growth under a default-deny flood. Each unique
// (dst_ip, dst_port, protocol) is one entry; overflow drops new blocks rather
// than evicting — reconciliation is best-effort reporting and enforcement is
// unaffected.
const maxRecentBlocks = 4096

// RecentBlock is the most recent blocked attempt for a (dst_ip, dst_port,
// protocol) tuple, carrying the attribution needed to re-report that attempt
// as late-allowed. At is the timestamp of the latest attempt so that a
// reconciliation event dated At supersedes every recorded retry for the tuple
// (the summary drops blocked events at or before the late-allowed timestamp).
type RecentBlock struct {
	SrcIP       string
	DstIP       string
	DstPort     uint16
	Protocol    string // audit protocol name, "TCP" or "UDP"
	Process     string
	PID         uint32
	StepOrdinal uint32
	// Container identity and the CNAME chain travel with the block: a
	// reconciled late-allow is a re-report of THIS attempt, and any identity
	// field dropped here is silently demoted in that re-report (container →
	// unknown tier in the summary, no cargowall.container_id in OTLP, no
	// CNAME drill-down). When adding a field to AuditEvent that a blocked
	// event carries, mirror it here and in Consume/reconcileRecentBlocks —
	// this struct is deliberately a subset, not the whole event, because the
	// reconcile re-derives destination fields from the NEW resolution.
	ContainerID     string
	ContainerOrigin bool
	CNAMEChain      []string
	At              time.Time
}

type recentBlockKey struct {
	port     uint16
	protocol string
}

// RecentBlocks is a short-TTL buffer of recently blocked TCP/UDP connections
// keyed by destination. It closes the reporting gap where a connection is
// blocked before its destination IP can be attributed to an allowed hostname
// (the client obtained the IP from a resolution path that never traversed the
// DNS proxy), so the in-band late-allow check in processEvent can't fire
// (#83). When the proxy finally sees address records for the destination and
// opens the firewall, it calls TakeMatching and re-reports the superseded
// blocks as connection_late_allowed.
//
// It subscribes to the audit stream as an EventSink. Consume runs under the
// audit logger's mutex and must not block; it only takes the buffer's own
// mutex for a map insert.
type RecentBlocks struct {
	mu   sync.Mutex
	ttl  time.Duration
	byIP map[string]map[recentBlockKey]RecentBlock
	size int
}

// NewRecentBlocks creates a buffer whose entries expire after ttl.
// A non-positive ttl selects DefaultRecentBlocksTTL.
func NewRecentBlocks(ttl time.Duration) *RecentBlocks {
	if ttl <= 0 {
		ttl = DefaultRecentBlocksTTL
	}
	return &RecentBlocks{
		ttl:  ttl,
		byIP: make(map[string]map[recentBlockKey]RecentBlock),
	}
}

// Consume records connection_blocked TCP/UDP events, keeping one entry per
// (dst_ip, dst_port, protocol): the latest attempt's timestamp, with
// identity fields degraded when live attempts from different origins
// disagree (see degradeDisagreement). Other event types — and protocols
// whose retries can't benefit from a late allow — are ignored, mirroring
// the restriction on the in-band late-allow path.
func (rb *RecentBlocks) Consume(event AuditEvent) {
	if event.EventType != EventConnectionBlocked || event.DstIP == "" {
		return
	}
	if _, ok := protocolTypeForAuditName(event.Protocol); !ok {
		return
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	key := recentBlockKey{port: event.DstPort, protocol: event.Protocol}
	if _, exists := rb.byIP[event.DstIP][key]; !exists {
		if rb.size >= maxRecentBlocks {
			rb.pruneExpiredLocked(time.Now())
			if rb.size >= maxRecentBlocks {
				return
			}
		}
		rb.size++
	}
	// Resolve the destination's map only after the prune above: pruning an
	// all-expired destination deletes its map from byIP, so a reference taken
	// beforehand would be orphaned — the write would land in a map nothing
	// points at, losing the block while rb.size still counts it.
	byKey := rb.byIP[event.DstIP]
	if byKey == nil {
		byKey = make(map[recentBlockKey]RecentBlock)
		rb.byIP[event.DstIP] = byKey
	}
	next := RecentBlock{
		SrcIP:           event.SrcIP,
		DstIP:           event.DstIP,
		DstPort:         event.DstPort,
		Protocol:        event.Protocol,
		Process:         event.Process,
		PID:             event.PID,
		StepOrdinal:     event.StepOrdinal,
		ContainerID:     event.ContainerID,
		ContainerOrigin: event.ContainerOrigin,
		CNAMEChain:      event.CNAMEChain,
		At:              event.Timestamp,
	}
	// The key is destination-only, so two sources (containers A and B, or a
	// container and a host process) blocked on the same tuple collapse into
	// one entry. Last-writer-wins would let the single late-allow re-report
	// state the last writer's identity as fact for every attempt — the
	// coin-flip attribution resolveJoin's disagreement policy exists to
	// prevent, on a different path. Keep the newest timestamp (the supersede
	// window must cover every retry) but degrade each identity field the
	// live entries disagree on; once contested, the entry stays degraded
	// until taken or expired.
	if prev, exists := byKey[key]; exists && !prev.At.Before(time.Now().Add(-rb.ttl)) {
		next = degradeDisagreement(prev, next)
	}
	byKey[key] = next
}

// degradeDisagreement folds a new blocked attempt into a live entry for the
// same destination tuple, blanking every identity field the two attempts
// disagree on. The zero values land in the re-report as "unattributed" —
// the honest claim when the attempt cannot be pinned to one origin. At is
// the max of the two: the late-allow supersede window must cover every
// recorded retry, and events can arrive out of timestamp order.
func degradeDisagreement(prev, next RecentBlock) RecentBlock {
	if next.At.Before(prev.At) {
		next.At = prev.At
	}
	if prev.SrcIP != next.SrcIP {
		next.SrcIP = ""
	}
	if prev.Process != next.Process {
		next.Process = ""
	}
	if prev.PID != next.PID {
		next.PID = 0
	}
	if prev.StepOrdinal != next.StepOrdinal {
		next.StepOrdinal = 0
	}
	if prev.ContainerID != next.ContainerID {
		next.ContainerID = ""
	}
	if prev.ContainerOrigin != next.ContainerOrigin {
		next.ContainerOrigin = false
	}
	return next
}

// TakeMatching removes and returns unexpired blocks to dstIP whose port and
// protocol the allow side covers and the deny side (when hasDeny) does not —
// the same allowMatches && !denyMatches rule the in-band late-allow path
// applies to a mixed verdict. Empty allowPorts means all ports; empty
// denyPorts with hasDeny means deny-all. A deny-covered entry is removed
// without being returned: its block was and remains correct, so it must not
// linger for a later reconcile pass to mislabel. Results are ordered by
// attempt time for deterministic reporting.
func (rb *RecentBlocks) TakeMatching(dstIP string, allowPorts, denyPorts []config.Port, hasDeny bool) []RecentBlock {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	byKey := rb.byIP[dstIP]
	if len(byKey) == 0 {
		return nil
	}

	cutoff := time.Now().Add(-rb.ttl)
	var taken []RecentBlock
	for key, b := range byKey {
		if b.At.Before(cutoff) {
			delete(byKey, key)
			rb.size--
			continue
		}
		proto, _ := protocolTypeForAuditName(b.Protocol) // recorded entries always map
		if !config.PortsCover(allowPorts, b.DstPort, proto) {
			continue
		}
		delete(byKey, key)
		rb.size--
		if hasDeny && config.PortsCover(denyPorts, b.DstPort, proto) {
			continue
		}
		taken = append(taken, b)
	}
	if len(byKey) == 0 {
		delete(rb.byIP, dstIP)
	}

	sort.Slice(taken, func(i, j int) bool { return taken[i].At.Before(taken[j].At) })
	return taken
}

// pruneExpiredLocked drops every expired entry. Called with rb.mu held, only
// when the buffer is full — steady-state expiry is handled lazily per-IP in
// TakeMatching.
func (rb *RecentBlocks) pruneExpiredLocked(now time.Time) {
	cutoff := now.Add(-rb.ttl)
	for ip, byKey := range rb.byIP {
		for key, b := range byKey {
			if b.At.Before(cutoff) {
				delete(byKey, key)
				rb.size--
			}
		}
		if len(byKey) == 0 {
			delete(rb.byIP, ip)
		}
	}
}

// protocolTypeForAuditName maps an audit-log protocol name (getProtocolName)
// back to the config protocol type used in rule port lists. Only TCP and UDP
// map — the protocols whose blocked SYN/datagram retries a late firewall open
// can rescue.
func protocolTypeForAuditName(name string) (config.ProtocolType, bool) {
	switch name {
	case "TCP":
		return config.ProtocolTCP, true
	case "UDP":
		return config.ProtocolUDP, true
	default:
		return "", false
	}
}
