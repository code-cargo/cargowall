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
	"strings"
	"sync"
	"time"
)

// maxRecentDNSBlocks caps buffer growth. Each unique refused name is one
// entry, and the flood this bounds is the one query filtering exists to
// stop — a tunneling client walking thousands of distinct labels. Overflow
// drops new refusals rather than evicting: reconciliation is best-effort
// reporting, and the refusals themselves are already logged and enforced.
const maxRecentDNSBlocks = 4096

// RecentDNSBlock is the most recent refused query for one domain, carrying
// the attribution needed to re-report that refusal as late-allowed. At is
// the timestamp of the latest refusal, so an event dated At supersedes every
// recorded retry for the name (the summary drops dns_blocked events at or
// before the late-allowed timestamp).
//
// Deliberately a subset of AuditEvent: the reconcile re-derives the rule
// fields from the ruleset that finally matched. Every identity field a
// dns_blocked event carries must be mirrored here, though — one dropped
// silently demotes the re-report (container → unknown tier in the summary,
// no step attribution in the causal grouping).
type RecentDNSBlock struct {
	Domain          string
	Process         string
	PID             uint32
	StepOrdinal     uint32
	StepAttrOutcome StepAttrOutcome
	ContainerID     string
	ContainerOrigin bool
	At              time.Time
}

// RecentDNSBlocks is a short-TTL buffer of recently refused DNS queries,
// keyed by domain. It closes the reporting gap where a query is refused
// before the rule that covers it exists: the auto-allow infrastructure set
// and the fetched policy both land after the proxy arms query filtering, so
// a name allowed moments later was still REFUSED — and stayed a dns_blocked
// record in the audit log and the SaaS push (#119).
//
// The connection path already reconciles its half this way (#83,
// RecentBlocks): when the ruleset changes, the DNS server re-evaluates the
// buffered names and re-reports the ones now allowed as
// dns_query_late_allowed, dated at the original refusal.
//
// It subscribes to the audit stream as an EventSink. Consume runs under the
// audit logger's mutex and must not block; it only takes this buffer's own
// mutex for a map insert.
type RecentDNSBlocks struct {
	mu       sync.Mutex
	ttl      time.Duration
	byDomain map[string]RecentDNSBlock
}

// NewRecentDNSBlocks creates a buffer whose entries expire after ttl. A
// non-positive ttl selects DefaultRecentBlocksTTL — the same bound the
// connection-side buffer uses, and for the same reason: long enough to
// cover a policy fetch that stalls behind a slow API, short enough that a
// re-labeled refusal is still plausibly the traffic the rule opened for.
func NewRecentDNSBlocks(ttl time.Duration) *RecentDNSBlocks {
	if ttl <= 0 {
		ttl = DefaultRecentBlocksTTL
	}
	return &RecentDNSBlocks{
		ttl:      ttl,
		byDomain: make(map[string]RecentDNSBlock),
	}
}

// Consume records dns_blocked events, keeping one entry per domain: the
// latest refusal's timestamp, with identity fields degraded when refusals
// from different clients disagree (see degradeDNSDisagreement).
//
// Audit-mode would-blocks are recorded too, matching RecentBlocks: the query
// was forwarded, but the report still claims it would have been denied, and
// a rule arriving moments later makes that claim just as wrong as an enforce
// refusal.
func (rb *RecentDNSBlocks) Consume(event AuditEvent) {
	if event.EventType != EventDNSBlocked || event.DstHostname == "" {
		return
	}
	domain := strings.ToLower(event.DstHostname)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if _, exists := rb.byDomain[domain]; !exists {
		if len(rb.byDomain) >= maxRecentDNSBlocks {
			rb.pruneExpiredLocked(time.Now())
			if len(rb.byDomain) >= maxRecentDNSBlocks {
				return
			}
		}
	}

	next := RecentDNSBlock{
		Domain:          domain,
		Process:         event.Process,
		PID:             event.PID,
		StepOrdinal:     event.StepOrdinal,
		StepAttrOutcome: event.StepAttrOutcome,
		ContainerID:     event.ContainerID,
		ContainerOrigin: event.ContainerOrigin,
		At:              event.Timestamp,
	}
	// One key per name, so two clients refused for the same domain (the A
	// and AAAA halves of one lookup agree; a container and a host process do
	// not) collapse into one entry. Last-writer-wins would let the single
	// late-allow re-report state the last writer's identity as fact for
	// every refusal, so keep the newest timestamp — the supersede window
	// must cover every retry — and blank each field the two disagree on.
	if prev, exists := rb.byDomain[domain]; exists && !prev.At.Before(time.Now().Add(-rb.ttl)) {
		next = degradeDNSDisagreement(prev, next)
	}
	rb.byDomain[domain] = next
}

// degradeDNSDisagreement folds a new refusal into a live entry for the same
// name, blanking every identity field the two disagree on. The zero values
// land in the re-report as "unattributed" — the honest claim when the
// refusals cannot be pinned to one origin. At is the max of the two: the
// supersede window must cover every recorded retry, and events can arrive
// out of timestamp order.
func degradeDNSDisagreement(prev, next RecentDNSBlock) RecentDNSBlock {
	if next.At.Before(prev.At) {
		next.At = prev.At
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
	if prev.StepAttrOutcome != next.StepAttrOutcome {
		next.StepAttrOutcome = ""
	}
	if prev.ContainerID != next.ContainerID {
		next.ContainerID = ""
	}
	if prev.ContainerOrigin != next.ContainerOrigin {
		next.ContainerOrigin = false
	}
	return next
}

// Domains returns the unexpired refused names, oldest refusal first, and
// drops the expired ones. Snapshot-then-Take keeps the caller's rule
// evaluation OUT of this buffer's critical section: the DNS server's
// predicate takes the config manager's lock, and nesting the two here would
// invent a lock order no other path observes.
func (rb *RecentDNSBlocks) Domains() []string {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.pruneExpiredLocked(time.Now())

	out := make([]RecentDNSBlock, 0, len(rb.byDomain))
	for _, b := range rb.byDomain {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })

	domains := make([]string, len(out))
	for i, b := range out {
		domains[i] = b.Domain
	}
	return domains
}

// Take removes and returns the entry for domain when it is still live. A
// missed take (expired, or already taken by a concurrent reconcile) reports
// false rather than an empty block, so a caller cannot emit a
// late-allowed event with no refusal behind it.
func (rb *RecentDNSBlocks) Take(domain string) (RecentDNSBlock, bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	b, ok := rb.byDomain[strings.ToLower(domain)]
	if !ok || b.At.Before(time.Now().Add(-rb.ttl)) {
		delete(rb.byDomain, strings.ToLower(domain))
		return RecentDNSBlock{}, false
	}
	delete(rb.byDomain, b.Domain)
	return b, true
}

// Restore puts back an entry Take removed whose re-report never landed, so a
// later reconcile pass can try again. Take has to run BEFORE the audit write
// (it is what claims the refusal, so two concurrent passes cannot both
// re-report it), which left a failed write destroying the only record that the
// refusal was superseded — the run then reports a denial the policy never
// intended, the exact failure #119 exists to prevent.
//
// An expired entry is not resurrected, and a refusal recorded for the name
// since the take wins: that is newer evidence of the same refusal, and
// Consume already folded the disagreement into it.
func (rb *RecentDNSBlocks) Restore(b RecentDNSBlock) {
	if b.Domain == "" {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if b.At.Before(time.Now().Add(-rb.ttl)) {
		return
	}
	if _, exists := rb.byDomain[b.Domain]; exists {
		return
	}
	if len(rb.byDomain) >= maxRecentDNSBlocks {
		rb.pruneExpiredLocked(time.Now())
		if len(rb.byDomain) >= maxRecentDNSBlocks {
			return
		}
	}
	rb.byDomain[b.Domain] = b
}

// pruneExpiredLocked drops every expired entry. Called with rb.mu held.
func (rb *RecentDNSBlocks) pruneExpiredLocked(now time.Time) {
	cutoff := now.Add(-rb.ttl)
	for domain, b := range rb.byDomain {
		if b.At.Before(cutoff) {
			delete(rb.byDomain, domain)
		}
	}
}
