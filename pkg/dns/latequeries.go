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

package dns

import (
	"github.com/miekg/dns"

	"github.com/code-cargo/cargowall/pkg/events"
)

// Late-allowed DNS queries (issue #119).
//
// Query filtering arms when the proxy starts listening, but the rules it
// filters against arrive later: the infrastructure auto-allow set, then the
// fetched policy. A query for a name that the run allows for its entire
// remaining life can therefore be REFUSED inside that window — and the
// dns_blocked record it leaves behind is pushed to the SaaS as a block,
// reporting a denial the policy never intended.
//
// The connection path solved its half of this in #83: RecentBlocks buffers
// blocked attempts, and the resolution that finally opens the firewall
// re-reports them as connection_late_allowed, dated at the original attempt
// so the summary supersedes them. This is the query-side twin — the same
// shape, keyed by name instead of destination IP, triggered by the ruleset
// changing instead of by an address record arriving.

// SetRecentDNSBlocks attaches the buffer of recently refused queries that
// reconcileRefusedQueries re-reports as late-allowed once a rule covering
// them loads. Requires an audit logger to emit the reconciliation events.
func (s *Server) SetRecentDNSBlocks(rb *events.RecentDNSBlocks) {
	s.recentDNSBlocks = rb
}

// reconcileRefusedQueries re-reports every buffered refusal whose name the
// current ruleset allows. Called when rules change
// (ApplyRulesToTrackedHostnames), which is the only moment a refused name
// can become allowed.
//
// Names still refused stay buffered: a later pass (or a later load) may yet
// cover them, and until their TTL expires the refusal remains the run's
// standing verdict.
func (s *Server) reconcileRefusedQueries() {
	if s.recentDNSBlocks == nil || s.auditLogger == nil {
		return
	}

	for _, domain := range s.recentDNSBlocks.Domains() {
		// TypeA, not the refusal's own qtype: the qtype gate in
		// isQueryAllowed only ever WIDENS (a canonically shaped reverse-DNS
		// PTR is allowed unconditionally), so evaluating the strict form
		// cannot late-allow a name the live path would still refuse.
		if !s.isQueryAllowed(domain, dns.TypeA) {
			continue
		}
		block, ok := s.recentDNSBlocks.Take(domain)
		if !ok {
			// Expired between the snapshot and the take, or claimed by a
			// concurrent pass. Either way there is no refusal left to
			// supersede, and emitting one anyway would invent an event.
			continue
		}

		// The rule that now covers the name, when one does: an allow can
		// also come from a search-domain suffix, a derived CNAME allow, or a
		// default-allow policy, none of which name a rule. An empty
		// matched_rule is the honest rendering of those.
		matchedRule := s.config.MatchHostnameRule(domain).AllowRule

		s.logger.Info("DNS query late-allowed (reconciled after rules loaded)",
			"domain", block.Domain,
			"matched_rule", matchedRule,
			"process", block.Process,
			"pid", block.PID,
			"refused_at", block.At)

		// Dated at the original refusal (block.At), not reconcile time, so
		// the event supersedes every dns_blocked record at or before it and
		// step correlation reflects when the query actually happened.
		if err := s.auditLogger.LogEvent(events.AuditEvent{
			Timestamp:       block.At,
			EventType:       events.EventDNSQueryLateAllowed,
			DstHostname:     block.Domain,
			MatchedRule:     matchedRule,
			Process:         block.Process,
			PID:             block.PID,
			StepOrdinal:     block.StepOrdinal,
			StepAttrOutcome: block.StepAttrOutcome,
			ContainerID:     block.ContainerID,
			ContainerOrigin: block.ContainerOrigin,
		}); err != nil {
			// Put the refusal back: the take already removed it, and losing it
			// here would leave the run reporting a dns_blocked the policy
			// never intended with no later pass able to supersede it.
			s.recentDNSBlocks.Restore(block)
			s.logger.Error("Failed to write DNS late-allow audit log", "error", err)
		}
	}
}
