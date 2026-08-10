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

// The post-verdict pipeline shared by every enforcement hook. cargowall has
// two: tc_egress, whose events arrive as packets on a ring buffer
// (processEvent), and the root-cgroup hook, whose events arrive as verdict
// records in socket context (ReportVerdict). Both must produce the same
// thing — a connection outcome with a resolved hostname, CNAME attribution,
// late-allow reconciliation, an audit record, and a notification — or the
// firewall's observable behavior would depend on which hook happened to see
// a flow first. The steps live here once, and each hook feeds them.

package events

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

// resolveDestination turns a destination IP into the hostname a connection
// event should report, plus the CNAME chain it was reached through.
//
// Order matters: the DNS cache first, then a single lazy PTR lookup per
// unique IP, then forward-matching the tracked hostnames. Finally, if the IP
// was reached as the CNAME target of an allowed host, the origin hostname
// the user actually allowed (chain[0]) replaces the resolved name and the
// full chain is returned as a drill-down — so a blocked derived connection
// attributes to the origin and the late-allow check below runs against the
// origin's rule.
func resolveDestination(configMgr *config.Manager, dstIP string, logger *slog.Logger) (hostname string, cnameChain []string) {
	hostname = configMgr.LookupHostnameByIP(dstIP)
	if hostname == "" {
		logger.Debug("DNS cache miss", "ip", dstIP)
	} else {
		logger.Debug("DNS cache hit", "hostname", hostname, "ip", dstIP)
	}

	// Lazy reverse DNS for IPs not in the cache. Each unique IP is only
	// looked up once.
	if hostname == "" && !reverseDNSAttempted(dstIP) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		names, err := reverseDNSResolver.LookupAddr(ctx, dstIP)
		cancel()
		if err == nil && len(names) > 0 {
			// Lowercased so an unmatched PTR name is reported in the same
			// canonical case as forward mappings and tracked-rule matches,
			// keeping connection-event output consistent (#65). PTR replies
			// can carry mixed/0x20-randomized case off the wire.
			ptrName := strings.ToLower(strings.TrimSuffix(names[0], "."))
			if tracked := configMgr.FindTrackedHostname(ptrName); tracked != "" {
				hostname = tracked
			} else {
				hostname = ptrName
			}
			configMgr.UpdateDNSMapping(hostname, dstIP)
			logger.Debug("Lazy reverse DNS resolved", "ip", dstIP, "hostname", hostname)
		}

		// If PTR failed, try forward-matching all tracked hostnames.
		if hostname == "" {
			if match := configMgr.ForwardMatchIP(dstIP); match != "" {
				hostname = match
				configMgr.UpdateDNSMapping(hostname, dstIP)
				logger.Debug("Forward DNS match resolved", "ip", dstIP, "hostname", hostname)
			}
		}
	}

	// CNAME attribution — see Manager.RecordCNAMEChain. For an edge IP
	// shared by several allowed origins, LookupCNAMEChain returns the most
	// recently-resolved one. Setting hostname = chain[0] is a no-op when the
	// resolved hostname already is the origin, but the chain is still
	// attached so the drill-down isn't dropped.
	if chain := configMgr.LookupCNAMEChain(dstIP); len(chain) > 0 && chain[0] != "" {
		cnameChain = chain
		hostname = chain[0]
	}
	return hostname, cnameChain
}

// isTCPOrUDP reports whether proto is one of the two port-bearing L4
// protocols cargowall reasons about. It is the shared "protocol deny?"
// discriminator for both hooks' post-verdict handling: a denied non-TCP/UDP
// protocol reports as a protocol block, and only TCP/UDP can be
// late-allowed (fw.AddIP opens BPF state for SYN/datagram retries; nothing
// else benefits). The TC path additionally decodes its wire shape with
// BpfBlockedEvent.IsProtocolBlock, which answers "did the kernel encode a
// protocol number in dst_port" — a different question about the same class.
func isTCPOrUDP(proto uint8) bool {
	return proto == unix.IPPROTO_TCP || proto == unix.IPPROTO_UDP
}

// tryLateAllow reconciles a denial against the current ruleset: if the
// destination actually resolves to an allowed hostname (e.g. a process
// bypassed the DNS proxy with a cached IP), it opens the firewall so future
// retries succeed and reports whether THIS connection should be treated as
// allowed. Without it, a denial that policy would permit never self-heals —
// which is why both hooks must run it, not just TC.
//
// Restricted to TCP/UDP — see isTCPOrUDP.
func tryLateAllow(configMgr *config.Manager, fw FirewallUpdater, hostname, dstIP string,
	dstPort uint16, proto uint8, logger *slog.Logger,
) (lateAllowed bool, matchedRule string) {
	if hostname == "" || fw == nil || !isTCPOrUDP(proto) {
		return false, ""
	}
	verdict := configMgr.MatchHostnameRule(hostname)
	if !verdict.HasAllow() {
		return false, ""
	}
	matchedRule = verdict.AllowRule
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return false, matchedRule
	}

	// Write the deny side first (if any) so a mixed verdict — e.g.
	// `*.compute.internal: deny 80` + `bastion: allow 22` — preserves the
	// deny on its ports even though we're opening the firewall for the allow
	// side. Order doesn't matter for correctness (per-port entries are
	// independent), but writing deny first makes the resulting BPF state
	// self-consistent if the allow write later fails.
	if verdict.HasDeny() {
		if _, denyErr := fw.AddIP(ip, config.ActionDeny, verdict.DenyPorts); denyErr != nil {
			logger.Error("Late-resolved deny add failed",
				"ip", dstIP, "hostname", hostname, "error", denyErr)
		}
	}

	changed, err := fw.AddIP(ip, config.ActionAllow, verdict.AllowPorts)
	if err != nil {
		// Surface the failure for triage — the event falls through to the
		// blocked branch (lateAllowed stays false), so absence of this log
		// plus a "Connection blocked" entry means the firewall write is the
		// proximate cause.
		logger.Error("Late-resolved IP add failed",
			"ip", dstIP, "hostname", hostname, "error", err)
		return false, matchedRule
	}
	if changed {
		// `changed` covers both "IP was new" and "IP was present but new
		// per-port entries were written" (shared-IP-different-ports case) —
		// see Firewall.AddIP contract.
		logger.Info("Late-resolved IP firewall state updated",
			"ip", dstIP, "hostname", hostname, "ports", verdict.AllowPorts)
	} else {
		// IP already in the BPF map with matching state — useful when
		// triaging "why didn't this connection succeed on retry?".
		logger.Debug("Late-resolved IP already in firewall",
			"ip", dstIP, "hostname", hostname, "ports", verdict.AllowPorts)
	}

	// Best-effort prediction of "will the retry succeed?" from this rule's
	// own ports: FirewallImpl reconciles per-port entries before the LPM
	// no-op check, so on err==nil the current rule's ports are in map_ports
	// even when the IP was already in the LPM from a different rule with
	// disjoint ports.
	//
	// For a mixed verdict (e.g. `*.foo: deny 80` + `bar: allow all` on
	// `bar.foo`), AllowPorts may be empty (all ports) while DenyPorts covers
	// the event's port. The retry on that port will still be blocked by the
	// deny side's per-port BPF entry, so it is NOT late-allowed.
	//
	// Caveat: this looks only at THIS hostname's verdict, not at other rules
	// that resolved to the same shared IP. If that IP already carries a
	// conflicting all-ports grant, the firewall's PortSpecific=0 stickiness
	// makes this rule's per-port entry inert, so the audited
	// late-allow/blocked label can diverge from the actual BPF verdict for
	// that edge. Enforcement is unaffected — this only governs the
	// audit/notification.
	allowMatches := dstPortAllowedByRule(dstPort, proto, verdict.AllowPorts)
	denyMatches := verdict.HasDeny() &&
		dstPortAllowedByRule(dstPort, proto, verdict.DenyPorts)
	return allowMatches && !denyMatches, matchedRule
}

// OutcomeKind is what happened to a connection. It is the ONLY thing a hook
// decides about presentation: which event type is stamped, how the line
// reads, and whether a notification fires all follow from it in emitOutcome.
type OutcomeKind uint8

const (
	OutcomeAllowed OutcomeKind = iota
	OutcomeLateAllowed
	OutcomeBlocked
	// OutcomeProtocolBlocked is a denied non-TCP/UDP protocol. It carries a
	// protocol number instead of a port, which is why NotifyPort exists.
	OutcomeProtocolBlocked
	// OutcomeWouldBlock is a shadow-mode report: policy denies, nothing was
	// blocked. Never a policy outcome.
	OutcomeWouldBlock
)

// Outcome is one fully-resolved connection outcome handed to the single
// emitter. Audit carries the identity and destination the hook already
// resolved (plus MidStream / MatchedRule / AutoAllowedType where they
// apply); everything else here is what the log line and notification need.
type Outcome struct {
	Kind  OutcomeKind
	Audit AuditEvent
	// SrcPort renders the log's src as ip:port. Zero omits the port (a
	// protocol block has none).
	SrcPort uint16
	// DisplayHostname is the destination as reported to operators: the
	// hostname when resolved, else the bare IP.
	DisplayHostname string
	// NotifyPort is what the notification tracker dedups on — the
	// destination port, or the protocol number for a protocol block.
	NotifyPort uint16
	// ProtocolNum is logged for protocol blocks only.
	ProtocolNum uint16
}

// emitOutcome is the single place a connection outcome becomes observable:
// it stamps the event type, writes the log line, records the audit event,
// and fires the notification. Both enforcement hooks funnel through it, so
// TC and the cgroup hook cannot drift in how they report the same outcome —
// which they had begun to do (mid-stream, protocol-block typing, log src
// formatting) when each owned its own fan-out.
func emitOutcome(o Outcome, notificationTracker *NotificationTracker,
	auditLogger *AuditLogger, logger *slog.Logger,
) {
	audit := o.Audit
	src := audit.SrcIP
	if o.SrcPort != 0 {
		src = fmt.Sprintf("%s:%d", audit.SrcIP, o.SrcPort)
	}
	attrs := []any{"src", src, "dst", o.DisplayHostname, "dst_ip", audit.DstIP}

	var msg string
	var notify bool

	switch o.Kind {
	case OutcomeAllowed:
		audit.EventType = EventConnectionAllowed
		msg = "Connection allowed"
		attrs = append(attrs, "dst_port", audit.DstPort)

	case OutcomeLateAllowed:
		// Policy outcome is allow (the retry will succeed), so no block
		// notification. MatchedRule is the rule's Value (pattern string for
		// glob rules) — distinct from DisplayHostname, which is the reported
		// destination.
		audit.EventType = EventConnectionLateAllowed
		msg = "Connection late-allowed"
		attrs = append(attrs, "dst_port", audit.DstPort, "matched_rule", audit.MatchedRule)

	case OutcomeProtocolBlocked:
		audit.EventType = EventProtocolBlocked
		audit.DstPort = 0 // the wire field carried a protocol number, not a port
		msg = "Protocol blocked"
		attrs = append(attrs, "protocol", audit.Protocol, "protocol_num", o.ProtocolNum)
		notify = true

	case OutcomeWouldBlock:
		// Explicit flags: LogEvent skips normalization for this type, so no
		// consumer can read it as a block that happened.
		audit.EventType = EventCgroupWouldBlock
		audit.WouldDeny = true
		audit.Blocked = false
		msg = "Connection would be blocked (cgroup shadow mode)"
		attrs = append(attrs, "dst_port", audit.DstPort)

	default: // OutcomeBlocked
		// Mid-stream means an established connection was killed because its
		// destination isn't allowed — surfaced distinctly so operators can
		// tell a killed connection from a refused new one. It stays
		// EventConnectionBlocked (with MidStream set) so the RecentBlocks
		// reconciler, summary pipeline, and OTLP mapping treat it like any
		// other block.
		audit.EventType = EventConnectionBlocked
		msg = "Connection blocked"
		if audit.MidStream {
			msg = "Connection blocked (mid-stream)"
		}
		attrs = append(attrs, "dst_port", audit.DstPort)
		notify = true
	}

	logConnEvent(logger, msg, &audit, attrs...)

	if auditLogger != nil {
		if err := auditLogger.LogEvent(audit); err != nil {
			logger.Error("Failed to write audit log", "error", err)
		}
	}
	if notify && notificationTracker != nil {
		notificationTracker.SendNotification(audit.DstHostname, audit.DstIP, o.NotifyPort)
	}
}

// prepareOutcome runs the post-verdict preparation shared by both hooks:
// destination resolution, late-allow reconciliation, and the base Outcome
// with its audit record. Each hook then adds only what is genuinely its own
// — identity enrichment/decoration and kind selection. Kept as one function
// so the two preparation paths cannot drift the way the two emission paths
// once did (see emitOutcome).
//
// denial gates tryLateAllow: allowed TC events and shadow-mode would-blocks
// must never open the firewall.
//
// One audit record underlies every outcome branch and every observable
// channel: the caller stamps its event type and type-specific fields onto
// this base, emitOutcome hands it to LogEvent and logs through
// logConnEvent, which reads identity from the same struct — so enrichment
// can never produce a log line that disagrees with the audit stream. (The
// process name is looked up from /proc since bpf_get_current_comm is
// unavailable in TC programs.)
func prepareOutcome(configMgr *config.Manager, fw FirewallUpdater, logger *slog.Logger,
	denial bool, srcIP, dstIP string, srcPort, dstPort uint16, proto uint8,
	pid, ordinal uint32,
) (out Outcome, lateAllowed bool, matchedRule string) {
	hostname, cnameChain := resolveDestination(configMgr, dstIP, logger)

	if denial {
		lateAllowed, matchedRule = tryLateAllow(configMgr, fw, hostname, dstIP,
			dstPort, proto, logger)
	}

	displayHostname := hostname
	if displayHostname == "" {
		displayHostname = dstIP
	}

	out = Outcome{
		Audit: AuditEvent{
			SrcIP:       srcIP,
			DstIP:       dstIP,
			DstHostname: hostname,
			DstPort:     dstPort,
			Protocol:    getProtocolName(proto),
			Process:     lookupProcessName(pid),
			PID:         pid,
			CNAMEChain:  cnameChain,
			StepOrdinal: ordinal,
		},
		SrcPort:         srcPort,
		DisplayHostname: displayHostname,
		NotifyPort:      dstPort,
	}
	return out, lateAllowed, matchedRule
}

// VerdictRecord is one policy outcome reported by a hook that adjudicates in
// socket context rather than from a packet at TC — today, the root-cgroup
// egress hook. Addresses are already resolved to strings by the producer,
// which knows the address family.
type VerdictRecord struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8

	PID         uint32
	StepOrdinal uint32

	// Dropped separates an enforced drop from a shadow-mode would-block.
	// A would-block is telemetry: nothing was blocked, so it must never be
	// reported as a policy outcome.
	Dropped bool

	// MidStream marks a denial of an established flow rather than a
	// connection attempt — the hook re-adjudicates every packet, so an
	// allowlist change can kill a live connection here exactly as at TC.
	MidStream bool

	// Decorate optionally adds identity the reporting hook cannot know —
	// container id and origin, supplied by pkg/containers. Nil when no
	// decorator is wired.
	Decorate func(*AuditEvent)
}

// ReportVerdict turns a hook verdict into a connection outcome, through the
// same post-verdict steps as a TC event: hostname and CNAME resolution,
// late-allow reconciliation, the audit record, and the block notification.
//
// This is the only event source for traffic the cgroup hook drops — such a
// packet dies at ip_finish_output, before the TC qdisc, so tc_egress never
// sees it and there is nothing to join against. That is exactly why it must
// not be a thinner path: a denial reported here has to self-heal via
// late-allow and carry a hostname just like any other.
func ReportVerdict(rec VerdictRecord, configMgr *config.Manager, notificationTracker *NotificationTracker,
	auditLogger *AuditLogger, fw FirewallUpdater, logger *slog.Logger,
) {
	// denial = rec.Dropped: shadow-mode would-blocks are hypothetical and
	// must not open the firewall — nothing was denied and TC's own verdict
	// still governs the flow.
	out, lateAllowed, matchedRule := prepareOutcome(configMgr, fw, logger,
		rec.Dropped, rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort, rec.Proto,
		rec.PID, rec.StepOrdinal)

	if rec.Decorate != nil {
		rec.Decorate(&out.Audit)
	}

	switch {
	case !rec.Dropped:
		out.Kind = OutcomeWouldBlock
		// A would-block keeps the mid-stream flag: shadow mode exists to
		// predict what enforcement would do, and "would kill an established
		// flow" is precisely the datum an operator weighs before flipping
		// --cgroup-enforce. TC's audit-mode would-denies carry it too.
		out.Audit.MidStream = rec.MidStream
	case lateAllowed:
		out.Kind = OutcomeLateAllowed
		out.Audit.MatchedRule = matchedRule
	case !isTCPOrUDP(rec.Proto):
		// A denied non-TCP/UDP protocol reports in the same shape TC gives
		// it, so flipping --cgroup-enforce never changes an event's type for
		// consumers that branch on it. The hook emits ports 0 for these, so
		// the protocol number is the notification/dedup key.
		out.Kind = OutcomeProtocolBlocked
		out.SrcPort = 0
		out.ProtocolNum = uint16(rec.Proto)
		out.NotifyPort = uint16(rec.Proto)
	default:
		out.Kind = OutcomeBlocked
		// Mid-stream is a property of a DENIAL — real (here) or predicted
		// (the would-block arm above) — never of a late-allow, whose whole
		// point is that the flow is not being killed.
		out.Audit.MidStream = rec.MidStream
	}

	emitOutcome(out, notificationTracker, auditLogger, logger)
}
