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

package events

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	EventConnectionBlocked     AuditEventType = "connection_blocked"
	EventConnectionAllowed     AuditEventType = "connection_allowed"
	EventConnectionLateAllowed AuditEventType = "connection_late_allowed"
	EventProtocolBlocked       AuditEventType = "protocol_blocked"
	EventDNSBlocked            AuditEventType = "dns_blocked"
	EventExistingConnection    AuditEventType = "existing_connection"
	EventStepBoundary          AuditEventType = "step_boundary"
	// EventDNSQueryLateAllowed re-reports a refused query whose name a rule
	// covered moments later — the auto-allow set and the fetched policy both
	// land after the proxy arms query filtering, so a name that was allowed
	// for the rest of the run was still REFUSED during that window (issue
	// #119). Dated at the original refusal so it supersedes the dns_blocked
	// records it re-reports, exactly as connection_late_allowed does for the
	// connection path (#83). Nothing was blocked at the time this event is
	// written; the refusal it describes already happened.
	EventDNSQueryLateAllowed AuditEventType = "dns_query_late_allowed"
	// EventContainerAttribution marks one container/exec workload being tagged
	// with a step ordinal (issue #106): a telemetry marker like step_boundary,
	// describing no connection. TagLatencyMS/Privileged/AttributionKind are
	// only meaningful on this type.
	EventContainerAttribution AuditEventType = "container_attribution"
	// EventCgroupWouldBlock is a connection the cgroup egress hook WOULD have
	// dropped, reported while that hook is in shadow mode (issue #106 phase
	// 3b). Nothing was blocked — TC's verdict still governed the packet.
	// These measure the blast radius of the surfaces the cgroup hook newly
	// adjudicates (loopback, docker bridge, container netns) before
	// enforcement is turned on, so they are telemetry, not policy outcomes.
	EventCgroupWouldBlock AuditEventType = "cgroup_would_block"
	// EventL7Blocked is a flow dropped by L7 (SNI/Host/QUIC) enforcement: the
	// destination IP was allowed at L4, but the TLS SNI / HTTP Host / QUIC name
	// the flow presented is not an allowed hostname on that IP. This is the
	// shared-edge tenant swap being stopped.
	EventL7Blocked AuditEventType = "l7_blocked"
	// EventL7WouldBlock is the observe-mode counterpart: L7 enforcement WOULD
	// have dropped the flow, but the packet was passed. Phase-A telemetry that
	// gates turning enforcement on — the L7 analogue of cgroup_would_block.
	EventL7WouldBlock AuditEventType = "l7_would_block"
)

// Step-ordinal sentinels, mirroring STEP_ORD_* in tcbpf.c. Real workflow
// steps get small ordinals starting at the daemon's --step-ordinal-base
// (opaque causal group IDs — correlate to plan steps via step_boundary
// events, not by position); 0 means the traffic's socket was never tagged.
const (
	StepOrdinalNone      uint32 = 0
	StepOrdinalPreDaemon uint32 = 0xFFFFFFFE // worker children that predate cargowall
	StepOrdinalRunner    uint32 = 0xFFFFFFFF // Runner.Worker itself / cargowall infra
)

// MaxRealStepOrdinal is the exclusive upper bound of real (non-sentinel)
// step ordinals: StepOrdinalPreDaemon minus a 2^16 margin, leaving room for
// any realistic number of steps above the configured ordinal base. Owned
// here next to the sentinels; pkg/steps bounds --step-ordinal-base with it,
// and the CI gates (scripts/ci/*.sh) mirror the same 0xFFFFFFFE - 65536
// arithmetic when selecting real-ordinal events.
const MaxRealStepOrdinal = StepOrdinalPreDaemon - 1<<16

// IsAllowedOutcome reports whether the event type represents an ALLOW outcome
// — the connection allows (regular and the late-allowed retry after the BPF
// map missed) plus the DNS query late-allow.
//
// dns_query_late_allowed belongs here even though nothing was allowed at the
// instant it was written: it supersedes the dns_blocked row it re-reports, and
// reconcileLateAllowedBlocks has already deleted that row by the time a
// renderer asks. Classifying it as a block would print the name as denied with
// nothing left to correct it, while its connection-side twin printed Allowed —
// the two halves of #119 disagreeing on the primary human-facing surface.
func (et AuditEventType) IsAllowedOutcome() bool {
	return et == EventConnectionAllowed || et == EventConnectionLateAllowed ||
		et == EventDNSQueryLateAllowed
}

// ReportedDestName is the destination identity a human- or SaaS-facing
// surface should print for this event. For an L7 denial the rejected identity
// is the SNI/Host the flow PRESENTED (L7Name) — DstHostname there is the
// allowed origin the shared edge IP happens to resolve to, which is exactly
// the name that must NOT be recorded as denied. Every export surface (summary
// tables, dedup keys, unique-hostname counts, SaaS push, OTLP) goes through
// this one helper so they cannot disagree.
//
// An L7 denial that recovered NO name (ECH, no SNI, no Host, a parse error)
// falls through to the bare IP, deliberately NOT to DstHostname: that is the
// allowed origin the shared edge resolves to, so reporting it would blame the
// allowed name for the denial — and, because these surfaces drive the
// allowlist suggestions, would tell the operator to allow a hostname their
// config already allows. The IP is the only identity such a flow actually
// established.
func (e *AuditEvent) ReportedDestName() string {
	if e.EventType == EventL7Blocked || e.EventType == EventL7WouldBlock {
		if e.L7Name != "" {
			return e.L7Name
		}
		return e.DstIP
	}
	if e.DstHostname != "" {
		return e.DstHostname
	}
	return e.DstIP
}

// StepAttrOutcome says how the sockdiag step lookup behind a dns_blocked
// event resolved (pkg/steps StepForClient). Defined next to AuditEvent —
// the one place the vocabulary lives — so the JSON field, OTLP export, and
// CI assertions cannot drift from the producer.
type StepAttrOutcome string

const (
	// StepAttrOK: client socket found and tagged; StepOrdinal is real (or a
	// sentinel).
	StepAttrOK StepAttrOutcome = "ok"
	// StepAttrUntagged: socket found but its cookie has no map_sock_step
	// entry — the owner is outside the tagged subtree (e.g. a systemd
	// service, systemd-resolved) or predates attach.
	StepAttrUntagged StepAttrOutcome = "untagged"
	// StepAttrNotFound: clean dump, no socket matched the client address.
	StepAttrNotFound StepAttrOutcome = "not_found"
	// StepAttrAmbiguous: only wildcard-bound candidates matched and there
	// were two or more — declined rather than guessed.
	StepAttrAmbiguous StepAttrOutcome = "ambiguous_wildcard"
	// StepAttrDumpError: the netlink dump itself failed.
	StepAttrDumpError StepAttrOutcome = "dump_error"
	// StepAttrShed: dropped under flood back-pressure without resolving.
	StepAttrShed StepAttrOutcome = "shed"
	// StepAttrUnsupported: the client address was not UDP/TCP.
	StepAttrUnsupported StepAttrOutcome = "unsupported_addr"
)

// StepAttribution is one resolved DNS-client attribution — the step
// lookup's result, copied field-for-field onto dns_blocked events. Owned
// here next to the outcome vocabulary so the producer (pkg/steps) and the
// consumer (pkg/dns) share one type without depending on each other.
type StepAttribution struct {
	Ordinal uint32          // step ordinal, 0 unless Outcome is StepAttrOK
	Outcome StepAttrOutcome // why the lookup resolved the way it did
	PID     uint32          // client socket owner's pid, 0 if unknown
	Process string          // owner's process name, "" if unknown
}

// AuditEvent represents a network event for audit logging
type AuditEvent struct {
	Timestamp       time.Time       `json:"timestamp"`
	EventType       AuditEventType  `json:"event_type"`
	SrcIP           string          `json:"src_ip,omitempty"`
	DstIP           string          `json:"dst_ip,omitempty"`
	DstHostname     string          `json:"dst_hostname,omitempty"`
	DstPort         uint16          `json:"dst_port,omitempty"`
	Protocol        string          `json:"protocol,omitempty"` // L4 protocol name ("TCP"/"UDP", see getProtocolName; the blocked protocol itself for protocol_blocked) — shipped to the summary backend and part of the dedup key, so a real value beats a hardcoded literal
	Process         string          `json:"process,omitempty"`
	PID             uint32          `json:"pid,omitempty"`
	MatchedRule     string          `json:"matched_rule,omitempty"` // the matching rule's Value (pattern string for glob rules), which can differ from the resolved DstHostname (e.g. rule `*.compute-1.amazonaws.com` matching `ec2-1-2-3-4.compute-1...`)
	AutoAllowedType string          `json:"auto_allowed_type,omitempty"`
	CNAMEChain      []string        `json:"cname_chain,omitempty"`       // CNAME chain origin..target when DstHostname was reached via a CNAME of an allowed host
	MidStream       bool            `json:"mid_stream,omitempty"`        // set on connection_blocked when the drop was a non-SYN TCP segment (established connection killed mid-stream, e.g. a pre-existing socket whose dst was never seeded)
	WouldDeny       bool            `json:"would_deny"`                  // true in audit mode (would have been denied)
	Blocked         bool            `json:"blocked"`                     // true in enforce mode (actually blocked)
	StepOrdinal     uint32          `json:"step_ordinal,omitempty"`      // workflow step that (transitively) created the socket — causal, not temporal; see StepOrdinal* sentinels
	StepAttrOutcome StepAttrOutcome `json:"step_attr_outcome,omitempty"` // dns_blocked only: how the sockdiag step lookup resolved — additive/omitempty like the container fields below

	// L7 (TLS SNI / HTTP Host / QUIC) enforcement. All additive/omitempty. On
	// l7_blocked/l7_would_block: L7Name is the SNI/Host the flow presented (may
	// be attacker-chosen — distinct from the DNS-resolved DstHostname),
	// L7Protocol is tls|http|quic, and L7Reason is why it was denied.
	L7Name     string `json:"l7_name,omitempty"`
	L7Protocol string `json:"l7_protocol,omitempty"`
	L7Reason   string `json:"l7_reason,omitempty"`

	// Container attribution (issue #106). All additive and omitempty: the
	// summary reader tolerates their absence, so old daemons and new
	// summaries (and vice versa) interoperate.
	ContainerID     string  `json:"container_id,omitempty"`     // 12-char Docker container id the traffic/tag belongs to
	ContainerOrigin bool    `json:"container_origin,omitempty"` // traffic classified as container-originated (with or without a step ordinal)
	AttributionKind string  `json:"attribution_kind,omitempty"` // container_attribution only: "start" | "exec" | "reconcile"
	TagLatencyMS    float64 `json:"tag_latency_ms,omitempty"`   // container_attribution only: docker event → tag-complete latency
	Privileged      bool    `json:"privileged,omitempty"`       // container_attribution only: container runs --privileged (host-root equivalent)
}

// EventSink receives every audit event after the audit/enforce mode flags
// have been normalized. Consume is called under the audit logger's mutex on
// the ring-buffer reader and DNS handler goroutines, so it must not block.
type EventSink interface {
	Consume(event AuditEvent)
}

// AuditLogger writes audit events to a JSON file (one event per line) and
// fans them out to any registered sinks. With an empty path it acts as a
// file-less event hub (sinks only).
type AuditLogger struct {
	file      *os.File
	encoder   *json.Encoder
	mu        sync.Mutex
	auditMode bool      // true = audit mode (log only), false = enforce mode (actually blocking)
	lastSync  time.Time // last time file.Sync() was called
	sinks     []EventSink
}

// NewAuditLogger creates a new audit logger that writes to the specified
// file. An empty path skips file output entirely — events still flow to
// sinks registered via AddSink.
func NewAuditLogger(path string, auditMode bool) (*AuditLogger, error) {
	a := &AuditLogger{auditMode: auditMode}
	if path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file: %w", err)
		}
		a.file = file
		a.encoder = json.NewEncoder(file)
	}
	return a, nil
}

// AddSink registers a sink that will receive every subsequent audit event.
func (a *AuditLogger) AddSink(s EventSink) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sinks = append(a.sinks, s)
}

// LogEvent normalizes and writes one audit event; it is the single logging
// entry point — call sites build an AuditEvent with the fields they know
// and hand it over (adding a field means adding a field, not re-threading
// every constructor signature). A zero Timestamp is stamped with the
// current time; late-allow reconciliation (#83) passes an explicit one to
// date the event at the original blocked attempt, so step correlation
// reflects when the connection actually happened and the event supersedes
// every blocked record at or before it.
func (a *AuditLogger) LogEvent(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Set the block status based on audit mode.
	// Skip for events that set their own flags (allowed, existing connection,
	// late-allowed — where the connection was initially dropped by BPF, or the
	// query refused by the proxy, but a subsequent rule match opened the
	// firewall, so the policy outcome is allow)
	// and for step boundaries and container attributions, which describe no
	// connection at all.
	// cgroup_would_block also sets its own flags: nothing was blocked (the
	// packet passed in shadow mode), so normalization must not stamp
	// Blocked=true from the run's enforce posture.
	// l7_would_block, like cgroup_would_block, is telemetry: the packet passed
	// (observe mode, or enforce under audit posture), so it sets its own flags
	// and must not be stamped Blocked from the run's enforce posture. l7_blocked
	// is a real drop and is normalized like any other block.
	if event.EventType != EventConnectionAllowed &&
		event.EventType != EventConnectionLateAllowed &&
		event.EventType != EventDNSQueryLateAllowed &&
		event.EventType != EventExistingConnection &&
		event.EventType != EventStepBoundary &&
		event.EventType != EventContainerAttribution &&
		event.EventType != EventCgroupWouldBlock &&
		event.EventType != EventL7WouldBlock {
		if a.auditMode {
			event.WouldDeny = true
			event.Blocked = false
		} else {
			event.WouldDeny = false
			event.Blocked = true
		}
	}

	for _, s := range a.sinks {
		s.Consume(event)
	}

	if a.encoder == nil {
		return nil
	}

	if err := a.encoder.Encode(event); err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}

	// Batch sync: only flush to disk if >1s since last sync
	now := time.Now()
	if now.Sub(a.lastSync) > time.Second {
		a.lastSync = now
		return a.file.Sync()
	}
	return nil
}

// LogExistingConnection logs a pre-existing connection that was found at startup
func (a *AuditLogger) LogExistingConnection(ip, hostname, matchedRule string, allowed bool, autoAllowedType string) error {
	return a.LogEvent(AuditEvent{
		Timestamp:       time.Now(),
		EventType:       EventExistingConnection,
		DstIP:           ip,
		DstHostname:     hostname,
		MatchedRule:     matchedRule,
		AutoAllowedType: autoAllowedType,
		Blocked:         !allowed,
		WouldDeny:       !allowed,
	})
}

// Close flushes pending writes and closes the audit log file
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.file != nil {
		_ = a.file.Sync()
		err := a.file.Close()
		a.file = nil
		return err
	}
	return nil
}

// SetAuditMode updates the audit mode flag at runtime.
func (a *AuditLogger) SetAuditMode(auditMode bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.auditMode = auditMode
}

// IsAuditMode returns true if running in audit mode
func (a *AuditLogger) IsAuditMode() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.auditMode
}
