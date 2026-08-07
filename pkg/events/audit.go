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
	// EventContainerAttribution marks one container/exec workload being tagged
	// with a step ordinal (issue #106): a telemetry marker like step_boundary,
	// describing no connection. TagLatencyMS/Privileged/AttributionKind are
	// only meaningful on this type.
	EventContainerAttribution AuditEventType = "container_attribution"
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

// IsConnectionAllowed reports whether the event type represents an allow
// outcome for a TCP/UDP connection — either a regular allow or a late-allowed
// retry after the BPF map missed.
func (et AuditEventType) IsConnectionAllowed() bool {
	return et == EventConnectionAllowed || et == EventConnectionLateAllowed
}

// AuditEvent represents a network event for audit logging
type AuditEvent struct {
	Timestamp       time.Time      `json:"timestamp"`
	EventType       AuditEventType `json:"event_type"`
	SrcIP           string         `json:"src_ip,omitempty"`
	DstIP           string         `json:"dst_ip,omitempty"`
	DstHostname     string         `json:"dst_hostname,omitempty"`
	DstPort         uint16         `json:"dst_port,omitempty"`
	Protocol        string         `json:"protocol,omitempty"` // L4 protocol name ("TCP"/"UDP", see getProtocolName; the blocked protocol itself for protocol_blocked) — shipped to the summary backend and part of the dedup key, so a real value beats a hardcoded literal
	Process         string         `json:"process,omitempty"`
	PID             uint32         `json:"pid,omitempty"`
	MatchedRule     string         `json:"matched_rule,omitempty"` // the matching rule's Value (pattern string for glob rules), which can differ from the resolved DstHostname (e.g. rule `*.compute-1.amazonaws.com` matching `ec2-1-2-3-4.compute-1...`)
	AutoAllowedType string         `json:"auto_allowed_type,omitempty"`
	CNAMEChain      []string       `json:"cname_chain,omitempty"`  // CNAME chain origin..target when DstHostname was reached via a CNAME of an allowed host
	MidStream       bool           `json:"mid_stream,omitempty"`   // set on connection_blocked when the drop was a non-SYN TCP segment (established connection killed mid-stream, e.g. a pre-existing socket whose dst was never seeded)
	WouldDeny       bool           `json:"would_deny"`             // true in audit mode (would have been denied)
	Blocked         bool           `json:"blocked"`                // true in enforce mode (actually blocked)
	StepOrdinal     uint32         `json:"step_ordinal,omitempty"` // workflow step that (transitively) created the socket — causal, not temporal; see StepOrdinal* sentinels

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
	// late-allowed — where the connection was initially dropped by BPF but a
	// subsequent rule match opened the firewall, so the policy outcome is allow)
	// and for step boundaries and container attributions, which describe no
	// connection at all.
	if event.EventType != EventConnectionAllowed &&
		event.EventType != EventConnectionLateAllowed &&
		event.EventType != EventExistingConnection &&
		event.EventType != EventStepBoundary &&
		event.EventType != EventContainerAttribution {
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
