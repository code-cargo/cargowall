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
	Protocol        string         `json:"protocol,omitempty"`
	Process         string         `json:"process,omitempty"`
	PID             uint32         `json:"pid,omitempty"`
	MatchedRule     string         `json:"matched_rule,omitempty"`
	AutoAllowedType string         `json:"auto_allowed_type,omitempty"`
	WouldDeny       bool           `json:"would_deny"` // true in audit mode (would have been denied)
	Blocked         bool           `json:"blocked"`    // true in enforce mode (actually blocked)
}

// AuditLogger writes audit events to a JSON file (one event per line)
type AuditLogger struct {
	file      *os.File
	encoder   *json.Encoder
	mu        sync.Mutex
	auditMode bool      // true = audit mode (log only), false = enforce mode (actually blocking)
	lastSync  time.Time // last time file.Sync() was called
}

// NewAuditLogger creates a new audit logger that writes to the specified file
func NewAuditLogger(path string, auditMode bool) (*AuditLogger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &AuditLogger{
		file:      file,
		encoder:   json.NewEncoder(file),
		auditMode: auditMode,
	}, nil
}

// LogEvent writes an audit event to the log file
func (a *AuditLogger) LogEvent(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Set the block status based on audit mode.
	// Skip for events that set their own flags (allowed, existing connection,
	// late-allowed — where the connection was initially dropped by BPF but a
	// subsequent rule match opened the firewall, so the policy outcome is allow).
	if event.EventType != EventConnectionAllowed &&
		event.EventType != EventConnectionLateAllowed &&
		event.EventType != EventExistingConnection {
		if a.auditMode {
			event.WouldDeny = true
			event.Blocked = false
		} else {
			event.WouldDeny = false
			event.Blocked = true
		}
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

// LogConnectionBlocked logs a blocked connection event. `protocol` is the L4
// protocol of the dropped packet (typically "TCP" or "UDP" — see
// getProtocolName); the field is shipped to the summary backend and rendered
// in the UI's Baseline Entries table, so a real value beats a generic literal.
func (a *AuditLogger) LogConnectionBlocked(srcIP, dstIP, hostname string, dstPort uint16, process string, pid uint32, protocol string) error {
	return a.LogEvent(AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventConnectionBlocked,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		DstHostname: hostname,
		DstPort:     dstPort,
		Protocol:    protocol,
		Process:     process,
		PID:         pid,
	})
}

// LogConnectionLateAllowed logs a connection that BPF initially dropped but
// that we then opened the firewall for after late hostname resolution matched
// an allow rule. The original SYN was lost, but the next retry will succeed.
// `protocol` is the L4 protocol of the dropped packet — see LogConnectionBlocked.
// `matchedRule` is the rule's Value (pattern string for glob rules, configured
// hostname for plain rules), which can differ from the resolved DstHostname
// (e.g. rule `*.compute-1.amazonaws.com` matching `ec2-1-2-3-4.compute-1...`).
func (a *AuditLogger) LogConnectionLateAllowed(srcIP, dstIP, hostname, matchedRule string, dstPort uint16, process string, pid uint32, protocol string) error {
	return a.LogEvent(AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventConnectionLateAllowed,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		DstHostname: hostname,
		DstPort:     dstPort,
		Protocol:    protocol,
		Process:     process,
		PID:         pid,
		MatchedRule: matchedRule,
	})
}

// LogConnectionAllowed logs an allowed TCP/UDP connection event. `protocol`
// is the L4 protocol from the BPF event (typically "TCP" or "UDP" — see
// getProtocolName); the field is shipped to the summary backend and feeds
// the dedup key, so a real value beats a hardcoded literal (auto-allowed DNS
// on :53 is the canonical UDP example).
func (a *AuditLogger) LogConnectionAllowed(srcIP, dstIP, hostname string, dstPort uint16, process string, pid uint32, autoAllowedType, protocol string) error {
	return a.LogEvent(AuditEvent{
		Timestamp:       time.Now(),
		EventType:       EventConnectionAllowed,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		DstHostname:     hostname,
		DstPort:         dstPort,
		Protocol:        protocol,
		Process:         process,
		PID:             pid,
		AutoAllowedType: autoAllowedType,
	})
}

// LogProtocolBlocked logs a blocked protocol event
func (a *AuditLogger) LogProtocolBlocked(srcIP, dstIP, hostname, protocol, process string, pid uint32) error {
	return a.LogEvent(AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventProtocolBlocked,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		DstHostname: hostname,
		Protocol:    protocol,
		Process:     process,
		PID:         pid,
	})
}

// LogDNSBlocked logs a blocked DNS query
func (a *AuditLogger) LogDNSBlocked(domain string) error {
	return a.LogEvent(AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventDNSBlocked,
		DstHostname: domain,
	})
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
