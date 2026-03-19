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
	EventConnectionBlocked  AuditEventType = "connection_blocked"
	EventConnectionAllowed  AuditEventType = "connection_allowed"
	EventProtocolBlocked    AuditEventType = "protocol_blocked"
	EventDNSBlocked         AuditEventType = "dns_blocked"
	EventExistingConnection AuditEventType = "existing_connection"
)

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
	// Skip for allowed events and existing connection events (they set their own flags).
	if event.EventType != EventConnectionAllowed &&
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

// LogConnectionBlocked logs a blocked connection event
func (a *AuditLogger) LogConnectionBlocked(srcIP, dstIP, hostname string, dstPort uint16, process string, pid uint32) error {
	return a.LogEvent(AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventConnectionBlocked,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		DstHostname: hostname,
		DstPort:     dstPort,
		Protocol:    "TCP/UDP",
		Process:     process,
		PID:         pid,
	})
}

// LogConnectionAllowed logs an allowed TCP connection event
func (a *AuditLogger) LogConnectionAllowed(srcIP, dstIP, hostname string, dstPort uint16, process string, pid uint32, autoAllowedType string) error {
	return a.LogEvent(AuditEvent{
		Timestamp:       time.Now(),
		EventType:       EventConnectionAllowed,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		DstHostname:     hostname,
		DstPort:         dstPort,
		Protocol:        "TCP",
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
