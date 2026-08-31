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
	"log/slog"
	"net"

	"github.com/code-cargo/cargowall/pkg/config"
)

// L7LateRegistrar scopes a hostname's IP for L7. It is a PARAMETER on the
// paths that open a /32, never an upgrade probed off FirewallUpdater, so a
// caller cannot drop the scope write by passing the bare firewall. nil means
// L7 is off, decided at the composition root.
type L7LateRegistrar interface {
	RegisterLateAllow(hostname string, ip net.IP, allowPorts []config.Port)
}

// ScopeAllowedIP is THE "L4 just opened this hostname's IP, so L7 must govern
// it too" step, called by every path that opens a /32 for a named host. Map
// writes are idempotent, so repeat calls are free.
//
// A nameless allow scopes nothing: an IP allowed without a hostname has no
// identity to bind. Whether a NAMED one scopes is the registrar's call — it
// scopes only IPs a name forward-resolved to (see dns.RegisterL7Identity).
func ScopeAllowedIP(l7 L7LateRegistrar, hostname string, ip net.IP, allowPorts []config.Port) {
	if l7 == nil || hostname == "" || ip == nil {
		return
	}
	l7.RegisterLateAllow(hostname, ip, allowPorts)
}

// L7Record is one denied L7 (SNI/Host/QUIC) adjudication reported by the
// oracle. The caller has already resolved the punt's socket cookie to
// pid/step through the same join origin records use, so an L7 denial carries
// the identical attribution as its sibling L4 outcomes.
type L7Record struct {
	SrcIP       string
	DstIP       string
	DstPort     uint16
	Proto       uint8 // L4 protocol number
	PID         uint32
	StepOrdinal uint32
	Name        string // SNI/Host the flow presented ("" when none was recovered)
	L7Protocol  string // "tls" | "http" | "quic"
	Reason      string // origin.L7Reason vocabulary
	Enforced    bool   // true: the flow was dropped; false: observe/audit would-block
	// Decorate optionally adds identity the oracle cannot know — container
	// id/origin, supplied by pkg/containers. Nil when no decorator is wired.
	Decorate func(*AuditEvent)
}

// ReportL7 turns one denied L7 adjudication into a log line, an audit record,
// and — for an enforced drop — the same operator notification an equivalent
// L4 block raises, with the same identity fields (process, step, container,
// hostname) as the L4 outcome pipeline. Deliberately NOT routed through
// emitOutcome: an L7 denial's destination IP is already L4-allowed by
// premise, so late-allow reconciliation must not run (it would "heal" a
// denial whose entire point is that the IP alone is not enough), and the
// hostname lookup stays cache-only (no PTR).
func ReportL7(rec L7Record, configMgr *config.Manager, auditLogger *AuditLogger,
	notificationTracker *NotificationTracker, logger *slog.Logger,
) {
	evtType := EventL7WouldBlock
	if rec.Enforced {
		evtType = EventL7Blocked
	}
	var hostname string
	if configMgr != nil {
		hostname = configMgr.LookupHostnameByIP(rec.DstIP)
	}
	audit := AuditEvent{
		EventType:   evtType,
		SrcIP:       rec.SrcIP,
		DstIP:       rec.DstIP,
		DstHostname: hostname,
		DstPort:     rec.DstPort,
		Protocol:    getProtocolName(rec.Proto),
		Process:     lookupProcessName(rec.PID),
		PID:         rec.PID,
		StepOrdinal: rec.StepOrdinal,
		L7Name:      rec.Name,
		L7Protocol:  rec.L7Protocol,
		L7Reason:    rec.Reason,
		WouldDeny:   !rec.Enforced,
	}
	if rec.Decorate != nil {
		rec.Decorate(&audit)
	}

	if logger != nil {
		msg := "L7 identity would be blocked"
		if rec.Enforced {
			msg = "L7 identity blocked"
		}
		logConnEvent(logger, msg, &audit,
			"src", rec.SrcIP, "dst_ip", rec.DstIP, "dst_port", rec.DstPort,
			"l7_protocol", rec.L7Protocol, "l7_name", rec.Name, "reason", rec.Reason)
	}
	if auditLogger != nil {
		_ = auditLogger.LogEvent(audit)
	}
	// Only a REAL drop notifies, matching emitOutcome's policy (would-blocks
	// are telemetry). The name is the rejected identity — the SNI/Host the
	// flow presented — and NEVER the edge's resolved hostname: on a shared
	// edge that name is the allowed tenant, so a nameless denial (ECH, no
	// SNI, a parse failure) would blame and deduplicate against a destination
	// policy permits. SendNotification falls back to the IP for an empty name,
	// which is the correct attribution here.
	if rec.Enforced && notificationTracker != nil {
		notificationTracker.SendNotification(rec.Name, rec.DstIP, rec.DstPort)
	}
}
