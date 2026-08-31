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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
)

func l7Rec(enforced bool) L7Record {
	return L7Record{
		SrcIP:       "10.0.0.9",
		DstIP:       "104.16.1.1",
		DstPort:     443,
		Proto:       6,
		PID:         4242,
		StepOrdinal: 7,
		Name:        "evil.example",
		L7Protocol:  "tls",
		Reason:      "name_mismatch",
		Enforced:    enforced,
	}
}

// TestReportL7 pins the event type and field mapping for both postures: an
// enforce-mode drop is l7_blocked (normalized to Blocked=true), an
// observe-mode denial is l7_would_block and must never read as a block.
func TestReportL7(t *testing.T) {
	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)

	ReportL7(l7Rec(true), nil, auditLogger, nil, newTestLogger())
	ReportL7(l7Rec(false), nil, auditLogger, nil, newTestLogger())

	require.Len(t, sink.events, 2)

	blocked := sink.events[0]
	assert.Equal(t, EventL7Blocked, blocked.EventType)
	assert.True(t, blocked.Blocked, "an enforced L7 drop is a real block")
	assert.Equal(t, "evil.example", blocked.L7Name)
	assert.Equal(t, "tls", blocked.L7Protocol)
	assert.Equal(t, "name_mismatch", blocked.L7Reason)
	assert.Equal(t, "104.16.1.1", blocked.DstIP)
	assert.Equal(t, uint16(443), blocked.DstPort)
	assert.Equal(t, "TCP", blocked.Protocol)
	assert.Equal(t, uint32(4242), blocked.PID)
	assert.Equal(t, uint32(7), blocked.StepOrdinal, "the cookie join's step must reach the record")

	would := sink.events[1]
	assert.Equal(t, EventL7WouldBlock, would.EventType)
	assert.True(t, would.WouldDeny)
	assert.False(t, would.Blocked, "observe mode blocked nothing")
}

// TestReportL7_HostnameAndDecoration: the DNS-resolved hostname for the
// destination IP (cache-only — this path runs on the punt reader) and the
// container decoration must land on the record, mirroring L4 outcomes.
func TestReportL7_HostnameAndDecoration(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))
	cm.UpdateDNSMapping("edge.example", "104.16.1.1")

	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)

	rec := l7Rec(true)
	rec.Decorate = func(a *AuditEvent) {
		a.ContainerOrigin = true
		a.ContainerID = "abc123def456"
	}
	ReportL7(rec, cm, auditLogger, nil, newTestLogger())

	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, "edge.example", ev.DstHostname)
	assert.True(t, ev.ContainerOrigin)
	assert.Equal(t, "abc123def456", ev.ContainerID)
}

// recordingL7 is the L7LateRegistrar cmd passes alongside the firewall when
// --tls-sni is on. It is a SEPARATE value from the firewall: L4 and L7 are two
// parameters, so a caller cannot drop the scope write by handing over a bare
// firewall.
type recordingL7 struct {
	registered []string
	ips        []string
	ports      [][]config.Port
}

func (r *recordingL7) RegisterLateAllow(hostname string, ip net.IP, allowPorts []config.Port) {
	r.registered = append(r.registered, hostname)
	r.ips = append(r.ips, ip.String())
	r.ports = append(r.ports, allowPorts)
}

// TestLateAllowRegistersL7: when the firewall seam carries the L7 upgrade, a
// late-allow must pin the hostname's L7 identity in the same reconciliation
// that reopens the /32 — closing the L4-open-but-L7-unscoped window.
func TestLateAllowRegistersL7(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "example.com",
		Action: config.ActionAllow,
	}}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	fw := &mockFirewallUpdater{}
	l7 := &recordingL7{}

	ReportVerdict(verdictRec(true), cm, nil, auditLogger, fw, l7, newTestLogger())

	require.NotEmpty(t, fw.addedIPs, "the L4 late-allow must still run")
	require.Equal(t, []string{"example.com"}, l7.registered,
		"the late-allowed name must be registered with L7")
	require.Equal(t, []string{"93.184.216.34"}, l7.ips)
}

// TestLateAllowShadowDoesNotRegisterL7: a would-block must not register L7
// identity, exactly as it must not open the firewall.
func TestLateAllowShadowDoesNotRegisterL7(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "example.com",
		Action: config.ActionAllow,
	}}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	auditLogger, err := NewAuditLogger("", true)
	require.NoError(t, err)
	fw := &mockFirewallUpdater{}
	l7 := &recordingL7{}

	ReportVerdict(verdictRec(false), cm, nil, auditLogger, fw, l7, newTestLogger())

	assert.Empty(t, fw.addedIPs)
	assert.Empty(t, l7.registered, "shadow telemetry must not touch L7 state")
}

// TestReportL7_NotifiesOnEnforce: an enforced L7 drop must raise the same
// operator notification an L4 block does, under the rejected SNI — while an
// observe-mode would-block (telemetry) must not.
func TestReportL7_NotifiesOnEnforce(t *testing.T) {
	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sm := &mockStateMachineClient{}
	tracker := NewNotificationTracker(sm, newTestLogger())

	ReportL7(l7Rec(true), nil, auditLogger, tracker, newTestLogger())  // enforced drop
	ReportL7(l7Rec(false), nil, auditLogger, tracker, newTestLogger()) // observe would-block

	require.Len(t, sm.calls, 1, "only the enforced drop notifies")
	require.Equal(t, "evil.example", sm.calls[0].hostname, "the notification names the rejected SNI")
}

// TestReportL7_NamelessDenialNotifiesByIP is the notification sibling of
// TestReportedDestName_NamelessL7Denial: a denial that recovered no name (ECH,
// no SNI, a parse failure) must NOT fall back to the edge's resolved hostname.
// That hostname is the allowed tenant on a shared edge, so notifying under it
// blames a destination policy permits — and dedups every such denial onto that
// one key, hiding the rest.
func TestReportL7_NamelessDenialNotifiesByIP(t *testing.T) {
	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)

	cfg := config.NewConfigManager()
	// The edge IP resolves to an ALLOWED tenant; the flow presented no name.
	cfg.UpdateDNSMapping("allowed.example", "104.16.1.1")

	sm := &mockStateMachineClient{}
	tracker := NewNotificationTracker(sm, newTestLogger())

	rec := l7Rec(true)
	rec.Name = "" // ECH / no-SNI / parse error: nothing recovered
	ReportL7(rec, cfg, auditLogger, tracker, newTestLogger())

	require.Len(t, sm.calls, 1)
	require.Empty(t, sm.calls[0].hostname,
		"a nameless denial must not be notified under the edge's allowed hostname")
	require.Equal(t, "104.16.1.1", sm.calls[0].ip)

	// A denial at the SAME edge under a different nameless flow dedups on the
	// IP, not on the allowed tenant's name.
	rec.DstPort = 8443
	ReportL7(rec, cfg, auditLogger, tracker, newTestLogger())
	require.Len(t, sm.calls, 2, "a different port is a distinct destination")
}

// TestReportedDestName_NamelessL7Denial: an L7 denial that recovered NO name
// (ECH, no SNI, a parse error) must report the destination IP, never
// DstHostname. DstHostname there is the ALLOWED origin the shared edge IP
// resolves to, so reporting it blames an allowed name for the denial — and,
// because this helper drives the allowlist suggestions, would tell the operator
// to allow a hostname their config already allows.
func TestReportedDestName_NamelessL7Denial(t *testing.T) {
	for _, et := range []AuditEventType{EventL7Blocked, EventL7WouldBlock} {
		ev := &AuditEvent{
			EventType:   et,
			DstIP:       "104.16.1.1",
			DstHostname: "allowed.example", // the edge's allowed origin
			L7Name:      "",                // ECH: no cleartext SNI recovered
		}
		require.Equal(t, "104.16.1.1", ev.ReportedDestName(),
			"%s with no recovered name must report the IP, not the allowed origin", et)

		// With a name recovered, that name is the reported identity.
		ev.L7Name = "evil.example"
		require.Equal(t, "evil.example", ev.ReportedDestName())
	}

	// Non-L7 events keep the hostname fallback.
	ev := &AuditEvent{EventType: EventConnectionBlocked, DstIP: "104.16.1.1", DstHostname: "allowed.example"}
	require.Equal(t, "allowed.example", ev.ReportedDestName())
}
