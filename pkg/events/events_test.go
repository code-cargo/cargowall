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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

// verdictPrimaryAction flattens a HostnameVerdict into a single Action for
// tests that were written before mixed verdicts existed. Returns the deny
// side if present (more restrictive wins for back-compat assertion shape),
// else the allow side, else "" for no-match.
func verdictPrimaryAction(v config.HostnameVerdict) config.Action {
	switch {
	case v.HasDeny():
		return config.ActionDeny
	case v.HasAllow():
		return config.ActionAllow
	default:
		return ""
	}
}

// TestSubdomainHandling exercises config.Manager subdomain matching logic
// from the events package perspective. The core logic under test lives in pkg/config.
func TestSubdomainHandling(t *testing.T) {
	tests := []struct {
		name             string
		defaultAction    config.Action
		rules            []config.Rule
		dnsHostname      string
		expectedAddToMap bool
		expectedAction   config.Action
		description      string
	}{
		{
			name:          "subdomain_blocked_with_default_allow",
			defaultAction: config.ActionAllow,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "google.com", Action: config.ActionDeny},
			},
			dnsHostname:      "www.google.com",
			expectedAddToMap: true,
			expectedAction:   config.ActionDeny,
			description:      "With default allow, subdomain www.google.com should be explicitly denied",
		},
		{
			name:          "subdomain_blocked_with_default_deny",
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "google.com", Action: config.ActionDeny},
			},
			dnsHostname:      "www.google.com",
			expectedAddToMap: false,
			expectedAction:   config.ActionDeny,
			description:      "With default deny, subdomain www.google.com doesn't need explicit deny rule",
		},
		{
			name:          "subdomain_allowed_with_default_deny",
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "google.com", Action: config.ActionAllow},
			},
			dnsHostname:      "www.google.com",
			expectedAddToMap: true,
			expectedAction:   config.ActionAllow,
			description:      "With default deny, subdomain www.google.com needs explicit allow rule",
		},
		{
			name:          "subdomain_allowed_with_default_allow",
			defaultAction: config.ActionAllow,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "google.com", Action: config.ActionAllow},
			},
			dnsHostname:      "www.google.com",
			expectedAddToMap: false,
			expectedAction:   config.ActionAllow,
			description:      "With default allow, subdomain www.google.com doesn't need explicit allow rule",
		},
		{
			name:          "exact_match_deny_with_default_allow",
			defaultAction: config.ActionAllow,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "google.com", Action: config.ActionDeny},
			},
			dnsHostname:      "google.com",
			expectedAddToMap: true,
			expectedAction:   config.ActionDeny,
			description:      "Exact match with different action than default should be added",
		},
		{
			name:          "no_match_with_default_deny",
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "google.com", Action: config.ActionAllow},
			},
			dnsHostname:      "example.com",
			expectedAddToMap: false,
			expectedAction:   "",
			description:      "Untracked hostname with default deny should not be added",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config manager
			cm := config.NewConfigManager()
			err := cm.LoadConfigFromRules(tt.rules, tt.defaultAction)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Test MatchHostnameRule
			v := cm.MatchHostnameRule(tt.dnsHostname)
			action := verdictPrimaryAction(v)

			if tt.expectedAction != "" && action != tt.expectedAction {
				t.Errorf("MatchHostnameRule(%s) = %s, want %s",
					tt.dnsHostname, action, tt.expectedAction)
			}

			// Test if rule would be added to map
			if v.Matched() {
				defaultAction := cm.GetDefaultAction()
				shouldAdd := action != defaultAction

				if shouldAdd != tt.expectedAddToMap {
					t.Errorf("%s: shouldAdd = %v, want %v (action=%s, default=%s)",
						tt.description, shouldAdd, tt.expectedAddToMap, action, defaultAction)
				}
			} else if tt.expectedAddToMap {
				t.Errorf("%s: expected hostname to be tracked but it wasn't", tt.description)
			}
		})
	}
}

// TestConflictHandling exercises config.Manager IP/CIDR conflict detection logic
// from the events package perspective. The core logic under test lives in pkg/config.
func TestConflictHandling(t *testing.T) {
	tests := []struct {
		name             string
		defaultAction    config.Action
		rules            []config.Rule
		dnsHostname      string
		dnsIP            string
		expectedAddToMap bool
		expectedAction   config.Action
		expectConflict   bool
		description      string
	}{
		{
			name:          "hostname_allow_vs_cidr_deny_default_allow",
			defaultAction: config.ActionAllow,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "google.com", Action: config.ActionAllow},
				{Type: config.RuleTypeCIDR, Value: "192.168.1.0/24", Action: config.ActionDeny},
			},
			dnsHostname:      "google.com",
			dnsIP:            "192.168.1.100",
			expectedAddToMap: true,
			expectedAction:   config.ActionDeny, // Most restrictive wins
			expectConflict:   true,
			description:      "Conflict between hostname allow and CIDR deny, deny should win",
		},
		{
			name:          "hostname_deny_vs_cidr_allow_default_deny",
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "safe.com", Action: config.ActionDeny},
				{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8", Action: config.ActionAllow},
			},
			dnsHostname:      "safe.com",
			dnsIP:            "10.0.0.50",
			expectedAddToMap: false,             // deny matches default
			expectedAction:   config.ActionDeny, // Most restrictive wins
			expectConflict:   true,
			description:      "Conflict with deny winning, but matches default so not added",
		},
		{
			name:          "hostname_allow_vs_cidr_deny_with_ports",
			defaultAction: config.ActionAllow,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "app.com", Action: config.ActionAllow, Ports: []config.Port{{Port: 443, Protocol: config.ProtocolAll}}},
				{Type: config.RuleTypeCIDR, Value: "172.16.0.0/16", Action: config.ActionDeny, Ports: []config.Port{{Port: 80, Protocol: config.ProtocolAll}}},
			},
			dnsHostname:      "app.com",
			dnsIP:            "172.16.0.100",
			expectedAddToMap: false, // No port overlap, no conflict
			expectedAction:   config.ActionAllow,
			expectConflict:   false,
			description:      "No conflict when ports don't overlap",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config manager
			cm := config.NewConfigManager()
			err := cm.LoadConfigFromRules(tt.rules, tt.defaultAction)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Test conflict detection
			v := cm.MatchHostnameRule(tt.dnsHostname)
			if !v.Matched() {
				t.Fatalf("Hostname %s not tracked", tt.dnsHostname)
			}
			hostnameAction := verdictPrimaryAction(v)

			// Get ports for hostname rule
			var hostnamePorts []config.Port
			for _, rule := range cm.GetResolvedRules() {
				if rule.Type == config.RuleTypeHostname && rule.Value == tt.dnsHostname {
					hostnamePorts = rule.Ports
					break
				}
			}

			// Check IP conflict
			ip := net.ParseIP(tt.dnsIP)
			finalAction, hasConflict, _ := cm.CheckIPRuleConflict(ip, tt.dnsHostname, hostnameAction, hostnamePorts)

			if hasConflict != tt.expectConflict {
				t.Errorf("%s: hasConflict = %v, want %v",
					tt.description, hasConflict, tt.expectConflict)
			}

			if finalAction != tt.expectedAction {
				t.Errorf("%s: finalAction = %s, want %s",
					tt.description, finalAction, tt.expectedAction)
			}

			// Check if it would be added to map
			defaultAction := cm.GetDefaultAction()
			shouldAdd := finalAction != defaultAction

			if shouldAdd != tt.expectedAddToMap {
				t.Errorf("%s: shouldAdd = %v, want %v (finalAction=%s, default=%s)",
					tt.description, shouldAdd, tt.expectedAddToMap, finalAction, defaultAction)
			}
		})
	}
}

func TestGetProtocolName(t *testing.T) {
	tests := []struct {
		proto    uint8
		expected string
	}{
		{1, "ICMP"},
		{2, "IGMP"},
		{6, "TCP"},
		{17, "UDP"},
		{41, "IPv6-in-IPv4"},
		{47, "GRE"},
		{50, "ESP"},
		{51, "AH"},
		{58, "ICMPv6"},
		{89, "OSPF"},
		{103, "PIM"},
		{132, "SCTP"},
		{255, "Protocol-255"},
		{99, "Protocol-99"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, getProtocolName(tt.proto))
		})
	}
}

// --- NotificationTracker tests (issue #6) ---

type mockStateMachineClient struct {
	calls []mockSMCall
	err   error // if set, SendCargoWallBlockNotification returns this
}

type mockSMCall struct {
	hostname string
	ip       string
	port     uint32
}

func (m *mockStateMachineClient) SendCargoWallBlockNotification(_ context.Context, hostname, ip string, port uint32) error {
	m.calls = append(m.calls, mockSMCall{hostname: hostname, ip: ip, port: port})
	return m.err
}

func TestNotificationTracker_SendNotification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("first_call_sends_notification", func(t *testing.T) {
		client := &mockStateMachineClient{}
		tracker := NewNotificationTracker(client, logger)

		tracker.SendNotification("example.com", "1.2.3.4", 443)
		require.Len(t, client.calls, 1)
		assert.Equal(t, "example.com", client.calls[0].hostname)
		assert.Equal(t, "1.2.3.4", client.calls[0].ip)
		assert.Equal(t, uint32(443), client.calls[0].port)
	})

	t.Run("duplicate_is_deduped", func(t *testing.T) {
		client := &mockStateMachineClient{}
		tracker := NewNotificationTracker(client, logger)

		tracker.SendNotification("example.com", "1.2.3.4", 443)
		tracker.SendNotification("example.com", "1.2.3.4", 443)
		assert.Len(t, client.calls, 1)
	})

	t.Run("different_destination_sends", func(t *testing.T) {
		client := &mockStateMachineClient{}
		tracker := NewNotificationTracker(client, logger)

		tracker.SendNotification("example.com", "1.2.3.4", 443)
		tracker.SendNotification("other.com", "5.6.7.8", 80)
		assert.Len(t, client.calls, 2)
	})

	t.Run("error_allows_retry", func(t *testing.T) {
		client := &mockStateMachineClient{err: fmt.Errorf("connection refused")}
		tracker := NewNotificationTracker(client, logger)

		// First call fails
		tracker.SendNotification("example.com", "1.2.3.4", 443)
		assert.Len(t, client.calls, 1)

		// Entry was removed from map on error, so retry succeeds
		client.err = nil
		tracker.SendNotification("example.com", "1.2.3.4", 443)
		assert.Len(t, client.calls, 2)
	})

	t.Run("empty_hostname_uses_ip_as_key", func(t *testing.T) {
		client := &mockStateMachineClient{}
		tracker := NewNotificationTracker(client, logger)

		tracker.SendNotification("", "1.2.3.4", 443)
		require.Len(t, client.calls, 1)
		assert.Equal(t, "", client.calls[0].hostname)
		assert.Equal(t, "1.2.3.4", client.calls[0].ip)

		// Same IP+port should be deduped
		tracker.SendNotification("", "1.2.3.4", 443)
		assert.Len(t, client.calls, 1)
	})
}

// --- lookupProcessName tests (issue #7) ---

func TestLookupProcessName_ZeroPID(t *testing.T) {
	assert.Equal(t, "", lookupProcessName(0))
}

// --- IsProtocolBlock tests (issue #106 phase 3a) ---

func TestBpfBlockedEvent_IsProtocolBlock(t *testing.T) {
	tests := []struct {
		name     string
		event    BpfBlockedEvent
		expected bool
	}{
		// The canonical shape: blocked, no source port, dst_port carries the
		// L4 protocol number instead of a real port.
		{"icmp_protocol_block", BpfBlockedEvent{Allowed: 0, SrcPort: 0, DstPort: 1}, true},
		// The boundary is DstPort < 256 (protocol numbers are one byte):
		// 255 is still a protocol number, 256 is a real port.
		{"proto_255_still_protocol", BpfBlockedEvent{Allowed: 0, SrcPort: 0, DstPort: 255}, true},
		{"port_256_is_connection", BpfBlockedEvent{Allowed: 0, SrcPort: 0, DstPort: 256}, false},
		// Protocol number 0 (HOPOPT) satisfies the encoding too.
		{"proto_zero", BpfBlockedEvent{}, true},
		// Allowed traffic is never a protocol block regardless of shape.
		{"allowed_low_dst_port", BpfBlockedEvent{Allowed: 1, SrcPort: 0, DstPort: 1}, false},
		// A source port means a real connection tuple, even to a low port.
		{"src_port_set_low_dst", BpfBlockedEvent{Allowed: 0, SrcPort: 54321, DstPort: 80}, false},
		{"blocked_tcp_syn", BpfBlockedEvent{Allowed: 0, SrcPort: 54321, DstPort: 443}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.event.IsProtocolBlock())
		})
	}
}

// --- ContainerEnricher tests (issue #106 phase 3a) ---

// fakeEnricher counts Enrich calls and stamps recognizable attribution onto
// the audit base, so tests can verify the mutation flows through to the
// event each outcome branch logs.
type fakeEnricher struct {
	calls int
}

func (f *fakeEnricher) Enrich(audit *AuditEvent, _ *BpfBlockedEvent) {
	f.calls++
	audit.StepOrdinal = 9
	audit.ContainerOrigin = true
	audit.ContainerID = "abc123def456"
}

// orphanEvent returns the no-socket-at-TC signature (pid 0, ordinal 0) that
// gates enrichment; callers override the verdict/tuple fields per branch.
func orphanEvent() BpfBlockedEvent {
	return BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
		// Pid and StepOrdinal stay 0: the NATed-container-flow signature.
	}
}

func TestProcessEvent_EnricherRunsForOrphanBlockedEvent(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	enr := &fakeEnricher{}
	raw := makeBpfEvent(orphanEvent())

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, nil, nil, newTestLogger(), enr)

	assert.Equal(t, 1, enr.calls, "orphan event (pid=0, ordinal=0) must be enriched exactly once")

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType)
	// The enricher's mutations must land on the logged event: enrichment
	// runs on the shared audit base before the outcome branches stamp their
	// event type.
	assert.Equal(t, uint32(9), events[0].StepOrdinal)
	assert.True(t, events[0].ContainerOrigin)
	assert.Equal(t, "abc123def456", events[0].ContainerID)
}

// identityEnricher rewrites the full identity, like the real container
// enricher does when an origin record resolves.
type identityEnricher struct{}

func (identityEnricher) Enrich(audit *AuditEvent, _ *BpfBlockedEvent) {
	audit.PID = 4242
	audit.Process = "containerproc"
	audit.StepOrdinal = 9
	audit.ContainerOrigin = true
	audit.ContainerID = "abc123def456"
}

// The daemon log line and the audit record must observe ONE identity: both
// are derived from the shared audit base AFTER enrichment. Pins the fix for
// the dual-identity bug where log lines kept the pre-enrich pid=0/process=""
// locals while the audit stream carried the enriched values.
func TestProcessEvent_LogLineObservesEnrichedIdentity(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	reverseDNS.reset()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	raw := makeBpfEvent(orphanEvent())
	processEvent(raw, cm, nil, nil, nil, nil, logger, identityEnricher{})

	out := logBuf.String()
	assert.Contains(t, out, "Connection blocked")
	assert.Contains(t, out, "process=containerproc")
	assert.Contains(t, out, "pid=4242")
	assert.Contains(t, out, "step_ordinal=9")
	assert.Contains(t, out, "container_origin=true")
	assert.Contains(t, out, "container_id=abc123def456")
	assert.NotContains(t, out, "pid=0", "the pre-enrich identity must not leak into any log attribute")
}

// The allowed branch logs from the same enriched base — locks in that
// enrichment happens before the verdict fan-out, not inside one branch.
func TestProcessEvent_EnricherRunsForOrphanAllowedEvent(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionAllow))

	enr := &fakeEnricher{}
	ev := orphanEvent()
	ev.Allowed = 1
	raw := makeBpfEvent(ev)

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, nil, nil, newTestLogger(), enr)

	assert.Equal(t, 1, enr.calls)

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionAllowed, events[0].EventType)
	assert.Equal(t, uint32(9), events[0].StepOrdinal)
	assert.True(t, events[0].ContainerOrigin)
	assert.Equal(t, "abc123def456", events[0].ContainerID)
}

func TestProcessEvent_EnricherSkippedWhenAttributed(t *testing.T) {
	// Either identity field set means the TC hook saw the socket and
	// attribution already happened; the enricher must not second-guess it.
	tests := []struct {
		name    string
		pid     uint32
		ordinal uint32
	}{
		{"pid_set", 1234, 0},
		{"ordinal_set", 0, 5},
		{"both_set", 1234, 5},
	}

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enr := &fakeEnricher{}
			ev := orphanEvent()
			ev.Pid = tt.pid
			ev.StepOrdinal = tt.ordinal
			raw := makeBpfEvent(ev)

			reverseDNS.reset()

			processEvent(raw, cm, nil, nil, nil, nil, newTestLogger(), enr)

			assert.Zero(t, enr.calls, "attributed events must not be enriched")
		})
	}
}

func TestProcessEvent_NilEnricherOrphanEventNoPanic(t *testing.T) {
	// The daemon runs enricher-less when the containers watcher is absent
	// (docker not installed, watcher failed): the nil guard must hold on the
	// exact signature that would otherwise trigger enrichment.
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	reverseDNS.reset()

	processEvent(makeBpfEvent(orphanEvent()), cm, nil, nil, nil, nil, newTestLogger(), nil)
}
