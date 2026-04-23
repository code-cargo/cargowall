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
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

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
			action, _, _ := cm.MatchHostnameRule(tt.dnsHostname)

			if tt.expectedAction != "" && action != tt.expectedAction {
				t.Errorf("MatchHostnameRule(%s) = %s, want %s",
					tt.dnsHostname, action, tt.expectedAction)
			}

			// Test if rule would be added to map
			if action != "" {
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
			hostnameAction, _, _ := cm.MatchHostnameRule(tt.dnsHostname)
			if hostnameAction == "" {
				t.Fatalf("Hostname %s not tracked", tt.dnsHostname)
			}

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

// --- reverseDNSAttempted tests (issue #5) ---

func TestReverseDNSAttempted(t *testing.T) {
	// Reset global cache
	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	// First lookup returns false (not yet attempted)
	assert.False(t, reverseDNSAttempted("10.0.0.1"))

	// Second lookup returns true (already attempted)
	assert.True(t, reverseDNSAttempted("10.0.0.1"))

	// Different IP returns false
	assert.False(t, reverseDNSAttempted("10.0.0.2"))
}

func TestReverseDNSAttempted_Eviction(t *testing.T) {
	// Reset global cache
	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	// Fill cache to max
	for i := range reverseDNSCacheMax {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		reverseDNSAttempted(ip)
	}

	reverseDNSMu.Lock()
	assert.Equal(t, reverseDNSCacheMax, len(reverseDNSCache))
	reverseDNSMu.Unlock()

	// Adding one more should evict the oldest and keep size at max
	assert.False(t, reverseDNSAttempted("172.16.0.1"))

	reverseDNSMu.Lock()
	assert.Equal(t, reverseDNSCacheMax, len(reverseDNSCache))
	reverseDNSMu.Unlock()
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

// --- processEvent tests (issue #8) ---

// mockFirewallUpdater records AddIP calls for testing.
type mockFirewallUpdater struct {
	addedIPs []mockAddIPCall
}

type mockAddIPCall struct {
	ip     net.IP
	action config.Action
	ports  []config.Port
}

func (m *mockFirewallUpdater) AddIP(ip net.IP, action config.Action, ports []config.Port) (bool, error) {
	m.addedIPs = append(m.addedIPs, mockAddIPCall{ip: ip, action: action, ports: ports})
	return true, nil
}

// makeBpfEvent serialises a BpfBlockedEvent into a byte slice suitable for
// processEvent. Uses binary.Write with NativeEndian to mirror the unsafe-
// pointer cast in processEvent, so the encoding stays in lockstep with the
// struct layout — adding a field to BpfBlockedEvent here doesn't require
// updating hand-written byte offsets.
func makeBpfEvent(event BpfBlockedEvent) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, int(unsafe.Sizeof(event))))
	if err := binary.Write(buf, binary.NativeEndian, &event); err != nil {
		panic(fmt.Sprintf("makeBpfEvent: binary.Write failed: %v", err))
	}
	return buf.Bytes()
}

// ipv4ToUint32 converts an IPv4 string to the big-endian uint32 representation
// used by BpfBlockedEvent (matching the shift logic in processEvent).
func ipv4ToUint32(ip string) uint32 {
	parts := net.ParseIP(ip).To4()
	return uint32(parts[0])<<24 | uint32(parts[1])<<16 | uint32(parts[2])<<8 | uint32(parts[3])
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProcessEvent_IPv4BlockedTCP(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	smClient := &mockStateMachineClient{}
	tracker := NewNotificationTracker(smClient, newTestLogger())
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	// Reset reverse DNS cache to avoid cross-test pollution
	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, tracker, auditLogger, nil, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType)
	assert.Equal(t, "93.184.216.34", events[0].DstIP)
	assert.Equal(t, uint16(443), events[0].DstPort)
	assert.True(t, events[0].Blocked)

	// Notification should have been sent
	assert.Len(t, smClient.calls, 1)
}

func TestProcessEvent_IPv4AllowedTCP(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionAllow))

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   1,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, nil, auditLogger, nil, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionAllowed, events[0].EventType)
}

func TestProcessEvent_ProtocolBlocked(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	smClient := &mockStateMachineClient{}
	tracker := NewNotificationTracker(smClient, newTestLogger())
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	// Protocol block: SrcPort=0, DstPort < 256 (protocol number)
	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_ICMP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("10.0.0.2"),
		SrcPort:   0,
		DstPort:   1, // ICMP
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, tracker, auditLogger, nil, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventProtocolBlocked, events[0].EventType)
	assert.Equal(t, "ICMP", events[0].Protocol)
}

func TestProcessEvent_LateResolvedIPAddedToFirewall(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow},
	}, config.ActionDeny))

	// Pre-populate the DNS mapping so LookupHostnameByIP finds it
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, nil, nil, fw, newTestLogger())

	require.Len(t, fw.addedIPs, 1)
	assert.Equal(t, config.ActionAllow, fw.addedIPs[0].action)
	assert.Equal(t, "93.184.216.34", fw.addedIPs[0].ip.String())
}

// TestProcessEvent_LateResolvedIPInheritsRulePorts is the regression test for
// the nil-ports security bug: when a port-scoped allow rule matches, the late-
// add path must pass those ports to the firewall (not nil, which the BPF
// program would interpret as allow-on-all-ports).
func TestProcessEvent_LateResolvedIPInheritsRulePorts(t *testing.T) {
	wantPorts := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "*.compute-1.amazonaws.com", Ports: wantPorts, Action: config.ActionAllow},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("ec2-1-2-3-4.compute-1.amazonaws.com", "1.2.3.4")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("1.2.3.4"),
		SrcPort:   54321,
		DstPort:   22, // attacker hits a non-allowed port; allow rule is for :443
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, nil, nil, fw, newTestLogger())

	require.Len(t, fw.addedIPs, 1)
	assert.Equal(t, config.ActionAllow, fw.addedIPs[0].action)
	assert.Equal(t, "1.2.3.4", fw.addedIPs[0].ip.String())
	assert.Equal(t, wantPorts, fw.addedIPs[0].ports)
}

// IPv6 sibling of TestProcessEvent_LateResolvedIPInheritsRulePorts. The v6
// AddIP path is mirrored from v4 but wasn't exercised end-to-end through
// the late-add flow — this locks down the protocol matrix.
func TestProcessEvent_LateResolvedIPv6InheritsRulePorts(t *testing.T) {
	wantPorts := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "*.example.com", Ports: wantPorts, Action: config.ActionAllow},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("api.example.com", "2001:db8::1")

	fw := &mockFirewallUpdater{}

	dstIPv6 := net.ParseIP("2001:db8::1")
	var dstIp6 [16]byte
	copy(dstIp6[:], dstIPv6.To16())

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 6,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		DstIp6:    dstIp6,
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, nil, nil, fw, newTestLogger())

	require.Len(t, fw.addedIPs, 1)
	assert.Equal(t, config.ActionAllow, fw.addedIPs[0].action)
	assert.Equal(t, "2001:db8::1", fw.addedIPs[0].ip.String())
	assert.Equal(t, wantPorts, fw.addedIPs[0].ports)
}

// TestProcessEvent_LateResolvedEmitsLateAllowedAudit verifies the audit-log
// fidelity fix: when the late-add succeeds, the triggering connection is logged
// as connection_late_allowed (with matched_rule), not connection_blocked, and
// the user is not notified that something was blocked.
func TestProcessEvent_LateResolvedEmitsLateAllowedAudit(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	smClient := &mockStateMachineClient{}
	tracker := NewNotificationTracker(smClient, newTestLogger())

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, tracker, auditLogger, fw, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionLateAllowed, events[0].EventType,
		"late-resolved blocked event must be logged as late-allowed, not blocked")
	// Exact-match rule case: MatchedRule and DstHostname coincide. The
	// pattern-rule case where they diverge is covered by
	// TestProcessEvent_LateResolvedMatchedRuleIsRulePatternNotHostname.
	assert.Equal(t, "example.com", events[0].MatchedRule)
	assert.Equal(t, "example.com", events[0].DstHostname)
	assert.False(t, events[0].Blocked)
	assert.False(t, events[0].WouldDeny)
	assert.Equal(t, "93.184.216.34", events[0].DstIP)
	assert.Equal(t, uint16(443), events[0].DstPort)

	// User-facing notification must be suppressed — the connection will succeed
	// on retry, so notifying the user that something was blocked would mislead.
	assert.Empty(t, smClient.calls, "no block notification should fire when late-allowed")
}

// Pattern and parent-domain rules don't have an identifier identical to the
// resolved destination. MatchedRule must report the rule that fired
// (`*.compute-1.amazonaws.com`), not the resolved subdomain — otherwise the
// audit log misrepresents which policy authorised the connection.
func TestProcessEvent_LateResolvedMatchedRuleIsRulePatternNotHostname(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "*.compute-1.amazonaws.com",
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow,
		},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("ec2-1-2-3-4.compute-1.amazonaws.com", "1.2.3.4")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("1.2.3.4"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, nil, auditLogger, fw, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionLateAllowed, events[0].EventType)
	assert.Equal(t, "ec2-1-2-3-4.compute-1.amazonaws.com", events[0].DstHostname,
		"DstHostname is the resolved destination")
	assert.Equal(t, "*.compute-1.amazonaws.com", events[0].MatchedRule,
		"MatchedRule must be the rule pattern, not the resolved subdomain")
}

// TestProcessEvent_BlockedNoMatchStillLogsBlocked makes sure the late-allowed
// branch only fires when there's a matching allow rule. Without one, the
// blocked event must continue to log connection_blocked and notify.
func TestProcessEvent_BlockedNoMatchStillLogsBlocked(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	smClient := &mockStateMachineClient{}
	tracker := NewNotificationTracker(smClient, newTestLogger())

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("not-allowed.example.org", "93.184.216.34")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, tracker, auditLogger, fw, newTestLogger())

	require.Empty(t, fw.addedIPs, "late-add must not fire when no allow rule matches")

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType)
	assert.True(t, events[0].Blocked)
	assert.Len(t, smClient.calls, 1, "notification must fire for genuine blocks")
}

// TestProcessEvent_LateResolvedDstPortNotInRulePortsStaysBlocked guards against
// a subtle bug: when the IP's hostname matches an allow rule but the event's
// dst_port is NOT in the rule's allow set, the retry will still be blocked,
// so we must report the event as blocked (not late-allowed) and notify.
//
// Concretely: rule allows port 443/tcp; attacker hits port 22; the late-add
// path opens nothing useful for port 22, so audit/notification must reflect
// the genuine block.
func TestProcessEvent_LateResolvedDstPortNotInRulePortsStaysBlocked(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	smClient := &mockStateMachineClient{}
	tracker := NewNotificationTracker(smClient, newTestLogger())

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "*.compute-1.amazonaws.com",
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow,
		},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("ec2-1-2-3-4.compute-1.amazonaws.com", "1.2.3.4")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("1.2.3.4"),
		SrcPort:   54321,
		DstPort:   22, // attacker hits non-allowed port
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, tracker, auditLogger, fw, newTestLogger())

	// AddIP still fires (so future port-443 retries succeed), but this
	// connection's audit/notification must reflect the genuine block.
	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType,
		"port not in rule ports must stay blocked, not late-allowed")
	assert.True(t, events[0].Blocked)
	assert.Len(t, smClient.calls, 1, "notification must fire for genuine blocks")
}

// A UDP event for the same port the rule allows over TCP must NOT be reported
// as late-allowed — the BPF retry on UDP would still be blocked because the
// port map is keyed by (ip, port, proto).
func TestProcessEvent_LateResolvedUDPEventNotAllowedByTCPRule(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	smClient := &mockStateMachineClient{}
	tracker := NewNotificationTracker(smClient, newTestLogger())

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "example.com",
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow,
		},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_UDP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, tracker, auditLogger, fw, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType,
		"UDP event must not be late-allowed against a TCP-only rule")
	assert.True(t, events[0].Blocked)
	assert.Len(t, smClient.calls, 1, "notification must fire when the protocol mismatch leaves the connection blocked")
}

// A TCP event for a port the rule allows over TCP must be reported as
// late-allowed — symmetric counterpart to the UDP test above.
func TestProcessEvent_LateResolvedTCPEventAllowedByTCPRule(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	smClient := &mockStateMachineClient{}
	tracker := NewNotificationTracker(smClient, newTestLogger())

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "example.com",
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow,
		},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, tracker, auditLogger, fw, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionLateAllowed, events[0].EventType,
		"TCP event matching a TCP rule must be late-allowed")
	assert.Empty(t, smClient.calls, "no block notification when late-allowed")
}

// ProtocolAll on a rule must overlap with any specific event protocol.
func TestProcessEvent_LateResolvedTCPEventAllowedByProtocolAllRule(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	smClient := &mockStateMachineClient{}
	tracker := NewNotificationTracker(smClient, newTestLogger())

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "example.com",
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolAll}}, Action: config.ActionAllow,
		},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, tracker, auditLogger, fw, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionLateAllowed, events[0].EventType,
		"ProtocolAll rule must overlap with TCP event")
	assert.Empty(t, smClient.calls, "no block notification when late-allowed")
}

func TestProcessEvent_IPv6Event(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	srcIPv6 := net.ParseIP("2001:db8::1")
	dstIPv6 := net.ParseIP("2001:db8::2")
	var srcIp6, dstIp6 [16]byte
	copy(srcIp6[:], srcIPv6.To16())
	copy(dstIp6[:], dstIPv6.To16())

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 6,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp6:    srcIp6,
		DstIp6:    dstIp6,
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, nil, auditLogger, nil, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType)
	assert.Equal(t, "2001:db8::2", events[0].DstIP)
}

func TestProcessEvent_TooShortBuffer(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	// Should not panic — processEvent should return early for short buffers
	processEvent([]byte{0x04}, cm, nil, nil, nil, newTestLogger())
}

func TestProcessEvent_AutoAllowedType(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))
	// Add a DNS auto-allow rule for 8.8.8.8:53
	cm.EnsureDNSAllowed([]string{"8.8.8.8"})

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   1,
		IpProto:   unix.IPPROTO_UDP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("8.8.8.8"),
		SrcPort:   54321,
		DstPort:   53,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, nil, auditLogger, nil, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionAllowed, events[0].EventType)
	assert.Equal(t, "dns", events[0].AutoAllowedType)
	// Regression: an allowed UDP event must record Protocol="UDP" so the
	// summary dedup key buckets it correctly. Pre-fix this read "TCP".
	assert.Equal(t, "UDP", events[0].Protocol)
}

func TestProcessEvent_NoAutoAllowedTypeForUserRule(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "93.184.216.0/24", Action: config.ActionAllow},
	}, config.ActionDeny))

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   1,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSMu.Unlock()

	processEvent(raw, cm, nil, auditLogger, nil, newTestLogger())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionAllowed, events[0].EventType)
	assert.Empty(t, events[0].AutoAllowedType, "user-configured rules should not have auto_allowed_type")
}
