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
//
// Caveat: binary.Write emits struct fields back-to-back with no implicit
// alignment padding. That matches the in-memory layout only when the struct
// has no implicit padding — currently guaranteed because every field is
// naturally aligned (the trailing StepOrdinal fills what was once explicit
// padding). makeBpfEventCompileCheck below
// asserts this invariant so a future field addition that introduces implicit
// padding fails loudly instead of silently producing the wrong bytes.
func makeBpfEvent(event BpfBlockedEvent) []byte {
	if binary.Size(&event) != int(unsafe.Sizeof(event)) {
		panic(fmt.Sprintf(
			"makeBpfEvent: BpfBlockedEvent has implicit padding (binary.Size=%d, unsafe.Sizeof=%d) — add an explicit pad field or switch this helper to an unsafe memcpy",
			binary.Size(&event), unsafe.Sizeof(event),
		))
	}
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
	reverseDNS.reset()

	processEvent(raw, cm, tracker, auditLogger, nil, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, nil, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, tracker, auditLogger, nil, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, nil, nil, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, nil, nil, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, nil, nil, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, tracker, auditLogger, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, tracker, auditLogger, fw, nil, newTestLogger(), nil)

	require.Empty(t, fw.addedIPs, "late-add must not fire when no allow rule matches")

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType)
	assert.True(t, events[0].Blocked)
	assert.Len(t, smClient.calls, 1, "notification must fire for genuine blocks")
}

// TestProcessEvent_CNAMEDerivedAttributesToOrigin covers the reporting fix for
// transparent CNAME support: a connection to a CNAME target's IP (the IP maps
// to the opaque edge name) must be reported under the origin hostname the user
// allowed, with the full chain surfaced as the cname_chain drill-down field.
func TestProcessEvent_CNAMEDerivedAttributesToOrigin(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "www.microsoft.com", Action: config.ActionAllow},
	}, config.ActionDeny))

	// The derived edge IP maps to the CNAME target (what LookupHostnameByIP
	// returns today), and the derived-allow enforcement recorded its chain.
	const edge = "e13678.dscb.akamaiedge.net"
	chain := []string{"www.microsoft.com", edge}
	cm.UpdateDNSMapping(edge, "23.62.177.200")
	cm.RecordCNAMEChain("23.62.177.200", chain, time.Hour)

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   1,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("23.62.177.200"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, nil, nil, newTestLogger(), nil)

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionAllowed, events[0].EventType)
	assert.Equal(t, "www.microsoft.com", events[0].DstHostname,
		"event must be attributed to the origin the user allowed, not the CNAME edge")
	assert.Equal(t, chain, events[0].CNAMEChain,
		"the full CNAME chain must be surfaced as the drill-down field")
}

// TestProcessEvent_CNAMEDerivedBlockedAttributesToOrigin checks the same
// origin attribution + chain surfacing on the blocked path: a derived edge IP
// hit on a port outside the origin rule's allow set (here the rule allows only
// :443, the connection hits :8080) must stay blocked AND report under the
// origin — the swap runs before the late-allow check so the origin's rule is
// the one consulted.
func TestProcessEvent_CNAMEDerivedBlockedAttributesToOrigin(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "www.microsoft.com",
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow,
		},
	}, config.ActionDeny))

	const edge = "e13678.dscb.akamaiedge.net"
	chain := []string{"www.microsoft.com", edge}
	cm.UpdateDNSMapping(edge, "23.62.177.200")
	cm.RecordCNAMEChain("23.62.177.200", chain, time.Hour)

	fw := &mockFirewallUpdater{}

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("23.62.177.200"),
		SrcPort:   54321,
		DstPort:   8080, // outside the origin rule's :443 allow set
	})

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, fw, nil, newTestLogger(), nil)

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType,
		":8080 is outside the origin rule's :443 allow set, so it stays blocked")
	assert.Equal(t, "www.microsoft.com", events[0].DstHostname)
	assert.Equal(t, chain, events[0].CNAMEChain)
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

	reverseDNS.reset()

	processEvent(raw, cm, tracker, auditLogger, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, tracker, auditLogger, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, tracker, auditLogger, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, tracker, auditLogger, fw, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, nil, nil, newTestLogger(), nil)

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType)
	assert.Equal(t, "2001:db8::2", events[0].DstIP)
}

func TestProcessEvent_TooShortBuffer(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	// Should not panic — processEvent should return early for short buffers
	processEvent([]byte{0x04}, cm, nil, nil, nil, nil, newTestLogger(), nil)
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

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, nil, nil, newTestLogger(), nil)

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

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, nil, nil, newTestLogger(), nil)

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionAllowed, events[0].EventType)
	assert.Empty(t, events[0].AutoAllowedType, "user-configured rules should not have auto_allowed_type")
}

// A mid-stream drop (non-SYN TCP segment of an established connection killed
// by attach) must surface as a normal connection_blocked audit event with the
// MidStream marker, so it is visible to operators and flows into RecentBlocks.
func TestProcessEvent_MidStreamBlocked(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	raw := makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4,
		Allowed:   0,
		IpProto:   unix.IPPROTO_TCP,
		Flags:     BpfEventFlagMidstream,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, nil, nil, newTestLogger(), nil)

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType)
	assert.True(t, events[0].MidStream)
	assert.Equal(t, "93.184.216.34", events[0].DstIP)
	assert.Equal(t, uint16(443), events[0].DstPort)
	assert.True(t, events[0].Blocked)
}

// The in-band late-allow path must also fire for mid-stream drops: when the
// killed connection's IP maps to an allowed hostname, the firewall re-opens
// and retransmits survive.
func TestProcessEvent_MidStreamLateAllowFires(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()

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
		Flags:     BpfEventFlagMidstream,
		SrcIp:     ipv4ToUint32("10.0.0.1"),
		DstIp:     ipv4ToUint32("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	})

	reverseDNS.reset()

	processEvent(raw, cm, nil, auditLogger, fw, nil, newTestLogger(), nil)

	require.Len(t, fw.addedIPs, 1)
	assert.Equal(t, config.ActionAllow, fw.addedIPs[0].action)
	assert.Equal(t, "93.184.216.34", fw.addedIPs[0].ip.String())

	events := readAuditEvents(t, auditPath)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionLateAllowed, events[0].EventType)
}
