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

package config

import (
	"net"
	"os"
	"reflect"
	"testing"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
)

func TestResolveRules_CIDR(t *testing.T) {
	tests := []struct {
		name     string
		config   FirewallConfig
		expected []struct {
			value     string
			prefixLen int
			hasIPNet  bool
			action    Action
		}
	}{
		{
			name: "basic CIDR blocks",
			config: FirewallConfig{
				Rules: []Rule{
					{Type: RuleTypeCIDR, Value: "192.168.1.0/24", Action: ActionAllow},
					{Type: RuleTypeCIDR, Value: "10.0.0.0/8", Action: ActionDeny},
					{Type: RuleTypeCIDR, Value: "172.16.0.0/16", Ports: []Port{{Port: 80, Protocol: ProtocolAll}, {Port: 443, Protocol: ProtocolAll}}, Action: ActionAllow},
				},
			},
			expected: []struct {
				value     string
				prefixLen int
				hasIPNet  bool
				action    Action
			}{
				{"192.168.1.0/24", 24, true, ActionAllow},
				{"10.0.0.0/8", 8, true, ActionDeny},
				{"172.16.0.0/16", 16, true, ActionAllow},
			},
		},
		{
			name: "single IP as CIDR",
			config: FirewallConfig{
				Rules: []Rule{
					{Type: RuleTypeCIDR, Value: "192.168.1.1", Action: ActionAllow},
					{Type: RuleTypeCIDR, Value: "10.0.0.1", Ports: []Port{{Port: 22, Protocol: ProtocolAll}}, Action: ActionDeny},
				},
			},
			expected: []struct {
				value     string
				prefixLen int
				hasIPNet  bool
				action    Action
			}{
				{"192.168.1.1", 32, true, ActionAllow},
				{"10.0.0.1", 32, true, ActionDeny},
			},
		},
		{
			name: "wildcard CIDR",
			config: FirewallConfig{
				Rules: []Rule{
					{Type: RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []Port{{Port: 80, Protocol: ProtocolAll}, {Port: 443, Protocol: ProtocolAll}}, Action: ActionAllow},
				},
			},
			expected: []struct {
				value     string
				prefixLen int
				hasIPNet  bool
				action    Action
			}{
				{"0.0.0.0/0", 0, true, ActionAllow},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewConfigManager()
			cm.config = &tt.config

			err := cm.resolveRules()
			if err != nil {
				t.Fatalf("resolveRules() error = %v", err)
			}

			if len(cm.resolvedRules) != len(tt.expected) {
				t.Fatalf("expected %d rules, got %d", len(tt.expected), len(cm.resolvedRules))
			}

			for i, rule := range cm.resolvedRules {
				expected := tt.expected[i]

				// Check Rule type
				if rule.Type != RuleTypeCIDR {
					t.Errorf("Rule[%d].Type = %v, want cidr", i, rule.Type)
				}

				// Check value
				if rule.Value != expected.value {
					t.Errorf("Rule[%d].Value = %v, want %v", i, rule.Value, expected.value)
				}

				// Check action
				if rule.Action != expected.action {
					t.Errorf("Rule[%d].Action = %v, want %v", i, rule.Action, expected.action)
				}

				// Check IPNet exists
				if expected.hasIPNet && rule.IPNet == nil {
					t.Errorf("Rule[%d].IPNet is nil, expected IPNet", i)
					continue
				}

				// Check prefix length
				if rule.IPNet != nil {
					ones, _ := rule.IPNet.Mask.Size()
					if ones != expected.prefixLen {
						t.Errorf("Rule[%d] prefix length = %d, want %d", i, ones, expected.prefixLen)
					}
				}

				// CIDR rules should not have IPs
				if len(rule.IPs) > 0 {
					t.Errorf("Rule[%d].IPs should be empty for CIDR rules, got %v", i, rule.IPs)
				}
			}
		})
	}
}

func TestResolveRules_Mixed(t *testing.T) {
	cm := NewConfigManager()
	cm.config = &FirewallConfig{
		Rules: []Rule{
			{Type: RuleTypeCIDR, Value: "192.168.0.0/16", Action: ActionAllow},
			{Type: RuleTypeHostname, Value: "localhost", Action: ActionAllow},
			{Type: RuleTypeCIDR, Value: "10.0.0.1", Ports: []Port{{Port: 22, Protocol: ProtocolAll}}, Action: ActionDeny},
		},
		DefaultAction: ActionDeny,
	}

	err := cm.resolveRules()
	if err != nil {
		t.Fatalf("resolveRules() error = %v", err)
	}

	if len(cm.resolvedRules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(cm.resolvedRules))
	}

	// Check first Rule (CIDR)
	if cm.resolvedRules[0].Type != RuleTypeCIDR {
		t.Errorf("Rule[0].Type = %v, want cidr", cm.resolvedRules[0].Type)
	}
	if cm.resolvedRules[0].IPNet == nil {
		t.Error("Rule[0].IPNet is nil")
	} else {
		ones, _ := cm.resolvedRules[0].IPNet.Mask.Size()
		if ones != 16 {
			t.Errorf("Rule[0] prefix length = %d, want 16", ones)
		}
	}

	// Check second Rule (hostname) - no longer resolves IPs during ResolveRules (JIT resolution)
	if cm.resolvedRules[1].Type != RuleTypeHostname {
		t.Errorf("Rule[1].Type = %v, want hostname", cm.resolvedRules[1].Type)
	}
	if cm.resolvedRules[1].Value != "localhost" {
		t.Errorf("Rule[1].Value = %v, want localhost", cm.resolvedRules[1].Value)
	}
	// IPs are now resolved JIT in DNS server, not during ResolveRules
	if cm.resolvedRules[1].IPNet != nil {
		t.Error("Rule[1].IPNet should be nil for hostname rules")
	}

	// Check third Rule (single IP as CIDR)
	if cm.resolvedRules[2].Type != RuleTypeCIDR {
		t.Errorf("Rule[2].Type = %v, want cidr", cm.resolvedRules[2].Type)
	}
	if cm.resolvedRules[2].IPNet == nil {
		t.Error("Rule[2].IPNet is nil")
	} else {
		ones, _ := cm.resolvedRules[2].IPNet.Mask.Size()
		if ones != 32 {
			t.Errorf("Rule[2] prefix length = %d, want 32", ones)
		}
		if !cm.resolvedRules[2].IPNet.IP.Equal(net.ParseIP("10.0.0.1").To4()) {
			t.Errorf("Rule[2].IPNet.IP = %v, want 10.0.0.1", cm.resolvedRules[2].IPNet.IP)
		}
	}
	expectedPort := Port{Port: 22, Protocol: ProtocolAll}
	if len(cm.resolvedRules[2].Ports) != 1 || cm.resolvedRules[2].Ports[0] != expectedPort {
		t.Errorf("Rule[2].Ports = %v, want [%v]", cm.resolvedRules[2].Ports, expectedPort)
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpfile, err := os.CreateTemp("", "cargowall-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	configData := `{
		"rules": [
			{"type": "cidr", "value": "192.168.1.0/24", "action": "allow"},
			{"type": "cidr", "value": "10.0.0.0/8", "ports": [{"value": 80, "protocol": "all"}, {"value": 443, "protocol": "all"}], "action": "allow"},
			{"type": "hostname", "value": "localhost", "ports": [{"value": 8080, "protocol": "all"}], "action": "allow"}
		],
		"defaultAction": "deny"
	}`

	if _, err := tmpfile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cm := NewConfigManager()
	err = cm.LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Check that rules were resolved
	if len(cm.resolvedRules) != 3 {
		t.Fatalf("expected 3 resolved rules, got %d", len(cm.resolvedRules))
	}

	// Check default action
	if cm.GetDefaultAction() != ActionDeny {
		t.Errorf("GetDefaultAction() = %v, want deny", cm.GetDefaultAction())
	}
}

func TestCIDRMatching(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		testIPs     []string
		shouldMatch []bool
	}{
		{
			name: "Class C network",
			cidr: "192.168.1.0/24",
			testIPs: []string{
				"192.168.1.1",
				"192.168.1.255",
				"192.168.2.1",
				"10.0.0.1",
			},
			shouldMatch: []bool{true, true, false, false},
		},
		{
			name: "Class A network",
			cidr: "10.0.0.0/8",
			testIPs: []string{
				"10.0.0.1",
				"10.255.255.255",
				"11.0.0.1",
				"192.168.1.1",
			},
			shouldMatch: []bool{true, true, false, false},
		},
		{
			name: "Single host /32",
			cidr: "192.168.1.1/32",
			testIPs: []string{
				"192.168.1.1",
				"192.168.1.2",
			},
			shouldMatch: []bool{true, false},
		},
		{
			name: "Wildcard 0.0.0.0/0",
			cidr: "0.0.0.0/0",
			testIPs: []string{
				"192.168.1.1",
				"10.0.0.1",
				"8.8.8.8",
			},
			shouldMatch: []bool{true, true, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipnet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.cidr, err)
			}

			for i, ipStr := range tt.testIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP %s", ipStr)
				}

				matches := ipnet.Contains(ip)
				if matches != tt.shouldMatch[i] {
					t.Errorf("CIDR %s contains %s = %v, want %v",
						tt.cidr, ipStr, matches, tt.shouldMatch[i])
				}
			}
		})
	}
}

func TestParseHostWithPorts(t *testing.T) {
	tests := []struct {
		input     string
		wantHost  string
		wantPorts []Port
	}{
		{"github.com", "github.com", nil},
		{"github.com:443", "github.com", []Port{{Port: 443, Protocol: ProtocolAll}}},
		{"github.com:443;80", "github.com", []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}}},
		{"10.0.0.0/8:443;80", "10.0.0.0/8", []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}}},
		{"10.0.0.0/8", "10.0.0.0/8", nil},
		{"example.com:443;80;8080", "example.com", []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}, {Port: 8080, Protocol: ProtocolAll}}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, ports := parseHostWithPorts(tt.input)
			if host != tt.wantHost {
				t.Errorf("parseHostWithPorts(%q) host = %q, want %q", tt.input, host, tt.wantHost)
			}
			if !reflect.DeepEqual(ports, tt.wantPorts) {
				t.Errorf("parseHostWithPorts(%q) ports = %v, want %v", tt.input, ports, tt.wantPorts)
			}
		})
	}
}

func TestLoadFromEnv_WithPorts(t *testing.T) {
	// Save and restore env vars
	envVars := []string{
		"CARGOWALL_DEFAULT_ACTION",
		"CARGOWALL_ALLOWED_HOSTS",
		"CARGOWALL_ALLOWED_CIDRS",
		"CARGOWALL_BLOCKED_HOSTS",
		"CARGOWALL_BLOCKED_CIDRS",
	}
	saved := make(map[string]string)
	for _, env := range envVars {
		saved[env] = os.Getenv(env)
	}
	t.Cleanup(func() {
		for _, env := range envVars {
			if saved[env] == "" {
				os.Unsetenv(env)
			} else {
				os.Setenv(env, saved[env])
			}
		}
	})

	// Set test env vars
	os.Setenv("CARGOWALL_DEFAULT_ACTION", "deny")
	os.Setenv("CARGOWALL_ALLOWED_HOSTS", "github.com:443;80,npmjs.org:443")
	os.Setenv("CARGOWALL_ALLOWED_CIDRS", "10.0.0.0/8:443;80")
	os.Unsetenv("CARGOWALL_BLOCKED_HOSTS")
	os.Unsetenv("CARGOWALL_BLOCKED_CIDRS")

	cm := NewConfigManager()
	err := cm.LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}

	if len(cm.config.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(cm.config.Rules))
	}

	// Check github.com rule
	r := cm.config.Rules[0]
	if r.Value != "github.com" || r.Type != RuleTypeHostname || r.Action != ActionAllow {
		t.Errorf("rule[0] = %+v, want hostname/github.com/allow", r)
	}
	if !reflect.DeepEqual(r.Ports, []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}}) {
		t.Errorf("rule[0].Ports = %v, want [{443 all} {80 all}]", r.Ports)
	}

	// Check npmjs.org rule
	r = cm.config.Rules[1]
	if r.Value != "npmjs.org" || r.Type != RuleTypeHostname || r.Action != ActionAllow {
		t.Errorf("rule[1] = %+v, want hostname/npmjs.org/allow", r)
	}
	if !reflect.DeepEqual(r.Ports, []Port{{Port: 443, Protocol: ProtocolAll}}) {
		t.Errorf("rule[1].Ports = %v, want [{443 all}]", r.Ports)
	}

	// Check CIDR rule
	r = cm.config.Rules[2]
	if r.Value != "10.0.0.0/8" || r.Type != RuleTypeCIDR || r.Action != ActionAllow {
		t.Errorf("rule[2] = %+v, want cidr/10.0.0.0/8/allow", r)
	}
	if !reflect.DeepEqual(r.Ports, []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}}) {
		t.Errorf("rule[2].Ports = %v, want [{443 all} {80 all}]", r.Ports)
	}
}

func TestLoadFromEnv_WildcardPattern(t *testing.T) {
	// Save and restore env vars
	envVars := []string{
		"CARGOWALL_DEFAULT_ACTION",
		"CARGOWALL_ALLOWED_HOSTS",
		"CARGOWALL_ALLOWED_CIDRS",
		"CARGOWALL_BLOCKED_HOSTS",
		"CARGOWALL_BLOCKED_CIDRS",
	}
	saved := make(map[string]string)
	for _, env := range envVars {
		saved[env] = os.Getenv(env)
	}
	t.Cleanup(func() {
		for _, env := range envVars {
			if saved[env] == "" {
				os.Unsetenv(env)
			} else {
				os.Setenv(env, saved[env])
			}
		}
	})

	// Set test env vars with wildcards
	os.Setenv("CARGOWALL_DEFAULT_ACTION", "deny")
	os.Setenv("CARGOWALL_ALLOWED_HOSTS", "*.github.com:443,github.com")
	os.Unsetenv("CARGOWALL_ALLOWED_CIDRS")
	os.Unsetenv("CARGOWALL_BLOCKED_HOSTS")
	os.Unsetenv("CARGOWALL_BLOCKED_CIDRS")

	cm := NewConfigManager()
	err := cm.LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}

	if len(cm.config.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cm.config.Rules))
	}

	// *.github.com is a glob pattern — should be preserved as-is (not normalized)
	if cm.config.Rules[0].Value != "*.github.com" {
		t.Errorf("rule[0].Value = %q, want %q (pattern should be preserved)", cm.config.Rules[0].Value, "*.github.com")
	}
	if !reflect.DeepEqual(cm.config.Rules[0].Ports, []Port{{Port: 443, Protocol: ProtocolAll}}) {
		t.Errorf("rule[0].Ports = %v, want [{443 all}]", cm.config.Rules[0].Ports)
	}

	// github.com should remain unchanged
	if cm.config.Rules[1].Value != "github.com" {
		t.Errorf("rule[1].Value = %q, want %q", cm.config.Rules[1].Value, "github.com")
	}
}

func TestGetTrackedHostnames(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "npmjs.org", Ports: []Port{{Port: 443, Protocol: ProtocolAll}}, Action: ActionAllow},
		{Type: RuleTypeCIDR, Value: "10.0.0.0/8", Action: ActionDeny},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	tracked := cm.GetTrackedHostnames()

	// Should only contain hostname rules, not CIDR rules
	if len(tracked) != 2 {
		t.Fatalf("expected 2 tracked hostnames, got %d: %v", len(tracked), tracked)
	}

	if action, ok := tracked["github.com"]; !ok || action != ActionAllow {
		t.Errorf("expected github.com=allow, got %q (present=%v)", action, ok)
	}
	if action, ok := tracked["npmjs.org"]; !ok || action != ActionAllow {
		t.Errorf("expected npmjs.org=allow, got %q (present=%v)", action, ok)
	}

	// Verify it returns a copy (mutations don't affect internal state)
	tracked["evil.com"] = ActionDeny
	tracked2 := cm.GetTrackedHostnames()
	if _, ok := tracked2["evil.com"]; ok {
		t.Error("GetTrackedHostnames should return a copy, not a reference")
	}
}

func TestEnsureDNSAllowed(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	initialRuleCount := len(cm.config.Rules)

	// Add DNS infrastructure IPs
	cm.EnsureDNSAllowed([]string{"127.0.0.1", "8.8.8.8", "172.17.0.1"})

	// Should have added 3 CIDR rules
	if len(cm.config.Rules) != initialRuleCount+3 {
		t.Fatalf("expected %d rules, got %d", initialRuleCount+3, len(cm.config.Rules))
	}

	// Verify each added rule
	for i, expected := range []string{"127.0.0.1/32", "8.8.8.8/32", "172.17.0.1/32"} {
		rule := cm.config.Rules[initialRuleCount+i]
		if rule.Value != expected {
			t.Errorf("rule[%d].Value = %q, want %q", initialRuleCount+i, rule.Value, expected)
		}
		if rule.Type != RuleTypeCIDR {
			t.Errorf("rule[%d].Type = %q, want cidr", initialRuleCount+i, rule.Type)
		}
		if rule.Action != ActionAllow {
			t.Errorf("rule[%d].Action = %q, want allow", initialRuleCount+i, rule.Action)
		}
		if !reflect.DeepEqual(rule.Ports, []Port{{Port: 53, Protocol: ProtocolUDP}}) {
			t.Errorf("rule[%d].Ports = %v, want [{53 udp}]", initialRuleCount+i, rule.Ports)
		}
		if rule.AutoAddedType != AutoAddedTypeDNS {
			t.Errorf("rule[%d].AutoAddedType = %q, want %q", initialRuleCount+i, rule.AutoAddedType, AutoAddedTypeDNS)
		}
	}

	// Resolved rules should also have been updated
	resolvedRules := cm.GetResolvedRules()
	found := 0
	for _, r := range resolvedRules {
		if r.Type == RuleTypeCIDR && r.Action == ActionAllow && len(r.Ports) == 1 && r.Ports[0] == (Port{Port: 53, Protocol: ProtocolUDP}) {
			if r.AutoAddedType != AutoAddedTypeDNS {
				t.Errorf("resolved rule AutoAddedType = %q, want %q", r.AutoAddedType, AutoAddedTypeDNS)
			}
			found++
		}
	}
	if found != 3 {
		t.Errorf("expected 3 DNS resolved rules, found %d", found)
	}
}

func TestEnsureDNSAllowed_NoDuplicates(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeCIDR, Value: "8.8.8.8/32", Ports: []Port{{Port: 53, Protocol: ProtocolUDP}}, Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	initialRuleCount := len(cm.config.Rules)

	// 8.8.8.8 is already allowed on port 53 -- should not be added again
	cm.EnsureDNSAllowed([]string{"8.8.8.8", "1.1.1.1"})

	// Only 1.1.1.1 should be added (8.8.8.8 already exists)
	if len(cm.config.Rules) != initialRuleCount+1 {
		t.Fatalf("expected %d rules, got %d (should not duplicate 8.8.8.8)", initialRuleCount+1, len(cm.config.Rules))
	}

	addedRule := cm.config.Rules[initialRuleCount]
	if addedRule.Value != "1.1.1.1/32" {
		t.Errorf("added rule Value = %q, want 1.1.1.1/32", addedRule.Value)
	}
}

func TestEnsureDNSAllowed_CoveredByCIDR(t *testing.T) {
	cm := NewConfigManager()
	// 0.0.0.0/0:53 covers everything on port 53
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []Port{{Port: 53, Protocol: ProtocolUDP}}, Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	initialRuleCount := len(cm.config.Rules)

	cm.EnsureDNSAllowed([]string{"8.8.8.8", "127.0.0.1"})

	// Both should be covered by the existing wildcard CIDR rule
	if len(cm.config.Rules) != initialRuleCount {
		t.Fatalf("expected %d rules (no additions), got %d", initialRuleCount, len(cm.config.Rules))
	}
}

func TestEnsureInfraAllowed_SetsAutoAddedType(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules(nil, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []Port{{Port: 80, Protocol: ProtocolTCP}})

	if len(cm.config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cm.config.Rules))
	}
	if cm.config.Rules[0].AutoAddedType != AutoAddedTypeAzureInfrastructure {
		t.Errorf("AutoAddedType = %q, want %q", cm.config.Rules[0].AutoAddedType, AutoAddedTypeAzureInfrastructure)
	}
}

func TestEnsureHostnameAllowed_SetsAutoAddedType(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules(nil, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cm.EnsureHostnameAllowed("github.com", []Port{{Port: 443, Protocol: ProtocolTCP}}, AutoAddedTypeGitHubService)

	if len(cm.config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cm.config.Rules))
	}
	if cm.config.Rules[0].AutoAddedType != AutoAddedTypeGitHubService {
		t.Errorf("AutoAddedType = %q, want %q", cm.config.Rules[0].AutoAddedType, AutoAddedTypeGitHubService)
	}
	if !reflect.DeepEqual(cm.config.Rules[0].Ports, []Port{{Port: 443, Protocol: ProtocolTCP}}) {
		t.Errorf("Ports = %v, want [{443 tcp}]", cm.config.Rules[0].Ports)
	}

	resolvedRules := cm.GetResolvedRules()
	if len(resolvedRules) != 1 {
		t.Fatalf("expected 1 resolved rule, got %d", len(resolvedRules))
	}
	if resolvedRules[0].AutoAddedType != AutoAddedTypeGitHubService {
		t.Errorf("resolved AutoAddedType = %q, want %q", resolvedRules[0].AutoAddedType, AutoAddedTypeGitHubService)
	}
	if !reflect.DeepEqual(resolvedRules[0].Ports, []Port{{Port: 443, Protocol: ProtocolTCP}}) {
		t.Errorf("resolved Ports = %v, want [{443 tcp}]", resolvedRules[0].Ports)
	}
}

func TestEnsureHostnameAllowed_AzureInfrastructureType(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules(nil, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cm.EnsureHostnameAllowed("blob.core.windows.net", []Port{{Port: 443, Protocol: ProtocolTCP}}, AutoAddedTypeAzureInfrastructure)

	if len(cm.config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cm.config.Rules))
	}
	if cm.config.Rules[0].AutoAddedType != AutoAddedTypeAzureInfrastructure {
		t.Errorf("AutoAddedType = %q, want %q", cm.config.Rules[0].AutoAddedType, AutoAddedTypeAzureInfrastructure)
	}
}

func TestGetAutoAllowedTypeForHostname(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules(nil, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cm.EnsureHostnameAllowed("github.com", []Port{{Port: 443, Protocol: ProtocolTCP}}, AutoAddedTypeGitHubService)
	cm.EnsureHostnameAllowed("blob.core.windows.net", []Port{{Port: 443, Protocol: ProtocolTCP}}, AutoAddedTypeAzureInfrastructure)

	// Exact match
	if got := cm.GetAutoAllowedTypeForHostname("github.com"); got != AutoAddedTypeGitHubService {
		t.Errorf("GetAutoAllowedTypeForHostname(github.com) = %q, want %q", got, AutoAddedTypeGitHubService)
	}
	// Subdomain match
	if got := cm.GetAutoAllowedTypeForHostname("api.github.com"); got != AutoAddedTypeGitHubService {
		t.Errorf("GetAutoAllowedTypeForHostname(api.github.com) = %q, want %q", got, AutoAddedTypeGitHubService)
	}
	// Azure match
	if got := cm.GetAutoAllowedTypeForHostname("myaccount.blob.core.windows.net"); got != AutoAddedTypeAzureInfrastructure {
		t.Errorf("GetAutoAllowedTypeForHostname(myaccount.blob.core.windows.net) = %q, want %q", got, AutoAddedTypeAzureInfrastructure)
	}
	// Unknown hostname
	if got := cm.GetAutoAllowedTypeForHostname("example.com"); got != AutoAddedTypeNone {
		t.Errorf("GetAutoAllowedTypeForHostname(example.com) = %q, want %q", got, AutoAddedTypeNone)
	}
}

func TestGetAutoAllowedType(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	// Add auto-added rules
	cm.EnsureDNSAllowed([]string{"8.8.8.8"})
	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []Port{{Port: 80, Protocol: ProtocolTCP}})
	cm.EnsureHostnameAllowed("actions.githubusercontent.com", []Port{{Port: 443, Protocol: ProtocolTCP}}, AutoAddedTypeGitHubService)

	// DNS rule should match on port 53
	if got := cm.GetAutoAllowedType("8.8.8.8", 53, ""); got != AutoAddedTypeDNS {
		t.Errorf("GetAutoAllowedType(8.8.8.8:53) = %q, want %q", got, AutoAddedTypeDNS)
	}
	// DNS rule should NOT match on port 443
	if got := cm.GetAutoAllowedType("8.8.8.8", 443, ""); got != AutoAddedTypeNone {
		t.Errorf("GetAutoAllowedType(8.8.8.8:443) = %q, want %q", got, AutoAddedTypeNone)
	}
	// Infra rule should match
	if got := cm.GetAutoAllowedType("169.254.169.254", 80, ""); got != AutoAddedTypeAzureInfrastructure {
		t.Errorf("GetAutoAllowedType(169.254.169.254:80) = %q, want %q", got, AutoAddedTypeAzureInfrastructure)
	}
	// Hostname rule should match
	if got := cm.GetAutoAllowedType("1.2.3.4", 443, "actions.githubusercontent.com"); got != AutoAddedTypeGitHubService {
		t.Errorf("GetAutoAllowedType(actions.githubusercontent.com) = %q, want %q", got, AutoAddedTypeGitHubService)
	}
	// Subdomain match
	if got := cm.GetAutoAllowedType("1.2.3.4", 443, "sub.actions.githubusercontent.com"); got != AutoAddedTypeGitHubService {
		t.Errorf("GetAutoAllowedType(sub.actions.githubusercontent.com) = %q, want %q", got, AutoAddedTypeGitHubService)
	}
	// User-configured rule should NOT match
	if got := cm.GetAutoAllowedType("1.2.3.4", 443, "github.com"); got != AutoAddedTypeNone {
		t.Errorf("GetAutoAllowedType(github.com) = %q, want %q (user-configured, not auto-added)", got, AutoAddedTypeNone)
	}
	// Unknown IP should NOT match
	if got := cm.GetAutoAllowedType("10.0.0.1", 443, ""); got != AutoAddedTypeNone {
		t.Errorf("GetAutoAllowedType(10.0.0.1:443) = %q, want %q", got, AutoAddedTypeNone)
	}
}

func TestLoadConfigFromCargoWall_SudoLockdown(t *testing.T) {
	cm := NewConfigManager()

	policy := &cargowallv1pb.CargoWallPolicy{
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		SudoLockdown: &cargowallv1pb.CargoWallPolicy_SudoLockdown{
			Enabled:       true,
			AllowCommands: []string{"apt-get install", "systemctl restart"},
		},
		Rules: []*cargowallv1pb.CargoWallPolicy_Rule{
			{
				Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME,
				Value:  "github.com",
				Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
				Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{
					{Port: 443, Protocol: datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_TCP},
				},
			},
		},
	}

	err := cm.LoadConfigFromCargoWall(policy)
	if err != nil {
		t.Fatalf("LoadConfigFromCargoWall() error = %v", err)
	}

	sl := cm.GetSudoLockdown()
	if sl == nil {
		t.Fatal("expected SudoLockdown to be non-nil")
	}
	if !sl.Enabled {
		t.Error("expected SudoLockdown.Enabled = true")
	}
	if !reflect.DeepEqual(sl.AllowCommands, []string{"apt-get install", "systemctl restart"}) {
		t.Errorf("SudoLockdown.AllowCommands = %v, want [apt-get install, systemctl restart]", sl.AllowCommands)
	}

	// Verify rules were also loaded correctly
	if len(cm.resolvedRules) != 1 {
		t.Fatalf("expected 1 resolved rule, got %d", len(cm.resolvedRules))
	}
	if cm.resolvedRules[0].Value != "github.com" {
		t.Errorf("rule Value = %q, want github.com", cm.resolvedRules[0].Value)
	}
	if !reflect.DeepEqual(cm.resolvedRules[0].Ports, []Port{{Port: 443, Protocol: ProtocolTCP}}) {
		t.Errorf("rule Ports = %v, want [{443 tcp}]", cm.resolvedRules[0].Ports)
	}
}

func TestLoadConfigFromCargoWall_NoSudoLockdown(t *testing.T) {
	cm := NewConfigManager()

	policy := &cargowallv1pb.CargoWallPolicy{
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		Rules: []*cargowallv1pb.CargoWallPolicy_Rule{
			{
				Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_CIDR,
				Value:  "10.0.0.0/8",
				Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
			},
		},
	}

	err := cm.LoadConfigFromCargoWall(policy)
	if err != nil {
		t.Fatalf("LoadConfigFromCargoWall() error = %v", err)
	}

	sl := cm.GetSudoLockdown()
	if sl != nil {
		t.Errorf("expected SudoLockdown to be nil, got %+v", sl)
	}
}

func TestLoadConfig_SudoLockdown(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "cargowall-sudo-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	configData := `{
		"rules": [
			{"type": "hostname", "value": "github.com", "ports": [{"value": 443, "protocol": "tcp"}], "action": "allow"}
		],
		"defaultAction": "deny",
		"sudoLockdown": {
			"enabled": true,
			"allowCommands": ["apt-get update", "npm install"]
		}
	}`

	if _, err := tmpfile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cm := NewConfigManager()
	err = cm.LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	sl := cm.GetSudoLockdown()
	if sl == nil {
		t.Fatal("expected SudoLockdown to be non-nil")
	}
	if !sl.Enabled {
		t.Error("expected SudoLockdown.Enabled = true")
	}
	if !reflect.DeepEqual(sl.AllowCommands, []string{"apt-get update", "npm install"}) {
		t.Errorf("SudoLockdown.AllowCommands = %v, want [apt-get update, npm install]", sl.AllowCommands)
	}

	// Verify rules were also loaded
	if len(cm.resolvedRules) != 1 {
		t.Fatalf("expected 1 resolved rule, got %d", len(cm.resolvedRules))
	}
	if cm.GetDefaultAction() != ActionDeny {
		t.Errorf("GetDefaultAction() = %v, want deny", cm.GetDefaultAction())
	}
}

func TestHostnamePatternRules(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "actions.githubusercontent.com.*.*.internal.cloudapp.net", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "**.storage.azure.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "evil.*.example.com", Action: ActionDeny},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	// Plain hostname rules still work
	if action := cm.GetTrackedHostnameAction("github.com"); action != ActionAllow {
		t.Errorf("GetTrackedHostnameAction(github.com) = %q, want allow", action)
	}
	if action := cm.GetTrackedHostnameAction("api.github.com"); action != ActionAllow {
		t.Errorf("GetTrackedHostnameAction(api.github.com) = %q, want allow", action)
	}

	// Pattern with two single wildcards in middle
	if action := cm.GetTrackedHostnameAction("actions.githubusercontent.com.abc123.phxx.internal.cloudapp.net"); action != ActionAllow {
		t.Errorf("two-star middle pattern should match, got %q", action)
	}
	if action := cm.GetTrackedHostnameAction("actions.githubusercontent.com.only1.internal.cloudapp.net"); action != "" {
		t.Errorf("two-star middle pattern should not match with only 1 label, got %q", action)
	}

	// Double-star pattern
	if action := cm.GetTrackedHostnameAction("westus2.storage.azure.com"); action != ActionAllow {
		t.Errorf("doublestar pattern should match one label, got %q", action)
	}
	if action := cm.GetTrackedHostnameAction("account.westus2.storage.azure.com"); action != ActionAllow {
		t.Errorf("doublestar pattern should match multiple labels, got %q", action)
	}
	if action := cm.GetTrackedHostnameAction("storage.azure.com"); action != "" {
		t.Errorf("doublestar pattern should not match zero labels, got %q", action)
	}

	// Deny pattern
	if action := cm.GetTrackedHostnameAction("evil.anything.example.com"); action != ActionDeny {
		t.Errorf("deny pattern should match, got %q", action)
	}

	// No match
	if action := cm.GetTrackedHostnameAction("unknown.com"); action != "" {
		t.Errorf("unknown hostname should not match, got %q", action)
	}
}

func TestFindTrackedHostnameWithPatterns(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "*.*.internal.cloudapp.net", Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	// Plain hostname
	if got := cm.FindTrackedHostname("api.github.com"); got != "github.com" {
		t.Errorf("FindTrackedHostname(api.github.com) = %q, want github.com", got)
	}

	// Pattern match returns the raw pattern
	if got := cm.FindTrackedHostname("abc.def.internal.cloudapp.net"); got != "*.*.internal.cloudapp.net" {
		t.Errorf("FindTrackedHostname(abc.def.internal.cloudapp.net) = %q, want *.*.internal.cloudapp.net", got)
	}

	// No match
	if got := cm.FindTrackedHostname("unknown.com"); got != "" {
		t.Errorf("FindTrackedHostname(unknown.com) = %q, want empty", got)
	}
}

func TestHostnamePatternNotInTrackedHostnames(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "*.*.internal.cloudapp.net", Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	tracked := cm.GetTrackedHostnames()

	// Pattern rules should NOT appear in the tracked hostnames map
	if _, ok := tracked["*.*.internal.cloudapp.net"]; ok {
		t.Error("pattern rule should not appear in trackedHostnames map")
	}
	// Plain hostname should be in the map
	if _, ok := tracked["github.com"]; !ok {
		t.Error("plain hostname should appear in trackedHostnames map")
	}
}

func TestLeadingWildcardIsPattern(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "*.github.com", Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	// "*.github.com" should be treated as a glob pattern, not normalized
	tracked := cm.GetTrackedHostnames()
	if _, ok := tracked["github.com"]; ok {
		t.Error("*.github.com should not be normalized to github.com")
	}
	if _, ok := tracked["*.github.com"]; ok {
		t.Error("pattern should not appear in trackedHostnames map")
	}

	// * matches exactly one label
	if action := cm.GetTrackedHostnameAction("api.github.com"); action != ActionAllow {
		t.Errorf("api.github.com should match *.github.com, got %q", action)
	}
	// * does NOT match two labels
	if action := cm.GetTrackedHostnameAction("a.b.github.com"); action != "" {
		t.Errorf("a.b.github.com should NOT match *.github.com (single * = one label), got %q", action)
	}
}
