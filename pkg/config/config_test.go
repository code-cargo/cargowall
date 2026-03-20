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
					{Type: RuleTypeCIDR, Value: "172.16.0.0/16", Ports: []uint16{80, 443}, Action: ActionAllow},
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
					{Type: RuleTypeCIDR, Value: "10.0.0.1", Ports: []uint16{22}, Action: ActionDeny},
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
					{Type: RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []uint16{80, 443}, Action: ActionAllow},
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
			{Type: RuleTypeCIDR, Value: "10.0.0.1", Ports: []uint16{22}, Action: ActionDeny},
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
	if len(cm.resolvedRules[2].Ports) != 1 || cm.resolvedRules[2].Ports[0] != 22 {
		t.Errorf("Rule[2].Ports = %v, want [22]", cm.resolvedRules[2].Ports)
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
			{"type": "cidr", "value": "10.0.0.0/8", "ports": [80, 443], "action": "allow"},
			{"type": "hostname", "value": "localhost", "ports": [8080], "action": "allow"}
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
		wantPorts []uint16
	}{
		{"github.com", "github.com", nil},
		{"github.com:443", "github.com", []uint16{443}},
		{"github.com:443;80", "github.com", []uint16{443, 80}},
		{"10.0.0.0/8:443;80", "10.0.0.0/8", []uint16{443, 80}},
		{"10.0.0.0/8", "10.0.0.0/8", nil},
		{"example.com:443;80;8080", "example.com", []uint16{443, 80, 8080}},
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

func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"*.github.com", "github.com"},
		{"github.com", "github.com"},
		{"*.*.example.com", "*.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeHostname(tt.input)
			if got != tt.want {
				t.Errorf("normalizeHostname(%q) = %q, want %q", tt.input, got, tt.want)
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
	if !reflect.DeepEqual(r.Ports, []uint16{443, 80}) {
		t.Errorf("rule[0].Ports = %v, want [443 80]", r.Ports)
	}

	// Check npmjs.org rule
	r = cm.config.Rules[1]
	if r.Value != "npmjs.org" || r.Type != RuleTypeHostname || r.Action != ActionAllow {
		t.Errorf("rule[1] = %+v, want hostname/npmjs.org/allow", r)
	}
	if !reflect.DeepEqual(r.Ports, []uint16{443}) {
		t.Errorf("rule[1].Ports = %v, want [443]", r.Ports)
	}

	// Check CIDR rule
	r = cm.config.Rules[2]
	if r.Value != "10.0.0.0/8" || r.Type != RuleTypeCIDR || r.Action != ActionAllow {
		t.Errorf("rule[2] = %+v, want cidr/10.0.0.0/8/allow", r)
	}
	if !reflect.DeepEqual(r.Ports, []uint16{443, 80}) {
		t.Errorf("rule[2].Ports = %v, want [443 80]", r.Ports)
	}
}

func TestLoadFromEnv_WildcardNormalization(t *testing.T) {
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

	// *.github.com should be normalized to github.com
	if cm.config.Rules[0].Value != "github.com" {
		t.Errorf("rule[0].Value = %q, want %q (wildcard should be normalized)", cm.config.Rules[0].Value, "github.com")
	}
	if !reflect.DeepEqual(cm.config.Rules[0].Ports, []uint16{443}) {
		t.Errorf("rule[0].Ports = %v, want [443]", cm.config.Rules[0].Ports)
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
		{Type: RuleTypeHostname, Value: "npmjs.org", Ports: []uint16{443}, Action: ActionAllow},
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
		if !reflect.DeepEqual(rule.Ports, []uint16{53}) {
			t.Errorf("rule[%d].Ports = %v, want [53]", initialRuleCount+i, rule.Ports)
		}
		if rule.AutoAddedType != AutoAddedTypeDNS {
			t.Errorf("rule[%d].AutoAddedType = %q, want %q", initialRuleCount+i, rule.AutoAddedType, AutoAddedTypeDNS)
		}
	}

	// Resolved rules should also have been updated
	resolvedRules := cm.GetResolvedRules()
	found := 0
	for _, r := range resolvedRules {
		if r.Type == RuleTypeCIDR && r.Action == ActionAllow && len(r.Ports) == 1 && r.Ports[0] == 53 {
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
		{Type: RuleTypeCIDR, Value: "8.8.8.8/32", Ports: []uint16{53}, Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	initialRuleCount := len(cm.config.Rules)

	// 8.8.8.8 is already allowed on port 53 — should not be added again
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
		{Type: RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []uint16{53}, Action: ActionAllow},
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

	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []uint16{80})

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

	cm.EnsureHostnameAllowed("github.com", []uint16{443}, AutoAddedTypeGitHubService)

	if len(cm.config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cm.config.Rules))
	}
	if cm.config.Rules[0].AutoAddedType != AutoAddedTypeGitHubService {
		t.Errorf("AutoAddedType = %q, want %q", cm.config.Rules[0].AutoAddedType, AutoAddedTypeGitHubService)
	}
	if !reflect.DeepEqual(cm.config.Rules[0].Ports, []uint16{443}) {
		t.Errorf("Ports = %v, want [443]", cm.config.Rules[0].Ports)
	}

	resolvedRules := cm.GetResolvedRules()
	if len(resolvedRules) != 1 {
		t.Fatalf("expected 1 resolved rule, got %d", len(resolvedRules))
	}
	if resolvedRules[0].AutoAddedType != AutoAddedTypeGitHubService {
		t.Errorf("resolved AutoAddedType = %q, want %q", resolvedRules[0].AutoAddedType, AutoAddedTypeGitHubService)
	}
	if !reflect.DeepEqual(resolvedRules[0].Ports, []uint16{443}) {
		t.Errorf("resolved Ports = %v, want [443]", resolvedRules[0].Ports)
	}
}

func TestEnsureHostnameAllowed_AzureInfrastructureType(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules(nil, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cm.EnsureHostnameAllowed("blob.core.windows.net", []uint16{443}, AutoAddedTypeAzureInfrastructure)

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

	cm.EnsureHostnameAllowed("github.com", []uint16{443}, AutoAddedTypeGitHubService)
	cm.EnsureHostnameAllowed("blob.core.windows.net", []uint16{443}, AutoAddedTypeAzureInfrastructure)

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
	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []uint16{80})
	cm.EnsureHostnameAllowed("actions.githubusercontent.com", []uint16{443}, AutoAddedTypeGitHubService)

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
