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
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

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

// portSetEqual compares two port lists as unordered sets (mergeDuplicateRules
// preserves a deterministic order, but the union semantics are what matter).
func portSetEqual(a, b []Port) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[Port]int, len(a))
	for _, p := range a {
		counts[p]++
	}
	for _, p := range b {
		counts[p]--
	}
	for _, c := range counts {
		if c != 0 {
			return false
		}
	}
	return true
}

// Issue #52: a policy that lists the same hostname/CIDR more than once must
// allow the UNION of those entries' ports, not just one entry's. The merge
// happens in applyLoadedConfig, so these tests drive it through
// LoadConfigFromRules (the four loaders share that tail).

func TestMergeDuplicateRules_HostnameAllowUnion(t *testing.T) {
	tcp443 := Port{Port: 443, Protocol: ProtocolTCP}
	tcp80 := Port{Port: 80, Protocol: ProtocolTCP}

	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Ports: []Port{tcp443}, Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "github.com", Ports: []Port{tcp80}, Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	// The two entries collapse into one rule across both views.
	if len(cm.config.Rules) != 1 {
		t.Fatalf("config.Rules: expected 1 merged rule, got %d", len(cm.config.Rules))
	}
	if len(cm.resolvedRules) != 1 {
		t.Fatalf("resolvedRules: expected 1 merged rule, got %d", len(cm.resolvedRules))
	}

	verdict := cm.MatchHostnameRule("github.com")
	if !verdict.HasAllow() {
		t.Fatalf("expected an allow verdict, got %+v", verdict)
	}
	if want := []Port{tcp443, tcp80}; !portSetEqual(verdict.AllowPorts, want) {
		t.Errorf("AllowPorts = %v, want union %v", verdict.AllowPorts, want)
	}
}

func TestMergeDuplicateRules_AllPortsSentinelAbsorbs(t *testing.T) {
	tcp443 := Port{Port: 443, Protocol: ProtocolTCP}

	// An all-ports entry (empty Ports) on either side makes the whole group
	// all-ports, regardless of order.
	for _, tc := range []struct {
		name  string
		rules []Rule
	}{
		{"all-ports first", []Rule{
			{Type: RuleTypeHostname, Value: "example.com", Action: ActionAllow},
			{Type: RuleTypeHostname, Value: "example.com", Ports: []Port{tcp443}, Action: ActionAllow},
		}},
		{"all-ports second", []Rule{
			{Type: RuleTypeHostname, Value: "example.com", Ports: []Port{tcp443}, Action: ActionAllow},
			{Type: RuleTypeHostname, Value: "example.com", Action: ActionAllow},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := NewConfigManager()
			if err := cm.LoadConfigFromRules(tc.rules, ActionDeny); err != nil {
				t.Fatalf("LoadConfigFromRules() error = %v", err)
			}
			verdict := cm.MatchHostnameRule("example.com")
			if !verdict.HasAllow() {
				t.Fatalf("expected an allow verdict, got %+v", verdict)
			}
			if len(verdict.AllowPorts) != 0 {
				t.Errorf("AllowPorts = %v, want empty (all ports)", verdict.AllowPorts)
			}
		})
	}
}

func TestMergeDuplicateRules_PatternUnion(t *testing.T) {
	tcp443 := Port{Port: 443, Protocol: ProtocolTCP}
	tcp80 := Port{Port: 80, Protocol: ProtocolTCP}

	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "*.github.com", Ports: []Port{tcp443}, Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "*.github.com", Ports: []Port{tcp80}, Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if len(cm.resolvedRules) != 1 {
		t.Fatalf("resolvedRules: expected 1 merged pattern rule, got %d", len(cm.resolvedRules))
	}
	verdict := cm.MatchHostnameRule("api.github.com")
	if want := []Port{tcp443, tcp80}; !portSetEqual(verdict.AllowPorts, want) {
		t.Errorf("AllowPorts = %v, want union %v", verdict.AllowPorts, want)
	}
}

func TestMergeDuplicateRules_DenyUnion(t *testing.T) {
	tcp443 := Port{Port: 443, Protocol: ProtocolTCP}
	tcp80 := Port{Port: 80, Protocol: ProtocolTCP}

	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "blocked.example.com", Ports: []Port{tcp80}, Action: ActionDeny},
		{Type: RuleTypeHostname, Value: "blocked.example.com", Ports: []Port{tcp443}, Action: ActionDeny},
	}, ActionAllow); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	verdict := cm.MatchHostnameRule("blocked.example.com")
	if !verdict.HasDeny() {
		t.Fatalf("expected a deny verdict, got %+v", verdict)
	}
	if want := []Port{tcp80, tcp443}; !portSetEqual(verdict.DenyPorts, want) {
		t.Errorf("DenyPorts = %v, want union %v", verdict.DenyPorts, want)
	}
}

func TestMergeDuplicateRules_CIDRUnionVisibleToConflictCheck(t *testing.T) {
	tcp80 := Port{Port: 80, Protocol: ProtocolTCP}
	tcp443 := Port{Port: 443, Protocol: ProtocolTCP}

	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeCIDR, Value: "1.2.3.4/32", Ports: []Port{tcp80}, Action: ActionDeny},
		{Type: RuleTypeCIDR, Value: "1.2.3.4/32", Ports: []Port{tcp443}, Action: ActionDeny},
	}, ActionAllow); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if len(cm.config.Rules) != 1 {
		t.Fatalf("config.Rules: expected 1 merged CIDR rule, got %d", len(cm.config.Rules))
	}
	if want := []Port{tcp80, tcp443}; !portSetEqual(cm.config.Rules[0].Ports, want) {
		t.Errorf("merged CIDR ports = %v, want union %v", cm.config.Rules[0].Ports, want)
	}

	// CheckIPRuleConflict reads cm.config.Rules. Port 443 was only on the
	// second duplicate; before the merge it was lost and this allow would
	// have been reported as non-conflicting.
	action, conflict, rule := cm.CheckIPRuleConflict(
		net.ParseIP("1.2.3.4"), "host.example.com", ActionAllow, []Port{tcp443},
	)
	if !conflict || action != ActionDeny {
		t.Errorf("CheckIPRuleConflict = (%v, %v, %q), want (deny, true, 1.2.3.4/32)", action, conflict, rule)
	}
}

func TestMergeDuplicateRules_OppositeActionsNotMerged(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "example.com", Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "example.com", Ports: []Port{{Port: 80, Protocol: ProtocolTCP}}, Action: ActionDeny},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	// Opposite actions are a conflict, not a union: both rules survive and the
	// existing matching-precedence logic decides the verdict (unchanged).
	if len(cm.config.Rules) != 2 {
		t.Fatalf("config.Rules: expected 2 rules (no merge across actions), got %d", len(cm.config.Rules))
	}
}

func TestMergeDuplicateRules_NoDuplicatesUnchanged(t *testing.T) {
	rules := []Rule{
		{Type: RuleTypeHostname, Value: "github.com", Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionAllow},
		{Type: RuleTypeCIDR, Value: "8.8.8.8/32", Ports: []Port{{Port: 53, Protocol: ProtocolUDP}}, Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "npmjs.org", Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionAllow},
	}
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(rules, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if len(cm.config.Rules) != len(rules) {
		t.Fatalf("config.Rules: expected %d rules unchanged, got %d", len(rules), len(cm.config.Rules))
	}
	// First-occurrence order is preserved.
	for i, want := range []string{"github.com", "8.8.8.8/32", "npmjs.org"} {
		if cm.config.Rules[i].Value != want {
			t.Errorf("config.Rules[%d].Value = %q, want %q", i, cm.config.Rules[i].Value, want)
		}
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

func TestLoadConfig_SearchDomains(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "cargowall-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	configData := `{
		"defaultAction": "deny",
		"rules": [],
		"searchDomains": [".compute.internal", "EC2.Internal", "  .compute.internal  "]
	}`

	if _, err := tmpfile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	cm := NewConfigManager()
	if err := cm.LoadConfig(tmpfile.Name()); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	got := cm.GetSearchDomains()
	want := []string{".compute.internal", ".ec2.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSearchDomains() = %v, want %v", got, want)
	}
}

func TestLoadConfig_SearchDomains_RejectsSingleLabel(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "cargowall-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// ".com" is a single-label suffix that would whitelist resolution for
	// half the public internet — must be rejected at config load.
	configData := `{
		"defaultAction": "deny",
		"rules": [],
		"searchDomains": [".com"]
	}`

	if _, err := tmpfile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	cm := NewConfigManager()
	err = cm.LoadConfig(tmpfile.Name())
	if err == nil {
		t.Fatal("LoadConfig() with .com searchDomain succeeded, want error")
	}
	if !strings.Contains(err.Error(), "two labels") {
		t.Errorf("LoadConfig() error = %q, want it to mention 'two labels'", err)
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
		wantErr   bool
	}{
		// IPv4 / hostname / CIDR — original behavior.
		{input: "github.com", wantHost: "github.com"},
		{input: "github.com:443", wantHost: "github.com", wantPorts: []Port{{Port: 443, Protocol: ProtocolAll}}},
		{input: "github.com:443;80", wantHost: "github.com", wantPorts: []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}}},
		{input: "10.0.0.0/8:443;80", wantHost: "10.0.0.0/8", wantPorts: []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}}},
		{input: "10.0.0.0/8", wantHost: "10.0.0.0/8"},
		{input: "example.com:443;80;8080", wantHost: "example.com", wantPorts: []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}, {Port: 8080, Protocol: ProtocolAll}}},
		{input: "192.168.1.1", wantHost: "192.168.1.1"},

		// Bare IPv6 — colons inside the address must NOT be split as host:port.
		{input: "::1", wantHost: "::1"},
		{input: "2001:db8::1", wantHost: "2001:db8::1"},

		// Bracketed IPv6 with port(s) — Go stdlib convention.
		{input: "[::1]:443", wantHost: "::1", wantPorts: []Port{{Port: 443, Protocol: ProtocolAll}}},
		{input: "[2001:db8::1]:443;80", wantHost: "2001:db8::1", wantPorts: []Port{{Port: 443, Protocol: ProtocolAll}, {Port: 80, Protocol: ProtocolAll}}},

		// IPv6 CIDR (bare and with ports).
		{input: "2001:db8::/32", wantHost: "2001:db8::/32"},
		{input: "2001:db8::/32:443", wantHost: "2001:db8::/32", wantPorts: []Port{{Port: 443, Protocol: ProtocolAll}}},

		// Bracketed form without a port suffix — preserved verbatim, no
		// error (downstream validation rejects the funny-looking host).
		{input: "[::1]", wantHost: "[::1]"},

		// Trailing colon with empty/whitespace suffix — strip the colon.
		{input: "github.com:", wantHost: "github.com"},
		{input: "github.com:   ", wantHost: "github.com"},
		{input: "github.com:;", wantHost: "github.com"},
		{input: "[::1]:", wantHost: "::1"},

		// Malformed port suffix — fail loudly. Both forms (bracketed +
		// trailing colon) return an error so a typo surfaces at config
		// load instead of becoming a literal-string hostname rule that
		// matches nothing.
		{input: "github.com:abc", wantErr: true},
		{input: "[::1]:abc", wantErr: true},
		{input: "github.com:443;abc", wantErr: true},
		{input: "[::1]:443;abc", wantErr: true},

		// Unbracketed IPv6 with multi-port suffix (`;` makes ParseIP fail,
		// so the entry falls through to the last-`:` split). Reject loudly
		// instead of silently accepting via the trailing-colon path. A
		// no-port valid IPv6 like "fe80::1:443" stays acceptable because
		// ParseIP claims it as a literal IPv6 above; users who want a
		// port must use the bracketed form.
		{input: "2001:db8::1:443;80", wantErr: true},
		// Malformed multi-colon junk also rejected uniformly via the
		// same check (was previously silently accepted as a literal
		// hostname rule with an attached port).
		{input: "fe80::g:80", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, ports, err := parseHostWithPorts(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseHostWithPorts(%q) err = nil, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHostWithPorts(%q) err = %v, want nil", tt.input, err)
			}
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

	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []Port{{Port: 80, Protocol: ProtocolTCP}}, AutoAddedTypeAzureInfrastructure)

	if len(cm.config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cm.config.Rules))
	}
	if cm.config.Rules[0].AutoAddedType != AutoAddedTypeAzureInfrastructure {
		t.Errorf("AutoAddedType = %q, want %q", cm.config.Rules[0].AutoAddedType, AutoAddedTypeAzureInfrastructure)
	}
}

func TestEnsureInfraAllowed_ICMP(t *testing.T) {
	cm := NewConfigManager()
	err := cm.LoadConfigFromRules(nil, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cm.EnsureInfraAllowed([]string{"168.63.129.16"}, []Port{PortICMP}, AutoAddedTypeAzureInfrastructure)

	if len(cm.config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cm.config.Rules))
	}
	r := cm.config.Rules[0]
	if r.Value != "168.63.129.16/32" {
		t.Errorf("rule Value = %q, want 168.63.129.16/32", r.Value)
	}
	if !reflect.DeepEqual(r.Ports, []Port{{Port: 0, Protocol: ProtocolICMP}}) {
		t.Errorf("Ports = %v, want [{0 icmp}]", r.Ports)
	}
	if r.AutoAddedType != AutoAddedTypeAzureInfrastructure {
		t.Errorf("AutoAddedType = %q, want %q", r.AutoAddedType, AutoAddedTypeAzureInfrastructure)
	}
}

func TestLoadConfigFromCargoWall_ICMPRule(t *testing.T) {
	cm := NewConfigManager()

	policy := &cargowallv1pb.CargoWallPolicy{
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		Rules: []*cargowallv1pb.CargoWallPolicy_Rule{
			{
				Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_CIDR,
				Value:  "168.63.129.16/32",
				Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
				Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{
					{Port: 0, Protocol: datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_ICMP},
				},
			},
		},
	}

	if err := cm.LoadConfigFromCargoWall(policy); err != nil {
		t.Fatalf("LoadConfigFromCargoWall() error = %v", err)
	}

	if len(cm.resolvedRules) != 1 {
		t.Fatalf("expected 1 resolved rule, got %d", len(cm.resolvedRules))
	}
	if !reflect.DeepEqual(cm.resolvedRules[0].Ports, []Port{{Port: 0, Protocol: ProtocolICMP}}) {
		t.Errorf("rule Ports = %v, want [{0 icmp}]", cm.resolvedRules[0].Ports)
	}
}

func TestLoadConfigFromCargoWall_ICMPAllowedOnHostname(t *testing.T) {
	cm := NewConfigManager()

	policy := &cargowallv1pb.CargoWallPolicy{
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		Rules: []*cargowallv1pb.CargoWallPolicy_Rule{
			{
				Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME,
				Value:  "example.com",
				Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
				Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{
					{Port: 0, Protocol: datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_ICMP},
				},
			},
		},
	}

	if err := cm.LoadConfigFromCargoWall(policy); err != nil {
		t.Fatalf("LoadConfigFromCargoWall() error = %v; hostname rules with ICMP should load", err)
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
	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []Port{{Port: 80, Protocol: ProtocolTCP}}, AutoAddedTypeAzureInfrastructure)
	cm.EnsureHostnameAllowed("actions.githubusercontent.com", []Port{{Port: 443, Protocol: ProtocolTCP}}, AutoAddedTypeGitHubService)

	// DNS rule should match on port 53
	if got := cm.GetAutoAllowedType("8.8.8.8", 53, ProtocolAll, ""); got != AutoAddedTypeDNS {
		t.Errorf("GetAutoAllowedType(8.8.8.8:53) = %q, want %q", got, AutoAddedTypeDNS)
	}
	// DNS rule should NOT match on port 443
	if got := cm.GetAutoAllowedType("8.8.8.8", 443, ProtocolAll, ""); got != AutoAddedTypeNone {
		t.Errorf("GetAutoAllowedType(8.8.8.8:443) = %q, want %q", got, AutoAddedTypeNone)
	}
	// Infra rule should match
	if got := cm.GetAutoAllowedType("169.254.169.254", 80, ProtocolAll, ""); got != AutoAddedTypeAzureInfrastructure {
		t.Errorf("GetAutoAllowedType(169.254.169.254:80) = %q, want %q", got, AutoAddedTypeAzureInfrastructure)
	}
	// Hostname rule should match
	if got := cm.GetAutoAllowedType("1.2.3.4", 443, ProtocolAll, "actions.githubusercontent.com"); got != AutoAddedTypeGitHubService {
		t.Errorf("GetAutoAllowedType(actions.githubusercontent.com) = %q, want %q", got, AutoAddedTypeGitHubService)
	}
	// Subdomain match
	if got := cm.GetAutoAllowedType("1.2.3.4", 443, ProtocolAll, "sub.actions.githubusercontent.com"); got != AutoAddedTypeGitHubService {
		t.Errorf("GetAutoAllowedType(sub.actions.githubusercontent.com) = %q, want %q", got, AutoAddedTypeGitHubService)
	}
	// User-configured rule should NOT match
	if got := cm.GetAutoAllowedType("1.2.3.4", 443, ProtocolAll, "github.com"); got != AutoAddedTypeNone {
		t.Errorf("GetAutoAllowedType(github.com) = %q, want %q (user-configured, not auto-added)", got, AutoAddedTypeNone)
	}
	// Unknown IP should NOT match
	if got := cm.GetAutoAllowedType("10.0.0.1", 443, ProtocolAll, ""); got != AutoAddedTypeNone {
		t.Errorf("GetAutoAllowedType(10.0.0.1:443) = %q, want %q", got, AutoAddedTypeNone)
	}
}

// Malformed port suffixes in env-loaded entries (e.g. `github.com:abc` or
// `[::1]:abc`) must surface as configuration errors from LoadFromEnv.
// Pre-fix they were silently accepted as literal-string hostname rules
// that matched no real DNS query.
func TestLoadFromEnv_MalformedPortSuffixIsError(t *testing.T) {
	tests := []struct {
		name   string
		envVar string
		value  string
	}{
		{"allowed-hosts: trailing junk", "CARGOWALL_ALLOWED_HOSTS", "github.com:abc"},
		{"allowed-hosts: bracketed junk", "CARGOWALL_ALLOWED_HOSTS", "[::1]:abc"},
		{"allowed-cidrs: trailing junk", "CARGOWALL_ALLOWED_CIDRS", "10.0.0.0/8:abc"},
		{"blocked-hosts: trailing junk", "CARGOWALL_BLOCKED_HOSTS", "evil.example.com:abc"},
		{"blocked-cidrs: bracketed junk", "CARGOWALL_BLOCKED_CIDRS", "[::1]:abc"},
		{"mixed-list: one good one bad", "CARGOWALL_ALLOWED_HOSTS", "github.com:443,evil.example.com:abc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearAllCargowallEnv(t)
			t.Setenv(tc.envVar, tc.value)
			cm := NewConfigManager()
			err := cm.LoadFromEnv()
			if err == nil {
				t.Fatalf("LoadFromEnv() = nil, want error mentioning the env var")
			}
			if !strings.Contains(err.Error(), tc.envVar) {
				t.Errorf("LoadFromEnv() error = %q, want it to mention %q", err.Error(), tc.envVar)
			}
		})
	}
}

// Mixed-case hostname lookup must hit the canonical-lowercase rule. Before
// the fix, GetAutoAllowedTypeForHostname compared via MatchesHostname's
// exact-equality on rule.Value (canonical lowercase) without lowercasing
// the input, so mixed-case callers lost the auto-allow attribution.
func TestGetAutoAllowedTypeForHostname_MixedCaseLookup(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)

	tests := []struct {
		query string
		want  AutoAddedType
	}{
		{"github.com", AutoAddedTypeGitHubService},
		{"GitHub.COM", AutoAddedTypeGitHubService},
		{"GITHUB.COM", AutoAddedTypeGitHubService},
		{"api.GitHub.com", AutoAddedTypeGitHubService}, // parent-suffix path
	}
	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			if got := cm.GetAutoAllowedTypeForHostname(tc.query); got != tc.want {
				t.Errorf("GetAutoAllowedTypeForHostname(%q) = %q, want %q", tc.query, got, tc.want)
			}
		})
	}
}

// Same fix applies to GetAutoAllowedType. Mixed-case hostname caller must
// still hit the canonical-lowercase hostname rule.
func TestGetAutoAllowedType_MixedCaseHostname(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)
	cm.UpdateDNSMapping("github.com", "140.82.114.4")

	if got := cm.GetAutoAllowedType("140.82.114.4", 443, ProtocolTCP, "GitHub.COM"); got != AutoAddedTypeGitHubService {
		t.Errorf("GetAutoAllowedType with mixed-case hostname = %q, want %q", got, AutoAddedTypeGitHubService)
	}
}

// Protocol-aware port match: two rules with the same port number but
// different protocols (TCP/443 vs UDP/443) must not conflate. The earlier
// implementation matched on port number alone, so a UDP query against a
// TCP-only auto-added rule would falsely report the auto-added type.
func TestGetAutoAllowedType_ProtocolSpecific(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.EnsureInfraAllowed(
		[]string{"203.0.113.1"},
		[]Port{{Port: 443, Protocol: ProtocolTCP}},
		AutoAddedTypeAzureInfrastructure,
	)

	// TCP/443 matches the TCP rule.
	if got := cm.GetAutoAllowedType("203.0.113.1", 443, ProtocolTCP, ""); got != AutoAddedTypeAzureInfrastructure {
		t.Errorf("TCP/443 = %q, want %q", got, AutoAddedTypeAzureInfrastructure)
	}
	// UDP/443 does NOT match (different protocol).
	if got := cm.GetAutoAllowedType("203.0.113.1", 443, ProtocolUDP, ""); got != AutoAddedTypeNone {
		t.Errorf("UDP/443 = %q, want %q (TCP-only rule must not conflate)", got, AutoAddedTypeNone)
	}
	// ICMP also does not match.
	if got := cm.GetAutoAllowedType("203.0.113.1", 0, ProtocolICMP, ""); got != AutoAddedTypeNone {
		t.Errorf("ICMP = %q, want %q", got, AutoAddedTypeNone)
	}
	// ProtocolAll query DOES match — supports callers without protocol
	// info (e.g. the events.go fallback path).
	if got := cm.GetAutoAllowedType("203.0.113.1", 443, ProtocolAll, ""); got != AutoAddedTypeAzureInfrastructure {
		t.Errorf("ProtocolAll/443 = %q, want %q (must match for protocol-unknown callers)", got, AutoAddedTypeAzureInfrastructure)
	}
}

// When a connection's IP matches BOTH a CIDR auto-allow rule and a
// hostname auto-allow rule (e.g. github.com resolves into an IP also
// covered by a broader allow CIDR), hostname attribution must win —
// it's more informative for audit output. Pre-fix the function returned
// whichever matched first in insertion order, so an early CIDR could
// shadow a later hostname.
func TestGetAutoAllowedType_HostnameWinsOverCIDR(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	// Order matters: CIDR added FIRST so insertion order would surface it
	// before the hostname rule below.
	cm.EnsureInfraAllowed([]string{"140.82.114.4"}, []Port{PortHTTPS}, AutoAddedTypeAzureInfrastructure)
	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)
	cm.UpdateDNSMapping("github.com", "140.82.114.4")

	// Connection to the IP via the hostname must attribute to the hostname rule.
	got := cm.GetAutoAllowedType("140.82.114.4", 443, ProtocolTCP, "github.com")
	if got != AutoAddedTypeGitHubService {
		t.Errorf("GetAutoAllowedType = %q, want %q (hostname must win over CIDR)", got, AutoAddedTypeGitHubService)
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

// newCMWithSearchDomains constructs a Manager loaded with rules + search
// domains for the strip-and-retry tests that follow. Tests using this share
// the same shape: NewConfigManager → LoadConfigFromRules(..., ActionDeny) →
// AddSearchDomains(...).
func newCMWithSearchDomains(t *testing.T, rules []Rule, searchDomains ...string) *Manager {
	t.Helper()
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(rules, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if len(searchDomains) > 0 {
		cm.AddSearchDomains(searchDomains, slog.Default())
	}
	return cm
}

// When both forms have exact deny rules with different port scopes, prefer
// the broader port coverage. Otherwise a port-scoped full-form deny would
// "win attribution" but leave traffic on the unblocked ports flowing
// through under an allow-by-default policy.
func TestMatchHostnameRule_BothDeny_BroaderPortCoverageWins(t *testing.T) {
	cm := newCMWithSearchDomains(t, []Rule{
		{
			Type:   RuleTypeHostname,
			Value:  "blocked.compute.internal",
			Ports:  []Port{{Port: 443, Protocol: ProtocolTCP}},
			Action: ActionDeny,
		},
		{Type: RuleTypeHostname, Value: "blocked", Action: ActionDeny}, // no ports = all
	}, ".compute.internal")

	v := cm.MatchHostnameRule("blocked.compute.internal")
	if !v.HasDeny() {
		t.Errorf("HasDeny = false, want true")
	}
	if v.HasAllow() {
		t.Errorf("HasAllow = true, want false")
	}
	// Stripped exact deny covers all ports (empty Ports). The broader-coverage
	// rule must win so traffic on ports != 443 is also denied.
	if len(v.DenyPorts) != 0 {
		t.Errorf("DenyPorts = %v, want [] (broader all-ports deny should win over port-443-only deny)", v.DenyPorts)
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
	if v := cm.MatchHostnameRule("api.github.com"); !v.HasAllow() {
		t.Errorf("api.github.com should match *.github.com (allow), got verdict %+v", v)
	}
	// * does NOT match two labels
	if v := cm.MatchHostnameRule("a.b.github.com"); v.Matched() {
		t.Errorf("a.b.github.com should NOT match *.github.com (single * = one label), got verdict %+v", v)
	}
}

func TestConsecutiveDoubleStarRejected(t *testing.T) {
	_, err := compileHostnamePattern("**.**.com")
	if err == nil {
		t.Error("expected error for consecutive ** segments, got nil")
	}

	_, err = compileHostnamePattern("foo.**.**.bar.com")
	if err == nil {
		t.Error("expected error for consecutive ** segments, got nil")
	}

	// Non-consecutive ** is fine
	_, err = compileHostnamePattern("**.foo.**.com")
	if err != nil {
		t.Errorf("non-consecutive ** should be valid, got error: %v", err)
	}
}

// Mirrors the GitHub Actions startup flow: the SaaS API hostname is added to
// an empty bootstrap config so the policy fetch can resolve, then
// LoadConfigFromCargoWall replaces the ruleset with the fetched policy (which
// does not contain the API hostname), then autoAllowInfraHosts re-adds it.
// Before the fix, the third step's EnsureHostnameAllowed call no-op'd on a
// stale trackedHostnames entry, leaving the hostname unmatched at DNS-filter
// time.
func TestEnsureHostnameAllowed_ReAddedAfterCargoWallReload(t *testing.T) {
	cm := NewConfigManager()

	// Bootstrap with an empty deny-all config and add the API hostname.
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules(nil) error = %v", err)
	}
	cm.EnsureHostnameAllowed("app.codecargo.com", []Port{PortHTTPS}, AutoAddedTypeCodeCargoService)
	if v := cm.MatchHostnameRule("app.codecargo.com"); !v.HasAllow() {
		t.Fatalf("after bootstrap, MatchHostnameRule(app.codecargo.com) = %+v, want allow", v)
	}

	// Simulate the API policy fetch landing a ruleset that does not include
	// the API hostname.
	policy := &cargowallv1pb.CargoWallPolicy{
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
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
	if err := cm.LoadConfigFromCargoWall(policy); err != nil {
		t.Fatalf("LoadConfigFromCargoWall() error = %v", err)
	}

	// After the reload, the API hostname is no longer in the ruleset.
	if v := cm.MatchHostnameRule("app.codecargo.com"); v.Matched() {
		t.Fatalf("after reload, MatchHostnameRule(app.codecargo.com) = %+v, want empty", v)
	}

	// autoAllowInfraHosts re-adds the API hostname. This must actually install
	// a rule, not no-op on a stale trackedHostnames entry from the bootstrap.
	cm.EnsureHostnameAllowed("app.codecargo.com", []Port{PortHTTPS}, AutoAddedTypeCodeCargoService)
	v := cm.MatchHostnameRule("app.codecargo.com")
	if !v.HasAllow() {
		t.Errorf("after re-add, MatchHostnameRule(app.codecargo.com) verdict = %+v, want allow", v)
	}
	if v.AllowRule != "app.codecargo.com" {
		t.Errorf("after re-add, AllowRule = %q, want app.codecargo.com", v.AllowRule)
	}
	if !reflect.DeepEqual(v.AllowPorts, []Port{PortHTTPS}) {
		t.Errorf("after re-add, AllowPorts = %v, want [{443 tcp}]", v.AllowPorts)
	}
}

// resolveRules clears trackedHostnames so the map only reflects the current
// ruleset. Without the clear, hostnames removed by a config reload would
// linger as ghost entries — making FindTrackedHostname / GetTrackedHostnames
// return matches that have no corresponding resolved rule.
func TestResolveRules_TrackedHostnamesReflectCurrentRuleset(t *testing.T) {
	cm := NewConfigManager()

	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "old.example.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("first LoadConfigFromRules() error = %v", err)
	}
	if _, ok := cm.GetTrackedHostnames()["old.example.com"]; !ok {
		t.Fatalf("expected old.example.com in trackedHostnames after first load")
	}

	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "new.example.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("second LoadConfigFromRules() error = %v", err)
	}

	tracked := cm.GetTrackedHostnames()
	if _, ok := tracked["old.example.com"]; ok {
		t.Errorf("old.example.com should be cleared after reload, still in trackedHostnames")
	}
	if _, ok := tracked["new.example.com"]; !ok {
		t.Errorf("new.example.com should be in trackedHostnames after reload")
	}
}

func TestNormalizeSearchDomains(t *testing.T) {
	got := normalizeSearchDomains([]string{
		"  .Compute.Internal  ",
		"ec2.internal",
		".compute.internal", // duplicate after normalization
	})
	want := []string{".compute.internal", ".ec2.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeSearchDomains() = %v, want %v", got, want)
	}
}

// Empty / whitespace-only entries are preserved by the normalizer so they
// fall through to validateSearchDomains, which rejects them. This prevents
// explicit misconfigs like `searchDomains: [""]` from silently passing.
func TestNormalizeSearchDomains_PreservesEmptyForValidation(t *testing.T) {
	got := normalizeSearchDomains([]string{
		".compute.internal",
		"",
		"  ",
	})
	if len(got) != 2 || got[0] != ".compute.internal" || got[1] != "" {
		t.Errorf("normalizeSearchDomains() = %v, want [.compute.internal \"\"]", got)
	}
	if err := validateSearchDomains(got); err == nil {
		t.Errorf("validateSearchDomains should reject empty entries that survived normalization")
	}
}

func TestLoadConfig_SearchDomains_RejectsEmptyEntry(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "cargowall-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	configData := `{
		"defaultAction": "deny",
		"rules": [],
		"searchDomains": [".compute.internal", ""]
	}`
	if _, err := tmpfile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	cm := NewConfigManager()
	if err := cm.LoadConfig(tmpfile.Name()); err == nil {
		t.Fatal("LoadConfig() with empty searchDomain entry succeeded, want error")
	}
}

func TestValidateSearchDomains(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{"valid AWS", []string{".compute.internal", ".ec2.internal"}, false},
		{"valid Azure", []string{".internal.cloudapp.net"}, false},
		{"valid nested", []string{".internal.example.com"}, false},
		{"reject single-label TLD", []string{".com"}, true},
		{"reject .local alone", []string{".local"}, true},
		{"reject empty", []string{""}, true},
		{"reject just dot", []string{"."}, true},
		{"reject uppercase (should be normalized first)", []string{".Compute.Internal"}, true},
		{"reject invalid char", []string{".comp_ute.internal"}, true},
		{"reject empty label", []string{".compute..internal"}, true},
		{"reject leading hyphen", []string{".-bad.example.com"}, true},
		{"reject trailing hyphen", []string{".bad-.example.com"}, true},
		{"reject label over 63 chars", []string{"." + strings.Repeat("a", 64) + ".example.com"}, true},
		{"accept 63-char label exactly", []string{"." + strings.Repeat("a", 63) + ".example.com"}, false},
		{"accept internal hyphen", []string{".us-west-2.compute.internal"}, false},
		// Public-suffix rejections — multi-label TLDs that pass label-count.
		{"reject .co.uk (PSL)", []string{".co.uk"}, true},
		{"reject .com.au (PSL)", []string{".com.au"}, true},
		{"reject .github.io (PSL — private)", []string{".github.io"}, true},
		// Private internal suffixes that extend beyond PSL entries are OK.
		{"accept .compute.internal (extends .internal PSL)", []string{".compute.internal"}, false},

		// Extension coverage:
		{"reject 64-char label (one over RFC 1035 limit)", []string{"." + strings.Repeat("a", 64) + ".internal"}, true},
		{"reject multi-byte unicode (non-ASCII)", []string{".bücher.de"}, true},
		{"accept IDN punycode form", []string{".xn--bcher-kva.example.com"}, false},
		// Foot-gun: lone "localhost" — single-label, rejected.
		{"reject localhost (single label)", []string{".localhost"}, true},
		// Foot-gun: lone "internal" — single-label, also a PSL entry.
		{"reject internal (single label + PSL)", []string{".internal"}, true},
		// Defensive: numeric-only labels are technically valid per RFC 1123.
		{"accept numeric label", []string{".1.example.com"}, false},
		// Kubernetes defaults are always-active for stripping (see
		// kubernetesSearchDomains). Configuring them as user search
		// domains would silently elevate them to DNS-filter bypass —
		// reject so the operator decides explicitly.
		{"reject K8s .cluster.local", []string{".cluster.local"}, true},
		{"reject K8s .svc.cluster.local", []string{".svc.cluster.local"}, true},
		{"reject K8s .default.svc.cluster.local", []string{".default.svc.cluster.local"}, true},
		// Subdomains of the K8s suffixes are NOT auto-rejected — those
		// are user-namespaced rules and the operator's intent is clear.
		{"accept subdomain of K8s suffix", []string{".myns.svc.cluster.local"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSearchDomains(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("validateSearchDomains(%v) = nil, want error", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateSearchDomains(%v) = %v, want nil", tc.input, err)
			}
		})
	}
}

func TestAddSearchDomains_Dedup(t *testing.T) {
	cm := NewConfigManager()
	cm.config = &FirewallConfig{
		SearchDomains: []string{".compute.internal"},
	}
	cm.AddSearchDomains([]string{".compute.internal", ".ec2.internal", "EC2.INTERNAL"}, slog.Default())

	got := cm.GetSearchDomains()
	want := []string{".compute.internal", ".ec2.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSearchDomains() = %v, want %v", got, want)
	}
}

// HasSearchDomainSuffix is the non-allocating predicate used on the DNS
// hot path. It must match the same suffixes GetSearchDomains exposes,
// case-insensitively.
func TestHasSearchDomainSuffix(t *testing.T) {
	cm := NewConfigManager()
	cm.config = &FirewallConfig{}
	cm.AddSearchDomains([]string{".compute.internal", ".ec2.internal"}, slog.Default())

	tests := []struct {
		hostname string
		want     bool
	}{
		{"ip-10-0-0-5.us-west-2.compute.internal", true},
		{"bastion.ec2.internal", true},
		{"BASTION.EC2.INTERNAL", true}, // case-insensitive
		{"example.com", false},
		{"evilnotcompute.internal", false}, // boundary: leading dot required
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.hostname, func(t *testing.T) {
			if got := cm.HasSearchDomainSuffix(tc.hostname); got != tc.want {
				t.Errorf("HasSearchDomainSuffix(%q) = %v, want %v", tc.hostname, got, tc.want)
			}
		})
	}

	// Nil config must not panic; returns false.
	empty := NewConfigManager()
	if empty.HasSearchDomainSuffix("any.compute.internal") {
		t.Errorf("HasSearchDomainSuffix on nil config = true, want false")
	}
}

func TestAddSearchDomains_KeepsValidSkipsInvalid(t *testing.T) {
	cm := NewConfigManager()
	cm.config = &FirewallConfig{}
	// ".com" is invalid (a public suffix) — it should be skipped while
	// ".compute.internal" is still added. User-supplied config paths
	// (proto/JSON/env) still fail-loud via validateSearchDomains; only the
	// in-process auto-allow path is tolerant.
	cm.AddSearchDomains([]string{".compute.internal", ".com"}, slog.Default())

	got := cm.GetSearchDomains()
	want := []string{".compute.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSearchDomains() = %v, want %v (invalid entry skipped, valid kept)", got, want)
	}
}

// AddSearchDomains must no-op on a nil config, matching the behavior of the
// other auto-allow helpers (EnsureDNSAllowed / EnsureInfraAllowed /
// EnsureHostnameAllowed). Otherwise the no-config fallback path would
// partially succeed with only the search-domain set populated.
func TestAddSearchDomains_NoConfigIsNoOp(t *testing.T) {
	cm := NewConfigManager()
	// cm.config is intentionally nil — simulate the fallback path where
	// LoadConfig / LoadFromEnv / LoadConfigFromCargoWall all failed.
	cm.AddSearchDomains([]string{".compute.internal"}, slog.Default())

	if got := cm.GetSearchDomains(); got != nil {
		t.Errorf("GetSearchDomains() = %v, want nil (no-op on nil config)", got)
	}
	if cm.config != nil {
		t.Errorf("cm.config should remain nil; got %+v", cm.config)
	}
}

func TestLoadFromEnv_SearchDomains(t *testing.T) {
	// Clear other config env vars so LoadFromEnv only sees searchDomains.
	for _, env := range []string{
		"CARGOWALL_DEFAULT_ACTION",
		"CARGOWALL_ALLOWED_HOSTS",
		"CARGOWALL_ALLOWED_CIDRS",
		"CARGOWALL_BLOCKED_HOSTS",
		"CARGOWALL_BLOCKED_CIDRS",
	} {
		t.Setenv(env, "")
		os.Unsetenv(env)
	}
	t.Setenv("CARGOWALL_SEARCH_DOMAINS", ".compute.internal, .ec2.internal")

	cm := NewConfigManager()
	if err := cm.LoadFromEnv(); err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}

	got := cm.GetSearchDomains()
	want := []string{".compute.internal", ".ec2.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSearchDomains() = %v, want %v", got, want)
	}
}

// clearOtherCargowallEnv unsets every CARGOWALL_* config var except
// CARGOWALL_SEARCH_DOMAINS so search-domain validation tests aren't
// shadowed by an unrelated ambient env value (e.g. a developer or CI
// runner with CARGOWALL_DEFAULT_ACTION=invalid set, which would make
// LoadFromEnv error out before reaching the search-domain validation).
func clearOtherCargowallEnv(t *testing.T) {
	t.Helper()
	for _, env := range []string{
		"CARGOWALL_DEFAULT_ACTION",
		"CARGOWALL_ALLOWED_HOSTS",
		"CARGOWALL_ALLOWED_CIDRS",
		"CARGOWALL_BLOCKED_HOSTS",
		"CARGOWALL_BLOCKED_CIDRS",
	} {
		t.Setenv(env, "")
		os.Unsetenv(env)
	}
}

// clearAllCargowallEnv unsets every CARGOWALL_* config var, including
// CARGOWALL_SEARCH_DOMAINS. Use when a test needs a truly empty env state;
// clearOtherCargowallEnv deliberately leaves CARGOWALL_SEARCH_DOMAINS for
// search-domain tests that set it themselves.
func clearAllCargowallEnv(t *testing.T) {
	t.Helper()
	clearOtherCargowallEnv(t)
	t.Setenv("CARGOWALL_SEARCH_DOMAINS", "")
	os.Unsetenv("CARGOWALL_SEARCH_DOMAINS")
}

// writeJSONConfig writes content to a temp file under t.TempDir() (which
// gets removed at test end) and returns the path. Used by LoadConfig tests
// that previously duplicated the os.CreateTemp + defer os.Remove dance.
func writeJSONConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write JSON config: %v", err)
	}
	return path
}

func TestLoadFromEnv_SearchDomains_Invalid(t *testing.T) {
	clearOtherCargowallEnv(t)
	t.Setenv("CARGOWALL_SEARCH_DOMAINS", ".com")
	cm := NewConfigManager()
	err := cm.LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "CARGOWALL_SEARCH_DOMAINS") {
		t.Errorf("LoadFromEnv() with .com = %v, want error mentioning CARGOWALL_SEARCH_DOMAINS", err)
	}
}

// CARGOWALL_SEARCH_DOMAINS=" " (whitespace) is the user setting the var
// but with no real value — fail loud instead of silently parsing as
// no-config.
func TestLoadFromEnv_SearchDomains_WhitespaceOnly(t *testing.T) {
	clearOtherCargowallEnv(t)
	t.Setenv("CARGOWALL_SEARCH_DOMAINS", " ")
	cm := NewConfigManager()
	err := cm.LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "CARGOWALL_SEARCH_DOMAINS") {
		t.Errorf("LoadFromEnv() with whitespace-only = %v, want error mentioning CARGOWALL_SEARCH_DOMAINS", err)
	}
}

// Trailing comma in the CSV (a common user typo) leaves an empty element
// after split — it should also fail loud so the user finds the mistake.
func TestLoadFromEnv_SearchDomains_TrailingComma(t *testing.T) {
	clearOtherCargowallEnv(t)
	t.Setenv("CARGOWALL_SEARCH_DOMAINS", ".compute.internal,")
	cm := NewConfigManager()
	err := cm.LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "CARGOWALL_SEARCH_DOMAINS") {
		t.Errorf("LoadFromEnv() with trailing comma = %v, want error mentioning CARGOWALL_SEARCH_DOMAINS", err)
	}
}

// LoadConfig from JSON followed by AddSearchDomains (the auto-allow path)
// must merge and dedup — neither path is allowed to clobber the other.
func TestLoadConfig_ThenAddSearchDomains_Merges(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "cargowall-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	configData := `{
		"defaultAction": "deny",
		"rules": [],
		"searchDomains": [".user.example.com"]
	}`
	if _, err := tmpfile.Write([]byte(configData)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	cm := NewConfigManager()
	if err := cm.LoadConfig(tmpfile.Name()); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Auto-allow path: adds AWS suffixes plus a duplicate of the JSON entry.
	cm.AddSearchDomains([]string{".compute.internal", ".ec2.internal", ".user.example.com"}, slog.Default())

	got := cm.GetSearchDomains()
	want := []string{".user.example.com", ".compute.internal", ".ec2.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSearchDomains() after merge = %v, want %v", got, want)
	}
}

// Concurrent loaders and readers must never observe a torn state
// (new cm.config but old cm.resolvedRules). Run under -race to catch
// any missed lock coverage. The deterministic check: every
// MatchHostnameRule reading must return EITHER the pre-load action
// (deny, default) OR the post-load action (allow) — never a stale
// resolved-rules view that disagrees with the live config.
func TestLoadConfigFromRules_AtomicWithResolveRules(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("initial LoadConfigFromRules() error = %v", err)
	}

	const (
		writes         = 200
		readers        = 4
		readsPerReader = 500
	)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < writes; i++ {
			var rules []Rule
			if i%2 == 0 {
				rules = []Rule{
					{Type: RuleTypeHostname, Value: "test.example.com", Action: ActionAllow},
				}
			}
			if err := cm.LoadConfigFromRules(rules, ActionDeny); err != nil {
				t.Errorf("LoadConfigFromRules iter %d: %v", i, err)
				return
			}
		}
	}()

	// Readers run in parallel with the writer. Each must always see a
	// coherent (Action, value) for test.example.com — either ("allow",
	// "test.example.com") or ("", "") matching the live config. A torn
	// read where action=allow but value="" (or vice versa) would mean
	// new cm.config was visible before its resolved-rule view.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < readsPerReader; i++ {
				v := cm.MatchHostnameRule("test.example.com")
				switch {
				case v.HasAllow():
					if v.AllowRule != "test.example.com" {
						t.Errorf("torn read: HasAllow but AllowRule=%q", v.AllowRule)
						return
					}
				case !v.Matched():
					// No rule visible — fine (rule may be in the process of being added).
				default:
					t.Errorf("unexpected verdict %+v", v)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// pickDenyForm: exact > broader-port > full-wins. Direct unit tests pin
// the helper independently of the surrounding MatchHostnameRule logic.
func TestPickDenyForm(t *testing.T) {
	tests := []struct {
		name          string
		valueFull     string
		hostname      string
		portsFull     []Port
		valueStripped string
		stripped      string
		portsStripped []Port
		wantStripped  bool
	}{
		{
			name:      "stripped exact, full parent — stripped wins",
			valueFull: "compute.internal", hostname: "blocked.compute.internal", portsFull: nil,
			valueStripped: "blocked", stripped: "blocked", portsStripped: nil,
			wantStripped: true,
		},
		{
			name:      "full exact, stripped parent — full wins",
			valueFull: "blocked.compute.internal", hostname: "blocked.compute.internal", portsFull: nil,
			valueStripped: "internal", stripped: "blocked", portsStripped: nil,
			wantStripped: false,
		},
		{
			name:      "both parent, stripped broader (no ports) — stripped wins",
			valueFull: "compute.internal", hostname: "x.compute.internal", portsFull: []Port{{Port: 443, Protocol: ProtocolTCP}},
			valueStripped: "", stripped: "x", portsStripped: nil,
			wantStripped: true,
		},
		{
			name:      "both parent, full broader (no ports) — full wins",
			valueFull: "", hostname: "x.compute.internal", portsFull: nil,
			valueStripped: "internal", stripped: "x", portsStripped: []Port{{Port: 443, Protocol: ProtocolTCP}},
			wantStripped: false,
		},
		{
			name:      "no dominance — full wins by default",
			valueFull: "a", hostname: "ab", portsFull: []Port{{Port: 80, Protocol: ProtocolTCP}},
			valueStripped: "b", stripped: "cb", portsStripped: []Port{{Port: 443, Protocol: ProtocolTCP}},
			wantStripped: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pickDenyForm(tc.valueFull, tc.hostname, tc.portsFull, tc.valueStripped, tc.stripped, tc.portsStripped)
			if got != tc.wantStripped {
				t.Errorf("pickDenyForm = %v, want %v", got, tc.wantStripped)
			}
		})
	}
}

// pickAllowForm: stripped wins iff stripped-exact AND full-not-exact.
func TestPickAllowForm(t *testing.T) {
	tests := []struct {
		name          string
		valueFull     string
		hostname      string
		valueStripped string
		stripped      string
		wantStripped  bool
	}{
		{
			name:      "stripped exact, full parent — stripped wins",
			valueFull: "compute.internal", hostname: "bastion.compute.internal",
			valueStripped: "bastion", stripped: "bastion",
			wantStripped: true,
		},
		{
			name:      "full exact, stripped parent — full wins (returns false)",
			valueFull: "bastion.compute.internal", hostname: "bastion.compute.internal",
			valueStripped: "internal", stripped: "bastion",
			wantStripped: false,
		},
		{
			name:      "both exact — full wins (returns false)",
			valueFull: "bastion.compute.internal", hostname: "bastion.compute.internal",
			valueStripped: "bastion", stripped: "bastion",
			wantStripped: false,
		},
		{
			name:      "neither exact — full wins",
			valueFull: "compute.internal", hostname: "x.compute.internal",
			valueStripped: "internal", stripped: "x",
			wantStripped: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pickAllowForm(tc.valueFull, tc.hostname, tc.valueStripped, tc.stripped)
			if got != tc.wantStripped {
				t.Errorf("pickAllowForm = %v, want %v", got, tc.wantStripped)
			}
		})
	}
}

// normalizeRules canonicalises rule values at load time so cm.config.Rules
// and cm.resolvedRules share the same byte sequence: hostnames are
// lower-cased and CIDRs are canonicalised (issue #64).
func TestNormalizeRules_CanonicalisesHostnameAndCIDR(t *testing.T) {
	rules := []Rule{
		{Type: RuleTypeHostname, Value: "GitHub.COM", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "*.Example.NET", Action: ActionAllow},
		{Type: RuleTypeCIDR, Value: "10.0.0.0/8", Action: ActionAllow},
	}
	normalizeRules(rules)
	if rules[0].Value != "github.com" {
		t.Errorf("hostname[0] = %q, want %q", rules[0].Value, "github.com")
	}
	if rules[1].Value != "*.example.net" {
		t.Errorf("hostname[1] = %q, want %q", rules[1].Value, "*.example.net")
	}
	if rules[2].Value != "10.0.0.0/8" {
		t.Errorf("already-canonical CIDR changed: got %q", rules[2].Value)
	}
}

// canonicalCIDR collapses textually-different-but-equivalent CIDR/IP forms to
// one canonical string (issue #64), and leaves unparseable values untouched so
// resolveRules can log them.
func TestCanonicalCIDR(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already-canonical IPv4 CIDR", "10.0.0.0/8", "10.0.0.0/8"},
		{"bare IPv4 → /32", "8.8.8.8", "8.8.8.8/32"},
		{"explicit /32 unchanged", "8.8.8.8/32", "8.8.8.8/32"},
		{"IPv4 host bits masked", "10.0.0.5/8", "10.0.0.0/8"},
		{"IPv6 case-folded", "2001:DB8::/32", "2001:db8::/32"},
		{"IPv6 zero-compression canonicalised", "2001:db8:0:0::/64", "2001:db8::/64"},
		{"bare IPv6 → /128", "2001:db8::1", "2001:db8::1/128"},
		{"bare IPv6 case-folded → /128", "2001:DB8::1", "2001:db8::1/128"},
		{"unparseable left untouched", "not-a-cidr", "not-a-cidr"},
		{"empty left untouched", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalCIDR(tc.in); got != tc.want {
				t.Errorf("canonicalCIDR(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Equivalent-but-differently-spelled CIDR forms must collapse to one rule and
// union their ports through the load-time merge (issue #64), the CIDR analogue
// of TestMergeDuplicateRules_HostnameAllowUnion.
func TestMergeDuplicateRules_EquivalentCIDRFormsUnion(t *testing.T) {
	tcp443 := Port{Port: 443, Protocol: ProtocolTCP}
	tcp80 := Port{Port: 80, Protocol: ProtocolTCP}

	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		// Same /128 host expressed as upper-case prefix, bare IP, and
		// lower-case prefix — three spellings of one rule.
		{Type: RuleTypeCIDR, Value: "2001:DB8::1/128", Ports: []Port{tcp443}, Action: ActionAllow},
		{Type: RuleTypeCIDR, Value: "2001:db8::1", Ports: []Port{tcp80}, Action: ActionAllow},
		{Type: RuleTypeCIDR, Value: "2001:db8:0:0::1/128", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cidrRules := make([]Rule, 0, len(cm.config.Rules))
	for _, r := range cm.config.Rules {
		if r.Type == RuleTypeCIDR {
			cidrRules = append(cidrRules, r)
		}
	}
	if len(cidrRules) != 1 {
		t.Fatalf("got %d CIDR rules, want 1 (equivalent forms should merge): %+v", len(cidrRules), cidrRules)
	}
	if cidrRules[0].Value != "2001:db8::1/128" {
		t.Errorf("merged CIDR value = %q, want %q", cidrRules[0].Value, "2001:db8::1/128")
	}
	// The third entry carries no ports — the all-ports sentinel absorbs the
	// rest, so the union is all-ports (empty).
	if len(cidrRules[0].Ports) != 0 {
		t.Errorf("merged ports = %v, want all-ports (empty)", cidrRules[0].Ports)
	}
}

func TestLoadConfigFromCargoWall_SearchDomains(t *testing.T) {
	policy := &cargowallv1pb.CargoWallPolicy{
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		SearchDomains: []string{".compute.internal", "ec2.internal"},
	}
	cm := NewConfigManager()
	if err := cm.LoadConfigFromCargoWall(policy); err != nil {
		t.Fatalf("LoadConfigFromCargoWall() error = %v", err)
	}

	got := cm.GetSearchDomains()
	want := []string{".compute.internal", ".ec2.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSearchDomains() = %v, want %v", got, want)
	}
}

// =============================================================================
// Direct tests for previously-untested exported functions (Phase 3)
// =============================================================================

// CheckIPRuleConflict finds the most-specific CIDR rule matching an IP and
// reports whether its action conflicts with the hostname-derived action.
// Cover the matrix: no CIDR match, matching CIDR with same action, matching
// CIDR with deny vs hostname allow, port-overlap-only conflict, port-disjoint
// (no conflict), IPv6 CIDR.
func TestCheckIPRuleConflict(t *testing.T) {
	tests := []struct {
		name           string
		rules          []Rule
		ip             string
		hostnameAction Action
		hostnamePorts  []Port
		wantAction     Action
		wantConflict   bool
		wantRuleValue  string
	}{
		{
			name:           "no CIDR rule covers IP",
			rules:          nil,
			ip:             "10.0.0.5",
			hostnameAction: ActionAllow,
			wantAction:     ActionAllow,
			wantConflict:   false,
		},
		{
			name: "matching CIDR has same action — no conflict",
			rules: []Rule{
				{Type: RuleTypeCIDR, Value: "10.0.0.0/8", Action: ActionAllow},
			},
			ip:             "10.0.0.5",
			hostnameAction: ActionAllow,
			wantAction:     ActionAllow,
			wantConflict:   false,
		},
		{
			name: "CIDR deny vs hostname allow — deny wins, conflict reported",
			rules: []Rule{
				{Type: RuleTypeCIDR, Value: "10.0.0.0/8", Action: ActionDeny},
			},
			ip:             "10.0.0.5",
			hostnameAction: ActionAllow,
			wantAction:     ActionDeny,
			wantConflict:   true,
			wantRuleValue:  "10.0.0.0/8",
		},
		{
			name: "longest-prefix wins (most specific)",
			rules: []Rule{
				{Type: RuleTypeCIDR, Value: "10.0.0.0/8", Action: ActionAllow},
				{Type: RuleTypeCIDR, Value: "10.0.0.0/24", Action: ActionDeny},
			},
			ip:             "10.0.0.5",
			hostnameAction: ActionAllow,
			wantAction:     ActionDeny,
			wantConflict:   true,
			wantRuleValue:  "10.0.0.0/24",
		},
		{
			name: "ports overlap → conflict",
			rules: []Rule{
				{Type: RuleTypeCIDR, Value: "10.0.0.0/8", Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionDeny},
			},
			ip:             "10.0.0.5",
			hostnameAction: ActionAllow,
			hostnamePorts:  []Port{{Port: 443, Protocol: ProtocolTCP}},
			wantAction:     ActionDeny,
			wantConflict:   true,
			wantRuleValue:  "10.0.0.0/8",
		},
		{
			name: "ports disjoint → no conflict even though IP matches",
			rules: []Rule{
				{Type: RuleTypeCIDR, Value: "10.0.0.0/8", Ports: []Port{{Port: 80, Protocol: ProtocolTCP}}, Action: ActionDeny},
			},
			ip:             "10.0.0.5",
			hostnameAction: ActionAllow,
			hostnamePorts:  []Port{{Port: 443, Protocol: ProtocolTCP}},
			wantAction:     ActionAllow,
			wantConflict:   false,
		},
		{
			// A bare IP is canonicalised to an explicit /32 at load time
			// (issue #64), so the reported conflicting rule is "10.0.0.5/32".
			name: "single-IP rule canonicalised to /32",
			rules: []Rule{
				{Type: RuleTypeCIDR, Value: "10.0.0.5", Action: ActionDeny},
			},
			ip:             "10.0.0.5",
			hostnameAction: ActionAllow,
			wantAction:     ActionDeny,
			wantConflict:   true,
			wantRuleValue:  "10.0.0.5/32",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := NewConfigManager()
			if err := cm.LoadConfigFromRules(tc.rules, ActionDeny); err != nil {
				t.Fatalf("LoadConfigFromRules() error = %v", err)
			}
			action, hasConflict, ruleValue := cm.CheckIPRuleConflict(
				net.ParseIP(tc.ip), "example.com", tc.hostnameAction, tc.hostnamePorts,
			)
			if action != tc.wantAction {
				t.Errorf("action = %q, want %q", action, tc.wantAction)
			}
			if hasConflict != tc.wantConflict {
				t.Errorf("hasConflict = %v, want %v", hasConflict, tc.wantConflict)
			}
			if tc.wantRuleValue != "" && ruleValue != tc.wantRuleValue {
				t.Errorf("ruleValue = %q, want %q", ruleValue, tc.wantRuleValue)
			}
		})
	}
}

// ForwardMatchIP looks up a hostname whose cached IPs include the given IP.
// Pattern rules are NOT in trackedHostnames so they don't match this path.
func TestForwardMatchIP(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "api.github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "*.example.com", Action: ActionAllow}, // pattern — not in trackedHostnames
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.UpdateDNSMapping("github.com", "140.82.114.4")
	cm.UpdateDNSMapping("api.github.com", "140.82.114.6")
	// Pattern rule has no tracked hostname; this mapping won't help ForwardMatchIP.
	cm.UpdateDNSMapping("anything.example.com", "1.2.3.4")

	tests := []struct {
		ip   string
		want string
	}{
		{"140.82.114.4", "github.com"},
		{"140.82.114.6", "api.github.com"},
		{"1.2.3.4", ""}, // pattern hostnames aren't tracked
		{"9.9.9.9", ""}, // unknown
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			if got := cm.ForwardMatchIP(tc.ip); got != tc.want {
				t.Errorf("ForwardMatchIP(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

// LookupHostnameByIP has two lookup paths: the ipToHostname reverse map
// (preferred), and a fallback scan of hostnameCache. Cover both.
func TestLookupHostnameByIP(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	// Path (a): IP in ipToHostname reverse map via UpdateDNSMapping.
	cm.UpdateDNSMapping("github.com", "140.82.114.4")
	if got := cm.LookupHostnameByIP("140.82.114.4"); got != "github.com" {
		t.Errorf("reverse-map path: got %q, want github.com", got)
	}

	// Path (b): IP in hostnameCache forward map but NOT in reverse map.
	// Directly populate hostnameCache (whitebox) to isolate the fallback.
	cm.mu.Lock()
	cm.hostnameCache["github.com"] = append(cm.hostnameCache["github.com"], net.ParseIP("140.82.114.99"))
	cm.mu.Unlock()
	if got := cm.LookupHostnameByIP("140.82.114.99"); got != "github.com" {
		t.Errorf("forward-cache fallback: got %q, want github.com", got)
	}

	// Path (c): IP in neither map → empty.
	if got := cm.LookupHostnameByIP("9.9.9.9"); got != "" {
		t.Errorf("unknown IP: got %q, want empty", got)
	}
}

// StripSearchDomains removes the longest matching K8s default or user-
// configured suffix and preserves the surviving prefix's original case.
func TestStripSearchDomains(t *testing.T) {
	tests := []struct {
		name          string
		searchDomains []string
		hostname      string
		want          string
	}{
		// K8s defaults are always active.
		{"k8s default", nil, "myservice.default.svc.cluster.local", "myservice"},
		{"k8s svc", nil, "myservice.svc.cluster.local", "myservice"},
		{"k8s cluster", nil, "myservice.cluster.local", "myservice"},

		// User-configured suffixes.
		{"user suffix", []string{".compute.internal"}, "bastion.compute.internal", "bastion"},

		// Longest-match between K8s and user. ".cluster.local" is K8s;
		// user adds ".internal.cluster.local" — the longer wins.
		{
			name:          "longest wins (user beats K8s)",
			searchDomains: []string{".internal.cluster.local"},
			hostname:      "x.internal.cluster.local",
			want:          "x",
		},

		// Case preservation on the surviving prefix; case-insensitive suffix match.
		{"preserves prefix case", []string{".compute.internal"}, "Bastion.Compute.Internal", "Bastion"},

		// FQDN trailing dot — DOES NOT strip (suffix match fails). Pin current
		// behavior so callers know they must trim the trailing dot themselves.
		{"FQDN trailing dot not stripped", []string{".compute.internal"}, "bastion.compute.internal.", "bastion.compute.internal."},

		// No match — returns input verbatim.
		{"no match", []string{".compute.internal"}, "example.com", "example.com"},

		// Empty input.
		{"empty input", nil, "", ""},

		// Hostname IS the suffix — defensive: returns empty (suffix consumes all).
		{
			name:          "hostname equals suffix without leading label",
			searchDomains: []string{".compute.internal"},
			hostname:      ".compute.internal",
			want:          "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := newCMWithSearchDomains(t, nil, tc.searchDomains...)
			if got := cm.StripSearchDomains(tc.hostname); got != tc.want {
				t.Errorf("StripSearchDomains(%q) = %q, want %q", tc.hostname, got, tc.want)
			}
		})
	}
}

// UpdateDNSMapping canonicalises the hostname to lowercase, stores
// (hostname, ip) in the reverse map + last-seen timestamp, and conditionally
// appends to hostnameCache only when the hostname is tracked.
func TestUpdateDNSMapping(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	// Mixed-case hostname must be stored lowercase so reverse lookups work.
	cm.UpdateDNSMapping("GitHub.COM", "140.82.114.4")
	if got := cm.LookupHostnameByIP("140.82.114.4"); got != "github.com" {
		t.Errorf("hostname not lowercased: got %q, want github.com", got)
	}

	// Tracked hostname → hostnameCache populated.
	cm.mu.RLock()
	cached := cm.hostnameCache["github.com"]
	cm.mu.RUnlock()
	if len(cached) != 1 || cached[0].String() != "140.82.114.4" {
		t.Errorf("hostnameCache[github.com] = %v, want [140.82.114.4]", cached)
	}

	// Same (hostname, ip) again → no duplicate in hostnameCache.
	cm.UpdateDNSMapping("github.com", "140.82.114.4")
	cm.mu.RLock()
	cached = cm.hostnameCache["github.com"]
	cm.mu.RUnlock()
	if len(cached) != 1 {
		t.Errorf("hostnameCache duplicated entry: got %v, want single entry", cached)
	}

	// Different IP for tracked hostname → appended.
	cm.UpdateDNSMapping("github.com", "140.82.114.5")
	cm.mu.RLock()
	cached = cm.hostnameCache["github.com"]
	cm.mu.RUnlock()
	if len(cached) != 2 {
		t.Errorf("hostnameCache len = %d, want 2", len(cached))
	}

	// Untracked hostname → reverse map updated, hostnameCache NOT populated.
	cm.UpdateDNSMapping("unknown.example.com", "1.2.3.4")
	if got := cm.LookupHostnameByIP("1.2.3.4"); got != "unknown.example.com" {
		t.Errorf("reverse map for untracked host: got %q, want unknown.example.com", got)
	}
	cm.mu.RLock()
	_, exists := cm.hostnameCache["unknown.example.com"]
	cm.mu.RUnlock()
	if exists {
		t.Errorf("hostnameCache must not have entry for untracked hostname")
	}

	// ipLastSeen recorded.
	cm.mu.RLock()
	_, seen := cm.ipLastSeen["140.82.114.4"]
	cm.mu.RUnlock()
	if !seen {
		t.Errorf("ipLastSeen must record timestamp for updated IP")
	}
}

// RecordCNAMEChain stores a lowercased copy of the chain keyed by IP and
// LookupCNAMEChain returns an independent copy. Empty inputs are ignored, and
// the entry shares the ipLastSeen-based cleanup lifecycle.
func TestRecordAndLookupCNAMEChain(t *testing.T) {
	cm := NewConfigManager()

	// nil/empty inputs are no-ops.
	cm.RecordCNAMEChain("", []string{"a", "b"})
	cm.RecordCNAMEChain("1.2.3.4", nil)
	if got := cm.LookupCNAMEChain("1.2.3.4"); got != nil {
		t.Errorf("empty chain must not be recorded: got %v", got)
	}

	// Mixed-case chain is stored lowercase.
	cm.RecordCNAMEChain("23.62.177.200", []string{"WWW.Microsoft.com", "E13678.dscb.AkamaiEdge.net"})
	got := cm.LookupCNAMEChain("23.62.177.200")
	want := []string{"www.microsoft.com", "e13678.dscb.akamaiedge.net"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LookupCNAMEChain = %v, want %v", got, want)
	}

	// Returned slice is a copy — mutating it must not corrupt cache state.
	got[0] = "tampered"
	if again := cm.LookupCNAMEChain("23.62.177.200"); again[0] != "www.microsoft.com" {
		t.Errorf("LookupCNAMEChain must return a copy; cache mutated to %v", again)
	}

	// Unknown IP → nil.
	if got := cm.LookupCNAMEChain("9.9.9.9"); got != nil {
		t.Errorf("unknown IP must return nil, got %v", got)
	}

	// ipLastSeen is touched so cleanupOldEntries can evict the chain.
	cm.mu.Lock()
	cm.ipLastSeen["23.62.177.200"] = time.Now().Add(-2 * dnsCacheTTL)
	cm.cleanupOldEntries()
	cm.mu.Unlock()
	if got := cm.LookupCNAMEChain("23.62.177.200"); got != nil {
		t.Errorf("stale CNAME chain must be evicted by cleanupOldEntries, got %v", got)
	}
}

// =============================================================================
// Direct tests for internal helpers (Phase 4)
// =============================================================================

// UnionPorts: empty (all-ports) absorbs the other; otherwise dedup'd
// union. Port is a comparable struct, so {Port, Protocol} is the dedup key.
func TestUnionPorts(t *testing.T) {
	tcp443 := Port{Port: 443, Protocol: ProtocolTCP}
	tcp80 := Port{Port: 80, Protocol: ProtocolTCP}
	udp443 := Port{Port: 443, Protocol: ProtocolUDP}

	tests := []struct {
		name   string
		p1, p2 []Port
		want   []Port
	}{
		{"both nil", nil, nil, nil},
		{"left empty absorbs", nil, []Port{tcp443}, nil},
		{"right empty absorbs", []Port{tcp443}, nil, nil},
		{"disjoint union", []Port{tcp80}, []Port{tcp443}, []Port{tcp80, tcp443}},
		{"identical dedup", []Port{tcp443}, []Port{tcp443}, []Port{tcp443}},
		{"same port different protocol kept", []Port{tcp443}, []Port{udp443}, []Port{tcp443, udp443}},
		{"partial overlap", []Port{tcp80, tcp443}, []Port{tcp443}, []Port{tcp80, tcp443}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := UnionPorts(tc.p1, tc.p2)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("UnionPorts(%v, %v) = %v, want %v", tc.p1, tc.p2, got, tc.want)
			}
		})
	}
}

// chosenAttributionName picks the right hostname for downstream re-lookups:
// exact / pattern rules attribute to the queried name; parent rules attribute
// to the parent's value (so the parent rule fires on re-lookup).
func TestChosenAttributionName(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		ruleValue string
		want      string
	}{
		{"exact match returns query", "github.com", "github.com", "github.com"},
		{"pattern returns query", "api.github.com", "*.github.com", "api.github.com"},
		{"pattern with double-star returns query", "a.b.example.com", "**.example.com", "a.b.example.com"},
		{"parent returns parent value", "api.github.com", "github.com", "github.com"},
		{"different value (not a parent) returns ruleValue", "x.y", "y", "y"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := chosenAttributionName(tc.query, tc.ruleValue); got != tc.want {
				t.Errorf("chosenAttributionName(%q, %q) = %q, want %q", tc.query, tc.ruleValue, got, tc.want)
			}
		})
	}
}

// autoAllowedPortMatch: empty rulePorts means "all ports"; otherwise both
// port number AND protocol must match (ProtocolsOverlap handles ProtocolAll
// on either side).
func TestAutoAllowedPortMatch(t *testing.T) {
	tests := []struct {
		name       string
		rulePorts  []Port
		queryPort  uint16
		queryProto ProtocolType
		want       bool
	}{
		{"empty rule ports = all ports", nil, 443, ProtocolTCP, true},
		{"exact TCP match", []Port{{Port: 443, Protocol: ProtocolTCP}}, 443, ProtocolTCP, true},
		{"port match, protocol mismatch", []Port{{Port: 443, Protocol: ProtocolTCP}}, 443, ProtocolUDP, false},
		{"different port", []Port{{Port: 80, Protocol: ProtocolTCP}}, 443, ProtocolTCP, false},
		{"rule ProtocolAll matches TCP query", []Port{{Port: 443, Protocol: ProtocolAll}}, 443, ProtocolTCP, true},
		{"rule TCP matches ProtocolAll query", []Port{{Port: 443, Protocol: ProtocolTCP}}, 443, ProtocolAll, true},
		{"multiple ports, query matches second", []Port{{Port: 80, Protocol: ProtocolTCP}, {Port: 443, Protocol: ProtocolTCP}}, 443, ProtocolTCP, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoAllowedPortMatch(tc.rulePorts, tc.queryPort, tc.queryProto); got != tc.want {
				t.Errorf("autoAllowedPortMatch(%v, %d, %s) = %v, want %v",
					tc.rulePorts, tc.queryPort, tc.queryProto, got, tc.want)
			}
		})
	}
}

// convertAction translates protobuf enum to Action; unknown values default
// to Deny (safe) and emit a slog.Warn so proto/code drift is diagnosable.
func TestConvertAction(t *testing.T) {
	tests := []struct {
		name     string
		input    datapb.CargoWallActionType
		want     Action
		wantWarn bool
	}{
		{"allow", datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW, ActionAllow, false},
		{"deny", datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY, ActionDeny, false},
		{"unspecified defaults to deny + warns", datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_UNSPECIFIED, ActionDeny, true},
		{"future enum value defaults to deny + warns", datapb.CargoWallActionType(99), ActionDeny, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var captured []string
			orig := slog.Default()
			t.Cleanup(func() { slog.SetDefault(orig) })
			slog.SetDefault(slog.New(slog.NewTextHandler(&captureWriter{out: &captured}, nil)))

			got := convertAction(tc.input)
			if got != tc.want {
				t.Errorf("convertAction(%v) = %q, want %q", tc.input, got, tc.want)
			}
			sawWarn := false
			for _, line := range captured {
				if strings.Contains(line, "Unknown CargoWallActionType") {
					sawWarn = true
					break
				}
			}
			if sawWarn != tc.wantWarn {
				t.Errorf("warn-on-unknown: got %v, want %v (captured: %v)", sawWarn, tc.wantWarn, captured)
			}
		})
	}
}

// captureWriter collects newline-delimited log records for TestConvertAction.
type captureWriter struct {
	out *[]string
}

func (cw *captureWriter) Write(p []byte) (int, error) {
	*cw.out = append(*cw.out, string(p))
	return len(p), nil
}

// convertProtocol translates protobuf enum to ProtocolType; unknown values
// return an error (unlike convertAction's safe-default-to-deny).
func TestConvertProtocol(t *testing.T) {
	tests := []struct {
		name    string
		input   datapb.CargoWallProtocol
		want    ProtocolType
		wantErr bool
	}{
		{"all", datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_ALL, ProtocolAll, false},
		{"tcp", datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_TCP, ProtocolTCP, false},
		{"udp", datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_UDP, ProtocolUDP, false},
		{"icmp", datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_ICMP, ProtocolICMP, false},
		{"future enum value returns error", datapb.CargoWallProtocol(99), "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := convertProtocol(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("convertProtocol(%v) error = nil, want non-nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("convertProtocol(%v) error = %v, want nil", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("convertProtocol(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ProtocolsOverlap: ProtocolAll on either side absorbs; otherwise exact match.
func TestProtocolsOverlap(t *testing.T) {
	tests := []struct {
		a, b ProtocolType
		want bool
	}{
		{ProtocolTCP, ProtocolTCP, true},
		{ProtocolUDP, ProtocolUDP, true},
		{ProtocolICMP, ProtocolICMP, true},
		{ProtocolTCP, ProtocolUDP, false},
		{ProtocolTCP, ProtocolICMP, false},
		{ProtocolUDP, ProtocolICMP, false},
		{ProtocolAll, ProtocolTCP, true},
		{ProtocolTCP, ProtocolAll, true},
		{ProtocolAll, ProtocolAll, true},
		// Defensive: empty strings (zero-value ProtocolType) match each other.
		{"", "", true},
	}
	for _, tc := range tests {
		t.Run(string(tc.a)+"_vs_"+string(tc.b), func(t *testing.T) {
			if got := ProtocolsOverlap(tc.a, tc.b); got != tc.want {
				t.Errorf("ProtocolsOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// =============================================================================
// Edge cases (Phase 5)
// =============================================================================

// cleanupOldEntries removes ipToHostname / ipLastSeen entries older than the
// package-level dnsCacheTTL (24h). Fresh entries must survive.
func TestCleanupOldEntries_RemovesAgedEntries(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	// Seed: one fresh entry (now), one aged past dnsCacheTTL (24h + 1m old).
	now := time.Now()
	cm.mu.Lock()
	cm.ipToHostname["1.2.3.4"] = "fresh.example.com"
	cm.ipLastSeen["1.2.3.4"] = now
	cm.ipToHostname["5.6.7.8"] = "aged.example.com"
	cm.ipLastSeen["5.6.7.8"] = now.Add(-25 * time.Hour)
	cm.cleanupOldEntries()
	cm.mu.Unlock()

	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if _, ok := cm.ipToHostname["1.2.3.4"]; !ok {
		t.Errorf("fresh entry removed unexpectedly")
	}
	if _, ok := cm.ipToHostname["5.6.7.8"]; ok {
		t.Errorf("aged entry should have been removed from ipToHostname")
	}
	if _, ok := cm.ipLastSeen["5.6.7.8"]; ok {
		t.Errorf("aged entry should have been removed from ipLastSeen")
	}
}

// UpdateDNSMapping triggers cleanupOldEntries when ipToHostname grows past
// maxCacheSize. Use a small cache size for a fast deterministic test.
func TestUpdateDNSMapping_TriggersCleanupAtCacheLimit(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.mu.Lock()
	cm.maxCacheSize = 3
	// Pre-fill with 3 aged entries (all eligible for cleanup).
	aged := time.Now().Add(-25 * time.Hour)
	cm.ipToHostname["1.1.1.1"] = "a.example.com"
	cm.ipLastSeen["1.1.1.1"] = aged
	cm.ipToHostname["2.2.2.2"] = "b.example.com"
	cm.ipLastSeen["2.2.2.2"] = aged
	cm.ipToHostname["3.3.3.3"] = "c.example.com"
	cm.ipLastSeen["3.3.3.3"] = aged
	cm.mu.Unlock()

	// One more UpdateDNSMapping pushes the count to 4, exceeding maxCacheSize
	// (3). The aged entries should be evicted.
	cm.UpdateDNSMapping("d.example.com", "4.4.4.4")

	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if got := len(cm.ipToHostname); got != 1 {
		t.Errorf("ipToHostname size = %d, want 1 (3 aged evicted, 1 fresh remains)", got)
	}
	if _, ok := cm.ipToHostname["4.4.4.4"]; !ok {
		t.Errorf("fresh entry missing from ipToHostname")
	}
}

// EnsureHostnameAllowed lowercases the hostname so MatchHostnameRule's
// case-insensitive lookup finds it.
func TestEnsureHostnameAllowed_MixedCase(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.EnsureHostnameAllowed("GitHub.COM", []Port{PortHTTPS}, AutoAddedTypeGitHubService)

	rules := cm.GetResolvedRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 resolved rule, got %d", len(rules))
	}
	if rules[0].Value != "github.com" {
		t.Errorf("rule.Value = %q, want %q", rules[0].Value, "github.com")
	}
}

// EnsureHostnameAllowed must short-circuit if the hostname is already
// tracked as allowed (no duplicate rule).
func TestEnsureHostnameAllowed_AlreadyTrackedNoOp(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)
	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)

	if got := len(cm.GetResolvedRules()); got != 1 {
		t.Errorf("expected 1 rule after duplicate EnsureHostnameAllowed, got %d", got)
	}
}

// EnsureHostnameAllowed pins behavior for pattern values like "*.foo.com":
// the rule is stored verbatim with Pattern=nil (current implementation
// doesn't compile patterns added via this path), so it matches via the
// exact / parent path only — NOT as a wildcard. Documents the contract so
// future maintainers either compile patterns here or remove this comment.
func TestEnsureHostnameAllowed_PatternStoredAsLiteral(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.EnsureHostnameAllowed("*.foo.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)

	// Exact-name lookup against the pattern string itself does match.
	if v := cm.MatchHostnameRule("*.foo.com"); !v.HasAllow() {
		t.Errorf("exact lookup against pattern string: got verdict %+v, want allow", v)
	}
	// But sub.foo.com does NOT match — because the rule is stored as a
	// literal hostname, not a compiled pattern.
	if v := cm.MatchHostnameRule("sub.foo.com"); v.Matched() {
		t.Errorf("pattern-style lookup against EnsureHostnameAllowed rule: got verdict %+v, want no match (current behavior)", v)
	}
}

// LoadFromEnv with both CARGOWALL_ALLOWED_HOSTS and CARGOWALL_BLOCKED_HOSTS
// produces rules of each action.
func TestLoadFromEnv_AllowedAndBlockedHosts(t *testing.T) {
	clearAllCargowallEnv(t)
	t.Setenv("CARGOWALL_ALLOWED_HOSTS", "github.com:443")
	t.Setenv("CARGOWALL_BLOCKED_HOSTS", "evil.example.com")

	cm := NewConfigManager()
	if err := cm.LoadFromEnv(); err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	actions := map[string]Action{}
	for _, r := range cm.config.Rules {
		actions[r.Value] = r.Action
	}
	if actions["github.com"] != ActionAllow {
		t.Errorf("github.com action = %q, want allow", actions["github.com"])
	}
	if actions["evil.example.com"] != ActionDeny {
		t.Errorf("evil.example.com action = %q, want deny", actions["evil.example.com"])
	}
}

// A hostname appearing in BOTH allow and blocked env vars produces TWO
// exact-match rules of opposite actions. matchHostnameRuleLocked
// iterates resolvedRules and overwrites `exactRule` on each match — so
// the LAST rule with the same value wins. LoadFromEnv parses ALLOWED_HOSTS
// before BLOCKED_HOSTS, so the deny rule is appended second and wins.
//
// Pin "deny wins" explicitly so a future change to the parse order, the
// resolveRulesLocked iteration, or the matchHostnameRuleLocked overwrite
// semantics fails this test loudly.
func TestLoadFromEnv_HostInBothAllowedAndBlocked(t *testing.T) {
	clearAllCargowallEnv(t)
	t.Setenv("CARGOWALL_ALLOWED_HOSTS", "ambiguous.example.com")
	t.Setenv("CARGOWALL_BLOCKED_HOSTS", "ambiguous.example.com")

	cm := NewConfigManager()
	if err := cm.LoadFromEnv(); err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	// Both rules present in config.Rules.
	if got := len(cm.config.Rules); got != 2 {
		t.Errorf("rule count = %d, want 2 (one allow + one deny)", got)
	}
	// The blocked rule (parsed second by LoadFromEnv) wins via the
	// last-match-overwrites-exactRule semantics of matchHostnameRuleLocked.
	v := cm.MatchHostnameRule("ambiguous.example.com")
	if !v.HasDeny() || v.HasAllow() {
		t.Errorf("ambiguous host verdict = %+v, want deny only (blocked rule appended second wins)", v)
	}
}

// HasSearchDomainSuffix with FQDN trailing dot: DOES NOT match. DNS
// responses sometimes carry FQDN-form names; callers must trim before
// querying. Pin the contract so a fix becomes a deliberate change.
func TestHasSearchDomainSuffix_FQDN(t *testing.T) {
	cm := NewConfigManager()
	cm.config = &FirewallConfig{}
	cm.AddSearchDomains([]string{".compute.internal"}, slog.Default())

	if cm.HasSearchDomainSuffix("host.compute.internal") != true {
		t.Errorf("non-FQDN form should match (sanity check)")
	}
	if cm.HasSearchDomainSuffix("host.compute.internal.") != false {
		t.Errorf("FQDN trailing dot currently does NOT match — pinning behavior. If this changes, update callers that pass FQDN names.")
	}
}

// StripSearchDomains: user adds an exact duplicate of a built-in Kubernetes
// suffix. Stripping should still happen exactly once (longest-match logic
// picks one of them, doesn't double-strip).
func TestStripSearchDomains_OverlapWithKubernetes(t *testing.T) {
	cm := newCMWithSearchDomains(t, nil, ".cluster.local")
	// `.cluster.local` is also in kubernetesSearchDomains. The longest-match
	// loop picks the longest matching suffix once; with two equal-length
	// candidates pointing at the same suffix, stripping is idempotent.
	if got := cm.StripSearchDomains("svc.cluster.local"); got != "svc" {
		t.Errorf("StripSearchDomains(svc.cluster.local) = %q, want %q (overlap must not double-strip)", got, "svc")
	}
}

// GetAutoAllowedType on a fresh manager (no config loaded) must not panic
// and must return AutoAddedTypeNone.
func TestGetAutoAllowedType_NilConfig(t *testing.T) {
	cm := NewConfigManager()
	if got := cm.GetAutoAllowedType("1.2.3.4", 443, ProtocolTCP, "example.com"); got != AutoAddedTypeNone {
		t.Errorf("GetAutoAllowedType on fresh manager = %q, want %q", got, AutoAddedTypeNone)
	}
}

// GetAutoAllowedType must NOT match deny-action rules even if they carry
// an AutoAddedType (this would be a misconfiguration; the function only
// reports the "why was this allowed" tag, not the "why was this denied").
func TestGetAutoAllowedType_DenyRuleIgnored(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{
			Type:          RuleTypeHostname,
			Value:         "blocked.example.com",
			Action:        ActionDeny,
			AutoAddedType: AutoAddedTypeGitHubService, // deliberately mismatched for the test
		},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if got := cm.GetAutoAllowedType("1.2.3.4", 443, ProtocolTCP, "blocked.example.com"); got != AutoAddedTypeNone {
		t.Errorf("deny rule's AutoAddedType leaked: got %q, want %q", got, AutoAddedTypeNone)
	}
}

// AddSearchDomains with an empty input slice should be a no-op (don't fail,
// don't mutate state). Defensive: an auto-allow caller might pass an empty
// list because a config knob produced no suffixes.
func TestAddSearchDomains_EmptyInput(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.AddSearchDomains(nil, slog.Default())
	cm.AddSearchDomains([]string{}, slog.Default())
	if got := cm.GetSearchDomains(); got != nil {
		t.Errorf("GetSearchDomains() after empty AddSearchDomains = %v, want nil", got)
	}
}

// =============================================================================
// MatchHostnameRule super-table (Phase 2a)
//
// Single table covering all precedence branches: exact > deny pattern >
// parent (longest suffix) > allow pattern, plus search-domain stripping
// (deny-anywhere wins, port-union on both-deny, narrower-exact-wins on
// allow). Each previously-named scenario survives as a sub-test via t.Run.
// =============================================================================

func TestMatchHostnameRule_Table(t *testing.T) {
	tests := []struct {
		name           string
		rules          []Rule
		searchDomains  []string
		defaultAction  Action // defaults to ActionDeny if zero
		query          string
		wantDenyRule   string
		wantDenyPorts  []Port
		wantAllowRule  string
		wantAllowPorts []Port
		skipPortCheck  bool
	}{
		// ----- Basic precedence (absorbs TestMatchHostnameRule, TestHostnamePatternRules) -----
		{
			name: "exact match returns that rule",
			rules: []Rule{
				{
					Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow,
					Ports: []Port{{Port: 443, Protocol: ProtocolTCP}},
				},
			},
			query:          "github.com",
			wantAllowRule:  "github.com",
			wantAllowPorts: []Port{{Port: 443, Protocol: ProtocolTCP}},
		},
		{
			name: "parent-domain match inherits parent rule's ports",
			rules: []Rule{
				{
					Type: RuleTypeHostname, Value: "example.com", Action: ActionAllow,
					Ports: []Port{{Port: 80, Protocol: ProtocolTCP}},
				},
			},
			query:          "api.example.com",
			wantAllowRule:  "example.com",
			wantAllowPorts: []Port{{Port: 80, Protocol: ProtocolTCP}},
		},
		{
			name: "longest-suffix parent wins",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "example.com", Action: ActionAllow},
				{
					Type: RuleTypeHostname, Value: "foo.example.com", Action: ActionAllow,
					Ports: []Port{{Port: 8080, Protocol: ProtocolTCP}},
				},
			},
			query:          "bar.foo.example.com",
			wantAllowRule:  "foo.example.com",
			wantAllowPorts: []Port{{Port: 8080, Protocol: ProtocolTCP}},
		},
		{
			name: "single-star wildcard pattern matches one label",
			rules: []Rule{
				{
					Type: RuleTypeHostname, Value: "*.example.com", Action: ActionAllow,
					Ports: []Port{{Port: 443, Protocol: ProtocolTCP}},
				},
			},
			query:          "api.example.com",
			wantAllowRule:  "*.example.com",
			wantAllowPorts: []Port{{Port: 443, Protocol: ProtocolTCP}},
		},
		{
			name: "double-star pattern matches multi-label suffix",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "**.example.com", Action: ActionAllow},
			},
			query:         "a.b.c.example.com",
			wantAllowRule: "**.example.com",
			skipPortCheck: true,
		},
		{
			name: "no match returns empty verdict",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
			},
			query:         "evil.example.com",
			skipPortCheck: true,
		},

		// ----- Deny precedence -----
		{
			name: "deny pattern beats parent allow",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "example.com", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "evil.*.example.com", Action: ActionDeny},
			},
			query:         "evil.foo.example.com",
			wantDenyRule:  "evil.*.example.com",
			skipPortCheck: true,
		},
		{
			name: "parent deny beats allow-pattern",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "example.com", Action: ActionDeny},
				{Type: RuleTypeHostname, Value: "*.example.com", Action: ActionAllow},
			},
			query:         "api.example.com",
			wantDenyRule:  "example.com",
			skipPortCheck: true,
		},

		// ----- Case insensitivity -----
		{
			name: "uppercase rule value matches lowercase query (normalized at load)",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "GitHub.COM", Action: ActionAllow},
			},
			query:         "github.com",
			wantAllowRule: "github.com",
			skipPortCheck: true,
		},
		{
			name: "lowercase rule value matches mixed-case query",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
			},
			query:         "GitHub.COM",
			wantAllowRule: "github.com",
			skipPortCheck: true,
		},

		// ----- Search-domain stripping -----
		{
			name: "short-name rule matches via stripping",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "bastion", Action: ActionAllow},
			},
			searchDomains: []string{".compute.internal"},
			query:         "bastion.compute.internal",
			wantAllowRule: "bastion",
			skipPortCheck: true,
		},
		{
			// Cross-action: full form allows (parent), stripped form denies
			// (exact). Verdict records BOTH so per-port BPF entries can be
			// written faithfully.
			name: "stripped deny + full parent allow → mixed verdict",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "compute.internal", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "blocked", Action: ActionDeny},
			},
			searchDomains: []string{".compute.internal"},
			query:         "blocked.compute.internal",
			wantDenyRule:  "blocked",
			wantAllowRule: "compute.internal",
			skipPortCheck: true,
		},
		{
			// Full form denies via a pattern, stripped form allows via an
			// exact-name rule. Both sides are recorded so port 22 (allow)
			// and port 80 (deny) can both be expressed at the BPF layer.
			name: "full deny pattern + stripped exact allow → mixed verdict",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "*.compute.internal", Action: ActionDeny},
				{Type: RuleTypeHostname, Value: "bastion", Action: ActionAllow},
			},
			searchDomains: []string{".compute.internal"},
			query:         "bastion.compute.internal",
			wantDenyRule:  "*.compute.internal",
			wantAllowRule: "bastion",
			skipPortCheck: true,
		},
		{
			name: "narrow exact deny beats parent deny (broader port coverage wins)",
			rules: []Rule{
				{
					Type: RuleTypeHostname, Value: "compute.internal",
					Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionDeny,
				},
				{Type: RuleTypeHostname, Value: "blocked", Action: ActionDeny},
			},
			searchDomains: []string{".compute.internal"},
			query:         "blocked.compute.internal",
			wantDenyRule:  "blocked",
			wantDenyPorts: nil,
		},
		{
			name: "narrow exact allow beats parent allow",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "compute.internal", Action: ActionAllow},
				{
					Type: RuleTypeHostname, Value: "bastion",
					Ports: []Port{{Port: 22, Protocol: ProtocolTCP}}, Action: ActionAllow,
				},
			},
			searchDomains:  []string{".compute.internal"},
			query:          "bastion.compute.internal",
			wantAllowRule:  "bastion",
			wantAllowPorts: []Port{{Port: 22, Protocol: ProtocolTCP}},
		},

		// ----- Both-deny port union -----
		{
			name: "both deny non-overlapping ports → union",
			rules: []Rule{
				{
					Type: RuleTypeHostname, Value: "compute.internal",
					Ports: []Port{{Port: 80, Protocol: ProtocolTCP}}, Action: ActionDeny,
				},
				{
					Type: RuleTypeHostname, Value: "blocked",
					Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionDeny,
				},
			},
			searchDomains: []string{".compute.internal"},
			query:         "blocked.compute.internal",
			wantDenyRule:  "blocked",
			wantDenyPorts: []Port{
				{Port: 80, Protocol: ProtocolTCP},
				{Port: 443, Protocol: ProtocolTCP},
			},
		},
		{
			name: "both deny same port different protocols → both preserved",
			rules: []Rule{
				{
					Type: RuleTypeHostname, Value: "compute.internal",
					Ports: []Port{{Port: 443, Protocol: ProtocolUDP}}, Action: ActionDeny,
				},
				{
					Type: RuleTypeHostname, Value: "blocked",
					Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionDeny,
				},
			},
			searchDomains: []string{".compute.internal"},
			query:         "blocked.compute.internal",
			wantDenyRule:  "blocked",
			wantDenyPorts: []Port{
				{Port: 443, Protocol: ProtocolUDP},
				{Port: 443, Protocol: ProtocolTCP},
			},
		},
		{
			name: "both deny overlapping ports → deduped",
			rules: []Rule{
				{
					Type: RuleTypeHostname, Value: "compute.internal",
					Ports: []Port{{Port: 80, Protocol: ProtocolTCP}, {Port: 443, Protocol: ProtocolTCP}}, Action: ActionDeny,
				},
				{
					Type: RuleTypeHostname, Value: "blocked",
					Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionDeny,
				},
			},
			searchDomains: []string{".compute.internal"},
			query:         "blocked.compute.internal",
			wantDenyRule:  "blocked",
			wantDenyPorts: []Port{
				{Port: 80, Protocol: ProtocolTCP},
				{Port: 443, Protocol: ProtocolTCP},
			},
		},

		// ----- Three-overlap parents (new coverage) -----
		{
			name: "three overlapping parents — longest wins",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "com", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "example.com", Action: ActionAllow},
				{
					Type: RuleTypeHostname, Value: "internal.example.com",
					Ports: []Port{{Port: 80, Protocol: ProtocolTCP}}, Action: ActionDeny,
				},
			},
			query:         "api.internal.example.com",
			wantDenyRule:  "internal.example.com",
			wantDenyPorts: []Port{{Port: 80, Protocol: ProtocolTCP}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defaultAction := tc.defaultAction
			if defaultAction == "" {
				defaultAction = ActionDeny
			}
			cm := NewConfigManager()
			if err := cm.LoadConfigFromRules(tc.rules, defaultAction); err != nil {
				t.Fatalf("LoadConfigFromRules() error = %v", err)
			}
			if len(tc.searchDomains) > 0 {
				cm.AddSearchDomains(tc.searchDomains, slog.Default())
			}

			v := cm.MatchHostnameRule(tc.query)
			// Deny side.
			switch {
			case tc.wantDenyRule == "" && v.HasDeny():
				t.Errorf("unexpected deny side: rule=%q ports=%v", v.DenyRule, v.DenyPorts)
			case tc.wantDenyRule != "" && !v.HasDeny():
				t.Errorf("missing deny side: want rule=%q", tc.wantDenyRule)
			case tc.wantDenyRule != "" && v.DenyRule != tc.wantDenyRule:
				t.Errorf("DenyRule = %q, want %q", v.DenyRule, tc.wantDenyRule)
			}
			if v.HasDeny() && !tc.skipPortCheck && !samePortSet(v.DenyPorts, tc.wantDenyPorts) {
				t.Errorf("DenyPorts = %v, want %v (order-insensitive)", v.DenyPorts, tc.wantDenyPorts)
			}
			// Allow side.
			switch {
			case tc.wantAllowRule == "" && v.HasAllow():
				t.Errorf("unexpected allow side: rule=%q ports=%v", v.AllowRule, v.AllowPorts)
			case tc.wantAllowRule != "" && !v.HasAllow():
				t.Errorf("missing allow side: want rule=%q", tc.wantAllowRule)
			case tc.wantAllowRule != "" && v.AllowRule != tc.wantAllowRule:
				t.Errorf("AllowRule = %q, want %q", v.AllowRule, tc.wantAllowRule)
			}
			if v.HasAllow() && !tc.skipPortCheck && !samePortSet(v.AllowPorts, tc.wantAllowPorts) {
				t.Errorf("AllowPorts = %v, want %v (order-insensitive)", v.AllowPorts, tc.wantAllowPorts)
			}
		})
	}
}

// =============================================================================
// FindTrackedHostname super-table (Phase 2b)
//
// Attribution must match MatchHostnameRule's verdict on a round-trip:
// MatchHostnameRule(FindTrackedHostname(query)) yields the same action as
// MatchHostnameRule(query). Each row asserts the attribution name AND the
// round-trip, so attribution-vs-verdict divergence is caught.
// =============================================================================

func TestFindTrackedHostname_Table(t *testing.T) {
	tests := []struct {
		name            string
		rules           []Rule
		searchDomains   []string
		query           string
		wantAttribution string
		// Round-trip: MatchHostnameRule(wantAttribution) should yield this
		// action. Empty means "skip round-trip check" (e.g. empty attribution).
		wantRoundTripAction Action
	}{
		// ----- Basic patterns / parent attribution -----
		{
			name: "plain parent match returns parent name",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
			},
			query:               "api.github.com",
			wantAttribution:     "github.com",
			wantRoundTripAction: ActionAllow,
		},
		{
			name: "pattern match returns the queried hostname",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "*.*.internal.cloudapp.net", Action: ActionAllow},
			},
			query:               "abc.def.internal.cloudapp.net",
			wantAttribution:     "abc.def.internal.cloudapp.net",
			wantRoundTripAction: ActionAllow,
		},
		{
			name: "no match returns empty",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
			},
			query:           "unknown.example.com",
			wantAttribution: "",
		},

		// ----- Longest-parent precedence -----
		{
			name: "longest-parent attribution matches MatchHostnameRule",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "internal.github.com", Action: ActionDeny},
			},
			query:               "api.internal.github.com",
			wantAttribution:     "internal.github.com",
			wantRoundTripAction: ActionDeny,
		},
		{
			name: "longest allow parent attribution preserves narrower port scope",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "example.com", Action: ActionAllow},
				{
					Type: RuleTypeHostname, Value: "api.example.com",
					Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}, Action: ActionAllow,
				},
			},
			query:               "v2.api.example.com",
			wantAttribution:     "api.example.com",
			wantRoundTripAction: ActionAllow,
		},

		// ----- Search-domain stripping -----
		{
			name: "stripped short-name allow attributes to short name",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "bastion", Action: ActionAllow},
			},
			searchDomains:       []string{".compute.internal"},
			query:               "bastion.compute.internal",
			wantAttribution:     "bastion",
			wantRoundTripAction: ActionAllow,
		},
		{
			name: "deny on stripped beats parent allow attribution",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "compute.internal", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "blocked", Action: ActionDeny},
			},
			searchDomains:       []string{".compute.internal"},
			query:               "blocked.compute.internal",
			wantAttribution:     "blocked",
			wantRoundTripAction: ActionDeny,
		},
		{
			name: "stripped deny pattern wins attribution over parent allow",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "foo", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "evil.*", Action: ActionDeny},
			},
			searchDomains:       []string{".compute.internal"},
			query:               "evil.foo.compute.internal",
			wantAttribution:     "evil.foo",
			wantRoundTripAction: ActionDeny,
		},
		{
			name: "stripped allow pattern doesn't masquerade as exact — parent allow on full wins",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "compute.internal", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "*.bar", Action: ActionAllow},
			},
			searchDomains:       []string{".compute.internal"},
			query:               "foo.bar.compute.internal",
			wantAttribution:     "compute.internal",
			wantRoundTripAction: ActionAllow,
		},
		{
			name: "narrow exact allow on stripped beats parent allow on full",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "compute.internal", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "bastion", Action: ActionAllow},
			},
			searchDomains:       []string{".compute.internal"},
			query:               "bastion.compute.internal",
			wantAttribution:     "bastion",
			wantRoundTripAction: ActionAllow,
		},
		{
			name: "full deny pattern beats stripped allow attribution",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "*.compute.internal", Action: ActionDeny},
				{Type: RuleTypeHostname, Value: "bastion", Action: ActionAllow},
			},
			searchDomains:       []string{".compute.internal"},
			query:               "bastion.compute.internal",
			wantAttribution:     "bastion.compute.internal", // chosenAttributionName(name, pattern) = name
			wantRoundTripAction: ActionDeny,
		},
		{
			name: "stripped deny pattern beats parent allow on full",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "compute.internal", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "evil.*", Action: ActionDeny},
			},
			searchDomains:       []string{".compute.internal"},
			query:               "evil.foo.compute.internal",
			wantAttribution:     "evil.foo",
			wantRoundTripAction: ActionDeny,
		},

		// ----- New rows from plan -----
		{
			name: "no match on either form returns empty",
			rules: []Rule{
				{Type: RuleTypeHostname, Value: "bastion", Action: ActionAllow},
			},
			searchDomains:   []string{".compute.internal"},
			query:           "totally.unknown.elsewhere.net",
			wantAttribution: "",
		},
		{
			name: "stripped exact AND full exact (both allow, full-wins default)",
			rules: []Rule{
				// Both forms match exact rules on different names.
				{Type: RuleTypeHostname, Value: "bastion.compute.internal", Action: ActionAllow},
				{Type: RuleTypeHostname, Value: "bastion", Action: ActionAllow},
			},
			searchDomains:       []string{".compute.internal"},
			query:               "bastion.compute.internal",
			wantAttribution:     "bastion.compute.internal", // full wins on no-tiebreak default
			wantRoundTripAction: ActionAllow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := NewConfigManager()
			if err := cm.LoadConfigFromRules(tc.rules, ActionDeny); err != nil {
				t.Fatalf("LoadConfigFromRules() error = %v", err)
			}
			if len(tc.searchDomains) > 0 {
				cm.AddSearchDomains(tc.searchDomains, slog.Default())
			}

			got := cm.FindTrackedHostname(tc.query)
			if got != tc.wantAttribution {
				t.Errorf("FindTrackedHostname(%q) = %q, want %q", tc.query, got, tc.wantAttribution)
			}
			// Round-trip: re-lookup must agree with the verdict for the original query.
			if tc.wantRoundTripAction != "" {
				v := cm.MatchHostnameRule(got)
				var ok bool
				switch tc.wantRoundTripAction {
				case ActionDeny:
					ok = v.HasDeny()
				case ActionAllow:
					ok = v.HasAllow()
				}
				if !ok {
					t.Errorf("round-trip MatchHostnameRule(%q) verdict = %+v, want %s side present",
						got, v, tc.wantRoundTripAction)
				}
			}
		})
	}
}

// samePortSet compares two Port slices ignoring order. Used by the
// MatchHostnameRule super-table because the both-deny union doesn't
// guarantee ordering between full/stripped ports.
func samePortSet(a, b []Port) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[Port]int, len(a))
	for _, p := range a {
		seen[p]++
	}
	for _, p := range b {
		if seen[p] == 0 {
			return false
		}
		seen[p]--
	}
	return true
}

// =============================================================================
// Loader validation table (Phase 2c)
//
// Consolidates invariants that every loader must enforce — ICMP rules,
// hostname-value case normalization, and error paths specific to each
// source format. Each row encapsulates its loader call via the `setup`
// closure, so a single table can exercise file / proto / env / direct-rule
// loaders side-by-side.
// =============================================================================

func TestLoadersValidation(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, cm *Manager) error
		wantErr string // substring match; "" means expect success
		verify  func(*testing.T, *Manager)
	}{
		// ----- ICMP non-zero port: rejected by every loader -----
		{
			name: "LoadConfig: ICMP rule with port != 0 rejected",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfig(writeJSONConfig(t, `{
					"defaultAction": "deny",
					"rules": [{"type": "cidr", "value": "8.8.8.8/32", "ports": [{"port": 80, "protocol": "icmp"}], "action": "allow"}]
				}`))
			},
			wantErr: "ICMP",
		},
		{
			name: "LoadConfigFromCargoWall: ICMP rule with port != 0 rejected",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
					DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
					Rules: []*cargowallv1pb.CargoWallPolicy_Rule{{
						Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_CIDR,
						Value:  "8.8.8.8/32",
						Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
						Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{{
							Port: 80, Protocol: datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_ICMP,
						}},
					}},
				})
			},
			wantErr: "ICMP",
		},
		{
			name: "LoadConfigFromRules: ICMP rule with port != 0 rejected",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfigFromRules([]Rule{
					{
						Type:   RuleTypeCIDR,
						Value:  "8.8.8.8/32",
						Action: ActionAllow,
						Ports:  []Port{{Port: 80, Protocol: ProtocolICMP}},
					},
				}, ActionDeny)
			},
			wantErr: "ICMP",
		},

		// ----- ICMP on IPv6 CIDR rejected -----
		{
			name: "LoadConfig: ICMP on IPv6 CIDR rejected",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfig(writeJSONConfig(t, `{
					"defaultAction": "deny",
					"rules": [{"type": "cidr", "value": "2001:db8::/32", "ports": [{"port": 0, "protocol": "icmp"}], "action": "allow"}]
				}`))
			},
			wantErr: "IPv4-only",
		},
		{
			name: "LoadConfigFromCargoWall: ICMP on IPv6 CIDR rejected",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
					DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
					Rules: []*cargowallv1pb.CargoWallPolicy_Rule{{
						Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_CIDR,
						Value:  "2001:db8::/32",
						Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
						Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{{
							Port: 0, Protocol: datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_ICMP,
						}},
					}},
				})
			},
			wantErr: "IPv4-only",
		},

		// ----- Hostname value case normalization: every loader lowercases -----
		{
			name: "LoadConfig: mixed-case hostname normalized to lowercase",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfig(writeJSONConfig(t, `{
					"defaultAction": "deny",
					"rules": [{"type": "hostname", "value": "GitHub.COM", "action": "allow"}]
				}`))
			},
			verify: func(t *testing.T, cm *Manager) {
				if cm.config.Rules[0].Value != "github.com" {
					t.Errorf("cm.config.Rules[0].Value = %q, want %q", cm.config.Rules[0].Value, "github.com")
				}
				if cm.GetResolvedRules()[0].Value != "github.com" {
					t.Errorf("GetResolvedRules()[0].Value = %q, want %q", cm.GetResolvedRules()[0].Value, "github.com")
				}
			},
		},
		{
			name: "LoadConfigFromCargoWall: mixed-case hostname normalized",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
					DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
					Rules: []*cargowallv1pb.CargoWallPolicy_Rule{{
						Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME,
						Value:  "GitHub.COM",
						Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
					}},
				})
			},
			verify: func(t *testing.T, cm *Manager) {
				if cm.config.Rules[0].Value != "github.com" {
					t.Errorf("cm.config.Rules[0].Value = %q", cm.config.Rules[0].Value)
				}
			},
		},
		{
			name: "LoadConfigFromRules: mixed-case hostname normalized",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfigFromRules([]Rule{
					{Type: RuleTypeHostname, Value: "GitHub.COM", Action: ActionAllow},
				}, ActionDeny)
			},
			verify: func(t *testing.T, cm *Manager) {
				if cm.config.Rules[0].Value != "github.com" {
					t.Errorf("cm.config.Rules[0].Value = %q", cm.config.Rules[0].Value)
				}
			},
		},
		{
			name: "LoadFromEnv: mixed-case hostname normalized",
			setup: func(t *testing.T, cm *Manager) error {
				clearAllCargowallEnv(t)
				t.Setenv("CARGOWALL_ALLOWED_HOSTS", "GitHub.COM")
				return cm.LoadFromEnv()
			},
			verify: func(t *testing.T, cm *Manager) {
				if cm.config.Rules[0].Value != "github.com" {
					t.Errorf("cm.config.Rules[0].Value = %q", cm.config.Rules[0].Value)
				}
			},
		},

		// ----- LoadConfig-specific error paths -----
		{
			name: "LoadConfig: non-existent file",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfig(filepath.Join(t.TempDir(), "does-not-exist.json"))
			},
			wantErr: "read config file",
		},
		{
			name: "LoadConfig: malformed JSON",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfig(writeJSONConfig(t, `{ this is not json`))
			},
			wantErr: "parse config",
		},

		// ----- LoadConfigFromCargoWall-specific error paths -----
		{
			name: "LoadConfigFromCargoWall: port > 65535 rejected",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
					DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
					Rules: []*cargowallv1pb.CargoWallPolicy_Rule{{
						Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME,
						Value:  "github.com",
						Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
						Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{{
							Port: 65536, Protocol: datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_TCP,
						}},
					}},
				})
			},
			wantErr: "invalid port",
		},
		{
			name: "LoadConfigFromCargoWall: unknown protocol enum",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
					DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
					Rules: []*cargowallv1pb.CargoWallPolicy_Rule{{
						Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME,
						Value:  "github.com",
						Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
						Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{{
							Port:     443,
							Protocol: datapb.CargoWallProtocol(99),
						}},
					}},
				})
			},
			wantErr: "unknown protocol",
		},
		{
			name: "LoadConfigFromCargoWall: unknown rule-type enum",
			setup: func(t *testing.T, cm *Manager) error {
				return cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
					DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
					Rules: []*cargowallv1pb.CargoWallPolicy_Rule{{
						Type:   datapb.CargoWallRuleType(99),
						Value:  "anything",
						Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
					}},
				})
			},
			wantErr: "unknown rule type",
		},

		// ----- LoadFromEnv-specific error paths -----
		{
			name: "LoadFromEnv: invalid CARGOWALL_DEFAULT_ACTION",
			setup: func(t *testing.T, cm *Manager) error {
				clearAllCargowallEnv(t)
				t.Setenv("CARGOWALL_DEFAULT_ACTION", "maybe")
				return cm.LoadFromEnv()
			},
			wantErr: "CARGOWALL_DEFAULT_ACTION",
		},
		{
			name: "LoadFromEnv: no env vars set returns 'no environment configuration found'",
			setup: func(t *testing.T, cm *Manager) error {
				clearAllCargowallEnv(t)
				return cm.LoadFromEnv()
			},
			wantErr: "no environment configuration",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := NewConfigManager()
			err := tc.setup(t, cm)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("setup() = nil, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("setup() error = %q, want it to contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("setup() error = %v, want nil", err)
			}
			if tc.verify != nil {
				tc.verify(t, cm)
			}
		})
	}
}

// =============================================================================
// Coverage gap closure (Phase 7)
//
// Pin behaviors that prior phases left implicit: nil-config safety across
// every guard, loader atomicity on validation failure, silent-drop of
// uncompilable patterns, IPv6 / malformed IPs skipped by ensureAllowed,
// empty-IP no-op in UpdateDNSMapping, defensive-copy contracts for the
// remaining getters, and DNS cache persistence across config reloads.
// =============================================================================

// Every Manager method that guards `cm.config == nil` must be safe on a
// fresh manager — return zero values, not panic. One table so future
// methods that adopt the same guard are easy to add.
func TestNilConfigSafety(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(t *testing.T, cm *Manager)
	}{
		{"GetDefaultAction returns ActionDeny", func(t *testing.T, cm *Manager) {
			if got := cm.GetDefaultAction(); got != ActionDeny {
				t.Errorf("GetDefaultAction() = %q, want %q", got, ActionDeny)
			}
		}},
		{"GetSudoLockdown returns nil", func(t *testing.T, cm *Manager) {
			if got := cm.GetSudoLockdown(); got != nil {
				t.Errorf("GetSudoLockdown() = %+v, want nil", got)
			}
		}},
		{"GetSearchDomains returns nil", func(t *testing.T, cm *Manager) {
			if got := cm.GetSearchDomains(); got != nil {
				t.Errorf("GetSearchDomains() = %v, want nil", got)
			}
		}},
		{"HasSearchDomainSuffix returns false", func(t *testing.T, cm *Manager) {
			if cm.HasSearchDomainSuffix("any.compute.internal") {
				t.Errorf("HasSearchDomainSuffix() = true, want false")
			}
		}},
		{"CheckIPRuleConflict returns input action with no conflict", func(t *testing.T, cm *Manager) {
			action, conflict, rule := cm.CheckIPRuleConflict(net.ParseIP("1.2.3.4"), "host", ActionAllow, nil)
			if action != ActionAllow || conflict || rule != "" {
				t.Errorf("got (%q, %v, %q), want (allow, false, \"\")", action, conflict, rule)
			}
		}},
		{"GetAutoAllowedType returns None", func(t *testing.T, cm *Manager) {
			if got := cm.GetAutoAllowedType("1.2.3.4", 443, ProtocolTCP, "host"); got != AutoAddedTypeNone {
				t.Errorf("GetAutoAllowedType() = %q, want None", got)
			}
		}},
		{"EnsureHostnameAllowed no-ops", func(t *testing.T, cm *Manager) {
			cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)
			if len(cm.GetResolvedRules()) != 0 {
				t.Errorf("expected no rule added on nil config, got %d", len(cm.GetResolvedRules()))
			}
		}},
		{"EnsureDNSAllowed no-ops", func(t *testing.T, cm *Manager) {
			cm.EnsureDNSAllowed([]string{"8.8.8.8"})
			if len(cm.GetResolvedRules()) != 0 {
				t.Errorf("expected no rule added on nil config, got %d", len(cm.GetResolvedRules()))
			}
		}},
		{"EnsureInfraAllowed no-ops", func(t *testing.T, cm *Manager) {
			cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []Port{PortHTTP}, AutoAddedTypeCloudMetadata)
			if len(cm.GetResolvedRules()) != 0 {
				t.Errorf("expected no rule added on nil config, got %d", len(cm.GetResolvedRules()))
			}
		}},
		{"AddSearchDomains no-ops", func(t *testing.T, cm *Manager) {
			cm.AddSearchDomains([]string{".compute.internal"}, slog.Default())
			if got := cm.GetSearchDomains(); got != nil {
				t.Errorf("expected no search domains added on nil config, got %v", got)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := NewConfigManager()
			// Intentionally do NOT call any loader — cm.config stays nil.
			tc.invoke(t, cm)
		})
	}
}

// applyLoadedConfig must be atomic: when validateRules rejects the new
// rule set, cm.config must remain the previously-loaded config (not nil,
// not partially mutated). Hot-reload reliability depends on this.
func TestApplyLoadedConfig_AtomicOnValidationError(t *testing.T) {
	cm := NewConfigManager()

	// Load a valid config first.
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("initial LoadConfigFromRules() error = %v", err)
	}
	if v := cm.MatchHostnameRule("github.com"); !v.HasAllow() {
		t.Fatalf("pre-reload: github.com verdict = %+v, want allow", v)
	}

	// Try to load a new config that fails validation (ICMP rule with port != 0).
	err := cm.LoadConfigFromRules([]Rule{
		{
			Type: RuleTypeCIDR, Value: "8.8.8.8/32",
			Ports: []Port{{Port: 80, Protocol: ProtocolICMP}}, Action: ActionAllow,
		},
	}, ActionDeny)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}

	// Verify the previous config is still in effect.
	if v := cm.MatchHostnameRule("github.com"); !v.HasAllow() {
		t.Errorf("after failed reload: github.com verdict = %+v, want allow (previous config must be preserved)", v)
	}
	if rules := cm.GetResolvedRules(); len(rules) != 1 || rules[0].Value != "github.com" {
		t.Errorf("resolvedRules after failed reload = %+v, want unchanged [github.com]", rules)
	}
}

// resolveRulesLocked silently drops rules whose patterns fail to compile
// (the load itself succeeds; the bad rule just doesn't appear in
// resolvedRules). Pin this so a future change to fail-loud is a deliberate
// decision rather than an accidental regression.
func TestResolveRules_InvalidPatternSilentlyDropped(t *testing.T) {
	cm := NewConfigManager()
	// "**.**.com" fails compileHostnamePattern (consecutive double-stars).
	// LoadConfigFromRules calls resolveRulesLocked which logs the error
	// and continues, dropping the rule from resolvedRules.
	err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "**.**.com", Action: ActionAllow},
	}, ActionDeny)
	if err != nil {
		t.Fatalf("LoadConfigFromRules() should not fail on bad pattern (current behavior): %v", err)
	}

	// Valid rule still works.
	if v := cm.MatchHostnameRule("github.com"); !v.HasAllow() {
		t.Errorf("valid rule lost: github.com verdict = %+v, want allow", v)
	}
	// Bad pattern silently dropped — no rule matches its target.
	if v := cm.MatchHostnameRule("foo.bar.com"); v.Matched() {
		t.Errorf("invalid pattern should have been dropped, but a rule matched foo.bar.com: verdict = %+v", v)
	}
	// Only the valid rule made it into resolvedRules.
	if got := len(cm.GetResolvedRules()); got != 1 {
		t.Errorf("resolvedRules count = %d, want 1 (invalid pattern dropped)", got)
	}
}

// ensureAllowed (used by EnsureDNSAllowed / EnsureInfraAllowed) silently
// skips empty strings, malformed IPs, and IPv6 addresses. Pin this so
// auto-allow callers don't have to defend against bad input themselves.
func TestEnsureAllowed_SkipsInvalidIPs(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	// Mix of one valid + three skipped.
	cm.EnsureDNSAllowed([]string{
		"",
		"not-an-ip",
		"2001:db8::1", // IPv6 — silently skipped (BPF maps are IPv4)
		"8.8.8.8",
	})
	rules := cm.GetResolvedRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (only 8.8.8.8 valid), got %d: %+v", len(rules), rules)
	}
	if rules[0].Value != "8.8.8.8/32" {
		t.Errorf("rule value = %q, want %q", rules[0].Value, "8.8.8.8/32")
	}
}

// UpdateDNSMapping with an empty IP must be a no-op (no panic, no entry
// added). Defensive against callers that pass a hostname before they have
// an IP — e.g. the lazy-resolve path in events.go.
func TestUpdateDNSMapping_EmptyIPIsNoOp(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	cm.UpdateDNSMapping("github.com", "")

	if got := cm.LookupHostnameByIP(""); got != "" {
		t.Errorf("empty-IP lookup should return empty, got %q", got)
	}
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if len(cm.ipToHostname) != 0 {
		t.Errorf("ipToHostname should not record empty-IP entries, got %v", cm.ipToHostname)
	}
	if len(cm.ipLastSeen) != 0 {
		t.Errorf("ipLastSeen should not record empty-IP entries, got %v", cm.ipLastSeen)
	}
}

// Defensive-copy contract: getters that return slices/maps must return
// fresh copies so callers can mutate them without affecting manager
// state. TestGetTrackedHostnames already covers GetTrackedHostnames; this
// extends to GetResolvedRules, GetSearchDomains, and GetIPToHostnameMap.
func TestDefensiveCopies(t *testing.T) {
	t.Run("GetResolvedRules returns a copy", func(t *testing.T) {
		cm := NewConfigManager()
		if err := cm.LoadConfigFromRules([]Rule{
			{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		}, ActionDeny); err != nil {
			t.Fatalf("LoadConfigFromRules() error = %v", err)
		}
		got := cm.GetResolvedRules()
		got[0].Value = "MUTATED"
		got2 := cm.GetResolvedRules()
		if got2[0].Value != "github.com" {
			t.Errorf("GetResolvedRules returned a reference: caller mutation leaked into manager state (got %q)", got2[0].Value)
		}
	})

	t.Run("GetSearchDomains returns a copy", func(t *testing.T) {
		cm := NewConfigManager()
		if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
			t.Fatalf("LoadConfigFromRules() error = %v", err)
		}
		cm.AddSearchDomains([]string{".compute.internal"}, slog.Default())
		got := cm.GetSearchDomains()
		got[0] = ".MUTATED"
		got2 := cm.GetSearchDomains()
		if got2[0] != ".compute.internal" {
			t.Errorf("GetSearchDomains returned a reference: caller mutation leaked (got %q)", got2[0])
		}
	})

	t.Run("GetIPToHostnameMap returns a copy", func(t *testing.T) {
		cm := NewConfigManager()
		if err := cm.LoadConfigFromRules([]Rule{
			{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		}, ActionDeny); err != nil {
			t.Fatalf("LoadConfigFromRules() error = %v", err)
		}
		cm.UpdateDNSMapping("github.com", "140.82.114.4")
		got := cm.GetIPToHostnameMap()
		got["140.82.114.4"] = "MUTATED"
		delete(got, "140.82.114.4")
		got["9.9.9.9"] = "injected"

		got2 := cm.GetIPToHostnameMap()
		if got2["140.82.114.4"] != "github.com" {
			t.Errorf("GetIPToHostnameMap returned a reference: caller deletion leaked")
		}
		if _, ok := got2["9.9.9.9"]; ok {
			t.Errorf("GetIPToHostnameMap returned a reference: caller insertion leaked")
		}
	})
}

// Reloading config rebuilds trackedHostnames but PRESERVES the DNS caches
// (hostnameCache, ipToHostname) so reverse lookups for IPs learned before
// the reload still work. Pin this so a future "reset all state on reload"
// change is deliberate.
func TestLoadConfig_PreservesDNSCacheAcrossReload(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("initial LoadConfigFromRules() error = %v", err)
	}
	cm.UpdateDNSMapping("github.com", "140.82.114.4")
	if got := cm.LookupHostnameByIP("140.82.114.4"); got != "github.com" {
		t.Fatalf("pre-reload reverse lookup failed: got %q", got)
	}

	// Reload with a completely different ruleset.
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "npmjs.org", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("reload LoadConfigFromRules() error = %v", err)
	}

	// trackedHostnames rebuilt — github.com no longer tracked.
	if _, ok := cm.GetTrackedHostnames()["github.com"]; ok {
		t.Errorf("trackedHostnames should have been rebuilt; github.com lingered")
	}
	if _, ok := cm.GetTrackedHostnames()["npmjs.org"]; !ok {
		t.Errorf("trackedHostnames missing new rule npmjs.org")
	}

	// DNS reverse map preserved — still resolves to the prior hostname.
	if got := cm.LookupHostnameByIP("140.82.114.4"); got != "github.com" {
		t.Errorf("DNS reverse cache lost across reload: got %q, want github.com", got)
	}
}
