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
	"testing"
	"time"
)

func TestMatchL7_RuleTier(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "auth.docker.io", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "blocked.example.com", Action: ActionDeny},
	}, ActionDeny); err != nil {
		t.Fatal(err)
	}
	// Bind the allowed name so this stays a test of the name/deny logic
	// rather than of the per-IP dimension.
	cm.RecordForwardResolution("auth.docker.io", "104.16.1.1")

	q := func(name string) L7Request {
		return L7Request{Name: name, DstIP: "104.16.1.1", DstPort: 443, Proto: 6}
	}
	if got := NewL7Policy(cm, nil).MatchName(q("auth.docker.io")); got != L7MatchOK {
		t.Errorf("allowed name = %v, want L7MatchOK", got)
	}
	if got := NewL7Policy(cm, nil).MatchName(q("evil.attacker.example")); got != L7NoMatch {
		t.Errorf("unlisted name = %v, want L7NoMatch", got)
	}
	if got := NewL7Policy(cm, nil).MatchName(q("blocked.example.com")); got != L7NoMatch {
		t.Errorf("denied name = %v, want L7NoMatch (fail toward denial)", got)
	}
}

// TestMatchL7_PerIPBinding: an allowed name presented at a destination it
// never resolved to comes back L7MatchElsewhere — distinct from a name no rule
// allows — so the caller can measure or enforce that dimension on its own
// gate. This is what stops an allowed name working as a passphrase for any
// L7-scoped IP.
func TestMatchL7_PerIPBinding(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "good.example", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatal(err)
	}
	cm.RecordForwardResolution("good.example", "104.16.1.1")

	bound := L7Request{Name: "good.example", DstIP: "104.16.1.1", DstPort: 443, Proto: 6}
	if got := NewL7Policy(cm, nil).MatchName(bound); got != L7MatchOK {
		t.Errorf("name at its resolved IP = %v, want L7MatchOK", got)
	}

	elsewhere := L7Request{Name: "good.example", DstIP: "203.0.113.7", DstPort: 443, Proto: 6}
	if got := NewL7Policy(cm, nil).MatchName(elsewhere); got != L7MatchElsewhere {
		t.Errorf("allowed name at an unrelated IP = %v, want L7MatchElsewhere", got)
	}

	// Round-robin: a second address for the same name also binds, because the
	// evidence store accumulates rather than replaces.
	cm.RecordForwardResolution("good.example", "104.16.2.2")
	roundRobin := L7Request{Name: "good.example", DstIP: "104.16.2.2", DstPort: 443, Proto: 6}
	if got := NewL7Policy(cm, nil).MatchName(roundRobin); got != L7MatchOK {
		t.Errorf("second round-robin address = %v, want L7MatchOK", got)
	}
	if got := NewL7Policy(cm, nil).MatchName(bound); got != L7MatchOK {
		t.Errorf("first address must still bind after a second is seen, got %v", got)
	}
}

// TestMatchL7_PortScoped: a name allowed only on a non-web port must not
// validate as an SNI on 443 (the shared-edge over-admit the port check closes).
func TestMatchL7_PortScoped(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "ssh.example.com", Action: ActionAllow, Ports: []Port{{Port: 22, Protocol: ProtocolTCP}}},
		{Type: RuleTypeHostname, Value: "web.example.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatal(err)
	}
	cm.RecordForwardResolution("ssh.example.com", "104.16.1.1")
	cm.RecordForwardResolution("web.example.com", "104.16.1.1")

	q := func(name string, port uint16) L7Request {
		return L7Request{Name: name, DstIP: "104.16.1.1", DstPort: port, Proto: 6}
	}
	if got := NewL7Policy(cm, nil).MatchName(q("ssh.example.com", 443)); got != L7NoMatch {
		t.Errorf(":22-only name on 443 = %v, want L7NoMatch", got)
	}
	if got := NewL7Policy(cm, nil).MatchName(q("ssh.example.com", 22)); got != L7MatchOK {
		t.Errorf(":22-only name on its own port = %v, want L7MatchOK", got)
	}
	if got := NewL7Policy(cm, nil).MatchName(q("web.example.com", 443)); got != L7MatchOK {
		t.Errorf("all-ports allow on 443 = %v, want L7MatchOK", got)
	}
}

// TestMatchL7_MixedVerdictPort: a deny rule wins only on the ports it names.
// A genuine mixed verdict (the full form denied on :80, the stripped form
// allowed on :443, via a search domain) must ADMIT a TLS flow on 443 — a
// name-wide deny would deny every such flow, even on the allowed port.
func TestMatchL7_MixedVerdictPort(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "api", Action: ActionAllow, Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}},
		{Type: RuleTypeHostname, Value: "api.compute.internal", Action: ActionDeny, Ports: []Port{{Port: 80, Protocol: ProtocolTCP}}},
	}, ActionDeny); err != nil {
		t.Fatal(err)
	}
	cm.AddSearchDomains([]string{".compute.internal"}, slog.Default())
	cm.RecordForwardResolution("api.compute.internal", "104.16.1.1")

	// Sanity: the verdict really is mixed (allow 443 on the stripped form,
	// deny 80 on the full form).
	v := cm.MatchHostnameRule("api.compute.internal")
	if !v.HasAllow() || !v.HasDeny() {
		t.Fatalf("test setup: want a mixed verdict, got HasAllow=%v HasDeny=%v", v.HasAllow(), v.HasDeny())
	}

	q := func(port uint16) L7Request {
		return L7Request{Name: "api.compute.internal", DstIP: "104.16.1.1", DstPort: port, Proto: 6}
	}
	if got := NewL7Policy(cm, nil).MatchName(q(443)); got != L7MatchOK {
		t.Errorf("TLS on the allowed port = %v, want L7MatchOK (deny 80 must not shadow allow 443)", got)
	}
	if got := NewL7Policy(cm, nil).MatchName(q(80)); got != L7NoMatch {
		t.Errorf("HTTP on the denied port = %v, want L7NoMatch", got)
	}
}

// TestMatchL7_DerivedTier: a client that legitimately dialed a CNAME target
// directly presents that target as its SNI/Host; it matches no hostname rule,
// so a rules-only policy would DENY it. The derived tier admits it,
// port-scoped, and an explicit covering deny still wins.
func TestMatchL7_DerivedTier(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "origin.example.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "blocked.edge.example", Action: ActionDeny},
	}, ActionDeny); err != nil {
		t.Fatal(err)
	}

	inherited := map[string][]Port{
		"edge.akamai.example":  nil, // all-ports inheritance
		"web.edge.example":     {{Port: 443, Protocol: ProtocolTCP}},
		"blocked.edge.example": nil, // learned, but explicitly denied by rule
	}
	derived := func(name string) ([]Port, bool) {
		p, ok := inherited[name]
		return p, ok
	}

	// Bind every name to the destination under test so this stays a test of
	// the derived tier. Derived targets bind through the recorded CNAME chain
	// (their names are hops in it), exactly as production establishes it.
	const edgeIP = "104.16.1.1"
	cm.RecordForwardResolution("origin.example.com", edgeIP)
	for _, chain := range [][]string{
		{"origin.example.com", "edge.akamai.example"},
		{"web-origin.example", "web.edge.example"},
		{"blocked-origin.example", "blocked.edge.example"},
	} {
		cm.RecordCNAMEChain(edgeIP, chain, time.Minute)
	}
	q := func(name string, port uint16, proto uint8) L7Request {
		return L7Request{Name: name, DstIP: edgeIP, DstPort: port, Proto: proto}
	}

	for _, tc := range []struct {
		name  string
		port  uint16
		proto uint8
		want  L7Match
	}{
		{"edge.akamai.example", 443, 6, L7MatchOK},
		{"edge.akamai.example", 80, 6, L7MatchOK},
		{"edge.akamai.example", 443, 17, L7MatchOK},
		{"web.edge.example", 443, 6, L7MatchOK},
		{"web.edge.example", 80, 6, L7NoMatch},      // inherited ports are enforced
		{"blocked.edge.example", 443, 6, L7NoMatch}, // deny beats the derived tier
		{"evil.attacker.example", 443, 6, L7NoMatch},
		{"origin.example.com", 443, 6, L7MatchOK}, // rule tier unaffected
	} {
		if got := NewL7Policy(cm, derived).MatchName(q(tc.name, tc.port, tc.proto)); got != tc.want {
			t.Errorf("MatchName(%s:%d proto %d) = %v, want %v", tc.name, tc.port, tc.proto, got, tc.want)
		}
	}
}

// TestMatchL7_RulePortMissDerivedCovers: a name that is BOTH an :22-only rule
// and a derived all-ports CNAME target must be admitted on 443 via the derived
// tier — the HasAllow branch must not shadow it.
func TestMatchL7_RulePortMissDerivedCovers(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "edge.example", Action: ActionAllow, Ports: []Port{{Port: 22, Protocol: ProtocolTCP}}},
	}, ActionDeny); err != nil {
		t.Fatal(err)
	}
	cm.RecordForwardResolution("edge.example", "104.16.1.1")
	derived := func(name string) ([]Port, bool) {
		return nil, name == "edge.example" // all-ports derived allow
	}
	q := L7Request{Name: "edge.example", DstIP: "104.16.1.1", DstPort: 443, Proto: 6}
	if got := NewL7Policy(cm, derived).MatchName(q); got != L7MatchOK {
		t.Errorf("443 = %v, want L7MatchOK: the :22 rule must not shadow the derived all-ports allow", got)
	}
}

// With no DNS proxy there is no derived set, and the policy must stay
// rules-only rather than nil-panic.
func TestMatchL7_NilDerived(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "origin.example.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatal(err)
	}
	cm.RecordForwardResolution("origin.example.com", "104.16.1.1")
	q := func(name string) L7Request {
		return L7Request{Name: name, DstIP: "104.16.1.1", DstPort: 443, Proto: 6}
	}
	if got := NewL7Policy(cm, nil).MatchName(q("origin.example.com")); got != L7MatchOK {
		t.Errorf("rule-allowed name with no derived tier = %v, want L7MatchOK", got)
	}
	if got := NewL7Policy(cm, nil).MatchName(q("edge.akamai.example")); got != L7NoMatch {
		t.Errorf("unknown name with no derived tier = %v, want L7NoMatch", got)
	}
}
