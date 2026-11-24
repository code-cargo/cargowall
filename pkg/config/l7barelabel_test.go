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
	"fmt"
	"log/slog"
	"testing"
	"time"
)

// builderIP is a public address, the shape of a dedicated build host.
const builderIP = "54.80.12.34"

func bareLabelManager(t *testing.T, rules ...Rule) *Manager {
	t.Helper()
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules(rules, ActionDeny); err != nil {
		t.Fatal(err)
	}
	return cm
}

func sniAt(name, ip string) L7Request {
	return L7Request{Name: name, DstIP: ip, DstPort: 443, Proto: 6, SNI: true}
}

var allowBuilders = Rule{Type: RuleTypeHostname, Value: "*.compute-1.amazonaws.com", Action: ActionAllow}

const builderName = "ec2-54-80-12-34.compute-1.amazonaws.com"

// A client that dials a dedicated host by address and presents an opaque
// per-machine label as its SNI passes when a name the policy allows there
// forward-resolved to that address.
func TestMatchL7_BareLabelAtBoundAllowedHost(t *testing.T) {
	cm := bareLabelManager(t, allowBuilders)
	cm.RecordForwardResolution(builderName, builderIP)
	p := NewL7Policy(cm, nil)

	if got := p.MatchName(sniAt("kq563vfqzm", builderIP)); got != L7MatchBareLabel {
		t.Errorf("bare label at a bound, allowed host = %v, want L7MatchBareLabel", got)
	}
	// The same over QUIC: it too is a server name.
	q := sniAt("kq563vfqzm", builderIP)
	q.Proto = 17
	if got := p.MatchName(q); got != L7MatchBareLabel {
		t.Errorf("bare label over QUIC = %v, want L7MatchBareLabel", got)
	}
}

func TestMatchL7_BareLabelRefused(t *testing.T) {
	cm := bareLabelManager(t, allowBuilders,
		Rule{Type: RuleTypeCIDR, Value: "198.51.100.0/24", Action: ActionAllow},
		Rule{Type: RuleTypeHostname, Value: "vault.corp.example", Action: ActionAllow},
		Rule{Type: RuleTypeHostname, Value: "kq563vfqzm", Action: ActionDeny},
	)
	cm.RecordForwardResolution(builderName, builderIP)
	// Bound, but to a name no rule allows (an audit-mode resolution).
	cm.RecordForwardResolution("other.example", "54.80.99.99")
	// Allowed names bound to non-public addresses.
	for _, ip := range []string{
		"10.1.2.3", "172.16.0.9", "192.168.1.10", "127.0.0.1", "169.254.1.1",
		"100.64.3.4", "fd00::10", "fe80::1", "::1",
	} {
		cm.RecordForwardResolution("vault.corp.example", ip)
	}
	// A reverse name: attribution only, never binding evidence.
	if !cm.RecordReverseName("ec2-54-80-77-77.compute-1.amazonaws.com", "54.80.77.77") {
		t.Fatal("reverse name not recorded")
	}
	p := NewL7Policy(cm, nil)

	for _, c := range []struct {
		desc string
		q    L7Request
	}{
		{"an address with nothing bound", sniAt("kq563vfqzm", "54.80.1.1")},
		{"an address bound only to a name no rule allows", sniAt("kq563vfqzm", "54.80.99.99")},
		{"an address allowed only by a CIDR", sniAt("kq563vfqzm", "198.51.100.7")},
		{"an address named only by a confirmed reverse name", sniAt("kq563vfqzm", "54.80.77.77")},
		{"a dotted name no rule allows", sniAt("kq563vfqzm.example", builderIP)},
		{"a bare label a deny rule names", sniAt("kq563vfqzm", builderIP)},
		{"an HTTP Host", L7Request{Name: "bucket", DstIP: builderIP, DstPort: 80, Proto: 6}},
		{"a 10/8 address", sniAt("vault", "10.1.2.3")},
		{"a 172.16/12 address", sniAt("vault", "172.16.0.9")},
		{"a 192.168/16 address", sniAt("vault", "192.168.1.10")},
		{"loopback", sniAt("vault", "127.0.0.1")},
		{"link-local", sniAt("vault", "169.254.1.1")},
		{"carrier-grade NAT", sniAt("vault", "100.64.3.4")},
		{"unique-local", sniAt("vault", "fd00::10")},
		{"IPv6 link-local", sniAt("vault", "fe80::1")},
		{"IPv6 loopback", sniAt("vault", "::1")},
	} {
		if got := p.MatchName(c.q); got != L7NoMatch {
			t.Errorf("%s: got %v, want L7NoMatch", c.desc, got)
		}
	}
	// Control for the deny-rule case: the same host passes another label.
	if got := p.MatchName(sniAt("zz9plural", builderIP)); got != L7MatchBareLabel {
		t.Errorf("control: another bare label at the builder = %v, want L7MatchBareLabel", got)
	}
}

// A deny rule covering the bound name on this port removes it as evidence;
// on a port the deny does not name, it still counts.
func TestMatchL7_BareLabelBoundNameDeniedOnPort(t *testing.T) {
	cm := bareLabelManager(t,
		// A mixed verdict, as TestMatchL7_MixedVerdictPort builds one: the
		// stripped form allowed on every port, the full form denied on 443.
		Rule{Type: RuleTypeHostname, Value: "builder", Action: ActionAllow},
		Rule{Type: RuleTypeHostname, Value: "builder.compute.internal", Action: ActionDeny, Ports: []Port{{Port: 443, Protocol: ProtocolTCP}}},
	)
	cm.AddSearchDomains([]string{".compute.internal"}, slog.Default())
	cm.RecordForwardResolution("builder.compute.internal", builderIP)
	if v := cm.MatchHostnameRule("builder.compute.internal"); !v.HasAllow() || !v.HasDeny() {
		t.Fatalf("the verdict must be mixed: %+v", v)
	}
	p := NewL7Policy(cm, nil)

	if got := p.MatchName(sniAt("kq563vfqzm", builderIP)); got != L7NoMatch {
		t.Errorf("bound name denied on 443: got %v, want L7NoMatch", got)
	}
	q := sniAt("kq563vfqzm", builderIP)
	q.DstPort = 8443
	if got := p.MatchName(q); got != L7MatchBareLabel {
		t.Errorf("bound name allowed on 8443: got %v, want L7MatchBareLabel", got)
	}
	// And a bound name allowed only on another port is no evidence here.
	cm2 := bareLabelManager(t,
		Rule{Type: RuleTypeHostname, Value: "ssh.example", Action: ActionAllow, Ports: []Port{{Port: 22, Protocol: ProtocolTCP}}})
	cm2.RecordForwardResolution("ssh.example", builderIP)
	if got := NewL7Policy(cm2, nil).MatchName(sniAt("kq563vfqzm", builderIP)); got != L7NoMatch {
		t.Errorf("bound name allowed only on :22: got %v, want L7NoMatch", got)
	}
}

// The derived CNAME tier and the flow's step tier count for the bound name
// as they would for a presented one.
func TestMatchL7_BareLabelOtherTiers(t *testing.T) {
	cm := bareLabelManager(t)
	cm.RecordForwardResolution("edge.cdn.example", builderIP)
	cm.RecordForwardResolution("step.example", "54.80.50.50")

	derived := func(name string) ([]Port, bool) { return nil, name == "edge.cdn.example" }
	steps := func(policy uint32, name string) ([]Port, bool) {
		return []Port{{Port: 443, Protocol: ProtocolTCP}}, policy == 2 && name == "step.example"
	}
	p := NewL7Policy(cm, derived).WithSteps(steps)

	if got := p.MatchName(sniAt("kq563vfqzm", builderIP)); got != L7MatchBareLabel {
		t.Errorf("bound derived CNAME target: got %v, want L7MatchBareLabel", got)
	}
	asStep := func(policy uint32) L7Request {
		q := sniAt("kq563vfqzm", "54.80.50.50")
		q.Policy = policy
		return q
	}
	if got := p.MatchName(asStep(2)); got != L7MatchBareLabel {
		t.Errorf("bound name the flow's step allows: got %v, want L7MatchBareLabel", got)
	}
	if got := p.MatchName(asStep(0)); got != L7NoMatch {
		t.Errorf("bound step name, judged as the job: got %v, want L7NoMatch", got)
	}
	if got := p.MatchName(asStep(3)); got != L7NoMatch {
		t.Errorf("bound step name, judged as another step: got %v, want L7NoMatch", got)
	}
}

// A bare label a hostname rule names goes through the ordinary tiers: bound
// it is L7MatchOK, unbound it is L7MatchElsewhere, never a bare-label pass.
func TestMatchL7_BareLabelNamedByRule(t *testing.T) {
	cm := bareLabelManager(t, allowBuilders, Rule{Type: RuleTypeHostname, Value: "vault", Action: ActionAllow})
	cm.RecordForwardResolution(builderName, builderIP)
	cm.RecordForwardResolution("vault", "54.80.60.60")
	p := NewL7Policy(cm, nil)

	if got := p.MatchName(sniAt("vault", "54.80.60.60")); got != L7MatchOK {
		t.Errorf("ruled bare label at its address: got %v, want L7MatchOK", got)
	}
	if got := p.MatchName(sniAt("vault", builderIP)); got != L7MatchElsewhere {
		t.Errorf("ruled bare label elsewhere: got %v, want L7MatchElsewhere", got)
	}
}

// Only the bound name that satisfied the check has its recency refreshed,
// so evidence nobody used still ages out.
func TestBoundNameAllowed_RefreshesOnlyTheMatch(t *testing.T) {
	cm := NewConfigManager()
	cm.RecordForwardResolution("a.example", builderIP)
	cm.RecordForwardResolution("b.example", builderIP)
	old := time.Now().Add(-time.Hour)
	cm.bindMu.Lock()
	for _, n := range []string{"a.example", "b.example"} {
		cm.bindings.byName[n].ips[builderIP] = old
		cm.bindings.byName[n].newest = old
	}
	cm.bindMu.Unlock()

	name, ok := cm.BoundNameAllowed(builderIP, func(n string) bool { return n == "b.example" })
	if !ok || name != "b.example" {
		t.Fatalf("BoundNameAllowed = %q, %v; want b.example, true", name, ok)
	}
	cm.bindMu.Lock()
	defer cm.bindMu.Unlock()
	if !cm.bindings.byName["a.example"].ips[builderIP].Equal(old) {
		t.Error("the name that did not answer was refreshed")
	}
	if !cm.bindings.byName["b.example"].ips[builderIP].After(old) {
		t.Error("the name that answered was not refreshed")
	}
}

// checkBindingIndex asserts byIP is exactly the inverse of byName.
func checkBindingIndex(t *testing.T, cm *Manager) {
	t.Helper()
	cm.bindMu.Lock()
	defer cm.bindMu.Unlock()
	pairs := 0
	for name, b := range cm.bindings.byName {
		for ip := range b.ips {
			pairs++
			if _, ok := cm.bindings.byIP[ip][name]; !ok {
				t.Fatalf("byName holds %s -> %s, byIP does not", name, ip)
			}
		}
	}
	indexed := 0
	for ip, names := range cm.bindings.byIP {
		if len(names) == 0 {
			t.Fatalf("byIP keeps an empty set for %s", ip)
		}
		for name := range names {
			indexed++
			b := cm.bindings.byName[name]
			if b == nil {
				t.Fatalf("byIP holds %s -> %s for an evicted name", ip, name)
			}
			if _, ok := b.ips[ip]; !ok {
				t.Fatalf("byIP holds %s -> %s, byName does not", ip, name)
			}
		}
	}
	if pairs != indexed {
		t.Fatalf("byName has %d pairs, byIP %d", pairs, indexed)
	}
}

// The reverse index follows the store through both eviction paths: an
// address dropped from a name past maxBindingIPsPerName, and a whole name
// dropped past maxBindingNames.
func TestBindingIndexConsistentAcrossEvictions(t *testing.T) {
	cm := NewConfigManager()
	for i := 0; i < maxBindingIPsPerName+10; i++ {
		cm.RecordForwardResolution("rr.example", fmt.Sprintf("54.80.%d.%d", i/256, i%256))
	}
	checkBindingIndex(t, cm)
	if _, ok := cm.BoundNameAllowed("54.80.0.0", func(string) bool { return true }); ok {
		t.Error("an address evicted from its name still answers")
	}

	for i := 0; i < maxBindingNames+10; i++ {
		cm.RecordForwardResolution(fmt.Sprintf("h%d.wildcard.example", i), "104.16.1.1")
		if i%1000 == 0 {
			cm.RecordCNAMEChain("104.16.2.2", []string{fmt.Sprintf("o%d.example", i), "edge.example"}, time.Minute)
		}
	}
	checkBindingIndex(t, cm)
	cm.bindMu.Lock()
	_, rrKept := cm.bindings.byName["rr.example"]
	_, rrIndexed := cm.bindings.byIP["54.80.0.40"]
	cm.bindMu.Unlock()
	if rrKept || rrIndexed {
		t.Errorf("the least-recent name survived the name cap: store %v, index %v", rrKept, rrIndexed)
	}
}
