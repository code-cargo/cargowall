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

package dns

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// recordingRegistrar captures what the DNS path scopes. FlushScopes clears
// the recorded scopes, mirroring the real map semantics, so a test can assert
// on exactly what survives a reload's flush + re-warm.
type recordingRegistrar struct {
	flushes int
	scopes  map[string]string
}

func (r *recordingRegistrar) FlushScopes() error {
	r.flushes++
	r.scopes = nil
	return nil
}

// portKey renders the ports handed to ScopeIP. The DNS layer's job is to pass
// a rule's ports for an IP it has forward-resolution evidence for; turning
// those into L7_SCOPE_* bits belongs to pkg/origin, which owns the map, and is
// covered by its TestL7ScopeFromPorts.
func portKey(ports []config.Port) string {
	if len(ports) == 0 {
		return "all-ports"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%s/%d", p.Protocol, p.Port)
	}
	return strings.Join(parts, ",")
}

func (r *recordingRegistrar) ScopeIP(ip net.IP, ports []config.Port) error {
	if r.scopes == nil {
		r.scopes = map[string]string{}
	}
	r.scopes[ip.String()] = portKey(ports)
	return nil
}

// TestRegisterL7ScopesOnlyBoundIPs confirms the seam is a no-op with no
// registrar and — the invariant this package owns — hands over only IPs a name
// was seen forward-resolving to. Which PORTS map to which L7 dimension is
// pkg/origin's call (TestL7ScopeFromPorts), not this layer's.
func TestRegisterL7ScopesOnlyBoundIPs(t *testing.T) {
	s := &Server{logger: slog.Default(), config: config.NewConfigManager()}

	// No registrar installed: must not panic.
	s.registerL7("auth.docker.io", net.ParseIP("104.16.0.1"), []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})

	rec := &recordingRegistrar{}
	s.SetL7Registrar(rec)
	// Scoping requires forward-resolution evidence (RegisterL7Identity).
	s.config.RecordForwardResolution("ssh.example.com", "104.16.0.2")
	s.config.RecordForwardResolution("auth.docker.io", "104.16.0.3")

	// A bound IP is handed over with the rule's ports verbatim.
	s.registerL7("auth.docker.io", net.ParseIP("104.16.0.3"), []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
	if rec.scopes["104.16.0.3"] != "tcp/443" {
		t.Errorf("scoped %q, want tcp/443", rec.scopes["104.16.0.3"])
	}

	// SCOPE IFF BOUND: the same 443 rule scopes nothing at an IP no forward
	// resolution ever produced. Reverse-DNS attribution is attacker-influenced
	// and mints no binding, so scoping on it would make --tls-sni-pin-ip deny
	// every flight to that IP.
	s.registerL7("auth.docker.io", net.ParseIP("203.0.113.9"), []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
	if _, scoped := rec.scopes["203.0.113.9"]; scoped {
		t.Errorf("scoped an IP with no forward-resolution evidence: %v", rec.scopes)
	}
}

// TestDerivedAllowPorts covers the L7 slow path's view of the derived
// CNAME-target set: a learned target resolves to its inherited ports, an
// unknown name does not, and a nil/absent cache is safe.
func TestDerivedAllowPorts(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "allowed.example.com", Action: config.ActionAllow},
	}, config.ActionDeny))

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	server.filterQueries = true

	const origin = "allowed.example.com."
	resp := makeCNAMEResponse(origin, []string{"edge.cdn.example.net"}, "")
	seedCachedResponse(server, origin, resp)

	query := new(dns.Msg)
	query.SetQuestion(origin, dns.TypeA)
	query.Id = 7101
	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	server.handleDNSQuery(w, query)
	w.AssertExpectations(t)

	ports, ok := server.DerivedAllowPorts("edge.cdn.example.net")
	assert.True(t, ok, "a learned CNAME target must be visible to the L7 matcher")
	assert.Empty(t, ports, "an all-ports origin passes an all-ports inheritance")

	// Case-insensitive, mirroring the query gate.
	_, ok = server.DerivedAllowPorts("EDGE.CDN.EXAMPLE.NET")
	assert.True(t, ok, "lookup must be case-insensitive")

	_, ok = server.DerivedAllowPorts("never.learned.example")
	assert.False(t, ok, "an unlearned name must not resolve")

	_, ok = server.DerivedAllowPorts("")
	assert.False(t, ok, "the empty name must not resolve")

	var nilServer *Server
	_, ok = nilServer.DerivedAllowPorts("edge.cdn.example.net")
	assert.False(t, ok, "a nil server must be safe")
}

// TestDerivedAllowPortsInheritsRulePorts: the ports a target inherits are the
// origin's allow ports, so the L7 matcher's port check on a derived name is as
// tight as it is on a rule-named one.
func TestDerivedAllowPortsInheritsRulePorts(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "web.example.com",
		Action: config.ActionAllow,
		Ports:  []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
	}}, config.ActionDeny))

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	server.filterQueries = true

	const origin = "web.example.com."
	seedCachedResponse(server, origin, makeCNAMEResponse(origin, []string{"edge.example.net"}, ""))

	query := new(dns.Msg)
	query.SetQuestion(origin, dns.TypeA)
	query.Id = 7102
	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	server.handleDNSQuery(w, query)
	w.AssertExpectations(t)

	ports, ok := server.DerivedAllowPorts("edge.example.net")
	require.True(t, ok)
	require.Len(t, ports, 1)
	assert.Equal(t, uint16(443), ports[0].Port)
	assert.Equal(t, config.ProtocolTCP, ports[0].Protocol)
}

// TestApplyRulesFlushesScopes: a reload must FLUSH the scope maps and re-warm
// them, not leave dropped rules' IPs L7-governed. Scope entries have no
// expiry and no reverse index, so enumeration cannot un-scope a dropped rule
// — and the fixed-size maps would eventually fill with dead entries and
// silently fail OPEN every newly resolved destination. The recording
// registrar mirrors map semantics (flush clears), so the surviving set is
// asserted directly.
func TestApplyRulesFlushesScopes(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "kept.example", Action: config.ActionAllow},
		{Type: config.RuleTypeHostname, Value: "gone.example", Action: config.ActionAllow},
	}, config.ActionAllow))

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	rec := &recordingRegistrar{}
	server.SetL7Registrar(rec)

	// Resolved (and scoped) under the old rules.
	server.hostnameIPs["kept.example"] = map[string]bool{"104.16.1.1": true}
	server.hostnameIPs["gone.example"] = map[string]bool{"104.16.2.2": true}
	// Both names forward-resolved to those IPs; scoping requires that evidence.
	cfg.RecordForwardResolution("kept.example", "104.16.1.1")
	cfg.RecordForwardResolution("gone.example", "104.16.2.2")
	server.registerL7("kept.example", net.ParseIP("104.16.1.1"), nil)
	server.registerL7("gone.example", net.ParseIP("104.16.2.2"), nil)
	require.Contains(t, rec.scopes, "104.16.2.2")

	// Policy reload drops gone.example.
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "kept.example", Action: config.ActionAllow},
	}, config.ActionAllow))
	server.ApplyRulesToTrackedHostnames()

	require.Equal(t, 1, rec.flushes, "a reload must flush the scope maps exactly once")
	assert.Equal(t, "all-ports", rec.scopes["104.16.1.1"],
		"a still-allowed tracked name's IP must re-scope after the flush")
	assert.NotContains(t, rec.scopes, "104.16.2.2",
		"a dropped rule's IP must not stay L7-governed across the reload")
}

// TestApplyRulesScopesDerivedTargets: ApplyRulesToTrackedHostnames is the
// ONE maps-are-writable replay for names resolved while the firewall (and
// before it the L7 registrar) was still nil — a cached edge label may never
// be re-queried, so whatever this pass skips stays L7-unscoped for the run.
// It must therefore replay BOTH allow tiers: rule hostnames AND derived
// CNAME targets, which match no rule — a skipped target stays L4-reachable
// (default-allow, a covering CIDR) with l7_scope_for returning 0, so no flow
// to it ever reaches the matcher. A derived target's IP is scoped on the
// ports it inherited; an explicit deny and an unmatched, underived name stay
// skipped.
func TestApplyRulesScopesDerivedTargets(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "origin.example.com", Action: config.ActionAllow},
		{Type: config.RuleTypeHostname, Value: "denied.example", Action: config.ActionDeny},
	}, config.ActionAllow)) // default ALLOW: allow-side writes short-circuit

	mockFw := firewall.NewMockFirewall(t)
	// The pure-deny name's L4 side still writes through the firewall; the L7
	// registrations are what this test is about.
	mockFw.On("AddIP", mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	server := newTestServer(t, cfg, mockFw)
	rec := &recordingRegistrar{}
	server.SetL7Registrar(rec)

	// Tracked during the nil-firewall window: a rule name, a derived target
	// (TTL-hot in cnameAllowed, inheriting :443), a denied name, and an
	// unmatched name.
	server.hostnameIPs["origin.example.com"] = map[string]bool{"104.16.1.1": true}
	server.hostnameIPs["edge.cdn.example.net"] = map[string]bool{"104.16.5.5": true}
	server.hostnameIPs["denied.example"] = map[string]bool{"203.0.113.9": true}
	server.hostnameIPs["unrelated.example"] = map[string]bool{"203.0.113.10": true}
	server.cnameAllowed.Put("edge.cdn.example.net",
		derivedAllow{ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}}, time.Minute)
	// Forward-resolution evidence for the names the replay may scope; the
	// denied and unmatched ones deliberately have none either way.
	cfg.RecordForwardResolution("origin.example.com", "104.16.1.1")
	cfg.RecordForwardResolution("edge.cdn.example.net", "104.16.5.5")

	server.ApplyRulesToTrackedHostnames()

	assert.Equal(t, "all-ports", rec.scopes["104.16.1.1"],
		"the rule hostname is scoped on its rule ports")
	assert.Equal(t, "tcp/443", rec.scopes["104.16.5.5"],
		"the derived target's IP is scoped on the ports it actually inherited")
	assert.NotContains(t, rec.scopes, "203.0.113.9", "an explicit deny is never scoped")
	assert.NotContains(t, rec.scopes, "203.0.113.10", "an unmatched, underived name stays skipped")

	// Once the derived TTL expires, a later replay no longer scopes the
	// target — the tier is TTL-bounded here exactly as it is in the matcher.
	server.cnameAllowed.Put("edge.cdn.example.net", derivedAllow{}, time.Nanosecond)
	time.Sleep(time.Millisecond)
	server.ApplyRulesToTrackedHostnames()
	assert.NotContains(t, rec.scopes, "104.16.5.5", "an expired derived TTL is not replayed")
}

// TestApplyVerdictSideRegistersUnderDefaultAllow: with default-action=allow,
// every allow verdict hits the short-circuit (no BPF write needed) — but the
// L7 identity must still be pinned, or map_l7_scope stays empty for the whole
// run and --tls-sni adjudicates nothing while reporting itself active.
func TestApplyVerdictSideRegistersUnderDefaultAllow(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "web.example", Action: config.ActionAllow},
	}, config.ActionAllow)) // default ALLOW

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	rec := &recordingRegistrar{}
	server.SetL7Registrar(rec)
	cfg.RecordForwardResolution("web.example", "104.16.1.1")

	// No AddIP expectation: the short-circuit means no BPF write happens.
	opened := server.applyVerdictSide(net.ParseIP("104.16.1.1"), "web.example",
		config.ActionAllow, nil, false)

	assert.False(t, opened, "the short-circuit still reports no L4 change")
	assert.Equal(t, "all-ports", rec.scopes["104.16.1.1"],
		"default-allow must still scope the IP")
}
