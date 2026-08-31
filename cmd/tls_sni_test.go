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

package cmd

import (
	"log/slog"
	"net"
	"testing"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/origin"
)

// What cmd owns for L7 is wiring, not policy: the name composition lives in
// config.L7Policy (pkg/config/l7policy_test.go covers the tiers, ports, and
// per-IP binding — cmd hands that value straight to the oracle, so there is
// nothing here to remap or re-test) and the punt-event address decode lives in
// package bpf (TestL7EventAddrs). These tests cover the seams this package
// actually holds.

func TestL7ModeName(t *testing.T) {
	if l7ModeName(origin.L7ModeEnforce) != "enforce" ||
		l7ModeName(origin.L7ModeObserve) != "observe" ||
		l7ModeName(origin.L7ModeOff) != "off" {
		t.Error("l7ModeName wrong")
	}
}

type passthroughFw struct{}

func (passthroughFw) AddIP(net.IP, config.Action, []config.Port) (bool, error) { return false, nil }

// cmdRecordingRegistrar records what the late-allow seam scopes.
type cmdRecordingRegistrar struct {
	scopes map[string][]config.Port // ip -> the rule ports handed over
}

func (r *cmdRecordingRegistrar) FlushScopes() error { r.scopes = nil; return nil }

func (r *cmdRecordingRegistrar) ScopeIP(ip net.IP, ports []config.Port) error {
	if r.scopes == nil {
		r.scopes = map[string][]config.Port{}
	}
	// The seam's job is WHICH IPs reach the registrar; turning ports into
	// L7_SCOPE_* bits is pkg/origin's (TestL7ScopeFromPorts).
	r.scopes[ip.String()] = ports
	return nil
}

// TestScopeAllowedIPNoopsWithoutL7: with --tls-sni off the registrar is nil at
// the composition root, so the shared helper is inert and the L4 pipeline is
// unchanged. A named allow with no registrar must not panic or scope.
func TestScopeAllowedIPNoopsWithoutL7(t *testing.T) {
	events.ScopeAllowedIP(nil, "web.example",
		net.ParseIP("104.16.7.1"), []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})

	// With a registrar but no hostname there is no identity to pin.
	rec := &cmdRecordingRegistrar{}
	cm := config.NewConfigManager()
	reg := l7LateRegistrar{l7: rec, cm: cm, logger: slog.Default()}
	events.ScopeAllowedIP(reg, "", net.ParseIP("104.16.7.1"), nil)
	if len(rec.scopes) != 0 {
		t.Errorf("scoped %v for a nameless allow; want nothing", rec.scopes)
	}
}

// TestGateExistingConnectionsScopesWithoutNewAdd: the existing-connection gate
// must scope L7 whenever the L4 side is open — not only when its own AddIP was
// the first writer. passthroughFw returns (false, nil), the "already in the LPM
// from a DNS or pre-population write" shape: gating registration on wasAdded
// left such a destination L4-open but L7-unscoped for the run. It routes
// through the same events.ScopeAllowedIP as the post-verdict late-allow.
//
// The IP must carry forward-resolution evidence, or RegisterL7Identity refuses
// to scope it — see TestGateExistingConnectionsSkipsUnboundIP.
func TestGateExistingConnectionsScopesWithoutNewAdd(t *testing.T) {
	cm := config.NewConfigManager()
	if err := cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "web.example", Action: config.ActionAllow},
	}, config.ActionDeny); err != nil {
		t.Fatal(err)
	}
	cm.UpdateDNSMapping("web.example", "104.16.7.1")
	cm.RecordForwardResolution("web.example", "104.16.7.1")

	rec := &cmdRecordingRegistrar{}
	reg := l7LateRegistrar{l7: rec, cm: cm, logger: slog.Default()}

	gateExistingConnections(existingConns{
		"104.16.7.1": {{Port: 443, Protocol: config.ProtocolTCP}},
	}, cm, passthroughFw{}, reg, nil, slog.Default())

	// An all-ports hostname rule reaches the registrar as an empty port list,
	// which pkg/origin maps to every dimension — the point being that it is
	// scoped at all despite wasAdded=false.
	got, scoped := rec.scopes["104.16.7.1"]
	if !scoped {
		t.Fatalf("IP was not scoped despite wasAdded=false; recorded %v", rec.scopes)
	}
	if len(got) != 0 {
		t.Errorf("ports = %v, want the rule's all-ports (empty) list", got)
	}
}

// TestGateExistingConnectionsSkipsUnboundIP: the existing-connection gate runs
// on hostnames that may have come from a reverse-DNS PTR, which an attacker at
// the destination controls and which never mints binding evidence. Scoping such
// an IP would make --tls-sni=enforce-pinned deny every flight to it, so it stays
// L4-governed.
func TestGateExistingConnectionsSkipsUnboundIP(t *testing.T) {
	cm := config.NewConfigManager()
	if err := cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "web.example", Action: config.ActionAllow},
	}, config.ActionDeny); err != nil {
		t.Fatal(err)
	}
	// Attribution only (the shape reverseDNSExistingConnections writes) — no
	// forward resolution ever recorded for this IP.
	cm.UpdateDNSMapping("web.example", "203.0.113.9")

	rec := &cmdRecordingRegistrar{}
	reg := l7LateRegistrar{l7: rec, cm: cm, logger: slog.Default()}

	gateExistingConnections(existingConns{
		"203.0.113.9": {{Port: 443, Protocol: config.ProtocolTCP}},
	}, cm, passthroughFw{}, reg, nil, slog.Default())

	if _, scoped := rec.scopes["203.0.113.9"]; scoped {
		t.Errorf("scoped an IP with no forward-resolution evidence: %v", rec.scopes)
	}
}
