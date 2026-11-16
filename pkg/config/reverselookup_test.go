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
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
)

func TestReverseLookupName(t *testing.T) {
	for name, want := range map[string]bool{
		"in-addr.arpa":             true,
		"ip6.arpa.":                true,
		"7.2.0.192.in-addr.arpa":   true,
		"x.ip6.arpa":               true,
		"*.in-addr.arpa":           true,
		"**.ip6.arpa":              true,
		"*.*.2.0.192.IN-ADDR.ARPA": true,
		"arpa":                     false,
		"home.arpa":                false,
		"ipv4only.arpa":            false,
		"in-addr.arpa.example.com": false,
		"myin-addr.arpa":           false,
		"*.myip6.arpa":             false,
		"github.com":               false,
	} {
		assert.Equal(t, want, ReverseLookupName(name), name)
	}
}

// A hostname allow rule for a reverse-lookup name, plain or a pattern, is
// dropped with one warning each, and the rest of the policy loads: other
// rules, a deny rule for such a name, and rules for other .arpa names.
func TestLoad_ReverseLookupHostRulesDropped(t *testing.T) {
	logs := captureLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "7.2.0.192.in-addr.arpa", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "ip6.arpa", Action: ActionAllow},
		{
			Type: RuleTypeHostname, Value: "*.in-addr.arpa", Action: ActionAllow,
			Ports: []Port{{Port: 53, Protocol: ProtocolUDP}},
		},
		{Type: RuleTypeHostname, Value: "**.IP6.ARPA", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "in-addr.arpa", Action: ActionDeny},
		{Type: RuleTypeHostname, Value: "home.arpa", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "ipv4only.arpa", Action: ActionAllow},
		{Type: RuleTypeCIDR, Value: "192.0.2.0/24", Action: ActionAllow},
	}, ActionDeny))
	assert.ElementsMatch(t, []string{"github.com", "in-addr.arpa", "home.arpa", "ipv4only.arpa", "192.0.2.0/24"},
		resolvedValues(cm.GetResolvedRules()))
	ws := warns(*logs)
	require.Len(t, ws, 4)
	for _, w := range ws {
		assert.Contains(t, w, "A hostname rule for a reverse-lookup name is dropped: a reverse lookup is answered "+
			"for an address the run allows; allow the address instead")
	}
	assert.False(t, cm.MatchHostnameRule("data.7.2.0.192.in-addr.arpa").HasAllow())
	assert.True(t, cm.MatchHostnameRule("printer.home.arpa").HasAllow())
}

// A CodeCargo policy with such a rule loads, enforcing, without it.
func TestLoadConfigFromCargoWall_ReverseLookupHostRuleDropped(t *testing.T) {
	logs := captureLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
		Mode:          datapb.CargoWallMode_CARGO_WALL_MODE_ENFORCE,
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		Rules: []*cargowallv1pb.CargoWallPolicy_Rule{
			{
				Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME,
				Value:  "github.com",
				Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
			},
			{
				Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME,
				Value:  "34.216.184.93.in-addr.arpa",
				Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
			},
		},
	}))
	assert.False(t, cm.IsAuditMode())
	assert.Equal(t, []string{"github.com"}, resolvedValues(cm.GetResolvedRules()))
	assert.Len(t, warns(*logs), 1)
}

// A local file's job and step rules are held to the same drop, the rest
// of each kept, and so are the environment's allowed hosts.
func TestLoadConfig_ReverseLookupHostRulesDropped(t *testing.T) {
	logs := captureLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeJSONConfig(t, `{"defaultAction": "deny",
		"rules": [
			{"type": "hostname", "value": "job.example", "action": "allow"},
			{"type": "hostname", "value": "*.ip6.arpa", "action": "allow"}],
		"steps": [{"id": "a", "rules": [
			{"type": "hostname", "value": "a.example"},
			{"type": "hostname", "value": "**.in-addr.arpa"}]}]}`)))
	assert.Equal(t, []string{"job.example"}, resolvedValues(cm.GetResolvedRules()))
	steps := cm.GetStepRules()
	require.Len(t, steps, 1)
	assert.Equal(t, []string{"a.example"}, resolvedValues(steps[0].Rules))
	assert.False(t, cm.StepAllowsHostname("4.3.2.1.in-addr.arpa"))
	assert.Len(t, warns(*logs), 2)

	*logs = nil
	t.Setenv("CARGOWALL_ALLOWED_HOSTS", "github.com,in-addr.arpa")
	cm = NewConfigManager()
	require.NoError(t, cm.LoadFromEnv())
	assert.Equal(t, []string{"github.com"}, resolvedValues(cm.GetResolvedRules()))
	assert.Len(t, warns(*logs), 1)
}

func TestLocalAddress(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.96.0.1":          true,
		"172.31.255.255":     true,
		"192.168.1.1":        true,
		"127.0.0.53":         true,
		"::1":                true,
		"169.254.169.254":    true,
		"fe80::1":            true,
		"fd00::1":            true,
		"100.64.0.1":         true,
		"100.127.255.255":    true,
		"::ffff:10.96.0.1":   true,
		"::ffff:100.100.1.1": true,
		"100.63.255.255":     false,
		"100.128.0.0":        false,
		"8.8.8.8":            false,
		"2001:db8::1":        false,
	} {
		assert.Equal(t, want, LocalAddress(netip.MustParseAddr(ip)), ip)
	}
}

// A search domain under a reverse-lookup zone is refused, wherever it is
// configured: a reverse lookup is answered for an address the run allows,
// never by a search domain.
func TestValidateSearchDomain_ReverseLookupZones(t *testing.T) {
	for _, d := range []string{".100.51.198.in-addr.arpa", ".in-addr.arpa", ".8.b.d.0.1.0.0.2.ip6.arpa", ".IP6.ARPA"} {
		err := validateSearchDomain(strings.ToLower(d))
		require.Error(t, err, d)
		assert.Contains(t, err.Error(), "under a reverse-lookup zone", d)
	}
	assert.NoError(t, validateSearchDomain(".compute.internal"))
}
