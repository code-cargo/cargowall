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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
)

func TestReverseLookupName(t *testing.T) {
	for name, want := range map[string]bool{
		"in-addr.arpa": true, "ip6.arpa.": true, "7.2.0.192.in-addr.arpa": true,
		"*.in-addr.arpa": true, "**.IP6.ARPA": true,
		"arpa": false, "home.arpa": false, "ipv4only.arpa": false,
		"in-addr.arpa.example.com": false, "myin-addr.arpa": false,
	} {
		assert.Equal(t, want, ReverseLookupName(name), name)
	}
}

func TestLocalAddress(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.96.0.1": true, "172.31.255.255": true, "192.168.1.1": true,
		"127.0.0.53": true, "::1": true, "169.254.169.254": true, "fe80::1": true,
		"fd00::1": true, "100.64.0.1": true, "100.127.255.255": true, "::ffff:10.96.0.1": true,
		"100.63.255.255": false, "100.128.0.0": false, "8.8.8.8": false, "2001:db8::1": false,
	} {
		assert.Equal(t, want, LocalAddress(netip.MustParseAddr(ip)), ip)
	}
}

func TestKnownAddress(t *testing.T) {
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeCIDR, Value: "203.0.113.0/24", Action: ActionAllow},
		{Type: RuleTypeCIDR, Value: "198.51.100.0/24", Action: ActionDeny},
	}, ActionDeny))
	cm.UpdateDNSMapping("named.example.com", "192.0.2.10")
	for ip, want := range map[string]bool{
		"192.0.2.10": true, "203.0.113.9": true, "::ffff:203.0.113.9": true,
		"198.51.100.7": false, "192.0.2.11": false, "8.8.8.8": false,
	} {
		assert.Equal(t, want, cm.KnownAddress(netip.MustParseAddr(ip)), ip)
	}
}

// A hostname allow rule for a reverse-lookup name is dropped at load, from
// every loader, the rest kept; a deny rule and other .arpa names stay.
func TestLoad_ReverseLookupHostRulesDropped(t *testing.T) {
	logs := captureUnspecLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "7.2.0.192.in-addr.arpa", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "*.ip6.arpa", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "in-addr.arpa", Action: ActionDeny},
		{Type: RuleTypeHostname, Value: "home.arpa", Action: ActionAllow},
		{Type: RuleTypeCIDR, Value: "192.0.2.0/24", Action: ActionAllow},
	}, ActionDeny))
	assert.ElementsMatch(t, []string{"github.com", "in-addr.arpa", "home.arpa", "192.0.2.0/24"},
		resolvedRuleValues(cm.GetResolvedRules()))
	ws := unspecWarns(*logs)
	require.Len(t, ws, 2)
	for _, w := range ws {
		assert.Contains(t, w, "A hostname rule for a reverse-lookup name is dropped")
	}

	// From a CodeCargo policy.
	logs2 := captureUnspecLogs(t)
	cm = NewConfigManager()
	require.NoError(t, cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
		Mode:          datapb.CargoWallMode_CARGO_WALL_MODE_ENFORCE,
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		Rules: []*cargowallv1pb.CargoWallPolicy_Rule{
			{Type: datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME, Value: "github.com", Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW},
			{Type: datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME, Value: "34.216.184.93.in-addr.arpa", Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW},
		},
	}))
	assert.False(t, cm.IsAuditMode(), "the policy loads, enforcing")
	assert.Equal(t, []string{"github.com"}, resolvedRuleValues(cm.GetResolvedRules()))
	assert.Len(t, unspecWarns(*logs2), 1)
}

// A search domain under a reverse zone is dropped at load, from every
// loader and the auto-added ones, the rest kept.
func TestSearchDomainsUnderReverseZonesDropped(t *testing.T) {
	const dropped = "A search domain under a reverse-lookup zone is dropped"

	logs := captureUnspecLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromCargoWall(&cargowallv1pb.CargoWallPolicy{
		Mode:          datapb.CargoWallMode_CARGO_WALL_MODE_ENFORCE,
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		SearchDomains: []string{".corp.internal", ".100.51.198.in-addr.arpa", "in-addr.arpa", ".8.b.d.0.1.0.0.2.IP6.ARPA"},
	}))
	assert.False(t, cm.IsAuditMode())
	assert.Equal(t, []string{".corp.internal"}, cm.GetSearchDomains())
	ws := unspecWarns(*logs)
	require.Len(t, ws, 3)
	for _, w := range ws {
		assert.Contains(t, w, dropped)
	}

	logs2 := captureUnspecLogs(t)
	cm = NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeJSONConfig(t, `{"defaultAction": "deny", "searchDomains": [".corp.internal", ".100.51.198.in-addr.arpa"]}`)))
	assert.Equal(t, []string{".corp.internal"}, cm.GetSearchDomains())
	assert.Len(t, unspecWarns(*logs2), 1)

	logs3 := captureUnspecLogs(t)
	t.Setenv("CARGOWALL_SEARCH_DOMAINS", ".corp.internal,.ip6.arpa")
	cm = NewConfigManager()
	require.NoError(t, cm.LoadFromEnv())
	assert.Equal(t, []string{".corp.internal"}, cm.GetSearchDomains())
	assert.Len(t, unspecWarns(*logs3), 1)

	logs4 := captureUnspecLogs(t)
	cm = NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, ActionDeny))
	cm.AddSearchDomains([]string{".corp.internal", ".100.51.198.in-addr.arpa"}, slog.Default())
	assert.Equal(t, []string{".corp.internal"}, cm.GetSearchDomains())
	assert.Len(t, unspecWarns(*logs4), 1)
}
