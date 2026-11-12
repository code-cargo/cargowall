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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
)

// captureUnspecLogs points the default logger at a buffer for the rest of t,
// and returns the lines it logs.
func captureUnspecLogs(t *testing.T) *[]string {
	t.Helper()
	var captured []string
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&captureWriter{out: &captured}, nil)))
	return &captured
}

func unspecWarns(logs []string) []string {
	var out []string
	for _, line := range logs {
		if strings.Contains(line, "level=WARN") {
			out = append(out, line)
		}
	}
	return out
}

func resolvedRuleValues(rules []ResolvedRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Value)
	}
	return out
}

// A CIDR rule with ports whose network is the unspecified address is dropped,
// with one warning and the rest of the policy kept: the single host spellings
// and every zero-based network from /1 up. /0 is the real wildcard and stays,
// as does a non-zero network and a portless zero network.
func TestLoad_UnspecifiedNetworkPorts(t *testing.T) {
	tcp443 := []Port{{Port: 443, Protocol: ProtocolTCP}}
	dropped := []string{
		"0.0.0.0/32", "0.0.0.0", "::/128", "::", "::ffff:0.0.0.0/128", "::ffff:0.0.0.0",
		"0.0.0.0/1", "0.0.0.0/8", "0.0.0.0/31", "::/1", "::/96", "::/127",
	}
	for _, value := range dropped {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			logs := captureUnspecLogs(t)
			cm := NewConfigManager()
			require.NoError(t, cm.LoadConfigFromRules([]Rule{
				{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
				{Type: RuleTypeCIDR, Value: value, Ports: tcp443, Action: action},
			}, ActionDeny), "%s %s", value, action)
			assert.Equal(t, []string{"github.com"}, resolvedRuleValues(cm.GetResolvedRules()), "%s %s", value, action)
			require.Len(t, unspecWarns(*logs), 1, "%s %s", value, action)
			assert.Contains(t, unspecWarns(*logs)[0], "Dropping a rule for the unspecified address with ports")
		}
	}
	// Kept: /0, a non-zero network, and the zero networks without ports.
	for _, value := range []string{"0.0.0.0/0", "::/0", "::ffff:0:0/96", "10.0.0.0/8", "0.0.0.0/8", "::/96"} {
		logs := captureUnspecLogs(t)
		cm := NewConfigManager()
		var ports []Port
		if strings.HasSuffix(value, "/8") || value == "0.0.0.0/0" || value == "::/0" || value == "::ffff:0:0/96" {
			ports = tcp443
		}
		if value == "0.0.0.0/8" || value == "::/96" {
			ports = nil // the zero networks only stay without ports
		}
		require.NoError(t, cm.LoadConfigFromRules([]Rule{{Type: RuleTypeCIDR, Value: value, Ports: ports, Action: ActionAllow}}, ActionDeny), value)
		require.Len(t, cm.GetResolvedRules(), 1, value)
		assert.Empty(t, unspecWarns(*logs), value)
	}
}

// A CodeCargo policy with such a rule still loads, enforcing, without it.
func TestLoadConfigFromCargoWall_UnspecifiedNetworkPorts(t *testing.T) {
	logs := captureUnspecLogs(t)
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
				Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_CIDR,
				Value:  "0.0.0.0/1",
				Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
				Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{
					{Port: 443, Protocol: datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_TCP},
				},
			},
		},
	}))
	assert.False(t, cm.IsAuditMode())
	assert.Equal(t, []string{"github.com"}, resolvedRuleValues(cm.GetResolvedRules()))
	assert.Len(t, unspecWarns(*logs), 1)
}

// The environment loader drops them too.
func TestLoadFromEnv_UnspecifiedNetworkPorts(t *testing.T) {
	logs := captureUnspecLogs(t)
	t.Setenv("CARGOWALL_ALLOWED_HOSTS", "github.com")
	t.Setenv("CARGOWALL_ALLOWED_CIDRS", "0.0.0.0/1:443,[::]:443,10.0.0.0/8:443")
	cm := NewConfigManager()
	require.NoError(t, cm.LoadFromEnv())
	assert.ElementsMatch(t, []string{"github.com", "10.0.0.0/8"}, resolvedRuleValues(cm.GetResolvedRules()))
	assert.Len(t, unspecWarns(*logs), 2)
}
