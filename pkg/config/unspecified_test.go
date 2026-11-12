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

// captureLogs points the default logger at a buffer for the rest of t, and
// returns the lines it logs.
func captureLogs(t *testing.T) *[]string {
	t.Helper()
	var captured []string
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&captureWriter{out: &captured}, nil)))
	return &captured
}

// warns returns the WARN lines among logs.
func warns(logs []string) []string {
	var out []string
	for _, line := range logs {
		if strings.Contains(line, "level=WARN") {
			out = append(out, line)
		}
	}
	return out
}

// resolvedValues lists the values of rules, in order.
func resolvedValues(rules []ResolvedRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Value)
	}
	return out
}

// A single-address rule for the unspecified address is dropped when it
// carries ports, in every spelling and under either action, with one warning
// and the rest of the policy kept; without ports it stays. Prefixes that
// merely start at the zero address, the any-destination rules among them,
// keep their ports.
func TestLoad_UnspecifiedHostPorts(t *testing.T) {
	tcp443 := []Port{{Port: 443, Protocol: ProtocolTCP}}
	for _, value := range []string{"0.0.0.0/32", "0.0.0.0", "::/128", "::", "::ffff:0.0.0.0/128", "::ffff:0.0.0.0"} {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			logs := captureLogs(t)
			cm := NewConfigManager()
			require.NoError(t, cm.LoadConfigFromRules([]Rule{
				{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
				{Type: RuleTypeCIDR, Value: value, Ports: tcp443, Action: action},
			}, ActionDeny), "%s %s", value, action)
			assert.Equal(t, []string{"github.com"}, resolvedValues(cm.GetResolvedRules()), "%s %s", value, action)
			require.Len(t, warns(*logs), 1, "%s %s", value, action)
			assert.Contains(t, warns(*logs)[0], "Dropping a rule for the unspecified address with ports")

			*logs = nil
			require.NoError(t, cm.LoadConfigFromRules([]Rule{{Type: RuleTypeCIDR, Value: value, Action: action}}, ActionDeny))
			assert.Len(t, cm.GetResolvedRules(), 1, "%s %s without ports", value, action)
			assert.Empty(t, warns(*logs), "%s %s without ports", value, action)
		}
	}
	for _, value := range []string{"0.0.0.0/0", "0.0.0.0/8", "::/0", "::/96", "::ffff:0:0/96"} {
		logs := captureLogs(t)
		cm := NewConfigManager()
		require.NoError(t, cm.LoadConfigFromRules([]Rule{{Type: RuleTypeCIDR, Value: value, Ports: tcp443, Action: ActionAllow}}, ActionDeny), value)
		require.Len(t, cm.GetResolvedRules(), 1, value)
		assert.Equal(t, tcp443, cm.GetResolvedRules()[0].Ports, value)
		assert.Empty(t, warns(*logs), value)
	}
}

// A CodeCargo policy with such a rule still loads, enforcing, without it.
func TestLoadConfigFromCargoWall_UnspecifiedHostPorts(t *testing.T) {
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
				Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_CIDR,
				Value:  "0.0.0.0",
				Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
				Ports: []*cargowallv1pb.CargoWallPolicy_PortRule{
					{Port: 443, Protocol: datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_TCP},
				},
			},
		},
	}))
	assert.False(t, cm.IsAuditMode())
	assert.Equal(t, []string{"github.com"}, resolvedValues(cm.GetResolvedRules()))
	assert.Len(t, warns(*logs), 1)
}

// The environment loader drops them too.
func TestLoadFromEnv_UnspecifiedHostPorts(t *testing.T) {
	logs := captureLogs(t)
	t.Setenv("CARGOWALL_ALLOWED_HOSTS", "github.com")
	t.Setenv("CARGOWALL_ALLOWED_CIDRS", "0.0.0.0:443,[::]:443,10.0.0.0/8:443")
	cm := NewConfigManager()
	require.NoError(t, cm.LoadFromEnv())
	assert.ElementsMatch(t, []string{"github.com", "10.0.0.0/8"}, resolvedValues(cm.GetResolvedRules()))
	assert.Len(t, warns(*logs), 2)
}

// A step's rules are held to the same drop, the rest of the step kept.
func TestLoadConfig_StepUnspecifiedHostPorts(t *testing.T) {
	logs := captureLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeJSONConfig(t, `{"defaultAction": "deny", "rules": [], "steps": [
		{"id": "a", "rules": [
			{"type": "hostname", "value": "a.example"},
			{"type": "cidr", "value": "::", "ports": [{"port": 443, "protocol": "tcp"}]}]}]}`)))
	steps := cm.GetStepRules()
	require.Len(t, steps, 1)
	assert.Equal(t, []string{"a.example"}, resolvedValues(steps[0].Rules))
	assert.Len(t, warns(*logs), 1)
}
