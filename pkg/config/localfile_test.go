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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rule wraps one job rule's JSON in a file.
func rule(r string) string { return `{"defaultAction": "deny", "rules": [` + r + `]}` }

// step wraps one step rule's JSON in a file.
func step(r string) string {
	return `{"defaultAction": "deny", "rules": [], "steps": [{"id": "build", "rules": [` + r + `]}]}`
}

// A local file that cargowall would read loosely doesn't load: every shape
// below would otherwise load as something other than what it spells.
func TestLoadConfig_RefusesLooseShapes(t *testing.T) {
	for _, tt := range []struct {
		name, body, want string
	}{
		// The top level.
		{"null", `null`, "the top level must be a JSON object"},
		{"an array", `[]`, "the top level must be a JSON object"},
		{"a string", `"rules"`, "the top level must be a JSON object"},
		{"not JSON", `rules: []`, "parse config"},
		{"data after the object", `{"rules": []} {"rules": []}`, "data after the top-level object"},
		{"an unknown top-level key", `{"rule": []}`, `has a key cargowall doesn't read: "rule"`},
		{"a top-level key in another case", `{"Rules": []}`, `has a key cargowall doesn't read: "Rules"`},
		{"a repeated top-level key", `{"rules": [], "rules": []}`, `repeats the key "rules"`},
		{"an unknown defaultAction", `{"defaultAction": "Allow"}`, `defaultAction "Allow" must be allow or deny`},

		// A rule's keys.
		{"an unknown rule key", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "port": []}`), `has a key cargowall doesn't read: "port"`},
		{"a rule key in another case", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "Ports": []}`), `"Ports"`},
		{"autoAddedType on a job rule", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "autoAddedType": "github_service"}`), "autoAddedType is set by cargowall"},

		// A rule cargowall would drop at resolve, or match to nothing.
		{"an unknown type", rule(`{"type": "Hostname", "value": "a.example", "action": "allow"}`), `unknown rule type "Hostname"`},
		{"no type", rule(`{"value": "a.example", "action": "allow"}`), `unknown rule type ""`},
		{"an empty hostname", rule(`{"type": "hostname", "value": "", "action": "allow"}`), "a hostname rule needs a value"},
		{"an invalid CIDR", rule(`{"type": "cidr", "value": "10.0.0.0/33", "action": "allow"}`), `"10.0.0.0/33" is not a CIDR or an IP address`},
		{"an invalid hostname pattern", rule(`{"type": "hostname", "value": "api-*.example.com", "action": "allow"}`), "invalid hostname pattern"},
		{"no action on a job rule", rule(`{"type": "hostname", "value": "a.example"}`), `action "" must be allow or deny`},
		{"an unknown action", rule(`{"type": "hostname", "value": "a.example", "action": "Allow"}`), `action "Allow" must be allow or deny`},
		{"a step rule that denies", step(`{"type": "hostname", "value": "a.example", "action": "deny"}`), "step rules only allow"},

		// Ports.
		{"a port as a number", rule(`{"type": "cidr", "value": "10.0.0.0/8", "action": "allow", "ports": [443]}`), "parse config"},
		{"an empty port list", rule(`{"type": "cidr", "value": "10.0.0.0/8", "action": "allow", "ports": []}`), "ports is empty; omit ports for every port"},
		{"a port with no protocol", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "ports": [{"port": 443}]}`), `rules[0].ports[0]: protocol "" must be all, tcp, udp or icmp`},
		{"an uppercase protocol", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "ports": [{"port": 443, "protocol": "TCP"}]}`), `protocol "TCP"`},
		{"an unknown protocol", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "ports": [{"port": 443, "protocol": "http"}]}`), `protocol "http"`},
		{"a protocol key in another case", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "ports": [{"port": 443, "Protocol": "tcp"}]}`), `"Protocol"`},
		{"a repeated protocol", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "ports": [{"port": 443, "protocol": "TCP", "protocol": "tcp"}]}`), `repeats the key "protocol"`},
		{"a repeat spelled with an escape", rule(`{"type": "hostname", "value": "a.example", "action": "allow", "ports": [{"port": 443, "protocol": "TCP", "protocol": "tcp"}]}`), `repeats the key "protocol"`},
		{"an ICMP port", rule(`{"type": "cidr", "value": "10.0.0.0/8", "action": "allow", "ports": [{"port": 8, "protocol": "icmp"}]}`), "ICMP rules must have port=0"},
		{"a step port with no protocol", step(`{"type": "hostname", "value": "a.example", "ports": [{"port": 443}]}`), `steps[0].rules[0].ports[0]: protocol ""`},
		{"an empty step port list", step(`{"type": "hostname", "value": "a.example", "ports": []}`), "steps[0].rules[0]: ports is empty"},

		// Steps and sudoLockdown.
		{"a step id the runner generates", `{"steps": [{"id": "__run_2", "rules": [{"type": "hostname", "value": "a.example"}]}]}`, "generated by the runner"},
		{"a step key in another case", `{"steps": [{"id": "build", "Rules": []}]}`, `"Rules"`},
		{"a repeated step key", `{"steps": [{"id": "a", "id": "b", "rules": []}]}`, `repeats the key "id"`},
		{"an unknown sudoLockdown key", `{"sudoLockdown": {"enable": true}}`, `has a key cargowall doesn't read: "enable"`},
		{"a repeated sudoLockdown", `{"sudoLockdown": {"enabled": true}, "sudoLockdown": {"allowCommands": []}}`, `repeats the key "sudoLockdown"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewConfigManager()
			err := cm.LoadConfig(writeJSONConfig(t, tt.body))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Empty(t, cm.GetResolvedRules(), "a refused file loads nothing")
		})
	}
}

// A file that spells what cargowall reads loads whole, a rule for the
// zero address with ports still dropped with a warning rather than failing
// the load.
func TestLoadConfig_StrictFileLoads(t *testing.T) {
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeJSONConfig(t, `{
		"defaultAction": "deny",
		"rules": [
			{"type": "hostname", "value": "github.com", "action": "allow", "ports": [{"port": 443, "protocol": "tcp"}]},
			{"type": "hostname", "value": "*.npmjs.org", "action": "allow"},
			{"type": "cidr", "value": "10.0.0.0/8", "action": "deny", "ports": [{"port": 22, "protocol": "all"}, {"port": 0, "protocol": "icmp"}]},
			{"type": "cidr", "value": "2001:db8::1", "action": "allow", "ports": [{"port": 53, "protocol": "udp"}]},
			{"type": "cidr", "value": "0.0.0.0/32", "action": "allow", "ports": [{"port": 443, "protocol": "tcp"}]}
		],
		"searchDomains": [".compute.internal"],
		"sudoLockdown": {"enabled": true, "allowCommands": ["/usr/bin/true"]},
		"steps": [{"id": "fetch", "rules": [{"type": "hostname", "value": "registry.npmjs.org", "action": "allow"}]}]
	}`)))
	assert.Len(t, cm.GetResolvedRules(), 4, "the zero-address rule is dropped, the rest kept")
	require.Len(t, cm.GetStepRules(), 1)
	assert.Len(t, cm.GetStepRules()[0].Rules, 1)
}

// The example file the README points at loads as it is.
func TestLoadConfig_ExampleFileLoads(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "config.example.json"))
	require.NoError(t, err)
	require.NoError(t, NewConfigManager().LoadConfig(writeJSONConfig(t, string(data))))
}
