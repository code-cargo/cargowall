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

package firewall

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
)

// AddPolicyIP runs its scope once the write is admitted, whole, and before
// any of it is written: a write the budget refuses, or the gate withholds,
// or that writes nothing, scopes nothing; one whose scope fails writes
// nothing and is refunded.
func TestAddPolicyIP_ScopesBetweenAdmissionAndWrite(t *testing.T) {
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	icmp := []config.Port{{Port: 0, Protocol: config.ProtocolICMP}}
	scopes := 0
	empty := func(t *testing.T, maps stepTestMaps) func() error {
		return func() error {
			scopes++
			for m := range numRuleMaps {
				assert.Zero(t, stepEntries(t, maps[m]), "%s written before the scope", m)
			}
			return nil
		}
	}

	t.Run("admitted, its denies and allows alike", func(t *testing.T) {
		scopes = 0
		fw, maps := newStepTestFirewall(ruleMapEntries, nil)
		cm := config.NewConfigManager()
		require.NoError(t, cm.LoadConfig(writeStepConfig(t,
			[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.98.0.0/16", Ports: []config.Port{p(22)}, Action: config.ActionDeny}},
			[]config.StepConfig{{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeHostname, Value: "a.example.com"}}}})))
		require.NoError(t, fw.UpdateAllowlistTC(cm))
		_, err := fw.AddPolicyIP(1, net.ParseIP("10.98.0.5"), []config.Port{p(22), p(443)}, empty(t, maps))
		require.NoError(t, err)
		assert.Equal(t, 1, scopes)
		assert.Len(t, entriesOf(t, maps[ruleMapPorts], 1), 2, "the deny on 22 and the allow on 443")
	})
	t.Run("the scope fails", func(t *testing.T) {
		fw, maps := newStepTestFirewall(ruleMapEntries, nil)
		full := errors.New("scope map full")
		_, err := fw.AddPolicyIP(1, testIPv4(10, 1), tcp443, func() error { return full })
		require.ErrorIs(t, err, full)
		for m := range numRuleMaps {
			assert.Zero(t, stepEntries(t, maps[m]), "%s", m)
			assert.Zero(t, fw.steps.used(m), "%s refunded", m)
		}
	})
	for _, c := range []struct {
		name  string
		setup func(fw *FirewallImpl)
		ip    net.IP
		ports []config.Port
		err   error
	}{
		{"the budget refuses it", func(fw *FirewallImpl) { fw.steps.setBudget(0) }, testIPv4(10, 2), tcp443, ErrStepBudget},
		{"the gate withholds it", func(fw *FirewallImpl) { fw.jobDenies = jobCIDRDenies(resolvedDeny("10.0.0.0/8")) }, testIPv4(10, 3), tcp443, nil},
		{"it writes nothing", func(*FirewallImpl) {}, testIPv6(10, 4), icmp, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			fw, _ := newStepTestFirewall(ruleMapEntries, nil)
			c.setup(fw)
			_, err := fw.AddPolicyIP(1, c.ip, c.ports, func() error {
				t.Error("scoped")
				return nil
			})
			if c.err != nil {
				require.ErrorIs(t, err, c.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// resolvedDeny is a job CIDR deny on all ports, as the sync resolves it.
func resolvedDeny(cidr string) []config.ResolvedRule {
	return []config.ResolvedRule{{Type: config.RuleTypeCIDR, Value: cidr, IPNet: mustCIDR(cidr), Action: config.ActionDeny}}
}

// Once a map refuses a step write for room, the job having taken the rest,
// the steps' budget there holds at what they have: the next write that
// would add an entry is refused at admission, before it scopes anything,
// with the job named as the cause.
func TestStepBudget_MapRefusalShrinksTheBudget(t *testing.T) {
	var logs bytes.Buffer
	fw, maps := newStepTestFirewall(10, slog.New(slog.NewTextHandler(&logs, nil)))
	fw.steps.setBudget(6) // a reservation of 4
	for i := range 6 {
		_, err := fw.AddIP(testIPv4(20, i), config.ActionAllow, nil)
		require.NoError(t, err)
	}
	for i := range 4 {
		_, err := fw.AddPolicyIP(1, testIPv4(10, i), nil, nil)
		require.NoError(t, err)
	}
	scopes := 0
	scope := func() error { scopes++; return nil }
	_, err := fw.AddPolicyIP(1, testIPv4(10, 4), nil, scope)
	require.ErrorIs(t, err, ErrStepBudget, "the map's own refusal")
	require.Equal(t, 1, scopes, "admitted by the ledger, so scoped")
	assert.Equal(t, 4, fw.steps.budget[ruleMapCIDRs], "held at what the steps hold")
	assert.Equal(t, 6, fw.steps.budget[ruleMapPorts], "a map that refused nothing keeps its budget")

	_, err = fw.AddPolicyIP(1, testIPv4(10, 5), nil, scope)
	require.ErrorIs(t, err, ErrStepBudget)
	assert.Equal(t, 1, scopes, "refused at admission, before the scope")
	fw.steps.warned = fw.steps.warned.Add(-2 * stepBudgetWarnInterval)
	_, err = fw.AddPolicyIP(1, testIPv4(10, 6), nil, scope)
	require.ErrorIs(t, err, ErrStepBudget)
	assert.Equal(t, 2, bytes.Count(logs.Bytes(), []byte(noRoomJob)), "the job is named as the cause")
	_, err = fw.AddPolicyIP(1, testIPv4(10, 0), nil, scope)
	require.NoError(t, err, "a held key still rewrites")
	assert.Len(t, maps[ruleMapCIDRs].store, 10)

	// The port map refusing names the port map, though the write's LPM
	// entry, unwritten, is refunded too: every writer writes a prefix's
	// port entries first.
	fw, maps = newStepTestFirewall(ruleMapEntries, nil)
	maps[ruleMapPorts].capacity = 1
	_, err = fw.AddIP(testIPv4(20, 0), config.ActionAllow, tcp443)
	require.NoError(t, err)
	_, err = fw.AddPolicyIP(1, testIPv4(10, 0), tcp443, nil)
	require.ErrorIs(t, err, ErrStepBudget)
	assert.Zero(t, fw.steps.budget[ruleMapPorts])
	assert.Equal(t, stepEntryBudget, fw.steps.budget[ruleMapCIDRs], "the trie had room")
}
