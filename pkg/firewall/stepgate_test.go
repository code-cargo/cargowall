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
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	rand "math/rand/v2"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// rulesV4 mirrors rules_v4 (bpf/verdict.h) for policy over the stateful
// mocks: the longest match, then for a port-specific one its port entry
// under the matched network, then the wildcard port, else no decision.
func rulesV4(maps stepTestMaps, policy uint32, ip net.IP, port uint16, proto uint8) (decided, allow bool) {
	ip4 := ip.To4()
	wildcard := func() (bool, bool) {
		if pv, ok := maps[ruleMapPorts].store[bpf.RulePortKey(policy, 0, port, proto, 0)]; ok {
			return true, pv.(bpf.TcBpfPortVal).Action == 1
		}
		return false, false
	}
	for plen := 32; plen >= 0; plen-- {
		network := binary.NativeEndian.Uint32(ip4.Mask(net.CIDRMask(plen, 32)))
		rv, ok := maps[ruleMapCIDRs].store[bpf.RuleKey(policy, uint32(plen), network)]
		if !ok {
			continue
		}
		rule := rv.(bpf.TcBpfLpmVal)
		if rule.PortSpecific == 0 {
			return true, rule.Action == 1
		}
		ruleNet := binary.NativeEndian.Uint32(ip4.Mask(net.CIDRMask(max(32-int(rule.HostBits), 0), 32)))
		if pv, ok := maps[ruleMapPorts].store[bpf.RulePortKey(policy, ruleNet, port, proto, rule.HostBits)]; ok {
			return true, pv.(bpf.TcBpfPortVal).Action == 1
		}
		return wildcard()
	}
	return wildcard()
}

// verdictV4 mirrors verdict_allowed_v4 for a packet judged as policy (0 for
// none) under a deny default: the job's rules first, then the step's.
func verdictV4(maps stepTestMaps, policy uint32, ip net.IP, port uint16) bool {
	decided, allow := rulesV4(maps, bpf.PolicyJob, ip, port, protoTCP)
	if decided {
		return allow
	}
	if policy != bpf.PolicyJob {
		if d, a := rulesV4(maps, policy, ip, port, protoTCP); d && a {
			return true
		}
	}
	return false
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// The gate's outcomes: what a step write to a destination keeps, given the
// job's CIDR denies the sync wrote.
func TestStepGate(t *testing.T) {
	tcp22 := portProto{Port: 22, Proto: protoTCP}
	tcp443 := portProto{Port: 443, Proto: protoTCP}
	rules := func(rs ...config.Rule) []config.ResolvedRule {
		out := make([]config.ResolvedRule, len(rs))
		for i, r := range rs {
			out[i] = config.ResolvedRule{Type: config.RuleTypeCIDR, Value: r.Value, IPNet: mustCIDR(r.Value), Ports: r.Ports, Action: r.Action}
		}
		return out
	}
	deny := func(v string, ports ...config.Port) config.Rule {
		return config.Rule{Value: v, Ports: ports, Action: config.ActionDeny}
	}
	p22, p443 := config.Port{Port: 22, Protocol: config.ProtocolTCP}, config.Port{Port: 443, Protocol: config.ProtocolTCP}
	for _, tt := range []struct {
		name  string
		job   []config.ResolvedRule
		dst   string
		ports []portProto
		want  []portProto
		deny  []portProto
		ok    bool
	}{
		{"no denies", nil, "10.0.0.1/32", nil, nil, nil, true},
		{"a deny elsewhere", rules(deny("10.1.0.0/16")), "10.0.0.1/32", nil, nil, nil, true},
		{"inside an all-ports deny", rules(deny("10.0.0.0/16")), "10.0.0.1/32", []portProto{tcp443}, nil, nil, false},
		{"at a deny's own prefix", rules(deny("10.0.0.0/24")), "10.0.0.0/24", nil, nil, nil, false},
		{"inside a deny on 22, writing 22 and 443", rules(deny("10.0.0.0/16", p22)), "10.0.0.1/32", []portProto{tcp22, tcp443}, []portProto{tcp443}, []portProto{tcp22}, true},
		{"inside a deny on 22, writing 22", rules(deny("10.0.0.0/16", p22)), "10.0.0.1/32", []portProto{tcp22}, nil, nil, false},
		{"inside a deny on 22, writing all ports", rules(deny("10.0.0.0/16", p22)), "10.0.0.1/32", nil, nil, nil, false},
		{"inside two port denies", rules(deny("10.0.0.0/16", p22), deny("10.0.0.0/24", p443)), "10.0.0.1/32", []portProto{tcp22, tcp443}, nil, nil, false},
		{"a wildcard port deny gates nothing", rules(deny("0.0.0.0/0", p22)), "10.0.0.1/32", []portProto{tcp22}, []portProto{tcp22}, nil, true},
		{"a host route deny gates nothing: nothing can hide it", rules(deny("10.0.0.1/32")), "10.0.0.1/32", nil, nil, nil, true},
		{"the whole space denied on all ports", rules(deny("0.0.0.0/0")), "10.0.0.1/32", nil, nil, nil, false},
		{"a deny inside the destination is the carve's, not the gate's", rules(deny("10.0.0.0/24")), "10.0.0.0/16", nil, nil, nil, true},
		{"IPv6", rules(deny("2001:db8::/32")), "2001:db8::1/128", nil, nil, nil, false},
		{"families don't mix", rules(deny("0.0.0.0/0")), "2001:db8::1/128", nil, nil, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fw, _ := newStepTestFirewall(ruleMapEntries, nil)
			fw.jobDenies = jobCIDRDenies(tt.job)
			got, deny, ok := fw.gateStepLocked(1, mustCIDR(tt.dst), tt.ports)
			require.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.want, got)
				assert.Equal(t, tt.deny, deny)
			}
		})
	}
}

// A job port-specific entry nested inside a job CIDR deny hides the deny
// from the kernel's job lookup on the entry's other ports. Whichever order
// the job's entries come in, and whether the step's install comes before
// the sync (which rebuilds the step tier) or after, the step never gets
// past the deny: the gate never lets it write there.
func TestStepGate_NestedJobEntryEitherOrder(t *testing.T) {
	host := net.ParseIP("10.98.0.12")
	for _, c := range []struct {
		name           string
		jobAllowFirst  bool
		stepBeforeSync bool
	}{
		{"deny synced, then the job's allow", false, false},
		{"the job's allow, then the deny synced", true, false},
		{"the step's install before the sync", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			fw, maps := newStepTestFirewall(ruleMapEntries, nil)
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfig(writeStepConfig(t,
				[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.98.0.0/16", Action: config.ActionDeny}},
				[]config.StepConfig{{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeHostname, Value: "svc.example.com"}}}})))
			step := func() {
				_, err := fw.AddPolicyIP(1, host, nil, nil)
				require.NoError(t, err)
			}
			if c.jobAllowFirst {
				_, err := fw.AddIP(host, config.ActionAllow, tcp443)
				require.NoError(t, err)
			}
			if c.stepBeforeSync {
				step()
			}
			require.NoError(t, fw.UpdateAllowlistTC(cm))
			if !c.jobAllowFirst {
				_, err := fw.AddIP(host, config.ActionAllow, tcp443)
				require.NoError(t, err)
			}
			if !c.stepBeforeSync {
				step()
			}
			assert.False(t, verdictV4(maps, 1, host, 22), "the step gets past the job's deny on 22")
			assert.Empty(t, entriesOf(t, maps[ruleMapCIDRs], 1), "no step entry inside the job's deny")
		})
	}
}

// For random job CIDR denies, job host entries nested inside them or not,
// step installs and step CIDR rules, in random order around the sync: a
// step's rules never allow a port a job CIDR deny covers (a job entry nested
// inside its own deny, written before it, may still allow the job itself:
// that order dependence is the job's, and no step's), and each host install
// made after the sync is allowed every port the gate leaves it.
func TestStepGate_Property(t *testing.T) {
	ports := []uint16{22, 80, 443, 8080}
	for seed := range uint64(40) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 2021))
			pick := func(vs ...[]config.Port) []config.Port { return vs[rng.IntN(len(vs))] }
			p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
			portSets := [][]config.Port{nil, {p(22)}, {p(443)}, {p(22), p(443)}, {p(8080)}}

			var denies []config.Rule
			for _, v := range []string{"10.98.0.0/16", "10.98.1.0/24", "10.98.2.8/29", "10.98.3.5/32"} {
				if rng.IntN(2) == 0 {
					denies = append(denies, config.Rule{Type: config.RuleTypeCIDR, Value: v, Ports: pick(portSets[:4]...), Action: config.ActionDeny})
				}
			}
			var stepCIDRs []config.Rule
			for _, v := range []string{"10.98.0.0/16", "10.98.1.0/25", "10.98.2.0/24"} {
				if rng.IntN(3) == 0 {
					stepCIDRs = append(stepCIDRs, config.Rule{Type: config.RuleTypeCIDR, Value: v, Ports: pick(portSets...)})
				}
			}
			if rng.IntN(2) == 0 {
				// A wildcard, whose allow a port-specific entry's miss falls through to.
				stepCIDRs = append(stepCIDRs, config.Rule{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: pick(portSets[1:4]...)})
			}
			stepCIDRs = append(stepCIDRs, config.Rule{Type: config.RuleTypeHostname, Value: "svc.example.com"})
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfig(writeStepConfig(t, denies,
				[]config.StepConfig{{ID: "a", Rules: stepCIDRs}, {ID: "b", Rules: []config.Rule{{Type: config.RuleTypeHostname, Value: "b.example.com"}}}})))

			fw, maps := newStepTestFirewall(ruleMapEntries, nil)
			hostIP := func() net.IP { return net.IPv4(10, 98, byte(rng.IntN(4)), byte(rng.IntN(16))).To4() }
			type install struct {
				policy uint32
				ip     net.IP
				ports  []config.Port
			}
			var after []install
			synced := false
			for i := range 30 {
				if !synced && (rng.IntN(10) == 0 || i == 29) {
					require.NoError(t, fw.UpdateAllowlistTC(cm))
					synced = true
					continue
				}
				if rng.IntN(2) == 0 {
					_, err := fw.AddIP(hostIP(), config.ActionAllow, pick(portSets[1:]...))
					require.NoError(t, err)
					continue
				}
				in := install{policy: uint32(1 + rng.IntN(2)), ip: hostIP(), ports: pick(portSets...)}
				_, err := fw.AddPolicyIP(in.policy, in.ip, in.ports, nil)
				require.NoError(t, err)
				if synced {
					after = append(after, in)
				}
			}

			// covered reports whether a job CIDR deny covers ip on port, and
			// whether one the gate reads (not a host route) covers ip on some
			// port but not all.
			covered := func(ip net.IP, port uint16) (denied, some bool) {
				for _, d := range denies {
					n := mustCIDR(d.Value)
					if !n.Contains(ip) {
						continue
					}
					ones, bits := n.Mask.Size()
					if len(d.Ports) == 0 || slices.Contains(d.Ports, p(port)) {
						denied = true
					}
					if len(d.Ports) > 0 && ones < bits {
						some = true
					}
				}
				return denied, some
			}
			for x := range 4 {
				for y := range 16 {
					ip := net.IPv4(10, 98, byte(x), byte(y)).To4()
					for _, port := range ports {
						if denied, _ := covered(ip, port); denied {
							for policy := uint32(1); policy <= 2; policy++ {
								require.False(t, verdictV4(maps, policy, ip, port) && !verdictV4(maps, bpf.PolicyJob, ip, port),
									"step %d allowed %s:%d past a job CIDR deny", policy, ip, port)
							}
						}
					}
				}
			}
			for _, in := range after {
				for _, port := range ports {
					denied, some := covered(in.ip, port)
					wants := !denied && (len(in.ports) == 0 && !some || slices.Contains(in.ports, p(port)))
					if wants {
						require.True(t, verdictV4(maps, in.policy, in.ip, port), "step %d's install of %s lost port %d", in.policy, in.ip, port)
					}
				}
			}
		})
	}
}

// A sync rebuilds the step tier: every step entry from before it is gone,
// and the ledger with it, so a second load that renumbers its steps can't
// hand one step another's entries.
func TestSync_RebuildsTheStepTier(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	load := func(steps []config.StepConfig) {
		cm := config.NewConfigManager()
		require.NoError(t, cm.LoadConfig(writeStepConfig(t, nil, steps)))
		require.NoError(t, fw.UpdateAllowlistTC(cm))
	}
	load([]config.StepConfig{
		{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.1.0.0/16"}}},
		{ID: "b", Rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.2.0.0/16"}}},
	})
	_, err := fw.AddPolicyIP(2, net.ParseIP("10.9.0.1"), tcp443, nil) // step b's DNS install
	require.NoError(t, err)
	require.Len(t, entriesOf(t, maps[ruleMapCIDRs], 2), 2)

	// The second load drops a; b becomes policy 1.
	load([]config.StepConfig{{ID: "b", Rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.2.0.0/16"}}}})
	assert.Equal(t, map[any]any{
		bpf.RuleKey(1, 16, binary.NativeEndian.Uint32(net.ParseIP("10.2.0.0").To4())): bpf.TcBpfLpmVal{Action: 1, HostBits: 16},
	}, entriesOf(t, maps[ruleMapCIDRs], 1), "policy 1 holds b's rule alone, none of a's")
	assert.Empty(t, entriesOf(t, maps[ruleMapCIDRs], 2), "nothing is left under policy 2")
	assert.Empty(t, entriesOf(t, maps[ruleMapPorts], 2))
	for m := range numRuleMaps {
		assert.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
	}
	assert.Nil(t, fw.stepIPs[policyIP{2, "10.9.0.1"}], "the DNS install's accumulator is gone too")
}

// The count the rate limit held back is flushed by the next step write once
// the interval is over, even when no refusal follows.
func TestStepBudget_HeldBackCountFlushed(t *testing.T) {
	var logs bytes.Buffer
	fw, _ := newStepTestFirewall(ruleMapEntries, slog.New(slog.NewTextHandler(&logs, nil)))
	fw.steps.setBudget(1)
	_, err := fw.AddPolicyIP(1, testIPv4(10, 0), nil, nil)
	require.NoError(t, err)
	for i := 1; i <= 4; i++ {
		_, err := fw.AddPolicyIP(1, testIPv4(10, i), nil, nil)
		require.ErrorIs(t, err, ErrStepBudget)
	}
	require.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("Step rule entr")), "three held back")

	_, err = fw.AddPolicyIP(1, testIPv4(10, 0), nil, nil) // a held key: free
	require.NoError(t, err)
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("Step rule entr")), "not within the interval")

	fw.steps.warned = time.Now().Add(-2 * stepBudgetWarnInterval)
	_, err = fw.AddPolicyIP(1, testIPv4(10, 0), nil, nil)
	require.NoError(t, err)
	assert.Contains(t, logs.String(), "since the last Warn")
	assert.Contains(t, logs.String(), "refused=3")
	assert.Zero(t, fw.steps.refused)
}

// A trimmed step write the map refuses part-way is fail-closed: its denies
// go in first, so what lands is fewer allows, never an allow whose misses
// fall through to a step wildcard on a port the job denies; and a step CIDR
// rule's is taken out again denies last, so a failed delete leaves it no
// LPM entry without its denies. Here the job's deny on 22 is hidden by a job
// entry nested inside it, the step has a wildcard on 22, and the map has
// room for the deny entry alone.
func TestStepGate_PartialWriteFailsClosed(t *testing.T) {
	host := net.ParseIP("10.98.0.5").To4()
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	setup := func(t *testing.T, ports int, stuck func(key any) bool, stepRules ...config.Rule) (*FirewallImpl, stepTestMaps) {
		t.Helper()
		fw, maps := newStepTestFirewall(ruleMapEntries, nil)
		maps[ruleMapPorts].capacity = ports
		_, err := fw.AddIP(host, config.ActionAllow, []config.Port{p(80)}) // nested, before the deny's sync
		require.NoError(t, err)
		fw.cidrsMap = &failingDeletes{cappedMap: maps[ruleMapCIDRs], fail: stuck}
		cm := config.NewConfigManager()
		require.NoError(t, cm.LoadConfig(writeStepConfig(t,
			[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.98.0.0/16", Ports: []config.Port{p(22)}, Action: config.ActionDeny}},
			[]config.StepConfig{{ID: "a", Rules: append([]config.Rule{
				{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []config.Port{p(22)}},
			}, stepRules...)}})))
		require.NoError(t, fw.UpdateAllowlistTC(cm))
		return fw, maps
	}
	stepAllows := func(maps stepTestMaps, port uint16) bool {
		return verdictV4(maps, 1, host, port) && !verdictV4(maps, bpf.PolicyJob, host, port)
	}

	t.Run("a host install", func(t *testing.T) {
		// Job: the host's 80 and the deny's 22. Step: the wildcard's 22, the
		// carve's 22, and room for one more.
		fw, maps := setup(t, 5, nil)
		_, err := fw.AddPolicyIP(1, host, []config.Port{p(22), p(443)}, nil)
		require.ErrorIs(t, err, ErrStepBudget)
		assert.False(t, stepAllows(maps, 22), "the step got past the job's deny on 22")
		assert.False(t, stepAllows(maps, 443), "fewer allows")
	})
	t.Run("a step CIDR rule", func(t *testing.T) {
		// Job: the host's 80 and the deny's 22. Step: the carve's 22 (carves
		// go first) and the wildcard's 22; the /24's write finds no room.
		_, maps := setup(t, 4, nil, config.Rule{Type: config.RuleTypeCIDR, Value: "10.98.0.0/24", Ports: []config.Port{p(22), p(443)}})
		assert.False(t, stepAllows(maps, 22), "the step got past the job's deny on 22")
		assert.False(t, stepAllows(maps, 443), "fewer allows")
	})
	t.Run("a step CIDR rule whose LPM entry can't be taken out", func(t *testing.T) {
		// Room for the /24's deny entry; its allow is refused, and the
		// delete of its LPM entry fails.
		lpm := bpf.RuleKey(1, 24, binary.NativeEndian.Uint32(net.ParseIP("10.98.0.0").To4()))
		fw, maps := setup(t, 5, func(key any) bool { return key == lpm },
			config.Rule{Type: config.RuleTypeCIDR, Value: "10.98.0.0/24", Ports: []config.Port{p(22), p(443)}})
		require.Contains(t, entriesOf(t, maps[ruleMapCIDRs], 1), lpm)
		assert.False(t, stepAllows(maps, 22), "the step got past the job's deny on 22")
		assert.False(t, stepAllows(maps, 443))
		for m := range numRuleMaps {
			assert.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
		}
	})
}

// A refused carve costs the step the prefix around it, never the job its
// deny: the carves go in before any prefix, and a prefix with a refused carve
// inside it is withheld. Here the job's deny on 22 is hidden at 10.1.2.3 by a
// job host entry nested inside it, and the steps' share of the port map has
// no room for the carve's deny entry.
func TestStepGate_RefusedCarveWithholdsThePrefix(t *testing.T) {
	host := net.ParseIP("10.1.2.3").To4()
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	var logs bytes.Buffer
	fw, maps := newStepTestFirewall(ruleMapEntries, slog.New(slog.NewTextHandler(&logs, nil)))
	fw.steps.budget[ruleMapPorts] = 0
	_, err := fw.AddIP(host, config.ActionAllow, []config.Port{p(443)}) // nested, before the deny's sync
	require.NoError(t, err)
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.1.0.0/16", Ports: []config.Port{p(22)}, Action: config.ActionDeny}},
		[]config.StepConfig{{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8"}}}})))
	require.NoError(t, fw.UpdateAllowlistTC(cm))

	assert.False(t, verdictV4(maps, 1, host, 22) && !verdictV4(maps, bpf.PolicyJob, host, 22), "the step got past the job's deny on 22")
	assert.Empty(t, entriesOf(t, maps[ruleMapCIDRs], 1), "the /8 is withheld with its carve")
	assert.Contains(t, logs.String(), "Step rule entry withheld")
	for m := range numRuleMaps {
		assert.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
	}
}

// A carve whose prefix is then refused protects nothing, and is taken out
// again, uncharged.
func TestStepGate_UnneededCarveRemoved(t *testing.T) {
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	fw.steps.budget[ruleMapCIDRs] = 1 // the carve's LPM entry, and no room for the /8's
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.1.0.0/16", Ports: []config.Port{p(22)}, Action: config.ActionDeny}},
		[]config.StepConfig{{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8"}}}})))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	for m := range numRuleMaps {
		assert.Zero(t, stepEntries(t, maps[m]), "%s", m)
		assert.Zero(t, fw.steps.used(m), "%s ledger", m)
	}
}

// failingDeletes is a mock map whose Delete fails for the keys fail picks.
type failingDeletes struct {
	*cappedMap
	fail func(key any) bool
}

func (m *failingDeletes) Delete(key any) error {
	if m.fail != nil && m.fail(deref(key)) {
		return errors.New("delete failed")
	}
	return m.cappedMap.Delete(key)
}

func failAll(any) bool { return true }

// A step entry whose delete fails at the sync's clear stays in the ledger,
// charged, and the next sync's clear takes it out.
func TestSync_FailedClearStaysCharged(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	cidrs := &failingDeletes{cappedMap: maps[ruleMapCIDRs]}
	fw.cidrsMap = cidrs
	_, err := fw.AddPolicyIP(1, net.ParseIP("10.9.0.1"), nil, nil)
	require.NoError(t, err)

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t, nil, nil)))
	cidrs.fail = failAll
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	assert.Len(t, entriesOf(t, maps[ruleMapCIDRs], 1), 1, "the delete failed")
	assert.Equal(t, 1, fw.steps.used(ruleMapCIDRs), "so the key stays charged")

	cidrs.fail = nil
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	assert.Empty(t, entriesOf(t, maps[ruleMapCIDRs], 1))
	assert.Zero(t, fw.steps.used(ruleMapCIDRs))
}

// A job deny on a family's whole space, on all ports, leaves a step's rules
// nothing there; the sync says so, per step and family, naming the rule.
func TestSync_WarnsOfWholeSpaceDenies(t *testing.T) {
	var logs bytes.Buffer
	fw, _ := newStepTestFirewall(ruleMapEntries, slog.New(slog.NewTextHandler(&logs, nil)))
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{
			{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Action: config.ActionDeny},
			{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8", Action: config.ActionDeny}, // not the whole space
			{Type: config.RuleTypeCIDR, Value: "::/0", Ports: []config.Port{{Port: 22, Protocol: config.ProtocolTCP}}, Action: config.ActionDeny},
		},
		[]config.StepConfig{
			{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeHostname, Value: "a.example.com"}}},
			{ID: "b", Rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8"}}},
		})))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	assert.Equal(t, 2, bytes.Count(logs.Bytes(), []byte("A step's rules allow nothing in IPv4")), "once per step")
	assert.Contains(t, logs.String(), "job_deny=0.0.0.0/0")
	assert.NotContains(t, logs.String(), "allow nothing in IPv6", "a deny on some ports leaves the rest")
}

// A carve's allows are for the prefixes written around it, never one a
// refused carve withheld: those allows would reach inside the refused
// carve's deny. Here the job denies 22 in 10.1.0.0/16 and every port in
// 10.1.5.0/24, the latter hidden at 10.1.5.9 by a nested job entry, and the
// steps' share of the trie has room for one carve.
func TestStepGate_CarveKeepsOnlyForWrittenPrefixes(t *testing.T) {
	host := net.ParseIP("10.1.5.9").To4()
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	fw.steps.budget[ruleMapCIDRs] = 1
	_, err := fw.AddIP(host, config.ActionAllow, []config.Port{p(80)})
	require.NoError(t, err)
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{
			{Type: config.RuleTypeCIDR, Value: "10.1.0.0/16", Ports: []config.Port{p(22)}, Action: config.ActionDeny},
			{Type: config.RuleTypeCIDR, Value: "10.1.5.0/24", Action: config.ActionDeny},
		},
		[]config.StepConfig{{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8", Ports: []config.Port{p(22), p(443)}}}}})))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	assert.False(t, verdictV4(maps, 1, host, 443) && !verdictV4(maps, bpf.PolicyJob, host, 443), "the step got past the job's deny on 443")
	for m := range numRuleMaps {
		assert.Zero(t, stepEntries(t, maps[m]), "%s: the /8 withheld, its landed carve taken out", m)
	}
}

// partialPrefixFirewall sets up the partial-prefix tests. The job denies 80
// in 10.0.0.0/8 and every port in 10.1.0.0/16, the latter hidden at
// 10.1.2.3 by a job host entry on 443 nested inside it. Step a allows 22,
// 443 and 80 in 10.0.0.0/9: the gate trims 80, written as a deny entry
// before the allows, and the /16 is carved out of the /9. The port map
// holds ports entries; wrap may swap in failing maps before the sync.
func partialPrefixFirewall(t *testing.T, ports int, wrap func(*FirewallImpl, stepTestMaps)) (*FirewallImpl, stepTestMaps) {
	t.Helper()
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	maps[ruleMapPorts].capacity = ports
	_, err := fw.AddIP(net.ParseIP("10.1.2.3"), config.ActionAllow, []config.Port{p(443)}) // nested, before the deny's sync
	require.NoError(t, err)
	if wrap != nil {
		wrap(fw, maps)
	}
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{
			{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8", Ports: []config.Port{p(80)}, Action: config.ActionDeny},
			{Type: config.RuleTypeCIDR, Value: "10.1.0.0/16", Action: config.ActionDeny},
		},
		[]config.StepConfig{{ID: "a", Rules: []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "10.0.0.0/9", Ports: []config.Port{p(22), p(443), p(80)}},
		}}})))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	return fw, maps
}

// A step prefix the map refuses part-way is taken out whole, so what landed
// of it can't outlive the carve removed as unneeded once it failed: the
// /9's deny entry and first allow land, and then the map is full.
func TestStepGate_PartialPrefixTakenOut(t *testing.T) {
	hidden, inside := net.ParseIP("10.1.2.3").To4(), net.ParseIP("10.0.0.5").To4()
	stepAllows := func(maps stepTestMaps, ip net.IP) bool {
		return verdictV4(maps, 1, ip, 22) && !verdictV4(maps, bpf.PolicyJob, ip, 22)
	}

	// Job: the /8's 80 and the host's 443. Step: the /9's 80 and 22.
	fw, maps := partialPrefixFirewall(t, 4, nil)
	assert.False(t, stepAllows(maps, hidden), "the step got past the job's deny on the /16")
	assert.False(t, stepAllows(maps, inside), "the refused /9 is gone")
	for m := range numRuleMaps {
		assert.Zero(t, stepEntries(t, maps[m]), "%s: the /9 taken out, and its carve", m)
		assert.Zero(t, fw.steps.used(m), "%s ledger", m)
	}

	// With room for all of it, the /9 is written around its carve.
	_, maps = partialPrefixFirewall(t, 5, nil)
	assert.False(t, stepAllows(maps, hidden), "the step got past the job's deny on the /16")
	assert.True(t, stepAllows(maps, inside))
}

// A refused prefix whose removal a failed delete leaves unconfirmed may
// still be partly live, so its carves stay: here the /9's LPM entry and its
// allow on 22 can't be deleted.
func TestStepGate_UnconfirmedRemovalKeepsCarves(t *testing.T) {
	network := binary.NativeEndian.Uint32(net.ParseIP("10.0.0.0").To4())
	stuck := []any{bpf.RuleKey(1, 9, network), bpf.RulePortKey(1, network, 22, protoTCP, 23)}
	fw, maps := partialPrefixFirewall(t, 4, func(fw *FirewallImpl, maps stepTestMaps) {
		fail := func(key any) bool { return slices.Contains(stuck, key) }
		fw.cidrsMap = &failingDeletes{cappedMap: maps[ruleMapCIDRs], fail: fail}
		fw.portsMap = &failingDeletes{cappedMap: maps[ruleMapPorts], fail: fail}
	})
	hidden := net.ParseIP("10.1.2.3").To4()
	require.Contains(t, entriesOf(t, maps[ruleMapPorts], 1), stuck[1], "the /9's 22 is still there")
	assert.False(t, verdictV4(maps, 1, hidden, 22) && !verdictV4(maps, bpf.PolicyJob, hidden, 22),
		"the step got past the job's deny on the /16")
	assert.Contains(t, entriesOf(t, maps[ruleMapCIDRs], 1), bpf.RuleKey(1, 16, binary.NativeEndian.Uint32(net.ParseIP("10.1.0.0").To4())),
		"the carve stays")
	for m := range numRuleMaps {
		assert.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
	}
}

// The IPv6 twin of the failed-LPM-delete case: a refused /48 inside a job
// deny on 22 keeps its deny entry on 22 while its LPM entry stays, so a
// miss can't fall through to the step's ::/0 wildcard on 22.
func TestStepGate_V6RemovalKeepsDeniesWithTheLPMEntry(t *testing.T) {
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	var network [16]byte
	copy(network[:], net.ParseIP("fd00:98::"))
	lpm := bpf.RuleKeyV6(1, 48, network)
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	// Job: the /32's 22. Step: the carve's 22, the wildcard's 22, the /48's 22.
	maps[ruleMapPortsV6].capacity = 4
	fw.cidrsV6Map = &failingDeletes{cappedMap: maps[ruleMapCIDRsV6], fail: func(key any) bool { return key == lpm }}
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{{Type: config.RuleTypeCIDR, Value: "fd00:98::/32", Ports: []config.Port{p(22)}, Action: config.ActionDeny}},
		[]config.StepConfig{{ID: "a", Rules: []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "::/0", Ports: []config.Port{p(22)}},
			{Type: config.RuleTypeCIDR, Value: "fd00:98::/48", Ports: []config.Port{p(22), p(443)}},
		}}})))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	require.Contains(t, entriesOf(t, maps[ruleMapCIDRsV6], 1), lpm)
	assert.Equal(t, bpf.TcBpfPortVal{Action: 0}, entriesOf(t, maps[ruleMapPortsV6], 1)[bpf.RulePortKeyV6(1, network, 22, protoTCP, 80)])
	for m := range numRuleMaps {
		assert.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
	}
}

// Removing a carve no written prefix needs leaves a step prefix written at
// the carve's own prefix whole: a step rule at a job deny's prefix, trimmed,
// writes the carve's entries itself. Here the job denies 22 in 10.1.0.0/16;
// step a allows all of 10.0.0.0/8, which the steps' share of the trie has no
// room for, and 22 and 443 in 10.1.0.0/16, trimmed to 443.
func TestStepGate_CarveAtAWrittenPrefixKept(t *testing.T) {
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	fw.steps.budget[ruleMapCIDRs] = 1 // the carve's LPM entry, which is the /16's
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.1.0.0/16", Ports: []config.Port{p(22)}, Action: config.ActionDeny}},
		[]config.StepConfig{{ID: "a", Rules: []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8"},
			{Type: config.RuleTypeCIDR, Value: "10.1.0.0/16", Ports: []config.Port{p(22), p(443)}},
		}}})))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	host := net.ParseIP("10.1.2.3").To4()
	assert.True(t, verdictV4(maps, 1, host, 443), "the /16 lost its entry with the carve")
	assert.False(t, verdictV4(maps, 1, host, 22))
	assert.False(t, verdictV4(maps, 1, net.ParseIP("10.2.0.1").To4(), 443), "the /8 was refused")
	for m := range numRuleMaps {
		assert.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
	}
}

// The gate property under refusals at random points of a step sync. A first
// sync writes everything with room; each map is then capped at the job's
// entries plus a random part of what the steps held, and a second sync
// rebuilds the step tier under that room, so writes are refused wherever it
// runs out: a carve, a prefix's denies, its allows part-way, a carve's
// allows. Step DNS installs follow. Wherever a job CIDR deny covers an
// address and port and the job's lookup is silent, no step allows it, and
// the ledger stays what the maps hold.
func TestStepGate_RefusalProperty(t *testing.T) {
	const seeds = 500
	ports := []uint16{22, 80, 443}
	refused := 0
	for seed := range uint64(seeds) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 2023))
			randPorts := func(all float64) []config.Port {
				if rng.Float64() < all {
					return nil
				}
				var out []config.Port
				for _, n := range ports {
					if rng.IntN(2) == 0 {
						out = append(out, config.Port{Port: n, Protocol: config.ProtocolTCP})
					}
				}
				if len(out) == 0 {
					out = append(out, config.Port{Port: ports[rng.IntN(len(ports))], Protocol: config.ProtocolTCP})
				}
				return out
			}
			// A prefix inside 10.0.0.0/24, and now and then a wider one.
			randPrefix := func() string {
				switch rng.IntN(20) {
				case 0:
					return "0.0.0.0/0"
				case 1:
					return "10.0.0.0/8"
				}
				ones := 24 + rng.IntN(9)
				return fmt.Sprintf("%s/%d", net.IPv4(10, 0, 0, byte(rng.IntN(256))).Mask(net.CIDRMask(ones, 32)), ones)
			}

			var job, denies []config.Rule
			for range 1 + rng.IntN(4) {
				d := config.Rule{Type: config.RuleTypeCIDR, Value: randPrefix(), Ports: randPorts(0.5), Action: config.ActionDeny}
				job, denies = append(job, d), append(denies, d)
			}
			for range rng.IntN(3) {
				job = append(job, config.Rule{Type: config.RuleTypeCIDR, Value: randPrefix(), Ports: randPorts(0), Action: config.ActionAllow})
			}
			rng.Shuffle(len(job), func(i, j int) { job[i], job[j] = job[j], job[i] })
			var steps []config.StepConfig
			for s := range 1 + rng.IntN(2) {
				sc := config.StepConfig{ID: fmt.Sprintf("s%d", s)}
				for range 1 + rng.IntN(3) {
					sc.Rules = append(sc.Rules, config.Rule{Type: config.RuleTypeCIDR, Value: randPrefix(), Ports: randPorts(0.4)})
				}
				steps = append(steps, sc)
			}
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfig(writeStepConfig(t, job, steps)))

			fw, maps := newStepTestFirewall(ruleMapEntries, nil)
			for range 1 + rng.IntN(4) { // job host entries, nested in the denies or not
				_, err := fw.AddIP(net.IPv4(10, 0, 0, byte(rng.IntN(256))), config.ActionAllow, randPorts(0.1))
				require.NoError(t, err)
			}
			require.NoError(t, fw.UpdateAllowlistTC(cm))
			capped := false
			for m := range numRuleMaps {
				if held := fw.steps.used(m); held > 0 {
					maps[m].capacity = len(maps[m].store) - held + rng.IntN(held+1)
					capped = capped || maps[m].capacity < len(maps[m].store)
				}
			}
			if capped {
				refused++
			}
			require.NoError(t, fw.UpdateAllowlistTC(cm))
			for range rng.IntN(5) {
				_, _ = fw.AddPolicyIP(uint32(1+rng.IntN(len(steps))), net.IPv4(10, 0, 0, byte(rng.IntN(256))), randPorts(0.4), nil)
			}

			for last := range 256 {
				ip := net.IPv4(10, 0, 0, byte(last)).To4()
				for _, port := range ports {
					covered := slices.ContainsFunc(denies, func(d config.Rule) bool {
						return mustCIDR(d.Value).Contains(ip) &&
							(len(d.Ports) == 0 || slices.Contains(d.Ports, config.Port{Port: port, Protocol: config.ProtocolTCP}))
					})
					if decided, _ := rulesV4(maps, bpf.PolicyJob, ip, port, protoTCP); !covered || decided {
						continue
					}
					for policy := uint32(1); policy <= uint32(len(steps)); policy++ {
						decided, allow := rulesV4(maps, policy, ip, port, protoTCP)
						require.False(t, decided && allow, "step %d allows %s:%d past a job CIDR deny", policy, ip, port)
					}
				}
			}
			for m := range numRuleMaps {
				assert.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
			}
		})
	}
	t.Logf("%d of %d seeds refused step writes in the second sync", refused, seeds)
}
