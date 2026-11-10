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
				_, err := fw.AddPolicyIP(1, host, nil)
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
				_, err := fw.AddPolicyIP(in.policy, in.ip, in.ports)
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
	_, err := fw.AddPolicyIP(2, net.ParseIP("10.9.0.1"), tcp443) // step b's DNS install
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
	_, err := fw.AddPolicyIP(1, testIPv4(10, 0), nil)
	require.NoError(t, err)
	for i := 1; i <= 4; i++ {
		_, err := fw.AddPolicyIP(1, testIPv4(10, i), nil)
		require.ErrorIs(t, err, ErrStepBudget)
	}
	require.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("Step rule entr")), "three held back")

	_, err = fw.AddPolicyIP(1, testIPv4(10, 0), nil) // a held key: free
	require.NoError(t, err)
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("Step rule entr")), "not within the interval")

	fw.steps.warned = time.Now().Add(-2 * stepBudgetWarnInterval)
	_, err = fw.AddPolicyIP(1, testIPv4(10, 0), nil)
	require.NoError(t, err)
	assert.Contains(t, logs.String(), "since the last Warn")
	assert.Contains(t, logs.String(), "refused=3")
	assert.Zero(t, fw.steps.refused)
}

// A trimmed step write the map refuses part-way is fail-closed: its denies
// go in first, so what lands is fewer allows, never an allow whose misses
// fall through to a step wildcard on a port the job denies. Here the job's
// deny on 22 is hidden by a job entry nested inside it, the step has a
// wildcard on 22, and the map has room for the deny entry alone.
func TestStepGate_PartialWriteFailsClosed(t *testing.T) {
	host := net.ParseIP("10.98.0.5").To4()
	p := func(n uint16) config.Port { return config.Port{Port: n, Protocol: config.ProtocolTCP} }
	setup := func(t *testing.T, ports int, stepRules ...config.Rule) (*FirewallImpl, stepTestMaps) {
		t.Helper()
		fw, maps := newStepTestFirewall(ruleMapEntries, nil)
		maps[ruleMapPorts].capacity = ports
		_, err := fw.AddIP(host, config.ActionAllow, []config.Port{p(80)}) // nested, before the deny's sync
		require.NoError(t, err)
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
		fw, maps := setup(t, 5)
		_, err := fw.AddPolicyIP(1, host, []config.Port{p(22), p(443)})
		require.ErrorIs(t, err, ErrStepBudget)
		assert.False(t, stepAllows(maps, 22), "the step got past the job's deny on 22")
		assert.False(t, stepAllows(maps, 443), "fewer allows")
	})
	t.Run("a step CIDR rule", func(t *testing.T) {
		// Job: the host's 80 and the deny's 22. Step: the wildcard's 22 and
		// the /24's deny on 22; its allow on 443 and the carve find no room.
		_, maps := setup(t, 4, config.Rule{Type: config.RuleTypeCIDR, Value: "10.98.0.0/24", Ports: []config.Port{p(22), p(443)}})
		assert.False(t, stepAllows(maps, 22), "the step got past the job's deny on 22")
		assert.False(t, stepAllows(maps, 443), "fewer allows")
	})
}
