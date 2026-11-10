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
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

func requireRootBPF(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	require.NoError(t, rlimit.RemoveMemlock())
}

// loadStepRulesObjects loads the tcbpf collection with the step-rules gate
// as asked, and a firewall over its maps.
func loadStepRulesObjects(t *testing.T, gate bool) (*bpf.TcBpfObjects, Firewall) {
	t.Helper()
	spec, err := bpf.LoadTcBpf()
	require.NoError(t, err)
	require.NoError(t, bpf.SetStepRules(spec, gate))
	var objs bpf.TcBpfObjects
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() { objs.Close() })
	fw := NewFirewall(objs.MapCidrs, objs.MapPorts, objs.MapCidrsV6, objs.MapPortsV6,
		objs.MapDefaultAction, objs.MapAuditMode, slog.New(slog.DiscardHandler))
	return &objs, fw
}

// TestStepRules_Verdict drives step rules through the real writers into the
// real maps, with the step-rules gate on, and reads back what the job's own
// traffic gets: cw_tc_egress judges each probe as the job, since a test
// run's packet carries a socket no step tag names. Step entries must allow
// none of it. Then each step entry is looked up where the kernel's verdict
// looks for it, under its policy, by the trie's own longest-prefix match:
// the step's lookup finds it, the job's doesn't. bpf/'s TestStepPolicyVerdicts
// proves the verdict reads a step's entries there, for real sockets.
func TestStepRules_Verdict(t *testing.T) {
	requireRootBPF(t)

	jobRules := []config.Rule{
		{Type: config.RuleTypeCIDR, Value: "10.60.0.10/32", Action: config.ActionAllow},
		{Type: config.RuleTypeCIDR, Value: "10.50.0.0/16", Action: config.ActionDeny},
		{Type: config.RuleTypeCIDR, Value: "2001:db8:60::10/128", Action: config.ActionAllow},
	}
	steps := []config.StepConfig{
		{ID: "a", Rules: []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "10.61.0.0/24", Ports: tcp443},
			{Type: config.RuleTypeCIDR, Value: "10.50.1.1"},
			{Type: config.RuleTypeCIDR, Value: "2001:db8:61::/48"},
		}},
		{ID: "b", Rules: []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []config.Port{{Port: 9000, Protocol: config.ProtocolTCP}}},
		}},
	}
	const policyA, policyB = 1, 2

	objs, fw := loadStepRulesObjects(t, true)
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t, jobRules, steps)))
	require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	// What the DNS path installs for a step's hostname rule.
	_, err := fw.AddPolicyIP(policyB, net.ParseIP("10.62.0.5"), tcp443)
	require.NoError(t, err)
	_, err = fw.AddPolicyIP(policyB, net.ParseIP("2001:db8:62::5"), nil)
	require.NoError(t, err)

	for _, p := range []struct {
		dst  string
		port uint16
		want uint32
	}{
		{"10.60.0.10", 22, verdictPass},
		{"2001:db8:60::10", 22, verdictPass},
		{"10.61.0.7", 443, verdictDrop},
		{"10.50.1.1", 443, verdictDrop},
		{"10.70.0.1", 9000, verdictDrop},
		{"10.62.0.5", 443, verdictDrop},
		{"2001:db8:61::7", 22, verdictDrop},
		{"2001:db8:62::5", 22, verdictDrop},
	} {
		ret, _, err := objs.CwTcEgress.Test(tcpSYN(t, p.dst, p.port))
		require.NoError(t, err)
		require.Equal(t, p.want, ret, "%s port %d as the job", p.dst, p.port)
	}

	v4 := func(s string) uint32 { return binary.NativeEndian.Uint32(net.ParseIP(s).To4()) }
	v6 := func(s string) (out [16]byte) { copy(out[:], net.ParseIP(s).To16()); return out }
	var val bpf.TcBpfLpmVal
	for _, c := range []struct {
		dst    string
		policy uint32
	}{
		{"10.61.0.7", policyA},
		{"10.50.1.1", policyA},
		{"10.62.0.5", policyB},
		{"2001:db8:61::7", policyA},
		{"2001:db8:62::5", policyB},
	} {
		lookup := func(policy uint32) error {
			if ip := net.ParseIP(c.dst); ip.To4() != nil {
				return objs.MapCidrs.Lookup(bpf.RuleKey(policy, 32, v4(c.dst)), &val)
			}
			return objs.MapCidrsV6.Lookup(bpf.RuleKeyV6(policy, 128, v6(c.dst)), &val)
		}
		require.NoError(t, lookup(c.policy), "%s under its step's policy", c.dst)
		require.Equal(t, uint8(1), val.Action, c.dst)
		other := uint32(policyA + policyB - c.policy)
		require.ErrorIs(t, lookup(other), ebpf.ErrKeyNotExist, "%s under the other step's policy", c.dst)
		if c.dst == "10.50.1.1" {
			// The job's deny is what the job's lookup finds.
			require.NoError(t, lookup(bpf.PolicyJob))
			require.Equal(t, uint8(0), val.Action)
			continue
		}
		require.ErrorIs(t, lookup(bpf.PolicyJob), ebpf.ErrKeyNotExist, "%s under the job's policy", c.dst)
	}
	var portVal bpf.TcBpfPortVal
	require.NoError(t, objs.MapPorts.Lookup(bpf.RulePortKey(policyB, 0, 9000, protoTCP, 0), &portVal))
	require.ErrorIs(t, objs.MapPorts.Lookup(bpf.RulePortKey(bpf.PolicyJob, 0, 9000, protoTCP, 0), &portVal), ebpf.ErrKeyNotExist)
}

// TestStepBudget_KernelMaps fills the steps' share of each real rule map,
// then the job's whole reservation, and shows the kernel takes no more: the
// maps hold exactly ruleMapEntries, and with the steps' share full the job
// still installs all it is reserved.
func TestStepBudget_KernelMaps(t *testing.T) {
	requireRootBPF(t)
	for _, c := range fillCases() {
		t.Run(c.m.String(), func(t *testing.T) {
			_, f := loadStepRulesObjects(t, true)
			fw := f.(*FirewallImpl)
			adds := stepEntryBudget / c.per
			for i := range adds {
				require.NoError(t, c.add(fw, uint32(1+i%3), 10, i), "step add %d", i)
			}
			require.ErrorIs(t, c.add(fw, 1, 10, adds), ErrStepBudget)
			for i := range jobReservedEntries / c.per {
				require.NoError(t, c.add(fw, bpf.PolicyJob, 20, i), "job add %d", i)
			}
			require.Error(t, c.add(fw, bpf.PolicyJob, 20, jobReservedEntries/c.per), "the map is full")
		})
	}
}
