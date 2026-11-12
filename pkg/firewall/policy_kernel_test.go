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
// as asked, its rule maps sized for a policy with steps, and a firewall over
// its maps.
func loadStepRulesObjects(t *testing.T, gate bool) (*bpf.TcBpfObjects, Firewall) {
	t.Helper()
	return loadSizedObjects(t, gate, true)
}

// loadSizedObjects loads the tcbpf collection with the step-rules gate and
// the rule maps' size as asked, and a firewall over its maps.
func loadSizedObjects(t *testing.T, gate, steps bool) (*bpf.TcBpfObjects, Firewall) {
	t.Helper()
	spec, err := bpf.LoadTcBpf()
	require.NoError(t, err)
	require.NoError(t, bpf.SetStepRules(spec, gate))
	require.NoError(t, bpf.SizeRuleMaps(spec, steps))
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
	_, err := fw.AddPolicyIP(policyB, net.ParseIP("10.62.0.5"), tcp443, nil)
	require.NoError(t, err)
	_, err = fw.AddPolicyIP(policyB, net.ParseIP("2001:db8:62::5"), nil, nil)
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
		require.ErrorIs(t, lookup(bpf.PolicyJob), ebpf.ErrKeyNotExist, "%s under the job's policy", c.dst)
	}
	// Step A's 10.50.1.1 lies inside the job's 10.50.0.0/16 deny: withheld.
	// Step B's wildcard port covers the deny's whole prefix: carved out of B
	// as a deny entry. The job's own lookup finds its deny.
	inDeny := bpf.RuleKey(0, 32, v4("10.50.1.1"))
	inDeny.Policy = policyA
	require.ErrorIs(t, objs.MapCidrs.Lookup(inDeny, &val), ebpf.ErrKeyNotExist, "withheld from step A")
	inDeny.Policy = policyB
	require.NoError(t, objs.MapCidrs.Lookup(inDeny, &val))
	require.Equal(t, bpf.TcBpfLpmVal{Action: 0, HostBits: 16}, val, "carved out of step B")
	inDeny.Policy = bpf.PolicyJob
	require.NoError(t, objs.MapCidrs.Lookup(inDeny, &val))
	require.Equal(t, uint8(0), val.Action)
	var portVal bpf.TcBpfPortVal
	require.NoError(t, objs.MapPorts.Lookup(bpf.RulePortKey(policyB, 0, 9000, protoTCP, 0), &portVal))
	require.ErrorIs(t, objs.MapPorts.Lookup(bpf.RulePortKey(bpf.PolicyJob, 0, 9000, protoTCP, 0), &portVal), ebpf.ErrKeyNotExist)
}

// TestStepBudget_KernelMaps fills the steps' share of each real rule map,
// then the job's whole reservation, and shows the kernel takes no more: the
// maps hold exactly bpf.RuleMapEntries, the firewall's step budget comes
// from their size, and with the steps' share full the job still installs
// all it is reserved.
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

// A job CIDR deny is written as a deny entry whatever the default action
// (unlike a hostname deny, which the DNS path writes nothing for under a
// deny default), so the kernel's job-first lookup returns it before a step's
// entry for an IP inside it is read: a step install there needs no
// withholding. A port-scoped CIDR deny is a deny on its ports alone; on any
// other the job's rules are silent, and a step may allow it. bpf/'s
// TestStepPolicyVerdicts proves the kernel side, the job's deny before the
// step's allow, for real sockets.
func TestStepRules_JobCIDRDenyUnderDenyDefault(t *testing.T) {
	requireRootBPF(t)
	objs, fw := loadStepRulesObjects(t, true)
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t, []config.Rule{
		{Type: config.RuleTypeCIDR, Value: "203.0.113.0/24", Action: config.ActionDeny},
		{Type: config.RuleTypeCIDR, Value: "198.51.100.0/24", Ports: tcp443, Action: config.ActionDeny},
	}, []config.StepConfig{{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeHostname, Value: "step.example.com"}}}})))
	require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	// What the DNS path installs if step.example.com resolves into either.
	for _, ip := range []string{"203.0.113.7", "198.51.100.7"} {
		_, err := fw.AddPolicyIP(1, net.ParseIP(ip), nil, nil)
		require.NoError(t, err)
	}

	v4 := func(s string) uint32 { return binary.NativeEndian.Uint32(net.ParseIP(s).To4()) }
	var val bpf.TcBpfLpmVal
	require.NoError(t, objs.MapCidrs.Lookup(bpf.RuleKey(bpf.PolicyJob, 32, v4("203.0.113.7")), &val))
	require.Equal(t, bpf.TcBpfLpmVal{Action: 0, HostBits: 8}, val, "the job's lookup finds the deny")
	require.NoError(t, objs.MapCidrs.Lookup(bpf.RuleKey(bpf.PolicyJob, 32, v4("198.51.100.7")), &val))
	require.Equal(t, bpf.TcBpfLpmVal{Action: 0, PortSpecific: 1, HostBits: 8}, val)
	var portVal bpf.TcBpfPortVal
	require.NoError(t, objs.MapPorts.Lookup(bpf.RulePortKey(bpf.PolicyJob, v4("198.51.100.0"), 443, protoTCP, 8), &portVal))
	require.Equal(t, uint8(0), portVal.Action, "the port-scoped deny, on its port")
	require.ErrorIs(t, objs.MapPorts.Lookup(bpf.RulePortKey(bpf.PolicyJob, v4("198.51.100.0"), 80, protoTCP, 8), &portVal),
		ebpf.ErrKeyNotExist, "and on no other")

	for _, p := range []struct {
		dst  string
		port uint16
	}{{"203.0.113.7", 80}, {"203.0.113.7", 443}, {"198.51.100.7", 443}, {"198.51.100.7", 80}} {
		ret, _, err := objs.CwTcEgress.Test(tcpSYN(t, p.dst, p.port))
		require.NoError(t, err)
		require.Equal(t, uint32(verdictDrop), ret, "%s port %d as the job", p.dst, p.port)
	}
}

// With the job past its reservation in a real map, a step write the ledger
// admits meets the kernel's own limit (E2BIG for a hash, ENOSPC for a trie),
// and is refused as one past the budget is, the job's entries named.
func TestStepBudget_KernelJobPastItsReservation(t *testing.T) {
	requireRootBPF(t)
	for _, c := range fillCases() {
		t.Run(c.m.String(), func(t *testing.T) {
			var logs bytes.Buffer
			objs, _ := loadStepRulesObjects(t, true)
			fw := NewFirewall(objs.MapCidrs, objs.MapPorts, objs.MapCidrsV6, objs.MapPortsV6,
				objs.MapDefaultAction, objs.MapAuditMode, slog.New(slog.NewTextHandler(&logs, nil))).(*FirewallImpl)
			const past = 64
			jobAdds := (jobReservedEntries + past) / c.per
			for i := range jobAdds {
				require.NoError(t, c.add(fw, bpf.PolicyJob, 20, i), "job add %d", i)
			}
			stepAdds := (ruleMapEntries - jobAdds*c.per) / c.per
			for i := range stepAdds {
				require.NoError(t, c.add(fw, uint32(1+i%3), 10, i), "step add %d", i)
			}
			err := c.add(fw, 1, 10, stepAdds)
			require.ErrorIs(t, err, ErrStepBudget)
			require.Less(t, fw.steps.used(c.m), stepEntryBudget, "the ledger had room; the map didn't")
			require.Contains(t, logs.String(), noRoomJob)
		})
	}
}

// For a policy without steps the rule maps load at the job's size alone,
// which leaves the steps no room: a step write is refused, the job's whole
// size still lands, and the kernel takes no more.
func TestStepBudget_KernelJobOnlySize(t *testing.T) {
	requireRootBPF(t)
	objs, f := loadSizedObjects(t, false, false)
	fw := f.(*FirewallImpl)
	require.Equal(t, bpf.RuleMapEntriesJobOnly, objs.MapCidrs.MaxEntries())
	_, err := fw.AddPolicyIP(1, testIPv4(10, 0), nil, nil)
	require.ErrorIs(t, err, ErrStepBudget)
	for i := range jobReservedEntries {
		_, err := fw.AddIP(testIPv4(20, i), config.ActionAllow, nil)
		require.NoError(t, err, "job add %d", i)
	}
	_, err = fw.AddIP(testIPv4(20, jobReservedEntries), config.ActionAllow, nil)
	require.Error(t, err)
}

// The nested job entry, on the real maps: a job port-specific host entry
// inside the job's CIDR deny, written before the deny's sync or after it,
// with the step's install before the sync or after. The step's policy never
// holds an entry inside the deny, so the step's lookup there finds nothing,
// and the job's own lookup is all that judges the host.
func TestStepGate_KernelNestedJobEntry(t *testing.T) {
	requireRootBPF(t)
	host := net.ParseIP("10.98.0.12")
	hostKey := bpf.RuleKey(1, 32, binary.NativeEndian.Uint32(host.To4()))
	for _, c := range []struct {
		name                          string
		jobAllowFirst, stepBeforeSync bool
	}{
		{"deny synced, then the job's allow", false, false},
		{"the job's allow, then the deny synced", true, false},
		{"the step's install before the sync", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			objs, fw := loadStepRulesObjects(t, true)
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfig(writeStepConfig(t,
				[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.98.0.0/16", Action: config.ActionDeny}},
				[]config.StepConfig{{ID: "a", Rules: []config.Rule{{Type: config.RuleTypeHostname, Value: "svc.example.com"}}}})))
			require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
			jobAllow := func() {
				_, err := fw.AddIP(host, config.ActionAllow, tcp443)
				require.NoError(t, err)
			}
			step := func() {
				_, err := fw.AddPolicyIP(1, host, nil, nil)
				require.NoError(t, err)
			}
			if c.jobAllowFirst {
				jobAllow()
			}
			if c.stepBeforeSync {
				step()
			}
			require.NoError(t, fw.UpdateAllowlistTC(cm))
			if !c.jobAllowFirst {
				jobAllow()
			}
			if !c.stepBeforeSync {
				step()
			}
			var val bpf.TcBpfLpmVal
			require.ErrorIs(t, objs.MapCidrs.Lookup(hostKey, &val), ebpf.ErrKeyNotExist, "no step entry inside the job's deny")
			ret, _, err := objs.CwTcEgress.Test(tcpSYN(t, host.String(), 22))
			require.NoError(t, err)
			require.Equal(t, uint32(verdictDrop), ret)
		})
	}
}

// refusingDeletes is a real map whose deletes fail.
type refusingDeletes struct{ *ebpf.Map }

func (refusingDeletes) Delete(any) error { return errors.New("delete failed") }

// RemovePolicyIP on the real maps. The LPM entry goes first, so a port
// entry whose delete then fails is left where nothing reads it: the trie's
// longest match for the address under the step's policy is the step's
// covering prefix, whose port entries the verdict looks up by that prefix,
// not by the address. A step's own /32 rule at an address a DNS install
// also opened keeps its entry, at the sync's value, and its port entry.
func TestRemovePolicyIP_KernelMaps(t *testing.T) {
	requireRootBPF(t)
	objs, f := loadStepRulesObjects(t, true)
	fw := f.(*FirewallImpl)
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t, []config.Rule{}, []config.StepConfig{{ID: "a", Rules: []config.Rule{
		{Type: config.RuleTypeCIDR, Value: "10.61.0.0/24", Ports: tcp443},
		{Type: config.RuleTypeCIDR, Value: "10.98.0.9/32", Ports: tcpPorts(8443)},
		{Type: config.RuleTypeHostname, Value: "a.example.com"},
	}}})))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	inPrefix, atRule, v6 := net.ParseIP("10.61.0.5"), net.ParseIP("10.98.0.9"), net.ParseIP("2001:db8:62::5")
	for _, ip := range []net.IP{inPrefix, atRule, v6} {
		_, err := fw.AddPolicyIP(1, ip, tcpPorts(443, 8080), nil)
		require.NoError(t, err)
	}
	v4 := func(ip net.IP) uint32 { return binary.NativeEndian.Uint32(ip.To4()) }
	var val bpf.TcBpfLpmVal
	var portVal bpf.TcBpfPortVal

	fw.portsMap = refusingDeletes{objs.MapPorts}
	require.NoError(t, fw.RemovePolicyIP(1, inPrefix))
	require.NoError(t, objs.MapCidrs.Lookup(bpf.RuleKey(1, 32, v4(inPrefix)), &val))
	require.Equal(t, bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1, HostBits: 8}, val, "the longest match is the step's /24")
	require.NoError(t, objs.MapPorts.Lookup(bpf.RulePortKey(1, v4(inPrefix), 8080, protoTCP, 0), &portVal),
		"the refused delete left the install's port entry")
	require.ErrorIs(t, objs.MapPorts.Lookup(bpf.RulePortKey(1, v4(net.ParseIP("10.61.0.0")), 8080, protoTCP, 8), &portVal),
		ebpf.ErrKeyNotExist, "and the /24's lookup doesn't reach it")
	fw.portsMap = objs.MapPorts

	require.NoError(t, fw.RemovePolicyIP(1, atRule))
	require.NoError(t, objs.MapCidrs.Lookup(bpf.RuleKey(1, 32, v4(atRule)), &val))
	require.Equal(t, bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1}, val, "the step's /32 rule stays")
	require.NoError(t, objs.MapPorts.Lookup(bpf.RulePortKey(1, v4(atRule), 8443, protoTCP, 0), &portVal))
	for _, port := range []uint16{443, 8080} {
		require.ErrorIs(t, objs.MapPorts.Lookup(bpf.RulePortKey(1, v4(atRule), port, protoTCP, 0), &portVal),
			ebpf.ErrKeyNotExist, "the install's port %d goes", port)
	}

	require.NoError(t, fw.RemovePolicyIP(1, v6))
	var n6 [16]byte
	copy(n6[:], v6.To16())
	require.ErrorIs(t, objs.MapCidrsV6.Lookup(bpf.RuleKeyV6(1, 128, n6), &val), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, objs.MapPortsV6.Lookup(bpf.RulePortKeyV6(1, n6, 443, protoTCP, 0), &portVal), ebpf.ErrKeyNotExist)
}
