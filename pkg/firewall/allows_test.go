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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// allowsCase is a packet Allows judges, and what it should say.
type allowsCase struct {
	policy uint32
	dst    string
	port   uint16
	want   bool
}

// allowsPolicy writes the policy the Allows tests judge by: the job's host
// allow on 443 and host deny on 443, a step's host installs, a step's
// wildcard port by its CIDR rule, and a subnet rule of each.
func allowsPolicy(t *testing.T, fw *FirewallImpl, defaultAction config.Action) {
	t.Helper()
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.40.0.0/16", Ports: tcp443, Action: config.ActionAllow}},
		[]config.StepConfig{
			{ID: "a", Rules: []config.Rule{
				{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: tcpPorts(9000)},
				{Type: config.RuleTypeCIDR, Value: "10.41.0.0/16", Ports: tcpPorts(8443)},
				{Type: config.RuleTypeHostname, Value: "a.example.com"},
			}},
			{ID: "b", Rules: []config.Rule{{Type: config.RuleTypeHostname, Value: "b.example.com"}}},
		})))
	require.NoError(t, fw.SetDefaultAction(defaultAction))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	_, err := fw.AddIP(net.ParseIP("10.1.0.1"), config.ActionAllow, tcp443)
	require.NoError(t, err)
	_, err = fw.AddIP(net.ParseIP("10.1.0.3"), config.ActionDeny, tcp443)
	require.NoError(t, err)
	for _, w := range []struct {
		ip    string
		ports []config.Port
	}{{"10.1.0.2", tcp443}, {"10.1.0.3", nil}, {"2001:db8:1::2", tcp443}} {
		_, err := fw.AddPolicyIP(1, net.ParseIP(w.ip), w.ports, nil)
		require.NoError(t, err)
	}
}

// What the job's rules decide holds for every policy; where they decide
// nothing, a step's own rules may allow, and the default action decides
// the rest. Host routes and wildcard ports, which an exact lookup finds;
// TestAllows_KernelParity takes the subnets, on the trie's own match.
var allowsCases = []allowsCase{
	{0, "10.1.0.1", 443, true},
	{1, "10.1.0.1", 443, true},
	{0, "10.1.0.1", 80, false},
	{0, "10.1.0.2", 443, false},
	{1, "10.1.0.2", 443, true},
	{2, "10.1.0.2", 443, false},
	{1, "10.1.0.2", 80, false},
	{1, "10.1.0.3", 443, false}, // the job's deny decides
	{1, "10.1.0.3", 80, true},   // the job's silence, the step's all ports
	{1, "10.9.9.9", 9000, true}, // the step's wildcard port
	{0, "10.9.9.9", 9000, false},
	{2, "10.9.9.9", 9000, false},
	{1, "2001:db8:1::2", 443, true},
	{0, "2001:db8:1::2", 443, false},
}

func TestAllows_JobFirstThenTheStep(t *testing.T) {
	fw, _ := newStepTestFirewall(ruleMapEntries, nil)
	allowsPolicy(t, fw, config.ActionDeny)
	for _, c := range allowsCases {
		assert.Equal(t, c.want, fw.Allows(c.policy, net.ParseIP(c.dst), c.port, unix.IPPROTO_TCP),
			"policy %d to %s:%d", c.policy, c.dst, c.port)
	}
	assert.False(t, fw.Allows(1, net.ParseIP("10.1.0.2"), 443, unix.IPPROTO_UDP), "by protocol")

	require.NoError(t, fw.SetDefaultAction(config.ActionAllow))
	assert.True(t, fw.Allows(0, net.ParseIP("10.9.9.9"), 22, unix.IPPROTO_TCP), "the default decides the rest")
	assert.False(t, fw.Allows(1, net.ParseIP("10.1.0.3"), 443, unix.IPPROTO_TCP), "whatever it is")
}

// Allows says what cw_tc_egress decides, on the real maps, where the trie's
// longest match is the kernel's own, so the subnets come in here. A test
// run's packet carries a dummy socket no step tag names, so the kernel
// judges it as the job: the job's policy is checked against the kernel,
// and the steps' against what their rules allow, through the same reads.
// bpf/'s TestStepPolicyVerdicts proves the kernel's step tier for real
// sockets.
func TestAllows_KernelParity(t *testing.T) {
	requireRootBPF(t)
	objs, f := loadStepRulesObjects(t, true)
	fw := f.(*FirewallImpl)
	allowsPolicy(t, fw, config.ActionDeny)
	cases := append(append([]allowsCase(nil), allowsCases...),
		allowsCase{0, "10.40.7.7", 443, true},
		allowsCase{0, "10.40.7.7", 80, false},
		allowsCase{1, "10.40.7.7", 443, true},
		allowsCase{1, "10.40.7.7", 8443, false},
		allowsCase{1, "10.41.7.7", 8443, true},
		allowsCase{0, "10.41.7.7", 8443, false},
		allowsCase{2, "10.41.7.7", 8443, false},
		allowsCase{1, "10.41.7.7", 9000, true}, // past the subnet's ports, to the wildcard
		allowsCase{1, "10.41.7.7", 22, false},
	)
	for _, c := range cases {
		assert.Equal(t, c.want, fw.Allows(c.policy, net.ParseIP(c.dst), c.port, unix.IPPROTO_TCP),
			"Allows, policy %d to %s:%d", c.policy, c.dst, c.port)
		if c.policy != bpf.PolicyJob {
			continue
		}
		ret, _, err := objs.CwTcEgress.Test(tcpSYN(t, c.dst, c.port))
		require.NoError(t, err)
		assert.Equal(t, c.want, ret == verdictPass, "the kernel, to %s:%d", c.dst, c.port)
	}
}
