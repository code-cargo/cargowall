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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// allowsCase is a packet Allows judges, and what it should say: TCP, or
// UDP with udp set.
type allowsCase struct {
	policy uint32
	dst    string
	port   uint16
	want   bool
	udp    bool
}

func (c allowsCase) proto() uint8 {
	if c.udp {
		return unix.IPPROTO_UDP
	}
	return unix.IPPROTO_TCP
}

// allowsPolicy writes the policy the Allows tests judge by: the job's host
// allow on 443 and host deny on 443, a step's host installs, a step's
// wildcard port by its CIDR rule, and a subnet rule of each.
func allowsPolicy(t *testing.T, fw *FirewallImpl, defaultAction config.Action) {
	t.Helper()
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t,
		[]config.Rule{
			{Type: config.RuleTypeCIDR, Value: "10.40.0.0/16", Ports: tcp443, Action: config.ActionAllow},
			{Type: config.RuleTypeCIDR, Value: "2001:db8:40::/48", Ports: tcp443, Action: config.ActionAllow},
			{Type: config.RuleTypeCIDR, Value: "10.43.0.0/16", Ports: []config.Port{{Port: 5353, Protocol: config.ProtocolUDP}}, Action: config.ActionAllow},
		},
		[]config.StepConfig{
			{ID: "a", Rules: []config.Rule{
				{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: tcpPorts(9000)},
				{Type: config.RuleTypeCIDR, Value: "10.41.0.0/16", Ports: tcpPorts(8443)},
				{Type: config.RuleTypeCIDR, Value: "2001:db8:41::/48", Ports: tcpPorts(8443)},
				{Type: config.RuleTypeCIDR, Value: "::/0", Ports: tcpPorts(9001)},
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
	{0, "10.1.0.1", 443, true, false},
	{1, "10.1.0.1", 443, true, false},
	{0, "10.1.0.1", 80, false, false},
	{0, "10.1.0.2", 443, false, false},
	{1, "10.1.0.2", 443, true, false},
	{2, "10.1.0.2", 443, false, false},
	{1, "10.1.0.2", 80, false, false},
	{1, "10.1.0.3", 443, false, false}, // the job's deny decides
	{1, "10.1.0.3", 80, true, false},   // the job's silence, the step's all ports
	{1, "10.9.9.9", 9000, true, false}, // the step's wildcard port
	{0, "10.9.9.9", 9000, false, false},
	{2, "10.9.9.9", 9000, false, false},
	{1, "2001:db8:1::2", 443, true, false},
	{0, "2001:db8:1::2", 443, false, false},
	{1, "2001:db8:1::2", 80, false, false},   // a port-specific host route, past its ports
	{1, "2001:db8:99::1", 9001, true, false}, // the step's IPv6 wildcard port
	{0, "2001:db8:99::1", 9001, false, false},
	{1, "2001:db8:1::2", 9001, true, false}, // past a host route's ports, to the wildcard
	{1, "2001:db8:99::1", 9002, false, false},
}

func TestAllows_JobFirstThenTheStep(t *testing.T) {
	fw, _ := newStepTestFirewall(ruleMapEntries, nil)
	allowsPolicy(t, fw, config.ActionDeny)
	for _, c := range allowsCases {
		assert.Equal(t, c.want, fw.Allows(c.policy, net.ParseIP(c.dst), c.port, c.proto()),
			"policy %d to %s:%d", c.policy, c.dst, c.port)
	}
	assert.False(t, fw.Allows(1, net.ParseIP("10.1.0.2"), 443, unix.IPPROTO_UDP), "by protocol")

	require.NoError(t, fw.SetDefaultAction(config.ActionAllow))
	assert.True(t, fw.Allows(0, net.ParseIP("10.9.9.9"), 22, unix.IPPROTO_TCP), "the default decides the rest")
	assert.False(t, fw.Allows(1, net.ParseIP("10.1.0.3"), 443, unix.IPPROTO_TCP), "whatever it is")

	fw, _ = newStepTestFirewall(ruleMapEntries, nil)
	assert.False(t, fw.Allows(0, net.ParseIP("10.9.9.9"), 22, unix.IPPROTO_TCP), "no default written denies, as the kernel's")
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
		allowsCase{0, "10.40.7.7", 443, true, false},
		allowsCase{0, "10.40.7.7", 80, false, false},
		allowsCase{1, "10.40.7.7", 443, true, false},
		allowsCase{1, "10.40.7.7", 8443, false, false},
		allowsCase{1, "10.41.7.7", 8443, true, false},
		allowsCase{0, "10.41.7.7", 8443, false, false},
		allowsCase{2, "10.41.7.7", 8443, false, false},
		allowsCase{1, "10.41.7.7", 9000, true, false}, // past the subnet's ports, to the wildcard
		allowsCase{1, "10.41.7.7", 22, false, false},
		allowsCase{0, "2001:db8:40::7", 443, true, false},
		allowsCase{0, "2001:db8:40:ffff::7", 443, true, false},
		allowsCase{0, "2001:db8:40::7", 80, false, false},
		allowsCase{1, "2001:db8:40::7", 80, false, false},
		allowsCase{1, "2001:db8:41::9", 8443, true, false},
		allowsCase{1, "2001:db8:41:ffff::9", 8443, true, false},
		allowsCase{1, "2001:db8:41::9", 22, false, false},
		allowsCase{1, "2001:db8:41::9", 9001, true, false}, // past the subnet's ports, to the wildcard
		allowsCase{0, "2001:db8:41::9", 8443, false, false},
		allowsCase{0, "10.43.1.1", 5353, true, true},
		allowsCase{0, "10.43.1.1", 5353, false, false}, // TCP, where the rule names UDP
		allowsCase{0, "10.40.7.7", 443, false, true},
	)
	for _, c := range cases {
		assert.Equal(t, c.want, fw.Allows(c.policy, net.ParseIP(c.dst), c.port, c.proto()),
			"Allows, policy %d to %s:%d udp=%v", c.policy, c.dst, c.port, c.udp)
		if c.policy != bpf.PolicyJob {
			continue
		}
		pkt := tcpSYN(t, c.dst, c.port)
		if c.udp {
			pkt = udpPacket(t, c.dst, c.port)
		}
		ret, _, err := objs.CwTcEgress.Test(pkt)
		require.NoError(t, err)
		assert.Equal(t, c.want, ret == verdictPass, "the kernel, to %s:%d udp=%v", c.dst, c.port, c.udp)
	}
}

// udpPacket builds an Ethernet frame carrying a UDP datagram to dst:port.
func udpPacket(t *testing.T, dst string, port uint16) []byte {
	t.Helper()
	pkt := tcpSYN(t, dst, port)
	ip4 := net.ParseIP(dst).To4() != nil
	l3, protoAt := 14+20, 14+9
	if !ip4 {
		l3, protoAt = 14+40, 14+6
	}
	pkt[protoAt] = unix.IPPROTO_UDP
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], port)
	binary.BigEndian.PutUint16(udp[4:], 8)
	pkt = append(pkt[:l3], udp...)
	if ip4 {
		binary.BigEndian.PutUint16(pkt[14+2:], uint16(20+len(udp)))
	} else {
		binary.BigEndian.PutUint16(pkt[14+4:], uint16(len(udp)))
	}
	return pkt
}
