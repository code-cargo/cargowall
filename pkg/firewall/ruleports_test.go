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
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// unknownPorts names a port, but with a protocol cargowall doesn't know.
var unknownPorts = []config.Port{{Port: 443, Protocol: "TCP"}}

// partlyKnownPorts names one port cargowall knows the protocol of, and one
// it doesn't.
var partlyKnownPorts = []config.Port{{Port: 443, Protocol: config.ProtocolTCP}, {Port: 80, Protocol: "TCP"}}

// A rule naming a port whose protocol cargowall doesn't know never reaches
// the maps as another rule, whatever its source: an allow is refused, and a
// deny keeps every port, the closed side. The loaders refuse such ports
// first.
func TestRulePorts_UnknownProtocolFailsClosed(t *testing.T) {
	var logs bytes.Buffer
	fw, maps := newStepTestFirewall(ruleMapEntries, slog.New(slog.NewTextHandler(&logs, nil)))
	host := func(a, b, c, d byte) *net.IPNet {
		return &net.IPNet{IP: net.IPv4(a, b, c, d).To4(), Mask: net.CIDRMask(32, 32)}
	}

	// The sync: an allow CIDR is left out; a deny CIDR is all ports.
	require.NoError(t, fw.addCIDRRuleLocked(bpf.PolicyJob, config.ResolvedRule{
		Type: config.RuleTypeCIDR, Value: "10.1.0.0/16", Action: config.ActionAllow, Ports: unknownPorts,
		IPNet: &net.IPNet{IP: net.IPv4(10, 1, 0, 0).To4(), Mask: net.CIDRMask(16, 32)},
	}, 1))
	assert.Empty(t, maps[ruleMapCIDRs].store, "an allow on an unknown protocol was written")
	require.NoError(t, fw.addCIDRRuleLocked(bpf.PolicyJob, config.ResolvedRule{
		Type: config.RuleTypeCIDR, Value: "10.2.0.0/16", Action: config.ActionDeny, Ports: unknownPorts,
		IPNet: &net.IPNet{IP: net.IPv4(10, 2, 0, 0).To4(), Mask: net.CIDRMask(16, 32)},
	}, 0))
	require.Len(t, maps[ruleMapCIDRs].store, 1)
	for _, v := range maps[ruleMapCIDRs].store {
		assert.Equal(t, bpf.TcBpfLpmVal{Action: 0, PortSpecific: 0, HostBits: 16}, v, "a deny on an unknown protocol denies every port")
	}
	assert.Empty(t, maps[ruleMapPorts].store)

	// The DNS path: an allow is refused with an error; a deny is all ports.
	_, err := fw.AddIP(net.IPv4(93, 184, 216, 34), config.ActionAllow, unknownPorts)
	require.ErrorIs(t, err, config.ErrUnknownProtocol)
	assert.Len(t, maps[ruleMapCIDRs].store, 1, "the refused allow wrote nothing")
	_, err = fw.AddIP(net.IPv4(93, 184, 216, 35), config.ActionDeny, unknownPorts)
	require.NoError(t, err)
	assert.Len(t, maps[ruleMapCIDRs].store, 2)
	assert.Empty(t, maps[ruleMapPorts].store)

	// A step's DNS install, before anything is charged or scoped, and a
	// step's own CIDR rule at the sync: both are allows, so both refused.
	scoped := false
	_, err = fw.AddPolicyIP(1, net.IPv4(93, 184, 216, 36), unknownPorts, func() error { scoped = true; return nil })
	require.ErrorIs(t, err, config.ErrUnknownProtocol)
	assert.False(t, scoped)
	fw.writeStepCIDRsLocked(config.StepRules{StepID: "a", Policy: 1, Rules: []config.ResolvedRule{{
		Type: config.RuleTypeCIDR, Value: "10.3.0.1/32", Action: config.ActionAllow, Ports: unknownPorts, IPNet: host(10, 3, 0, 1),
	}}})
	assert.Equal(t, [numRuleMaps]int{2, 0, 0, 0}, storeSizes(maps), "no step entry, and nothing charged")
	assert.Empty(t, fw.steps.keys[ruleMapCIDRs])

	assert.Contains(t, logs.String(), "level=ERROR")
	assert.Contains(t, logs.String(), "Refusing an allow rule naming a port whose protocol cargowall doesn't know")
	assert.Contains(t, logs.String(), "Keeping a deny rule naming a port whose protocol cargowall doesn't know on every port")
}

// The sync's hostname rules take the same guard: a policy loader that let
// an unknown protocol through would still have its allow refused and its
// deny kept on every port.
func TestRulePorts_SyncHostnameRule(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, slog.New(slog.DiscardHandler))
	cm := config.NewConfigManager()
	rules := []config.Rule{
		{Type: config.RuleTypeHostname, Value: "allow.example.com", Action: config.ActionAllow, Ports: unknownPorts},
		{Type: config.RuleTypeHostname, Value: "deny.example.com", Action: config.ActionDeny, Ports: unknownPorts},
	}
	require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionAllow))
	cm.UpdateDNSMapping("allow.example.com", "93.184.216.34")
	cm.UpdateDNSMapping("deny.example.com", "93.184.216.35")
	require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionAllow))
	require.NoError(t, fw.UpdateAllowlistTC(cm))

	require.Len(t, maps[ruleMapCIDRs].store, 1, "only the deny reaches the maps")
	for k, v := range maps[ruleMapCIDRs].store {
		assert.Equal(t, bpf.RuleKey(bpf.PolicyJob, 32, binaryIP(93, 184, 216, 35)), k)
		assert.Equal(t, uint8(0), v.(bpf.TcBpfLpmVal).Action)
		assert.Equal(t, uint8(0), v.(bpf.TcBpfLpmVal).PortSpecific, "the deny is on every port")
	}
	assert.Empty(t, maps[ruleMapPorts].store)
}

// The guard's Error is logged once per action and port list: the DNS path
// asks again for every answer, and the late allow for every blocked packet.
func TestRulePorts_LogsOncePerPortList(t *testing.T) {
	var logs bytes.Buffer
	fw, _ := newStepTestFirewall(ruleMapEntries, slog.New(slog.NewTextHandler(&logs, nil)))
	for _, ip := range []net.IP{net.IPv4(93, 184, 216, 34), net.IPv4(93, 184, 216, 35), net.IPv4(93, 184, 216, 34)} {
		_, err := fw.AddIP(ip, config.ActionAllow, unknownPorts)
		require.ErrorIs(t, err, config.ErrUnknownProtocol)
	}
	_, err := fw.AddIP(net.IPv4(93, 184, 216, 36), config.ActionAllow, []config.Port{{Port: 80, Protocol: "TCP"}})
	require.ErrorIs(t, err, config.ErrUnknownProtocol)
	_, err = fw.AddIP(net.IPv4(93, 184, 216, 37), config.ActionDeny, unknownPorts)
	require.NoError(t, err)
	assert.Equal(t, 3, bytes.Count(logs.Bytes(), []byte("level=ERROR")), "one per action and port list: %s", logs.String())
}

// A list with one port of an unknown protocol is the rule written no more
// than one with only such ports: the allow is refused rather than installed
// on its other ports, and the deny kept on every port, by the sync, the DNS
// path and the step gate's reading of the job's denies alike.
func TestRulePorts_PartlyKnownListFailsClosed(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, slog.New(slog.DiscardHandler))
	pp, ok := fw.rulePorts(partlyKnownPorts, 1, "r")
	assert.False(t, ok)
	assert.Nil(t, pp)
	pp, ok = fw.rulePorts(partlyKnownPorts, 0, "r")
	assert.True(t, ok)
	assert.Nil(t, pp, "every port")

	_, err := fw.AddIP(net.IPv4(93, 184, 216, 34), config.ActionAllow, partlyKnownPorts)
	require.ErrorIs(t, err, config.ErrUnknownProtocol)
	assert.Empty(t, maps[ruleMapCIDRs].store)
	_, err = fw.AddIP(net.IPv4(93, 184, 216, 35), config.ActionDeny, partlyKnownPorts)
	require.NoError(t, err)
	require.Len(t, maps[ruleMapCIDRs].store, 1)
	for _, v := range maps[ruleMapCIDRs].store {
		assert.Equal(t, uint8(0), v.(bpf.TcBpfLpmVal).PortSpecific, "the deny is on every port")
	}
	assert.Empty(t, maps[ruleMapPorts].store)

	denies := jobCIDRDenies([]config.ResolvedRule{{
		Type: config.RuleTypeCIDR, Value: "10.2.0.0/16", Action: config.ActionDeny, Ports: partlyKnownPorts,
		IPNet: &net.IPNet{IP: net.IPv4(10, 2, 0, 0).To4(), Mask: net.CIDRMask(16, 32)},
	}})
	require.Len(t, denies, 1)
	assert.Nil(t, denies[0].ports, "the step gate reads the deny on every port, as the sync wrote it")
}

// Ports that do expand pass through unchanged, and no ports means every
// port, as always.
func TestRulePorts_KnownPortsUnchanged(t *testing.T) {
	fw, _ := newStepTestFirewall(ruleMapEntries, nil)
	pp, ok := fw.rulePorts([]config.Port{{Port: 443, Protocol: config.ProtocolTCP}, {Port: 53, Protocol: config.ProtocolUDP}}, 1, "r")
	assert.True(t, ok)
	assert.Equal(t, []portProto{{Port: 443, Proto: protoTCP}, {Port: 53, Proto: protoUDP}}, pp)
	pp, ok = fw.rulePorts(nil, 1, "r")
	assert.True(t, ok)
	assert.Nil(t, pp)
}

// binaryIP is an IPv4 address as the rule maps key it.
func binaryIP(a, b, c, d byte) uint32 { return binary.NativeEndian.Uint32([]byte{a, b, c, d}) }
