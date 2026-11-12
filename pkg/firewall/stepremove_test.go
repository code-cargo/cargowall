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

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

func tcpPorts(ns ...uint16) []config.Port {
	out := make([]config.Port, len(ns))
	for i, n := range ns {
		out[i] = config.Port{Port: n, Protocol: config.ProtocolTCP}
	}
	return out
}

// hostKeys is policy's LPM key at ip's host route, and its port key there
// for TCP port, in ip's family.
func hostKeys(policy uint32, ip net.IP, port uint16) (lpm, portKey any) {
	if ip4 := ip.To4(); ip4 != nil {
		n := binary.NativeEndian.Uint32(ip4)
		return bpf.RuleKey(policy, 32, n), bpf.RulePortKey(policy, n, port, protoTCP, 0)
	}
	var n [16]byte
	copy(n[:], ip.To16())
	return bpf.RuleKeyV6(policy, 128, n), bpf.RulePortKeyV6(policy, n, port, protoTCP, 0)
}

// families is the LPM and port maps of ip's family.
func families(ip net.IP) (lpm, ports ruleMap) {
	if ip.To4() != nil {
		return ruleMapCIDRs, ruleMapPorts
	}
	return ruleMapCIDRsV6, ruleMapPortsV6
}

// RemovePolicyIP takes out what a step policy's DNS installs added at an
// address: the LPM entry and its port entries, uncharged, and the
// accumulator, so a later install there starts afresh rather than from the
// withdrawn one's all-ports grant. Another policy's entries there stay, and
// the job's: policy 0 is refused, and nothing of it touched.
func TestRemovePolicyIP_TakesOutTheInstalls(t *testing.T) {
	for _, ip := range []net.IP{testIPv4(10, 1), testIPv6(10, 1)} {
		t.Run(ip.String(), func(t *testing.T) {
			fw, maps := newStepTestFirewall(ruleMapEntries, nil)
			lpmMap, portMap := families(ip)
			_, err := fw.AddIP(ip, config.ActionAllow, tcp443)
			require.NoError(t, err)
			for _, policy := range []uint32{1, 2} {
				_, err := fw.AddPolicyIP(policy, ip, tcpPorts(443, 8080), nil)
				require.NoError(t, err)
			}
			job := [2]int{len(entriesOf(t, maps[lpmMap], bpf.PolicyJob)), len(entriesOf(t, maps[portMap], bpf.PolicyJob))}
			require.Equal(t, [2]int{1, 1}, job)

			require.Error(t, fw.RemovePolicyIP(bpf.PolicyJob, ip), "the job's entries are AddIP's")
			assert.Equal(t, job, [2]int{len(entriesOf(t, maps[lpmMap], bpf.PolicyJob)), len(entriesOf(t, maps[portMap], bpf.PolicyJob))})

			require.NoError(t, fw.RemovePolicyIP(1, ip))
			assert.Empty(t, entriesOf(t, maps[lpmMap], 1))
			assert.Empty(t, entriesOf(t, maps[portMap], 1))
			assert.Len(t, entriesOf(t, maps[lpmMap], 2), 1, "another policy's entries stay")
			assert.Len(t, entriesOf(t, maps[portMap], 2), 2)
			assert.Equal(t, job, [2]int{len(entriesOf(t, maps[lpmMap], bpf.PolicyJob)), len(entriesOf(t, maps[portMap], bpf.PolicyJob))},
				"and the job's")
			assert.Equal(t, 1, fw.steps.used(lpmMap), "uncharged")
			assert.Equal(t, 2, fw.steps.used(portMap))
			assert.NotContains(t, fw.stepIPs, policyIP{1, ip.String()})

			_, err = fw.AddPolicyIP(1, ip, nil, nil) // all ports
			require.NoError(t, err)
			require.NoError(t, fw.RemovePolicyIP(1, ip))
			_, err = fw.AddPolicyIP(1, ip, tcp443, nil)
			require.NoError(t, err)
			lpm, port := hostKeys(1, ip, 443)
			assert.Equal(t, bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1}, maps[lpmMap].store[lpm],
				"the next install is port-scoped, not the withdrawn one's all ports")
			assert.Contains(t, maps[portMap].store, port)

			require.NoError(t, fw.RemovePolicyIP(3, ip), "nothing installed: nothing to take out")
		})
	}
}

// The LPM entry goes first: its port entries are never read without it.
// When it can't be deleted, the call fails and leaves everything, the port
// entries, their charges and the accumulator; a port entry whose delete
// fails after it is left charged, unread, for the next sync to take out.
func TestRemovePolicyIP_LPMFirst(t *testing.T) {
	ip := testIPv4(10, 2)
	lpm, port := hostKeys(1, ip, 443)

	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	_, err := fw.AddPolicyIP(1, ip, tcp443, nil)
	require.NoError(t, err)
	fw.cidrsMap = &failingDeletes{cappedMap: maps[ruleMapCIDRs], fail: failAll}
	require.Error(t, fw.RemovePolicyIP(1, ip))
	assert.Contains(t, maps[ruleMapCIDRs].store, lpm)
	assert.Contains(t, maps[ruleMapPorts].store, port, "no port entry taken out before its LPM entry")
	assert.Equal(t, 1, fw.steps.used(ruleMapCIDRs))
	assert.Equal(t, 1, fw.steps.used(ruleMapPorts))
	assert.Contains(t, fw.stepIPs, policyIP{1, ip.String()})

	fw, maps = newStepTestFirewall(ruleMapEntries, nil)
	_, err = fw.AddPolicyIP(1, ip, tcp443, nil)
	require.NoError(t, err)
	fw.portsMap = &failingDeletes{cappedMap: maps[ruleMapPorts], fail: failAll}
	require.NoError(t, fw.RemovePolicyIP(1, ip), "the LPM entry is gone, so the port entry is never read")
	assert.NotContains(t, maps[ruleMapCIDRs].store, lpm)
	assert.Contains(t, maps[ruleMapPorts].store, port)
	assert.Equal(t, 1, fw.steps.used(ruleMapPorts), "still charged, for the next sync's clear")
}

// A step's own /32 or /128 CIDR rule at an address a DNS install of the
// same step also opened shares its entries there. Withdrawing the install
// takes out what it added and nothing of the rule: the LPM entry gets the
// sync's value back, the rule's port entries and charges stay, and so does
// the rule's part of the accumulator, so the next install there adds to the
// rule as the first did.
func TestRemovePolicyIP_KeepsTheStepsOwnRule(t *testing.T) {
	for _, c := range []struct {
		cidr string
		ip   net.IP
	}{
		{"10.98.0.9/32", net.ParseIP("10.98.0.9")},
		{"2001:db8:98::9/128", net.ParseIP("2001:db8:98::9")},
	} {
		t.Run(c.cidr, func(t *testing.T) {
			fw, maps := newStepTestFirewall(ruleMapEntries, nil)
			lpmMap, portMap := families(c.ip)
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfig(writeStepConfig(t,
				[]config.Rule{{Type: config.RuleTypeCIDR, Value: "10.97.0.0/16", Action: config.ActionAllow}},
				[]config.StepConfig{{ID: "a", Rules: []config.Rule{
					{Type: config.RuleTypeCIDR, Value: c.cidr, Ports: tcpPorts(8443)},
					{Type: config.RuleTypeHostname, Value: "a.example.com"},
				}}})))
			require.NoError(t, fw.UpdateAllowlistTC(cm))
			lpm, rulePort := hostKeys(1, c.ip, 8443)
			_, dnsPort := hostKeys(1, c.ip, 443)
			synced := bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1}
			require.Equal(t, synced, maps[lpmMap].store[lpm])
			used := [2]int{fw.steps.used(lpmMap), fw.steps.used(portMap)}

			_, err := fw.AddPolicyIP(1, c.ip, tcp443, nil)
			require.NoError(t, err)
			require.Contains(t, maps[portMap].store, dnsPort)
			require.NoError(t, fw.RemovePolicyIP(1, c.ip))
			assert.Equal(t, synced, maps[lpmMap].store[lpm], "the rule's LPM entry stays")
			assert.Contains(t, maps[portMap].store, rulePort, "and its port entry")
			assert.NotContains(t, maps[portMap].store, dnsPort, "the install's goes")
			assert.Equal(t, used, [2]int{fw.steps.used(lpmMap), fw.steps.used(portMap)}, "charged as the sync left it")

			_, err = fw.AddPolicyIP(1, c.ip, nil, nil) // all ports
			require.NoError(t, err)
			require.Equal(t, bpf.TcBpfLpmVal{Action: 1}, maps[lpmMap].store[lpm])
			require.NoError(t, fw.RemovePolicyIP(1, c.ip))
			assert.Equal(t, synced, maps[lpmMap].store[lpm], "the sync's value back")
			_, err = fw.AddPolicyIP(1, c.ip, tcp443, nil)
			require.NoError(t, err)
			assert.Equal(t, synced, maps[lpmMap].store[lpm], "the next install adds to the rule, port-scoped")
			assert.Contains(t, maps[portMap].store, dnsPort)
			assert.Contains(t, maps[portMap].store, rulePort)

			fw.portsMap = &failingDeletes{cappedMap: maps[ruleMapPorts], fail: failAll}
			fw.portsV6Map = &failingDeletes{cappedMap: maps[ruleMapPortsV6], fail: failAll}
			require.Error(t, fw.RemovePolicyIP(1, c.ip), "an install's port entry is read under the rule's LPM entry")
		})
	}
}
