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
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// unspecifiedAddrs are the unspecified address in each spelling a writer can
// be handed: IPv4, IPv4-mapped IPv6 (which the writers take as IPv4), and
// IPv6.
var unspecifiedAddrs = []string{"0.0.0.0", "::ffff:0.0.0.0", "::"}

// TestUnspecifiedHost_Verdict: a host entry's port entries are keyed where
// the verdict reads the any-destination wildcard when the host is the zero
// address. The writers refuse it, so every destination of either family keeps
// the verdict the rest of the policy gives it, and nothing is written.
func TestUnspecifiedHost_Verdict(t *testing.T) {
	requireRootBPF(t)

	for _, addr := range unspecifiedAddrs {
		for _, tt := range []struct {
			name   string
			def    config.Action
			action config.Action
			ports  []config.Port
			want   uint32
		}{
			{"allow on one port under default deny", config.ActionDeny, config.ActionAllow, tcp443, verdictDrop},
			{"deny on one port under default allow", config.ActionAllow, config.ActionDeny, tcp443, verdictPass},
			{"allow on all ports under default deny", config.ActionDeny, config.ActionAllow, nil, verdictDrop},
		} {
			t.Run(addr+" "+tt.name, func(t *testing.T) {
				objs, fw := loadSizedObjects(t, false, false)
				require.NoError(t, fw.SetDefaultAction(tt.def))
				changed, err := fw.AddIP(net.ParseIP(addr), tt.action, tt.ports)
				require.NoError(t, err)
				assert.False(t, changed)
				for _, dst := range []string{"93.184.216.34", "2606:2800:220:1::1"} {
					ret, _, err := objs.CwTcEgress.Test(tcpSYN(t, dst, 443))
					require.NoError(t, err)
					require.Equal(t, tt.want, ret, "%s port 443", dst)
				}
				requireRuleMapsEmpty(t, objs)
			})
		}
	}
}

// TestUnspecifiedHost_SyncVerdict covers the sync's /32 and /128 writes: a
// static rule without ports, which a load accepts, and the DNS
// infrastructure auto-allow, which reaches the sync without a load's
// validation and carries port 53.
func TestUnspecifiedHost_SyncVerdict(t *testing.T) {
	requireRootBPF(t)

	for _, tt := range []struct {
		name  string
		rules []config.Rule
		dns   []string
	}{
		{"static rules without ports", []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "0.0.0.0/32", Action: config.ActionAllow},
			{Type: config.RuleTypeCIDR, Value: "::/128", Action: config.ActionAllow},
		}, nil},
		{"DNS infrastructure auto-allow", []config.Rule{}, []string{"0.0.0.0", "::"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objs, fw := loadSizedObjects(t, false, false)
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfigFromRules(tt.rules, config.ActionDeny))
			if tt.dns != nil {
				cm.EnsureDNSAllowed(tt.dns)
			}
			require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
			require.NoError(t, fw.UpdateAllowlistTC(cm))
			for _, dst := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
				ret, _, err := objs.CwTcEgress.Test(udpDatagram(t, dst, 53))
				require.NoError(t, err)
				require.Equal(t, uint32(verdictDrop), ret, "%s udp 53", dst)
				ret, _, err = objs.CwTcEgress.Test(tcpSYN(t, dst, 443))
				require.NoError(t, err)
				require.Equal(t, uint32(verdictDrop), ret, "%s tcp 443", dst)
			}
			requireRuleMapsEmpty(t, objs)
		})
	}
}

// TestZeroAddressSubnet_Verdict: a subnet's port entries are keyed with its
// host bits, so a subnet starting at the zero address is not the
// any-destination wildcard and keeps its ports to itself.
func TestZeroAddressSubnet_Verdict(t *testing.T) {
	requireRootBPF(t)

	objs, fw := loadSizedObjects(t, false, false)
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "0.0.0.0/8", Ports: tcp443, Action: config.ActionAllow},
		{Type: config.RuleTypeCIDR, Value: "::/96", Ports: tcp443, Action: config.ActionAllow},
	}, config.ActionDeny))
	require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	for _, p := range []verdictProbe{
		{"0.1.2.3", 443, verdictPass},
		{"93.184.216.34", 443, verdictDrop},
		{"::102:304", 443, verdictPass},
		{"2606:2800:220:1::1", 443, verdictDrop},
	} {
		ret, _, err := objs.CwTcEgress.Test(tcpSYN(t, p.dst, p.port))
		require.NoError(t, err)
		require.Equal(t, p.want, ret, "%s port %d", p.dst, p.port)
	}
}

// TestUnspecifiedHost_StepPolicy: a step's DNS install at the unspecified
// address is refused before it is charged, scoped or written, and taking it
// out leaves the step's own wildcard port entries, which share the keys a
// host entry there would have, in place.
func TestUnspecifiedHost_StepPolicy(t *testing.T) {
	requireRootBPF(t)

	const policyA = 1
	tcp9000 := []config.Port{{Port: 9000, Protocol: config.ProtocolTCP}}
	objs, fw := loadStepRulesObjects(t, true)
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfig(writeStepConfig(t, nil, []config.StepConfig{{ID: "a", Rules: []config.Rule{
		{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: tcp9000},
		{Type: config.RuleTypeCIDR, Value: "::/0", Ports: tcp9000},
	}}})))
	require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	impl := fw.(*FirewallImpl)
	charged := ledgerSizes(impl)

	for _, addr := range unspecifiedAddrs {
		scoped := false
		changed, err := fw.AddPolicyIP(policyA, net.ParseIP(addr), tcp443, func() error {
			scoped = true
			return nil
		})
		require.NoError(t, err, addr)
		assert.False(t, changed, addr)
		assert.False(t, scoped, "%s scoped", addr)
		assert.Equal(t, charged, ledgerSizes(impl), "%s charged", addr)
		require.NoError(t, fw.RemovePolicyIP(policyA, net.ParseIP(addr)), addr)
		assert.Equal(t, charged, ledgerSizes(impl), "%s uncharged", addr)
	}

	var val bpf.TcBpfPortVal
	require.NoError(t, objs.MapPorts.Lookup(bpf.RulePortKey(policyA, 0, 9000, protoTCP, 0), &val))
	require.Equal(t, uint8(1), val.Action)
	require.NoError(t, objs.MapPortsV6.Lookup(bpf.RulePortKeyV6(policyA, [16]byte{}, 9000, protoTCP, 0), &val))
	require.Equal(t, uint8(1), val.Action)
	require.ErrorIs(t, objs.MapPorts.Lookup(bpf.RulePortKey(policyA, 0, 443, protoTCP, 0), &val), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, objs.MapPortsV6.Lookup(bpf.RulePortKeyV6(policyA, [16]byte{}, 443, protoTCP, 0), &val), ebpf.ErrKeyNotExist)
}

// TestUnspecifiedHost_StepSyncRule: a step's own rule for the unspecified
// address, which loads without ports, is refused before the step is charged
// for it, so the step holds exactly what it would without the rule.
func TestUnspecifiedHost_StepSyncRule(t *testing.T) {
	requireRootBPF(t)

	charged := func(rules ...config.Rule) [numRuleMaps]int {
		_, fw := loadStepRulesObjects(t, true)
		cm := config.NewConfigManager()
		require.NoError(t, cm.LoadConfig(writeStepConfig(t, nil, []config.StepConfig{{ID: "a", Rules: rules}})))
		require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
		require.NoError(t, fw.UpdateAllowlistTC(cm))
		return ledgerSizes(fw.(*FirewallImpl))
	}
	subnet := config.Rule{Type: config.RuleTypeCIDR, Value: "10.61.0.0/24", Ports: tcp443}
	assert.Equal(t, charged(subnet), charged(subnet,
		config.Rule{Type: config.RuleTypeCIDR, Value: "0.0.0.0/32"},
		config.Rule{Type: config.RuleTypeCIDR, Value: "::/128"},
	))
}

// TestUnspecifiedHost_RemoveIPKeepsWildcard: the job's any-destination port
// entries survive installs and a removal at the unspecified address.
func TestUnspecifiedHost_RemoveIPKeepsWildcard(t *testing.T) {
	requireRootBPF(t)

	for _, addr := range unspecifiedAddrs {
		t.Run(addr, func(t *testing.T) {
			objs, fw := loadSizedObjects(t, false, false)
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
				{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: tcp443, Action: config.ActionAllow},
				{Type: config.RuleTypeCIDR, Value: "::/0", Ports: tcp443, Action: config.ActionAllow},
			}, config.ActionDeny))
			require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
			require.NoError(t, fw.UpdateAllowlistTC(cm))

			ip := net.ParseIP(addr)
			for _, step := range []struct {
				name string
				do   func() error
			}{
				{"allow on 22", func() error {
					_, err := fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 22, Protocol: config.ProtocolTCP}})
					return err
				}},
				{"deny on 443", func() error { _, err := fw.AddIP(ip, config.ActionDeny, tcp443); return err }},
				{"removal", func() error { return fw.RemoveIP(ip) }},
			} {
				require.NoError(t, step.do(), step.name)
				for _, dst := range []string{"93.184.216.34", "2606:2800:220:1::1"} {
					for port, want := range map[uint16]uint32{443: verdictPass, 22: verdictDrop} {
						ret, _, err := objs.CwTcEgress.Test(tcpSYN(t, dst, port))
						require.NoError(t, err)
						require.Equal(t, want, ret, "%s port %d after the %s", dst, port, step.name)
					}
				}
			}
		})
	}
}

// TestUnspecifiedHost_CachedAnswer: a port-scoped hostname rule whose cached
// answers are the unspecified address installs nothing at the sync, and the
// job's any-destination port entries stay as they were.
func TestUnspecifiedHost_CachedAnswer(t *testing.T) {
	requireRootBPF(t)

	objs, fw := loadSizedObjects(t, false, false)
	cm := config.NewConfigManager()
	rules := []config.Rule{
		{Type: config.RuleTypeHostname, Value: "example.com", Ports: []config.Port{{Port: 22, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow},
		{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: tcp443, Action: config.ActionAllow},
		{Type: config.RuleTypeCIDR, Value: "::/0", Ports: tcp443, Action: config.ActionAllow},
	}
	require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "0.0.0.0")
	cm.UpdateDNSMapping("example.com", "::")
	// A load resolves the rule against what the cache holds.
	require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionDeny))
	var cached []string
	for _, r := range cm.GetResolvedRules() {
		for _, ip := range r.IPs {
			cached = append(cached, ip.String())
		}
	}
	require.ElementsMatch(t, []string{"0.0.0.0", "::"}, cached)
	require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
	require.NoError(t, fw.UpdateAllowlistTC(cm))

	for _, dst := range []string{"93.184.216.34", "2606:2800:220:1::1"} {
		for port, want := range map[uint16]uint32{443: verdictPass, 22: verdictDrop} {
			ret, _, err := objs.CwTcEgress.Test(tcpSYN(t, dst, port))
			require.NoError(t, err)
			require.Equal(t, want, ret, "%s port %d", dst, port)
		}
	}
	var val bpf.TcBpfLpmVal
	require.ErrorIs(t, objs.MapCidrs.Lookup(bpf.RuleKey(bpf.PolicyJob, 32, 0), &val), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, objs.MapCidrsV6.Lookup(bpf.RuleKeyV6(bpf.PolicyJob, 128, [16]byte{}), &val), ebpf.ErrKeyNotExist)
}

// TestUnspecifiedHost_WarnsOncePerAddress: each refused address is logged
// once, however often and under whichever policy it comes back.
func TestUnspecifiedHost_WarnsOncePerAddress(t *testing.T) {
	var logs bytes.Buffer
	fw, maps := newStepTestFirewall(ruleMapEntries, slog.New(slog.NewTextHandler(&logs, nil)))
	for range 2 {
		for _, addr := range unspecifiedAddrs {
			_, err := fw.AddIP(net.ParseIP(addr), config.ActionAllow, tcp443)
			require.NoError(t, err)
			_, err = fw.AddPolicyIP(1, net.ParseIP(addr), tcp443, nil)
			require.NoError(t, err)
		}
	}
	assert.Equal(t, [numRuleMaps]int{}, storeSizes(maps))
	out := logs.String()
	assert.Equal(t, 2, strings.Count(out, "level=WARN"), out)
	assert.Equal(t, 1, strings.Count(out, "ip=0.0.0.0 "), out)
	assert.Equal(t, 1, strings.Count(out, "ip=:: "), out)
}

// TestRemoveIP_ZeroAddress_DeletesNothing: RemoveIP leaves the zero address
// alone even if port state were somehow recorded for it, so the
// any-destination wildcard's entries, which share its key, are never deleted.
func TestRemoveIP_ZeroAddress_DeletesNothing(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "::"} {
		fw, mocks := newTestFirewall()
		fw.ipPorts[addr] = &ipPortState{ports: []portProto{{Port: 443, Proto: protoTCP}}}
		require.NoError(t, fw.RemoveIP(net.ParseIP(addr)))
		for _, name := range []string{"cidrs", "ports", "cidrsV6", "portsV6"} {
			assert.Empty(t, mocks[name].deletes, "%s: map_%s deleted a key", addr, name)
		}
		assert.Contains(t, fw.ipPorts, addr, "%s: state untouched", addr)
	}
}

// requireRuleMapsEmpty fails if any of the four rule maps holds an entry.
func requireRuleMapsEmpty(t *testing.T, objs *bpf.TcBpfObjects) {
	t.Helper()
	for name, m := range map[string]*ebpf.Map{
		"cidrs": objs.MapCidrs, "ports": objs.MapPorts, "cidrs_v6": objs.MapCidrsV6, "ports_v6": objs.MapPortsV6,
	} {
		var k, v []byte
		it := m.Iterate()
		require.False(t, it.Next(&k, &v), "map_%s holds an entry", name)
		require.NoError(t, it.Err())
	}
}

// ledgerSizes counts the keys the step ledger holds in each rule map.
func ledgerSizes(f *FirewallImpl) (out [numRuleMaps]int) {
	for m := range numRuleMaps {
		out[m] = len(f.steps.keys[m])
	}
	return out
}

// udpDatagram builds an Ethernet frame carrying an empty UDP datagram to
// dst:port.
func udpDatagram(t *testing.T, dst string, port uint16) []byte {
	t.Helper()
	frame := tcpSYN(t, dst, port)
	l3 := 14 + 20
	if net.ParseIP(dst).To4() == nil {
		l3 = 14 + 40
		frame[14+6] = 17
		binary.BigEndian.PutUint16(frame[14+4:], 8)
	} else {
		frame[14+9] = 17
		binary.BigEndian.PutUint16(frame[14+2:], 20+8)
	}
	frame = frame[:l3+8]
	binary.BigEndian.PutUint16(frame[l3+4:], 8)
	return frame
}
