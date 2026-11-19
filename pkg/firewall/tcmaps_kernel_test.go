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
	rand "math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/tcmaps"
)

// TestTCMapsMatchKernel checks tcmaps against the TC program it describes.
// Random rule sets around a few addresses, in both families, are written by
// UpdateAllowlistTC (the compile), followed by random AddIP host adds (the
// runtime fold through the same accumulator). Every probe packet through
// tc_egress must get the verdict tcmaps.Allows gives for the same rules with
// the adds appended. The rules mix subnets with their network address and a
// host inside them, port-scoped and all-ports rules, both actions, the
// zero-address wildcards and the DNS auto-allow. Root only, so it runs in
// make test-ci's sudo pass.
func TestTCMapsMatchKernel(t *testing.T) {
	v4 := []string{"0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24", "10.0.0.0/32", "10.0.0.2/32", "10.0.0.3/32", "10.1.0.0/16"}
	v6 := []string{"::/0", "2001:db8::/32", "2001:db8::/64", "2001:db8::/128", "2001:db8::2/128", "2001:db8:1::/48"}
	hosts := []string{"10.0.0.2", "10.0.0.3", "10.0.0.0", "2001:db8::2", "2001:db8::"}
	portSets := [][]config.Port{
		nil,
		{{Port: 53, Protocol: config.ProtocolUDP}},
		{{Port: 53, Protocol: config.ProtocolTCP}},
		{{Port: 53, Protocol: config.ProtocolAll}},
		{{Port: 443, Protocol: config.ProtocolTCP}},
		{{Port: 0, Protocol: config.ProtocolICMP}},
		{{Port: 53, Protocol: config.ProtocolUDP}, {Port: 443, Protocol: config.ProtocolTCP}},
	}
	addrs := []string{"10.0.0.2", "10.0.0.0", "10.0.0.3", "10.1.0.0", "10.2.3.4", "192.0.2.1", "2001:db8::2", "2001:db8::", "2001:db8::3", "2001:db8:1::", "2001:db9::1"}
	probes := []tcmaps.PortProto{
		{Port: 53, Proto: protoUDP},
		{Port: 53, Proto: protoTCP},
		{Port: 443, Proto: protoTCP},
		{Port: 22, Proto: protoTCP},
		{Port: 123, Proto: protoUDP},
		{Port: 0, Proto: protoICMP},
	}

	// One set of objects for every iteration, the rule maps emptied between
	// them: loading and freeing a fresh set per iteration leaves the kernel's
	// deferred program frees to pile up.
	objs, _ := loadUnspecObjs(t)
	rng := rand.New(rand.NewPCG(226, 1))
	pick := func(xs []string) string { return xs[rng.IntN(len(xs))] }
	action := func() config.Action {
		if rng.IntN(3) == 0 {
			return config.ActionDeny
		}
		return config.ActionAllow
	}
	for iter := range 1000 {
		var rules []config.Rule
		for range 1 + rng.IntN(6) {
			prefix, ports := pick(v4), portSets[rng.IntN(len(portSets))]
			if rng.IntN(3) == 0 {
				// The loader refuses an explicit ICMP port on an IPv6 rule.
				prefix = pick(v6)
				for slices.ContainsFunc(ports, func(p config.Port) bool { return p.Protocol == config.ProtocolICMP }) {
					ports = portSets[rng.IntN(len(portSets))]
				}
			}
			rules = append(rules, config.Rule{Type: config.RuleTypeCIDR, Value: prefix, Ports: ports, Action: action()})
		}
		defaultAction := config.ActionDeny
		if rng.IntN(4) == 0 {
			defaultAction = config.ActionAllow
		}
		cm := config.NewConfigManager()
		require.NoError(t, cm.LoadConfigFromRules(rules, defaultAction))
		if rng.IntN(2) == 0 {
			cm.EnsureDNSAllowed([]string{"10.0.0.2"})
		}

		clearRuleMaps(t, objs)
		fw := NewFirewall(objs.MapCidrs, objs.MapPorts, objs.MapCidrsV6, objs.MapPortsV6,
			objs.MapDefaultAction, objs.MapAuditMode, slog.New(slog.DiscardHandler))
		require.NoError(t, fw.SetDefaultAction(cm.GetDefaultAction()))
		require.NoError(t, fw.UpdateAllowlistTC(cm))

		model := cm.TCRules()
		for range rng.IntN(4) {
			ip, a, ports := pick(hosts), action(), portSets[rng.IntN(len(portSets))]
			_, err := fw.AddIP(net.ParseIP(ip), a, ports)
			require.NoError(t, err)
			host := netip.MustParseAddr(ip)
			model = append(model, tcmaps.Rule{
				Prefix: netip.PrefixFrom(host, host.BitLen()),
				Allow:  a == config.ActionAllow, Ports: config.TCPorts(ports),
			})
		}
		want := tcmaps.Compile(model)

		for _, a := range addrs {
			dst := netip.MustParseAddr(a)
			for _, p := range probes {
				if dst.Is6() && p.Proto == protoICMP {
					continue // ICMPv6 passes before the maps
				}
				ret, _, err := objs.TcEgress.Test(probePacket(dst, p))
				require.NoError(t, err)
				require.Equal(t, want.Allows(dst, p, defaultAction == config.ActionAllow), ret == unspecVerdictPass,
					"iteration %d: %s %+v\nrules %v\nmodel %+v\ndefault %s", iter, a, p, cm.GetResolvedRules(), model, defaultAction)
			}
		}
	}
}

// clearRuleMaps deletes every entry from the four rule maps.
func clearRuleMaps(t *testing.T, objs *bpf.TcBpfObjects) {
	t.Helper()
	for _, m := range []*ebpf.Map{objs.MapCidrs, objs.MapPorts, objs.MapCidrsV6, objs.MapPortsV6} {
		var keys [][]byte
		var k, v []byte
		it := m.Iterate()
		for it.Next(&k, &v) {
			keys = append(keys, slices.Clone(k))
		}
		require.NoError(t, it.Err())
		for _, key := range keys {
			require.NoError(t, m.Delete(key))
		}
	}
	requireRuleMapsEmpty(t, objs)
}

// probePacket builds an Ethernet frame carrying a TCP SYN, a UDP datagram or
// an ICMP echo request to dst.
func probePacket(dst netip.Addr, p tcmaps.PortProto) []byte {
	var l4 []byte
	switch p.Proto {
	case protoTCP:
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:], 40000)
		binary.BigEndian.PutUint16(l4[2:], p.Port)
		l4[12] = 5 << 4
		l4[13] = 0x02 // SYN
	case protoUDP:
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:], 40000)
		binary.BigEndian.PutUint16(l4[2:], p.Port)
		binary.BigEndian.PutUint16(l4[4:], 8)
	default:
		l4 = make([]byte, 8)
		l4[0] = 8 // echo request
	}
	eth := make([]byte, 14)
	if dst.Is4() {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(l4)))
		ip[8] = 64
		ip[9] = p.Proto
		copy(ip[12:16], []byte{192, 168, 1, 100})
		d := dst.As4()
		copy(ip[16:20], d[:])
		return append(append(eth, ip...), l4...)
	}
	binary.BigEndian.PutUint16(eth[12:], 0x86DD)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
	ip[6] = p.Proto
	ip[7] = 64
	copy(ip[8:24], net.ParseIP("2001:db8:ffff::1").To16())
	d := dst.As16()
	copy(ip[24:40], d[:])
	return append(append(eth, ip...), l4...)
}
