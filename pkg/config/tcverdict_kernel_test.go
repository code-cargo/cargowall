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

package config_test

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	rand "math/rand/v2"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

const (
	protoICMP uint8 = 1
	protoTCP  uint8 = 6
	protoUDP  uint8 = 17

	tcActOK = 0
)

// TestTCModelMatchesKernel checks the auto-allow's verdict model against the
// TC program itself: random rule sets around one address are programmed into
// the real maps by the firewall, and every probe packet must get the verdict
// the model predicts. The rules mix subnets with their network address and a
// host inside them, port-scoped and all-ports rules, both actions, the
// 0.0.0.0/0 wildcard and the DNS auto-allow, which is where the model and a
// rule merely containing an address part ways.
func TestTCModelMatchesKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	require.NoError(t, rlimit.RemoveMemlock())

	prefixes := []string{
		"0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24",
		"10.0.0.0/32", "10.0.0.2/32", "10.0.0.3/32", "10.1.0.0/16",
	}
	portSets := [][]config.Port{
		nil,
		{{Port: 53, Protocol: config.ProtocolUDP}},
		{{Port: 53, Protocol: config.ProtocolTCP}},
		{{Port: 53, Protocol: config.ProtocolAll}},
		{{Port: 443, Protocol: config.ProtocolTCP}},
		{{Port: 0, Protocol: config.ProtocolICMP}},
		{{Port: 53, Protocol: config.ProtocolUDP}, {Port: 443, Protocol: config.ProtocolTCP}},
	}
	addrs := []string{"10.0.0.2", "10.0.0.0", "10.0.0.3", "10.1.0.0", "10.2.3.4", "192.0.2.1"}
	probes := []struct {
		port  uint16
		proto uint8
	}{{53, protoUDP}, {53, protoTCP}, {443, protoTCP}, {22, protoTCP}, {123, protoUDP}, {0, protoICMP}}

	rng := rand.New(rand.NewPCG(226, 1))
	for iter := range 1000 {
		var rules []config.Rule
		for range 1 + rng.IntN(5) {
			action := config.ActionAllow
			if rng.IntN(3) == 0 {
				action = config.ActionDeny
			}
			rules = append(rules, config.Rule{
				Type:   config.RuleTypeCIDR,
				Value:  prefixes[rng.IntN(len(prefixes))],
				Ports:  portSets[rng.IntN(len(portSets))],
				Action: action,
			})
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

		var objs bpf.TcBpfObjects
		require.NoError(t, bpf.LoadTcBpfObjects(&objs, nil))
		fw := firewall.NewFirewall(objs.MapCidrs, objs.MapPorts, objs.MapCidrsV6, objs.MapPortsV6,
			objs.MapDefaultAction, objs.MapAuditMode, slog.New(slog.DiscardHandler))
		require.NoError(t, fw.SetDefaultAction(cm.GetDefaultAction()))
		require.NoError(t, fw.UpdateAllowlistTC(cm))

		for _, a := range addrs {
			addr := netip.MustParseAddr(a)
			for _, p := range probes {
				ret, _, err := objs.TcEgress.Test(probePacket(addr, p.port, p.proto))
				require.NoError(t, err)
				want := config.TCModelAllows(cm, addr, p.port, p.proto)
				require.Equal(t, want, ret == tcActOK,
					"iteration %d: %s port %d proto %d\nrules %s\ndefault %s",
					iter, a, p.port, p.proto, fmt.Sprint(cm.GetResolvedRules()), defaultAction)
			}
		}
		objs.Close()
	}
}

// probePacket builds an Ethernet frame carrying an IPv4 TCP SYN, UDP datagram
// or ICMP echo request to dst.
func probePacket(dst netip.Addr, port uint16, proto uint8) []byte {
	var l4 []byte
	switch proto {
	case protoTCP:
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:], 40000)
		binary.BigEndian.PutUint16(l4[2:], port)
		l4[12] = 5 << 4
		l4[13] = 0x02 // SYN
	case protoUDP:
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:], 40000)
		binary.BigEndian.PutUint16(l4[2:], port)
		binary.BigEndian.PutUint16(l4[4:], 8)
	default:
		l4 = make([]byte, 8)
		l4[0] = 8 // echo request
	}
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{192, 168, 1, 100})
	d := dst.As4()
	copy(ip[16:20], d[:])
	return append(append(eth, ip...), l4...)
}
