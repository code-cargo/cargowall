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

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

const (
	verdictPass = 0 // TC_ACT_OK
	verdictDrop = 2 // TC_ACT_SHOT
)

type verdictProbe struct {
	dst  string
	port uint16
	want uint32
}

// TestUpdateAllowlistTC_Verdict drives policy through the real writer into
// the real TC maps and reads the decision back from tc_egress. The mock-map
// tests above pin which entries get written and bpf/ pins how the verdict
// reads hand-written entries; this is the seam between them, where a subnet
// rule's port entries were once keyed where the verdict never looked —
// allowing nothing inside the subnet and, under a default allow, denying
// nothing either.
func TestUpdateAllowlistTC_Verdict(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	require.NoError(t, rlimit.RemoveMemlock())

	tcp443 := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	tests := []struct {
		name   string
		def    config.Action
		rules  []config.Rule
		probes []verdictProbe
	}{
		{
			name:  "IPv4 subnet allow on one port",
			def:   config.ActionDeny,
			rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.0.0.0/24", Ports: tcp443, Action: config.ActionAllow}},
			probes: []verdictProbe{
				{"10.0.0.0", 443, verdictPass},
				{"10.0.0.5", 443, verdictPass},
				{"10.0.0.255", 443, verdictPass},
				{"10.0.0.5", 22, verdictDrop},
				{"10.0.1.5", 443, verdictDrop},
			},
		},
		{
			name:  "IPv4 subnet deny on one port under default allow",
			def:   config.ActionAllow,
			rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.0.0.0/24", Ports: tcp443, Action: config.ActionDeny}},
			probes: []verdictProbe{
				{"10.0.0.5", 443, verdictDrop},
				{"10.0.0.5", 22, verdictPass},
				{"10.0.1.5", 443, verdictPass},
			},
		},
		{
			name:  "IPv4 subnet allow on all ports",
			def:   config.ActionDeny,
			rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.0.0.0/24", Action: config.ActionAllow}},
			probes: []verdictProbe{
				{"10.0.0.5", 443, verdictPass},
				{"10.0.0.5", 22, verdictPass},
				{"10.0.1.5", 443, verdictDrop},
			},
		},
		{
			name:  "IPv4 host route allow on one port",
			def:   config.ActionDeny,
			rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "10.0.0.5/32", Ports: tcp443, Action: config.ActionAllow}},
			probes: []verdictProbe{
				{"10.0.0.5", 443, verdictPass},
				{"10.0.0.5", 22, verdictDrop},
				{"10.0.0.6", 443, verdictDrop},
			},
		},
		{
			name: "IPv4 subnets sharing a network address keep their own ports",
			def:  config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeCIDR, Value: "10.0.0.0/16", Ports: []config.Port{{Port: 8443, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow},
				{Type: config.RuleTypeCIDR, Value: "10.0.0.0/24", Ports: tcp443, Action: config.ActionAllow},
			},
			probes: []verdictProbe{
				{"10.0.0.5", 443, verdictPass},
				{"10.0.0.5", 8443, verdictDrop}, // the /24 is the match, and it lists only 443
				{"10.0.9.5", 8443, verdictPass},
				{"10.0.9.5", 443, verdictDrop},
			},
		},
		{
			name:  "IPv6 subnet allow on one port",
			def:   config.ActionDeny,
			rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "2001:db8:1::/48", Ports: tcp443, Action: config.ActionAllow}},
			probes: []verdictProbe{
				{"2001:db8:1::", 443, verdictPass},
				{"2001:db8:1:ffff::5", 443, verdictPass},
				{"2001:db8:1:ffff::5", 22, verdictDrop},
				{"2001:db8:2::5", 443, verdictDrop},
			},
		},
		{
			name:  "IPv6 subnet allow on one port, prefix inside the low half",
			def:   config.ActionDeny,
			rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "2001:db8:1:2:3::/80", Ports: tcp443, Action: config.ActionAllow}},
			probes: []verdictProbe{
				{"2001:db8:1:2:3:ffff:ffff:ffff", 443, verdictPass},
				{"2001:db8:1:2:3:ffff:ffff:ffff", 22, verdictDrop},
				{"2001:db8:1:2:4::1", 443, verdictDrop},
			},
		},
		{
			name:  "IPv6 subnet deny on one port under default allow",
			def:   config.ActionAllow,
			rules: []config.Rule{{Type: config.RuleTypeCIDR, Value: "2001:db8:1::/48", Ports: tcp443, Action: config.ActionDeny}},
			probes: []verdictProbe{
				{"2001:db8:1:ffff::5", 443, verdictDrop},
				{"2001:db8:1:ffff::5", 22, verdictPass},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs bpf.TcBpfObjects
			require.NoError(t, bpf.LoadTcBpfObjects(&objs, nil))
			t.Cleanup(func() { objs.Close() })

			fw := NewFirewall(objs.MapCidrs, objs.MapPorts, objs.MapCidrsV6, objs.MapPortsV6,
				objs.MapDefaultAction, objs.MapAuditMode, slog.New(slog.DiscardHandler))
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfigFromRules(tt.rules, tt.def))
			require.NoError(t, fw.SetDefaultAction(tt.def))
			require.NoError(t, fw.UpdateAllowlistTC(cm))

			for _, p := range tt.probes {
				ret, _, err := objs.TcEgress.Test(tcpSYN(t, p.dst, p.port))
				require.NoError(t, err)
				require.Equal(t, p.want, ret, "%s port %d", p.dst, p.port)
			}
		})
	}
}

// tcpSYN builds an Ethernet frame carrying a TCP SYN to dst:port.
func tcpSYN(t *testing.T, dst string, port uint16) []byte {
	t.Helper()
	ip := net.ParseIP(dst)
	require.NotNil(t, ip, dst)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], port)
	tcp[12] = 5 << 4 // data offset
	tcp[13] = 0x02   // SYN

	eth := make([]byte, 14)
	if ip4 := ip.To4(); ip4 != nil {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		hdr := make([]byte, 20)
		hdr[0] = 0x45
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(hdr)+len(tcp)))
		hdr[8] = 64
		hdr[9] = 6
		copy(hdr[12:16], net.IPv4(192, 168, 1, 100).To4())
		copy(hdr[16:20], ip4)
		return append(append(eth, hdr...), tcp...)
	}
	binary.BigEndian.PutUint16(eth[12:], 0x86DD)
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:], uint16(len(tcp)))
	hdr[6] = 6
	hdr[7] = 64
	copy(hdr[8:24], net.ParseIP("2001:db8:ffff::1").To16())
	copy(hdr[24:40], ip.To16())
	return append(append(eth, hdr...), tcp...)
}
