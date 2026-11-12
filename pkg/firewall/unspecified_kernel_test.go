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

const (
	unspecVerdictPass = 0 // TC_ACT_OK
	unspecVerdictDrop = 2 // TC_ACT_SHOT
)

var unspecAddrs = []string{"0.0.0.0", "::ffff:0.0.0.0", "::"}

func loadUnspecObjs(t *testing.T) (*bpf.TcBpfObjects, Firewall) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	var objs bpf.TcBpfObjects
	require.NoError(t, bpf.LoadTcBpfObjects(&objs, nil))
	t.Cleanup(func() { objs.Close() })
	fw := NewFirewall(objs.MapCidrs, objs.MapPorts, objs.MapCidrsV6, objs.MapPortsV6,
		objs.MapDefaultAction, objs.MapAuditMode, slog.New(slog.DiscardHandler))
	return &objs, fw
}

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

// TestUnspecifiedHost_Verdict: AddIP of the unspecified address installs
// nothing, so every destination keeps the verdict the rest of the policy
// gives it, in both families and the v4-mapped spelling.
func TestUnspecifiedHost_Verdict(t *testing.T) {
	tcp443 := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	for _, addr := range unspecAddrs {
		for _, tt := range []struct {
			name   string
			def    config.Action
			action config.Action
			want   uint32
		}{
			{"allow under default deny", config.ActionDeny, config.ActionAllow, unspecVerdictDrop},
			{"deny under default allow", config.ActionAllow, config.ActionDeny, unspecVerdictPass},
		} {
			t.Run(addr+" "+tt.name, func(t *testing.T) {
				objs, fw := loadUnspecObjs(t)
				require.NoError(t, fw.SetDefaultAction(tt.def))
				changed, err := fw.AddIP(net.ParseIP(addr), tt.action, tcp443)
				require.NoError(t, err)
				for _, dst := range []string{"93.184.216.34", "2606:2800:220:1::1"} {
					ret, _, err := objs.TcEgress.Test(unspecSYN(t, dst, 443))
					require.NoError(t, err)
					require.Equal(t, tt.want, ret, "%s:443", dst)
				}
				require.False(t, changed)
				requireRuleMapsEmpty(t, objs)
			})
		}
	}
}

// TestUnspecifiedNetwork_SyncVerdict covers the sync: the host and
// zero-network spellings a load drops never reach the maps, and the DNS
// auto-allow at the zero address installs no wildcard.
func TestUnspecifiedNetwork_SyncVerdict(t *testing.T) {
	tcp443 := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	for _, tt := range []struct {
		name  string
		rules []config.Rule
		dns   []string
	}{
		{"host spellings", []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "0.0.0.0/32", Ports: tcp443, Action: config.ActionAllow},
			{Type: config.RuleTypeCIDR, Value: "::/128", Ports: tcp443, Action: config.ActionAllow},
		}, nil},
		{"zero networks", []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "0.0.0.0/1", Ports: tcp443, Action: config.ActionAllow},
			{Type: config.RuleTypeCIDR, Value: "0.0.0.0/31", Ports: tcp443, Action: config.ActionAllow},
			{Type: config.RuleTypeCIDR, Value: "::/1", Ports: tcp443, Action: config.ActionAllow},
			{Type: config.RuleTypeCIDR, Value: "::/127", Ports: tcp443, Action: config.ActionAllow},
		}, nil},
		{"DNS auto-allow", nil, []string{"0.0.0.0", "::"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objs, fw := loadUnspecObjs(t)
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfigFromRules(tt.rules, config.ActionDeny))
			if tt.dns != nil {
				cm.EnsureDNSAllowed(tt.dns)
			}
			require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
			require.NoError(t, fw.UpdateAllowlistTC(cm))
			for _, dst := range []string{"1.2.3.4", "200.1.2.3", "2001:db8::1", "2606:2800:220:1::1"} {
				ret, _, err := objs.TcEgress.Test(unspecSYN(t, dst, 443))
				require.NoError(t, err)
				require.Equal(t, uint32(unspecVerdictDrop), ret, "%s:443", dst)
			}
			requireRuleMapsEmpty(t, objs)
		})
	}
}

// TestUnspecifiedNetwork_NonZeroSubnetUnchanged: this release's port-scoped
// subnets are keyed by their network, so a non-zero one is left exactly as it
// was. Dropping the zero networks must not touch that behaviour.
func TestUnspecifiedNetwork_NonZeroSubnetUnchanged(t *testing.T) {
	objs, fw := loadUnspecObjs(t)
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8", Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow},
	}, config.ActionDeny))
	require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
	require.NoError(t, fw.UpdateAllowlistTC(cm))
	var val bpf.TcBpfLpmVal
	require.NoError(t, objs.MapCidrs.Lookup(&bpf.TcBpfLpmKey{Prefixlen: 8, Ip: binary.NativeEndian.Uint32(net.ParseIP("10.0.0.0").To4())}, &val))
	var pv bpf.TcBpfPortVal
	require.NoError(t, objs.MapPorts.Lookup(&bpf.TcBpfPortKey{Ip: binary.NativeEndian.Uint32(net.ParseIP("10.0.0.0").To4()), Port: 443, Proto: 6}, &pv))
}

// TestUnspecifiedHost_RemoveIPKeepsWildcard: the job's any-destination port
// entries survive installs and a removal at the unspecified address.
func TestUnspecifiedHost_RemoveIPKeepsWildcard(t *testing.T) {
	tcp443 := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	for _, addr := range unspecAddrs {
		t.Run(addr, func(t *testing.T) {
			objs, fw := loadUnspecObjs(t)
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
				{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: tcp443, Action: config.ActionAllow},
				{Type: config.RuleTypeCIDR, Value: "::/0", Ports: tcp443, Action: config.ActionAllow},
			}, config.ActionDeny))
			require.NoError(t, fw.SetDefaultAction(config.ActionDeny))
			require.NoError(t, fw.UpdateAllowlistTC(cm))

			ip := net.ParseIP(addr)
			_, err := fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 22, Protocol: config.ProtocolTCP}})
			require.NoError(t, err)
			_, err = fw.AddIP(ip, config.ActionDeny, tcp443)
			require.NoError(t, err)
			require.NoError(t, fw.RemoveIP(ip))

			for _, dst := range []string{"93.184.216.34", "2606:2800:220:1::1"} {
				ret, _, err := objs.TcEgress.Test(unspecSYN(t, dst, 443))
				require.NoError(t, err)
				require.Equal(t, uint32(unspecVerdictPass), ret, "%s:443 after removal", dst)
				ret, _, err = objs.TcEgress.Test(unspecSYN(t, dst, 22))
				require.NoError(t, err)
				require.Equal(t, uint32(unspecVerdictDrop), ret, "%s:22 after removal", dst)
			}
		})
	}
}

// unspecSYN builds an Ethernet frame carrying a TCP SYN to dst:port.
func unspecSYN(t *testing.T, dst string, port uint16) []byte {
	t.Helper()
	ip := net.ParseIP(dst)
	require.NotNil(t, ip, dst)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], port)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
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
