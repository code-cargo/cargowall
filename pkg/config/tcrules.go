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

package config

import (
	"log/slog"
	"net"
	"net/netip"

	"github.com/code-cargo/cargowall/pkg/tcmaps"
)

// TCRules returns the resolved rules as the TC maps' compile input, in the
// order the firewall writes them.
func (cm *Manager) TCRules() []tcmaps.Rule {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return tcRules(cm.resolvedRules)
}

// tcRules converts resolved rules for tcmaps.Compile: a CIDR rule is its
// network, a hostname rule each address it has resolved to as a host.
func tcRules(rules []ResolvedRule) []tcmaps.Rule {
	out := make([]tcmaps.Rule, 0, len(rules))
	for _, r := range rules {
		allow := r.Action == ActionAllow
		ports := TCPorts(r.Ports)
		switch r.Type {
		case RuleTypeCIDR:
			if r.IPNet == nil {
				continue // invalid CIDR, never written
			}
			ones, _ := r.IPNet.Mask.Size()
			addr, ok := tcAddr(r.IPNet.IP)
			if !ok {
				continue
			}
			out = append(out, tcmaps.Rule{
				Prefix:   netip.PrefixFrom(addr, ones),
				Allow:    allow,
				Ports:    ports,
				Wildcard: len(ports) > 0 && (r.Value == "0.0.0.0/0" || r.Value == "::/0"),
				Label:    r.Value,
			})
		case RuleTypeHostname:
			for _, ip := range r.IPs {
				if addr, ok := tcAddr(ip); ok {
					out = append(out, tcmaps.Rule{
						Prefix: netip.PrefixFrom(addr, addr.BitLen()),
						Allow:  allow,
						Ports:  ports,
						Label:  r.Value,
					})
				}
			}
		}
	}
	return out
}

// tcAddr is ip as the maps key it: IPv4 (including the IPv4-mapped form) as
// a 4-byte address, anything else as 16 bytes.
func tcAddr(ip net.IP) (netip.Addr, bool) {
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFrom4([4]byte(ip4)), true
	}
	if ip16 := ip.To16(); ip16 != nil {
		return netip.AddrFrom16([16]byte(ip16)), true
	}
	return netip.Addr{}, false
}

// TCPorts expands rule ports into port entries: ProtocolAll becomes ICMP, TCP
// and UDP, since the program looks entries up by the packet's exact
// protocol, and ICMP is always port 0. An unknown protocol is skipped with a
// warning. An empty result means all ports.
func TCPorts(ports []Port) []tcmaps.PortProto {
	if len(ports) == 0 {
		return nil
	}
	out := make([]tcmaps.PortProto, 0, len(ports)*3)
	for _, p := range ports {
		switch p.Protocol {
		case ProtocolTCP:
			out = append(out, tcmaps.PortProto{Port: p.Port, Proto: tcmaps.ProtoTCP})
		case ProtocolUDP:
			out = append(out, tcmaps.PortProto{Port: p.Port, Proto: tcmaps.ProtoUDP})
		case ProtocolICMP:
			out = append(out, tcmaps.PortProto{Port: 0, Proto: tcmaps.ProtoICMP})
		case ProtocolAll:
			out = append(out,
				tcmaps.PortProto{Port: 0, Proto: tcmaps.ProtoICMP},
				tcmaps.PortProto{Port: p.Port, Proto: tcmaps.ProtoTCP},
				tcmaps.PortProto{Port: p.Port, Proto: tcmaps.ProtoUDP})
		default:
			slog.Warn("Unknown protocol in port rule, skipping", "port", p.Port, "protocol", p.Protocol)
		}
	}
	return out
}
