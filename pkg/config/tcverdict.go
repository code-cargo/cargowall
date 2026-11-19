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
	"net"
	"net/netip"
)

// IANA protocol numbers, as the TC program keys its port map.
const (
	tcProtoICMP uint8 = 1
	tcProtoTCP  uint8 = 6
	tcProtoUDP  uint8 = 17
)

// tcProbe is one (port, protocol) a packet can carry. ICMP has no port, so
// its probe is always port 0.
type tcProbe struct {
	port  uint16
	proto uint8
}

type tcPortKey struct {
	addr netip.Addr
	tcProbe
}

// tcLPM is an LPM entry's value. Under portSpecific the program ignores allow
// and decides from the port map, but the firewall still compares it when it
// decides whether a host write is a no-op.
type tcLPM struct {
	allow        bool
	portSpecific bool
}

// tcHost is the accumulated all-ports state of one /32: the firewall
// package's ipPortState. Its LPM value is all-ports deny, else all-ports
// allow, else port-specific under the action of the latest contribution.
type tcHost struct {
	allPortsAllow bool
	allPortsDeny  bool
}

func (h *tcHost) lpm(allow bool) tcLPM {
	switch {
	case h.allPortsDeny:
		return tcLPM{allow: false}
	case h.allPortsAllow:
		return tcLPM{allow: true}
	}
	return tcLPM{allow: allow, portSpecific: true}
}

// tcModel is the IPv4 verdict the TC program gives under a rule set: the maps
// the firewall's UpdateAllowlistTC writes from the rules, and the lookup
// bpf/tcbpf.c makes against them. It exists so an auto-allow can tell whether
// a destination is really reachable, which a rule merely containing the
// address does not settle:
//   - the LPM trie returns only the longest matching prefix, so a narrower
//     port-specific entry shadows a broader all-ports one;
//   - a subnet's port entries are keyed by its network address but looked up
//     by the packet's destination, so they only ever answer for that one
//     address;
//   - a port-scoped 0.0.0.0/0 rule is a wildcard port entry, consulted when
//     the LPM has no match or its port-specific match has no entry;
//   - a host's first contribution looks its address up in the LPM, which
//     answers with the longest covering entry, and folds an all-ports one
//     into the host's state: a host inside an all-ports allow stays allowed
//     on every port, and one inside an all-ports deny stays denied. When the
//     host's value then equals what the lookup returned, no /32 is written.
//
// Hostname rules contribute the addresses they have resolved so far, as /32s.
// IPv6 is not modelled: the auto-allows install only IPv4 entries.
type tcModel struct {
	subnets      map[netip.Prefix]tcLPM
	hosts        map[netip.Addr]*tcHost
	installed    map[netip.Addr]tcLPM // the /32 entries written
	ports        map[tcPortKey]bool   // true = allow
	defaultAllow bool
}

func newTCModel(rules []ResolvedRule, defaultAction Action) *tcModel {
	m := &tcModel{
		subnets:      make(map[netip.Prefix]tcLPM),
		hosts:        make(map[netip.Addr]*tcHost),
		installed:    make(map[netip.Addr]tcLPM),
		ports:        make(map[tcPortKey]bool),
		defaultAllow: defaultAction == ActionAllow,
	}
	for _, r := range rules {
		allow := r.Action == ActionAllow
		probes := tcProbes(r.Ports)
		switch r.Type {
		case RuleTypeCIDR:
			if r.IPNet == nil {
				continue
			}
			addr, ok := tcAddr(r.IPNet.IP)
			if !ok {
				continue
			}
			ones, _ := r.IPNet.Mask.Size()
			if r.Value == "0.0.0.0/0" && len(probes) > 0 {
				for _, p := range probes {
					m.ports[tcPortKey{netip.IPv4Unspecified(), p}] = allow
				}
				continue
			}
			m.add(netip.PrefixFrom(addr, ones), allow, probes)
		case RuleTypeHostname:
			for _, ip := range r.IPs {
				if addr, ok := tcAddr(ip); ok {
					m.add(netip.PrefixFrom(addr, 32), allow, probes)
				}
			}
		}
	}
	return m
}

// add mirrors the firewall's addCIDRv4: a /32 goes to addHost, and a subnet
// is a direct LPM write (last write wins) with its port entries keyed by its
// network address. The unspecified address is refused as the key of a
// port-scoped subnet.
func (m *tcModel) add(prefix netip.Prefix, allow bool, probes []tcProbe) {
	addr := prefix.Addr()
	if prefix.Bits() == 32 {
		m.addHost(addr, allow, probes)
		return
	}
	if addr.IsUnspecified() && len(probes) > 0 {
		return
	}
	m.subnets[prefix] = tcLPM{allow: allow, portSpecific: len(probes) > 0}
	for _, p := range probes {
		m.ports[tcPortKey{addr, p}] = allow
	}
}

// addHost mirrors the firewall's addIPv4Locked and writePortsV4.
func (m *tcModel) addHost(addr netip.Addr, allow bool, probes []tcProbe) {
	if addr.IsUnspecified() {
		return
	}
	existing, exists := m.lookup(addr)
	h := m.hosts[addr]
	if h == nil {
		h = &tcHost{}
		if exists && !existing.portSpecific {
			if existing.allow {
				h.allPortsAllow = true
			} else {
				h.allPortsDeny = true
			}
		}
		m.hosts[addr] = h
	}
	switch {
	case len(probes) == 0:
		if allow {
			h.allPortsAllow = true
		} else {
			h.allPortsDeny = true
		}
	case h.allPortsAllow || h.allPortsDeny:
		// Inert under an all-ports grant, so never written.
	default:
		for _, p := range probes {
			m.ports[tcPortKey{addr, p}] = allow
		}
	}
	if val := h.lpm(allow); !exists || existing != val {
		m.installed[addr] = val
	}
}

// lookup is the LPM's answer for addr: its /32 if one is written, else the
// longest subnet containing it.
func (m *tcModel) lookup(addr netip.Addr) (tcLPM, bool) {
	if v, ok := m.installed[addr]; ok {
		return v, true
	}
	best, found := -1, false
	var out tcLPM
	for prefix, s := range m.subnets {
		if prefix.Bits() > best && prefix.Contains(addr) {
			best, out, found = prefix.Bits(), s, true
		}
	}
	return out, found
}

// allows is the TC program's verdict for a packet to addr carrying p.
func (m *tcModel) allows(addr netip.Addr, p tcProbe) bool {
	e, ok := m.lookup(addr)
	switch {
	case !ok:
		return m.wildcardVerdict(p)
	case !e.portSpecific:
		return e.allow
	}
	return m.portVerdict(addr, p)
}

func (m *tcModel) portVerdict(addr netip.Addr, p tcProbe) bool {
	if allow, ok := m.ports[tcPortKey{addr, p}]; ok {
		return allow
	}
	return m.wildcardVerdict(p)
}

func (m *tcModel) wildcardVerdict(p tcProbe) bool {
	if allow, ok := m.ports[tcPortKey{netip.IPv4Unspecified(), p}]; ok {
		return allow
	}
	return m.defaultAllow
}

// portDenied reports whether a deny port entry is keyed on addr for p: a rule
// for this address and port, which a later allow on the same key would
// overwrite.
func (m *tcModel) portDenied(addr netip.Addr, p tcProbe) bool {
	allow, ok := m.ports[tcPortKey{addr, p}]
	return ok && !allow
}

// probes returns every (port, protocol) whose verdict can differ at any
// address: each one a port entry names, ICMP, and one TCP and one UDP port no
// entry names, which stands in for all the others.
func (m *tcModel) probes() []tcProbe {
	seen := map[tcProbe]bool{{0, tcProtoICMP}: true}
	out := []tcProbe{{0, tcProtoICMP}}
	for k := range m.ports {
		if !seen[k.tcProbe] {
			seen[k.tcProbe] = true
			out = append(out, k.tcProbe)
		}
	}
	for _, proto := range []uint8{tcProtoTCP, tcProtoUDP} {
		for port := uint16(1); ; port++ {
			p := tcProbe{port, proto}
			if !seen[p] {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// tcProbes expands rule ports the way the firewall's expandPorts does:
// ProtocolAll becomes ICMP, TCP and UDP, and ICMP is always port 0. An empty
// result means all ports.
func tcProbes(ports []Port) []tcProbe {
	var out []tcProbe
	for _, p := range ports {
		switch p.Protocol {
		case ProtocolTCP:
			out = append(out, tcProbe{p.Port, tcProtoTCP})
		case ProtocolUDP:
			out = append(out, tcProbe{p.Port, tcProtoUDP})
		case ProtocolICMP:
			out = append(out, tcProbe{0, tcProtoICMP})
		case ProtocolAll:
			out = append(out, tcProbe{0, tcProtoICMP}, tcProbe{p.Port, tcProtoTCP}, tcProbe{p.Port, tcProtoUDP})
		}
	}
	return out
}

func tcAddr(ip net.IP) (netip.Addr, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(ip4)), true
}
