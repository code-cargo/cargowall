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

// Package tcmaps compiles a rule set into the entries bpf/tcbpf.c reads, and
// answers the verdict that program gives a packet against them. The firewall
// writes what Compile produces, and folds its runtime host adds through the
// same Host accumulator, so the compile is the one description of the maps:
// anything that needs to know what TC will decide (the infrastructure
// auto-allows) asks it rather than re-deriving the layout.
//
// The layout it encodes:
//   - The LPM trie holds one entry per prefix and returns only the longest
//     match. Its value is all-ports (decided by its action) or port-specific
//     (decided by the port map).
//   - Port entries are keyed by address, port and protocol. A subnet keys its
//     entries by its network address, but the program looks them up by the
//     packet's destination, so they only ever answer for that one address.
//   - A port-scoped 0.0.0.0/0 or ::/0 rule writes wildcard port entries at the
//     zero address, consulted when the LPM has no match or its port-specific
//     match has no entry. Nothing else may key port entries there.
//   - A host's (/32, /128) contributions accumulate (Host): an all-ports deny
//     beats an all-ports allow, and an all-ports grant beats any port-specific
//     contribution. A host's first contribution folds in the LPM's answer for
//     its address, so a host inside an all-ports allow stays allowed on every
//     port and one inside an all-ports deny stays denied.
//   - The IPv6 program passes ICMPv6 before the maps, so ICMP never reaches a
//     v6 entry (StripICMP).
package tcmaps

import (
	"net/netip"
	"slices"
)

// IANA protocol numbers, as the program keys its port maps.
const (
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// PortProto is one port entry's port and protocol. ICMP has no port, so its
// port is always 0.
type PortProto struct {
	Port  uint16
	Proto uint8
}

// Rule is one rule's contribution, in the order the rules are written.
type Rule struct {
	// Prefix is the rule's network, or a host prefix (/32, /128) for a
	// single address. IPv4 is held unmapped.
	Prefix netip.Prefix
	Allow  bool
	// Ports is empty for a rule on all ports.
	Ports []PortProto
	// Wildcard marks a port-scoped 0.0.0.0/0 or ::/0 rule, which writes the
	// any-destination port entries rather than an LPM entry.
	Wildcard bool
	// Label names the rule in Notes.
	Label string
}

// LPM is an LPM entry's value. Under PortSpecific the program ignores Allow
// and decides from the port map, but a host write still compares it to decide
// whether it is a no-op.
type LPM struct {
	Allow        bool
	PortSpecific bool
}

// PortKey is a port entry's key. The zero address is the wildcard's.
type PortKey struct {
	Addr netip.Addr
	PortProto
}

// Maps is a compiled rule set.
type Maps struct {
	// Subnets are the LPM entries for prefixes wider than a host.
	Subnets map[netip.Prefix]LPM
	// Hosts are the host accumulators. A host's LPM entry is written only
	// when Installed.
	Hosts map[netip.Addr]*Host
	// Ports are the port entries, true for allow.
	Ports map[PortKey]bool
	// Notes are the contributions the compile dropped, for the writer to log.
	Notes []Note
}

// NoteKind is why a contribution was dropped.
type NoteKind int

const (
	// NoteUnspecified: the rule's address or network is the zero address,
	// where only the wildcard may key port entries.
	NoteUnspecified NoteKind = iota
	// NoteV6ICMPOnly: an IPv6 rule naming only ICMP, which the program
	// passes before the maps.
	NoteV6ICMPOnly
	// NoteInertPorts: a port-specific contribution to a host that already
	// has an all-ports grant of the opposite action.
	NoteInertPorts
)

// Note records a dropped contribution.
type Note struct {
	Kind NoteKind
	// Label is the rule's value for a subnet, the address for a host.
	Label string
	Host  bool
	// Allow is the dropped contribution's action, Ports its ports, and
	// HostAllow the all-ports grant that made it inert (NoteInertPorts).
	Allow     bool
	HostAllow bool
	Ports     []PortProto
}

// Compile builds the maps a rule set writes, rule by rule in order, starting
// from empty maps.
func Compile(rules []Rule) *Maps {
	m := &Maps{
		Subnets: make(map[netip.Prefix]LPM),
		Hosts:   make(map[netip.Addr]*Host),
		Ports:   make(map[PortKey]bool),
	}
	for _, r := range rules {
		m.add(r)
	}
	return m
}

func (m *Maps) add(r Rule) {
	addr := r.Prefix.Addr()
	if r.Wildcard {
		zero := netip.IPv4Unspecified()
		if addr.Is6() {
			zero = netip.IPv6Unspecified()
		}
		for _, p := range r.Ports {
			m.Ports[PortKey{zero, p}] = r.Allow
		}
		return
	}
	if r.Prefix.Bits() == addr.BitLen() {
		m.addHost(addr, r.Allow, r.Ports)
		return
	}
	ports := r.Ports
	if addr.Is6() {
		var skip bool
		if ports, skip = StripICMP(ports); skip {
			m.Notes = append(m.Notes, Note{Kind: NoteV6ICMPOnly, Label: r.Label})
			return
		}
	}
	if addr.IsUnspecified() && len(ports) > 0 {
		m.Notes = append(m.Notes, Note{Kind: NoteUnspecified, Label: r.Label})
		return
	}
	m.Subnets[r.Prefix] = LPM{Allow: r.Allow, PortSpecific: len(ports) > 0}
	for _, p := range ports {
		m.Ports[PortKey{addr, p}] = r.Allow
	}
}

func (m *Maps) addHost(addr netip.Addr, allow bool, ports []PortProto) {
	if addr.IsUnspecified() {
		m.Notes = append(m.Notes, Note{Kind: NoteUnspecified, Label: addr.String(), Host: true})
		return
	}
	if addr.Is6() {
		var skip bool
		if ports, skip = StripICMP(ports); skip {
			m.Notes = append(m.Notes, Note{Kind: NoteV6ICMPOnly, Label: addr.String(), Host: true})
			return
		}
	}
	existing, exists := m.Lookup(addr)
	h := m.Hosts[addr]
	if h == nil {
		h = NewHost(existing, exists)
		m.Hosts[addr] = h
	}
	w := h.Add(allow, ports, existing, exists)
	if w.Inert {
		m.Notes = append(m.Notes, Note{
			Kind: NoteInertPorts, Label: addr.String(), Host: true,
			Allow: allow, HostAllow: !h.AllPortsDeny, Ports: ports,
		})
	}
	for _, p := range w.Ports {
		m.Ports[PortKey{addr, p}] = allow
	}
	if w.WriteLPM {
		h.LPM, h.Installed = w.LPM, true
	}
}

// Lookup is the LPM's answer for addr: its host entry if one is installed,
// else the longest subnet of its family containing it.
func (m *Maps) Lookup(addr netip.Addr) (LPM, bool) {
	if h, ok := m.Hosts[addr]; ok && h.Installed {
		return h.LPM, true
	}
	best, found := -1, false
	var out LPM
	for prefix, v := range m.Subnets {
		if prefix.Bits() > best && prefix.Addr().Is4() == addr.Is4() && prefix.Contains(addr) {
			best, out, found = prefix.Bits(), v, true
		}
	}
	return out, found
}

// Allows is the program's verdict for a packet to addr carrying p, under the
// given default action. For IPv6 it covers TCP and UDP; ICMPv6 passes before
// the maps.
func (m *Maps) Allows(addr netip.Addr, p PortProto, defaultAllow bool) bool {
	e, ok := m.Lookup(addr)
	if ok && !e.PortSpecific {
		return e.Allow
	}
	if ok {
		if allow, found := m.Ports[PortKey{addr, p}]; found {
			return allow
		}
	}
	zero := netip.IPv4Unspecified()
	if addr.Is6() {
		zero = netip.IPv6Unspecified()
	}
	if allow, found := m.Ports[PortKey{zero, p}]; found {
		return allow
	}
	return defaultAllow
}

// PortDenied reports whether a deny port entry is keyed on addr for p: a rule
// for this address and port, which a later allow on the same key would
// overwrite.
func (m *Maps) PortDenied(addr netip.Addr, p PortProto) bool {
	allow, ok := m.Ports[PortKey{addr, p}]
	return ok && !allow
}

// StripICMP removes ICMP from an IPv6 rule's ports: the v6 program passes
// ICMPv6 before the maps, so a v6 ICMP port entry is dead, and keeping it
// would leave a port-specific entry that blackholes TCP and UDP. skip reports
// a rule that named only ICMP, which installs nothing: an all-ports entry
// would broaden it to all of TCP and UDP. The input is returned unchanged
// when it holds no ICMP.
func StripICMP(ports []PortProto) (filtered []PortProto, skip bool) {
	if !slices.ContainsFunc(ports, isICMP) {
		return ports, false
	}
	filtered = slices.DeleteFunc(slices.Clone(ports), isICMP)
	return filtered, len(filtered) == 0
}

func isICMP(p PortProto) bool { return p.Proto == ProtoICMP }
