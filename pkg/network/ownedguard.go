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

package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// GuardTable names the tables that guard the container DNS addresses
// cargowall adds to lo, of each address's family: ip for ContainerDNSIPv4,
// with an arp one beside it where the kernel has the family, and ip6 for
// ContainerDNSIPv6. A guard comes and
// goes with its address (OwnedAddrs), whether or not the DNS redirect is in
// place, and is owned, like the redirect's table, by the socket that made
// it, so it dies with the process however that ends.
const GuardTable = "cargowall_guard"

// maxMasterHops bounds the walk up an interface's masters: port, bond,
// bridge, VRF is as deep as hosts stack them.
const maxMasterHops = 8

// Uplinks is what an address's guard drops on even though it may be a
// bridge, read once at startup: the interface TC attaches to (ifname) and
// each family's default-route interface, with every master above each, up
// to the top of the chain (a port's bond, the bond's bridge). What arrives
// from the LAN arrives on the top one, so a host whose uplink is bridged
// (br0, vmbr0) would otherwise admit its whole LAN: eno1 in bond0 in vmbr0,
// as Proxmox stacks them, or a default route on br100 above eth0.100.
//
// What it misses is no worse than main, whose bridge-IP listener every
// link could reach: a bridged LAN that is neither on the TC interface's
// chain nor the default route's, a bridge named br-* (OVS's br-ex), which
// the guard admits by name as the redirect's DNAT sends from it, and an
// uplink moved into a bridge mid-job.
func Uplinks(ifname string) []string {
	var uplinks []string
	seen := map[string]bool{"": true, "lo": true}
	for _, start := range append([]string{ifname}, defaultRouteLinks()...) {
		for name, hops := start, 0; !seen[name] && hops < maxMasterHops; name, hops = masterOf(name), hops+1 {
			seen[name] = true
			uplinks = append(uplinks, name)
		}
	}
	return uplinks
}

// DockerBridge reports whether the interface named name is a bridge Docker
// made, as Docker names them: docker0, or br- and the 12 lowercase hex
// characters that start a network's ID. Other bridges, br-* ones too (OVS's
// br-ex, OpenWrt's br-lan), and Proxmox's vmbr0, are not; the guard's br-*
// admission and the DNAT's br-+ match are broader on purpose.
func DockerBridge(name string) bool {
	id, ok := strings.CutPrefix(name, "br-")
	if !ok {
		return name == "docker0"
	}
	return len(id) == 12 && strings.Trim(id, "0123456789abcdef") == ""
}

// defaultRouteLinks names the interfaces each family's default route
// leaves by, as the kernel matches the route for an address on no network
// (a documentation one), policy routing included; none for a family
// without a default route.
func defaultRouteLinks() []string {
	var names []string
	for _, dst := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")} {
		replies, err := fibMatch(dst)
		if err != nil {
			continue
		}
		for _, m := range replies {
			if len(m.Data) < unix.SizeofRtMsg || m.Data[1] != 0 || m.Data[7] != unix.RTN_UNICAST {
				continue
			}
			_, oifs := routeAttrs(m.Data[unix.SizeofRtMsg:])
			for _, index := range oifs {
				if ifi, err := net.InterfaceByIndex(index); err == nil {
					names = append(names, ifi.Name)
				}
			}
		}
	}
	return names
}

// masterOf names the device the interface named name is a port of, "" for
// none or when that cannot be read. It asks rtnetlink rather than sysfs,
// which shows the network namespace that mounted it.
func masterOf(name string) string {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	// struct ifinfomsg: family, pad, type, index, flags, change.
	req := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(req[4:], uint32(ifi.Index))
	replies, err := rtnetlink(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETLINK, Flags: netlink.Request},
		Data:   req,
	})
	if err != nil || len(replies) == 0 || len(replies[0].Data) < unix.SizeofIfInfomsg {
		return ""
	}
	ad, err := netlink.NewAttributeDecoder(replies[0].Data[unix.SizeofIfInfomsg:])
	if err != nil {
		return ""
	}
	for ad.Next() {
		if ad.Type() == unix.IFLA_MASTER {
			if master, err := net.InterfaceByIndex(int(ad.Uint32())); err == nil {
				return master.Name
			}
		}
	}
	return ""
}

// guardChains is addr's guard in the table of its family. The address is
// on lo, but the kernel delivers a packet for a local address whichever
// interface it arrives on: a neighbour on the uplink could use the proxy as
// its resolver through it. So input, a filter hook, admits what arrives for
// addr only as admitted says: on lo, or on a bridge other than an uplink.
// And forward drops whatever would be forwarded to addr, which happens only
// were the address gone while cargowall runs: container DNS sent to it, by
// daemon.json or the redirect's DNAT, would then leave by the uplink, to
// whatever answers for the address there. A table of one family needs no
// family match.
func guardChains(addr netip.Addr, uplinks []string) []redirectChain {
	dst := daddr(expr.CmpOpEq, addr.AsSlice())
	if addr.Is6() {
		dst = daddr6(expr.CmpOpEq, net.IP(addr.AsSlice()))
	}
	return []redirectChain{
		{
			name: "input", kind: "filter", hook: unix.NF_INET_LOCAL_IN, priority: filterPriority,
			rules: admitted(dst, uplinks),
		},
		{
			name: "forward", kind: "filter", hook: unix.NF_INET_FORWARD, priority: filterPriority,
			rules: [][]expr.Any{slices.Concat(dst, verdict(expr.VerdictDrop))},
		},
	}
}

// arpChains is the IPv4 address's guard in the arp table. The kernel
// answers ARP for a local address on every link (arp_ignore 0), so a
// neighbour asking for 169.254.0.53 would get this host's MAC, and with a
// real holder of the address on the link, traffic meant for it. So input
// admits a request for addr as admitted says. IPv6 needs no such table:
// neighbour discovery answers only for the receiving link's own addresses.
// The table is best-effort (installGuard): the ip table is the boundary,
// and drops what arrives for addr either way.
func arpChains(addr netip.Addr, uplinks []string) []redirectChain {
	request := []expr.Any{
		// hlen and plen: an Ethernet and IPv4 request, which puts the
		// target protocol address 24 bytes in.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 4, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6, 4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 1}}, // ARPOP_REQUEST
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.AsSlice()},
	}
	return []redirectChain{
		{name: "input", kind: "filter", hook: nfARPIn, priority: filterPriority, rules: admitted(request, uplinks)},
	}
}

// admitted is a guard's rules for what match selects arriving for its
// address: dropped on an uplink; admitted on what the redirect's DNAT
// sends there from, docker0 and br-*, and on any bridge, which is how
// container DNS that names the address arrives (docker0, a br-* network, a
// network named with com.docker.network.bridge.name, a default bridge
// renamed in daemon.json, and bridges created later); and dropped on
// anything else but lo.
func admitted(match []expr.Any, uplinks []string) [][]expr.Any {
	var rules [][]expr.Any
	for _, uplink := range uplinks {
		rules = append(rules, slices.Concat(match, iifname(expr.CmpOpEq, uplink), verdict(expr.VerdictDrop)))
	}
	for _, bridge := range [][]expr.Any{
		iifname(expr.CmpOpEq, "docker0"), iifnamePrefix(expr.CmpOpEq, "br-"), iifkind(expr.CmpOpEq, "bridge"),
	} {
		rules = append(rules, slices.Concat(match, bridge, verdict(expr.VerdictAccept)))
	}
	return append(rules, slices.Concat(match, iifname(expr.CmpOpNeq, "lo"), verdict(expr.VerdictDrop)))
}

// ownedGuard is one address's guard: its tables and the sockets that made
// them.
type ownedGuard struct {
	tables []guardTable
}

// guardTable is one table of a guard and the socket that made it.
type guardTable struct {
	conn  *netlink.Conn
	fam   tableFamily
	owned bool // the kernel took the owner flag
}

// installGuard installs addr's guard, asking for its tables owned with
// ownerFlag (zero for unowned): a kernel that refuses the flag, before
// 5.12, gets them unowned, which a run that dies without removing them
// leaves until the next run's replace them. A table of the name another
// live socket owns refuses the install, and the guard's ip or ip6 table is
// installed or the guard is not. Its arp table, in family arp
// (familyARP, or one the kernel refuses when a test stands in for a kernel
// without it), is best-effort: CONFIG_NF_TABLES_ARP is a kernel option of
// its own, off by default and missing from minimal guest kernels, and ARP
// answered for the address is hygiene, not a way past the ip table. One
// that cannot be installed is logged, Info for a kernel without the family
// and Warn for anything else, and the guard goes without it.
func installGuard(addr netip.Addr, uplinks []string, ownerFlag uint32, arp tableFamily, logger *slog.Logger) (
	*ownedGuard, error,
) {
	type table struct {
		fam        tableFamily
		chains     []redirectChain
		bestEffort bool
	}
	tables := []table{{familyIP, guardChains(addr, uplinks), false}, {arp, arpChains(addr, uplinks), true}}
	if addr.Is6() {
		tables = []table{{familyIP6, guardChains(addr, uplinks), false}}
	}
	g := &ownedGuard{}
	for _, t := range tables {
		var msgs []netlink.Message
		for _, c := range t.chains {
			m, err := chainMsgs(t.fam, GuardTable, c)
			if err != nil {
				return nil, errors.Join(fmt.Errorf("nftables: %w", err), g.remove())
			}
			msgs = append(msgs, m...)
		}
		conn, owned, refused, err := installOwnedTable(t.fam, GuardTable, ownerFlag, msgs)
		if err != nil && t.bestEffort {
			noARPGuard(addr, err, logger)
			continue
		}
		if err != nil {
			return nil, errors.Join(err, g.remove())
		}
		if refused != nil {
			logger.Debug("The kernel refused an owned guard table, so it went in unowned",
				"table", t.fam.String()+" "+GuardTable, "refusal", refused)
		}
		g.tables = append(g.tables, guardTable{conn: conn, fam: t.fam, owned: owned})
	}
	return g, nil
}

// noARPGuard logs addr going without its arp table, which err kept out.
func noARPGuard(addr netip.Addr, err error, logger *slog.Logger) {
	const cost = "the IP guard still drops what arrives for it, but a neighbour asking for it by ARP gets this host's MAC"
	if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP) {
		logger.Info("The kernel has no nftables arp family (CONFIG_NF_TABLES_ARP), so the container DNS address "+
			"goes without its ARP guard: "+cost, "addr", addr, "error", err)
		return
	}
	logger.Warn("The container DNS address's ARP guard could not be installed, so it goes without one: "+cost,
		"addr", addr, "error", err)
}

// remove deletes the guard's tables and closes the sockets that made them.
// An owned table goes with its socket, so its failed delete is no error. An
// unowned one's is retried once on a new socket, and is then the error,
// unless the table is gone.
func (g *ownedGuard) remove() error {
	var errs []error
	for _, t := range g.tables {
		msg, err := delTableMsg(t.fam, GuardTable)
		if err == nil {
			err = transact(t.conn, []netlink.Message{msg})
		}
		_ = t.conn.Close()
		if err == nil || t.owned || errors.Is(err, unix.ENOENT) {
			continue
		}
		if err = deleteTable(t.fam, GuardTable); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("nftables: deleting table %s %s: %w (nft delete table %s %s)",
				t.fam, GuardTable, err, t.fam, GuardTable))
		}
	}
	g.tables = nil
	return errors.Join(errs...)
}
