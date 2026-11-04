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
	"sync"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The addresses the proxy listens on for container DNS, which cargowall adds
// to lo and the redirect sends DNS arriving on a docker bridge to. They are
// cargowall's own, unlike a bridge's address, which belongs to Docker and
// which any process can hold port 53 on. They exist before any bridge does
// and don't change with the daemon's addressing.
//
// The IPv4 one is link-local, so never routed off-host, and in the /24 that
// dynamic link-local configuration may not pick (RFC 3927 2.1). It is clear
// of what clouds, Kubernetes add-ons and CNIs use in 169.254.0.0/16. The IPv6
// one is in a unique local /48 whose global ID was drawn at random once (RFC
// 4193 3.2), clear of every fixed ULA prefix in common use. A DNAT to ::1 or
// to a link-local address from a bridge cannot work, and one to 127/8 needs
// route_localnet, which exposes the host's loopback services to every
// container.
var (
	ContainerDNSIPv4 = netip.MustParseAddr("169.254.0.53")
	ContainerDNSIPv6 = netip.MustParseAddr("fd97:d1fb:f215::53")
)

// ownedLabel marks cargowall's IPv4 address on lo, telling a run's leftover
// from the same address put there by something else: 169.254.0.53 has other
// users. IPv6 addresses carry no label, and the ULA's /48 is cargowall's
// alone, so on lo it is always a leftover.
const ownedLabel = "lo:cargowall"

// OwnedAddrs adds the container DNS addresses to lo, each with its guard
// (GuardTable), and at teardown removes the ones it added. An address left
// by a run that did not tear down is taken over, and removed in turn. Add
// and Remove may run concurrently: a forced shutdown removes from another
// goroutine while the proxy's Start adds. Remove waits for an Add in
// progress, and an Add after Remove refuses.
type OwnedAddrs struct {
	upstream netip.Addr // the DNS upstream: an owned address equal to it is refused
	uplinks  []string   // what the guards drop on though it is a bridge (Uplinks)
	logger   *slog.Logger
	// ownerFlag is the flag the guard tables are asked for with:
	// NFT_TABLE_F_OWNER, or zero when a test stands in for a kernel without
	// owned tables.
	ownerFlag uint32
	// arpFamily is the family the IPv4 address's arp table is asked for in:
	// familyARP, or one the kernel refuses when a test stands in for a
	// kernel without it.
	arpFamily tableFamily
	// deleteAddr removes an address from lo: loopbackAddr's RTM_DELADDR, or
	// a failure when a test stands in for one.
	deleteAddr func(netip.Addr) error

	mu    sync.Mutex
	added []ownedAddr
	done  bool
}

// ownedAddr is an address Add added, and its guard.
type ownedAddr struct {
	addr  netip.Addr
	guard *ownedGuard
}

// NewOwnedAddrs returns the addresses to Add, for a proxy whose upstream is
// upstream (the zero Addr for none), on a host whose uplinks are uplinks
// (Uplinks). Register its Remove first. An uplink that is a Docker bridge,
// which the guards drop on, is warned about here, once (DockerBridge): a
// default route or a TC interface there puts the guard's uplink drop ahead of
// its containers' DNS.
func NewOwnedAddrs(upstream netip.Addr, uplinks []string, logger *slog.Logger) *OwnedAddrs {
	for _, name := range uplinks {
		if DockerBridge(name) {
			logger.Warn(fmt.Sprintf("Containers on this bridge cannot resolve names: it carries the host's "+
				"default route or is the interface cargowall attaches to, so DNS arriving on it for %s and %s, "+
				"where daemon.json and the DNS redirect send it, is dropped; on that link cargowall cannot tell a "+
				"container from a LAN neighbour", ContainerDNSIPv4, ContainerDNSIPv6), "bridge", name)
		}
	}
	return &OwnedAddrs{
		upstream: upstream, uplinks: uplinks, logger: logger, ownerFlag: nftTableFOwner, arpFamily: familyARP,
		deleteAddr: func(addr netip.Addr) error { return loopbackAddr(unix.RTM_DELADDR, 0, addr, "") },
	}
}

// Add adds addr to lo, as a host route, unless something already holds it
// (holder): then it says why, and the address is not added. Nothing on the
// host may already answer for it, or the proxy's listener would take that
// over, or container DNS would be handed to that instead. Its guard goes in
// first, so the address is never there unguarded, and an address whose
// guard cannot be installed is refused too: Docker DNS interception needs
// nf_tables for it, with or without the DNS redirect. A leftover is added
// afresh, as this run would add it. An address already added is not added
// again.
func (o *OwnedAddrs) Add(addr netip.Addr) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		return errors.New("teardown has begun")
	}
	if slices.ContainsFunc(o.added, func(a ownedAddr) bool { return a.addr == addr }) {
		return nil
	}
	leftover, err := o.holder(addr)
	if err != nil {
		return err
	}
	guard, err := installGuard(addr, o.uplinks, o.ownerFlag, o.arpFamily, o.logger)
	if err != nil {
		return fmt.Errorf("its guard cannot be installed (Docker DNS interception needs nf_tables for it): %w", err)
	}
	if leftover {
		if err := o.deleteAddr(addr); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return errors.Join(err, guard.remove())
		}
	}
	if err := loopbackAddr(unix.RTM_NEWADDR, netlink.Create|netlink.Replace, addr, ownedLabel); err != nil {
		return errors.Join(err, guard.remove())
	}
	if leftover {
		o.logger.Info("Took over the container DNS address a previous run left on lo", "addr", addr)
	}
	o.added = append(o.added, ownedAddr{addr: addr, guard: guard})
	return nil
}

// Remove removes the addresses Add added, each before its guard, so none is
// there unguarded: an address that cannot be removed keeps its guard, which
// below 5.12, where the guard is unowned, outlives the process with it. An
// address already gone is no error. Safe to call more than once, and
// nil-safe.
func (o *OwnedAddrs) Remove() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.done = true
	var errs []error
	for _, a := range o.added {
		err := o.deleteAddr(a.addr)
		if err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("%w; its guard stays", err))
			continue
		}
		errs = append(errs, a.guard.remove())
	}
	o.added = nil
	return errors.Join(errs...)
}

// holder is why addr is not cargowall's to add, nil when it is. It is
// refused when it is the proxy's own upstream, which the proxy would then
// forward container DNS to itself through; when it is assigned to an
// interface, other than as cargowall's leftover on lo (leftover); and when
// a route more specific than the generic one for its range sends it
// through a link (specificRoute). It is refused too when the host's
// addresses or routes cannot be read: the fail-closed side.
func (o *OwnedAddrs) holder(addr netip.Addr) (leftover bool, err error) {
	if addr == o.upstream {
		return false, errors.New("it is the DNS upstream, so the proxy would forward container DNS to itself")
	}
	leftover, err = assigned(addr)
	if err != nil {
		return false, err
	}
	return leftover, specificRoute(addr)
}

// assigned reports whether addr is cargowall's leftover on lo, and is an
// error when it is assigned anywhere else, or on lo by something else.
func assigned(addr netip.Addr) (leftover bool, err error) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return false, fmt.Errorf("its interfaces cannot be read: %w", err)
	}
	family := byte(unix.AF_INET)
	if addr.Is6() {
		family = unix.AF_INET6
	}
	replies, err := rtnetlink(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETADDR, Flags: netlink.Request | netlink.Dump},
		Data:   []byte{family, 0, 0, 0, 0, 0, 0, 0},
	})
	if err != nil {
		return false, fmt.Errorf("its addresses cannot be read: %w", err)
	}
	for _, m := range replies {
		if len(m.Data) < unix.SizeofIfAddrmsg {
			continue
		}
		index := int(binary.NativeEndian.Uint32(m.Data[4:8]))
		have, label := ifaddrAttrs(m.Data[unix.SizeofIfAddrmsg:])
		if have != addr {
			continue
		}
		if index == lo.Index && (addr.Is6() || label == ownedLabel) {
			leftover = true
			continue
		}
		if index == lo.Index {
			return false, errors.New("it is already assigned to lo by something other than cargowall")
		}
		return false, fmt.Errorf("it is already assigned to %s", ifName(index))
	}
	return leftover, nil
}

// ifaddrAttrs reads an address message's address, the local one where it
// has both (a point-to-point link's peer is the other), and its label.
func ifaddrAttrs(b []byte) (addr netip.Addr, label string) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return netip.Addr{}, ""
	}
	var local, address netip.Addr
	for ad.Next() {
		switch ad.Type() {
		case unix.IFA_LOCAL:
			local, _ = netip.AddrFromSlice(ad.Bytes())
		case unix.IFA_ADDRESS:
			address, _ = netip.AddrFromSlice(ad.Bytes())
		case unix.IFA_LABEL:
			label = ad.String()
		}
	}
	if local.IsValid() {
		return local.Unmap(), label
	}
	return address.Unmap(), label
}

// specificRoute is an error when a route more specific than the generic one
// for addr's range sends addr through a link: a network that uses the
// address, which another host on it may hold. The generic ones are
// everything up to 169.254.0.0/16 for the IPv4 address, the link-local route
// NetworkManager and cloud images put on an uplink, and everything up to the
// ULA's random /48, exclusive, for the IPv6 one (::/0, fd00::/8, fc00::/7).
// The route is the one the kernel matches for addr (RTM_F_FIB_MATCH, which
// reports its own prefix rather than the host route a plain lookup clones),
// so policy routing is taken into account. Only a unicast route through a
// link counts: a local, blackhole, prohibit, unreachable or throw one
// leaves the address to no one, and the local route its addition makes
// wins over it; no route at all is no holder either. The kernel answers the
// lookup of all but the local one with the error the route stands for:
// EINVAL for blackhole, EACCES for prohibit, EHOSTUNREACH for unreachable,
// ENETUNREACH for throw and for none.
func specificRoute(addr netip.Addr) error {
	generic := 16
	if addr.Is6() {
		generic = 47
	}
	replies, err := fibMatch(addr)
	if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EACCES) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("its routes cannot be read: %w", err)
	}
	for _, m := range replies {
		if len(m.Data) < unix.SizeofRtMsg || m.Data[7] != unix.RTN_UNICAST || int(m.Data[1]) <= generic {
			continue
		}
		dst, oifs := routeAttrs(m.Data[unix.SizeofRtMsg:])
		prefix := netip.PrefixFrom(dst, int(m.Data[1]))
		if len(oifs) == 0 {
			return fmt.Errorf("it is routed by %s", prefix)
		}
		return fmt.Errorf("it is routed through %s by %s", ifName(oifs[0]), prefix)
	}
	return nil
}

// fibMatch is the route the kernel matches for addr, as it is configured
// (RTM_F_FIB_MATCH), rather than the host route a plain lookup clones.
func fibMatch(addr netip.Addr) ([]netlink.Message, error) {
	family := byte(unix.AF_INET)
	if addr.Is6() {
		family = unix.AF_INET6
	}
	// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
	// type, flags.
	rtm := make([]byte, unix.SizeofRtMsg)
	rtm[0], rtm[1] = family, byte(addr.BitLen())
	binary.NativeEndian.PutUint32(rtm[8:], unix.RTM_F_FIB_MATCH)
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.RTA_DST, addr.AsSlice())
	attrs, err := ae.Encode()
	if err != nil {
		return nil, err
	}
	return rtnetlink(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETROUTE, Flags: netlink.Request},
		Data:   append(rtm, attrs...),
	})
}

// routeAttrs reads a route message's destination and output interfaces:
// its one (RTA_OIF), or each of a multipath route's next hops'.
func routeAttrs(b []byte) (dst netip.Addr, oifs []int) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return netip.Addr{}, nil
	}
	for ad.Next() {
		switch ad.Type() {
		case unix.RTA_DST:
			dst, _ = netip.AddrFromSlice(ad.Bytes())
		case unix.RTA_OIF:
			oifs = append(oifs, int(ad.Uint32()))
		case unix.RTA_MULTIPATH:
			// struct rtnexthop: len, flags, hops, ifindex, then the hop's
			// attributes, to len.
			for hops := ad.Bytes(); len(hops) >= unix.SizeofRtNexthop; {
				n := int(binary.NativeEndian.Uint16(hops))
				if n < unix.SizeofRtNexthop || n > len(hops) {
					break
				}
				oifs = append(oifs, int(int32(binary.NativeEndian.Uint32(hops[4:]))))
				hops = hops[(n+3)&^3:]
			}
		}
	}
	return dst.Unmap(), oifs
}

// loopbackAddr adds (RTM_NEWADDR) or removes (RTM_DELADDR) addr on lo, as a
// host route, with label for an IPv4 address where one is given. Neither may
// become a source address the kernel picks for traffic of its own: for a
// route out of an interface with no address of its family (a Calico
// workload's cali*), it falls back to lo's, and that traffic would leave
// from an address whose guard drops the reply. So the IPv4 address is of
// host scope, which no such route takes, and the IPv6 one is deprecated
// (preferred lifetime 0, valid for ever), which source selection passes
// over for any other. Neither stops a socket bound to it from answering
// from it. An IPv6 address skips duplicate address detection, which could
// hold it tentative, unbindable, for a second or more.
func loopbackAddr(typ netlink.HeaderType, flags netlink.HeaderFlags, addr netip.Addr, label string) error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	// struct ifaddrmsg: family, prefixlen, flags, scope, index.
	ifa := make([]byte, unix.SizeofIfAddrmsg)
	ifa[0], ifa[1] = unix.AF_INET, 32
	if addr.Is6() {
		ifa[0], ifa[1], ifa[2] = unix.AF_INET6, 128, unix.IFA_F_NODAD
	}
	ifa[3] = unix.RT_SCOPE_HOST
	if addr.Is6() {
		ifa[3] = unix.RT_SCOPE_UNIVERSE // IPv6 takes its scope from the address
	}
	binary.NativeEndian.PutUint32(ifa[4:], uint32(lo.Index))
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.IFA_LOCAL, addr.AsSlice())
	ae.Bytes(unix.IFA_ADDRESS, addr.AsSlice())
	if label != "" && addr.Is4() {
		ae.String(unix.IFA_LABEL, label)
	}
	if typ == unix.RTM_NEWADDR && addr.Is6() {
		// struct ifa_cacheinfo: preferred and valid lifetimes, then the
		// timestamps the kernel keeps.
		info := make([]byte, unix.SizeofIfaCacheinfo)
		binary.NativeEndian.PutUint32(info[4:], ^uint32(0)) // INFINITY_LIFE_TIME
		ae.Bytes(unix.IFA_CACHEINFO, info)
	}
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = rtnetlink(netlink.Message{
		Header: netlink.Header{Type: typ, Flags: netlink.Request | netlink.Acknowledge | flags},
		Data:   append(ifa, attrs...),
	})
	if err != nil {
		return fmt.Errorf("rtnetlink: %s on lo: %w", addr, err)
	}
	return nil
}

// rtnetlink runs one request on a socket of its own.
func rtnetlink(msg netlink.Message) ([]netlink.Message, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.Execute(msg)
}

// ifName names interface index for a reason, by its index when it has gone.
func ifName(index int) string {
	if ifi, err := net.InterfaceByIndex(index); err == nil {
		return ifi.Name
	}
	return fmt.Sprintf("interface %d", index)
}
