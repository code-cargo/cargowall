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
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The guard admits container DNS on any bridge, whatever it is named: one a
// network names with com.docker.network.bridge.name, or a default bridge
// renamed in daemon.json, as much as docker0 and br-*. An uplink is dropped
// though it is a bridge, and so is anything that is not one.
func TestOwnedAddrs_GuardAdmitsBridgesButUplinks(t *testing.T) {
	enterNetns(t)
	type link struct {
		port      *os.File // the tap whose frames the bridge receives
		mac       net.HardwareAddr
		src, src6 net.IP
	}
	peer := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	// bridged is a bridge with a tap for its port, which delivers to the
	// bridge's own address: a control that frames pass the port.
	bridged := func(bridge, port string, n byte) link {
		newBridge(t, bridge)
		tap := addTunTap(t, port, nil, unix.IFF_TAP)
		enslave(t, port, bridge)
		own := netip.AddrFrom4([4]byte{10, 60, n, 1})
		setAddr(t, netip.PrefixFrom(own, 24), netip.Addr{}, bridge, "")
		setAddr(t, netip.MustParsePrefix(fmt.Sprintf("fd60:%d::1/64", n)), netip.Addr{}, bridge, "")
		ifi, err := net.InterfaceByName(bridge)
		require.NoError(t, err)
		c := link{tap, ifi.HardwareAddr, net.IPv4(10, 60, n, 2), net.ParseIP(fmt.Sprintf("fd60:%d::2", n))}
		l := listenUDP(t, netip.AddrPortFrom(own, 5300).String())
		got := ""
		for deadline := time.Now().Add(arrives); got == "" && time.Now().Before(deadline); {
			_, err := tap.Write(ether(c.mac, peer, 0x0800, udp4(c.src, own.AsSlice(), 5000, 5300, "control")))
			require.NoError(t, err)
			got, _ = received(t, l, absent)
		}
		require.Equal(t, "control", got, "%s must deliver to its own address", bridge)
		return c
	}
	custom := bridged("custom0", "tap0", 1) // com.docker.network.bridge.name=custom0
	uplink := bridged("br0", "tap1", 2)     // a host whose uplink is bridged
	plain := addTun(t, "cw0", net.IPv4(10, 56, 0, 1))
	assert.Equal(t, []string{"tap1", "br0"}, Uplinks("tap1"), "a bridge port's bridge is an uplink too")
	assert.Equal(t, []string{"cw0"}, Uplinks("cw0"))
	assert.Empty(t, Uplinks("lo"))

	owned := NewOwnedAddrs(netip.Addr{}, []string{"br0"}, discardLogger())
	t.Cleanup(func() { _ = owned.Remove() })
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, owned.Add(addr))
	}
	l, l6 := listenUDP(t, containerAddr(ContainerDNSIPv4)), listenUDP(t, containerAddr(ContainerDNSIPv6))
	v4, v6 := net.IP(ContainerDNSIPv4.AsSlice()), net.IP(ContainerDNSIPv6.AsSlice())
	for _, c := range []struct {
		name  string
		link  link
		admit bool
	}{{"custom0", custom, true}, {"br0, the uplink", uplink, false}} {
		wait := map[bool]time.Duration{true: arrives, false: absent}[c.admit]
		_, err := c.link.port.Write(ether(c.link.mac, peer, 0x0800, udp4(c.link.src, v4, 5000, 53, c.name)))
		require.NoError(t, err)
		got, _ := received(t, l, wait)
		assert.Equal(t, c.admit, got == c.name, "%s: IPv4 admitted", c.name)
		_, err = c.link.port.Write(ether(c.link.mac, peer, 0x86dd, udp6(c.link.src6, v6, 5000, 53, c.name+"6")))
		require.NoError(t, err)
		got, _ = received(t, l6, wait)
		assert.Equal(t, c.admit, got == c.name+"6", "%s: IPv6 admitted", c.name)
	}
	_, err := plain.Write(udp4(net.IPv4(10, 56, 0, 2), v4, 5000, 53, "tun"))
	require.NoError(t, err)
	got, _ := received(t, l, absent)
	assert.Empty(t, got, "a link that is no bridge is dropped")
}

// An address must not become a source the kernel picks for traffic of its
// own. A route out of an interface with no address of the family, as a
// Calico workload's cali* is, falls back to another interface's address,
// and lo's comes first: traffic from an owned address would meet its guard
// on the way back. Here the uplink's addresses stay the source with the
// owned ones added, even toward a destination sharing the IPv6 one's /48,
// which longest-prefix matching would otherwise give it.
func TestOwnedAddrs_NotASourceAddress(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 56, 0, 1))
	addAddr6(t, "cw0", net.ParseIP("fd56::1"))
	addTunTap(t, "cali0", nil, unix.IFF_TUN)
	addRoute(t, netip.MustParsePrefix("198.51.100.0/24"), "cali0")
	addRoute(t, netip.MustParsePrefix("fd97:d1fb:f215:1::/64"), "cali0") // narrower than the /48, but not over ::53
	source := func(dst string) netip.Addr {
		c, err := net.Dial("udp", dst)
		require.NoError(t, err)
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	}
	want4, want6 := netip.MustParseAddr("10.56.0.1"), netip.MustParseAddr("fd56::1")
	require.Equal(t, want4, source("198.51.100.7:80"), "the route out of cali0 takes the uplink's address")
	require.Equal(t, want6, source("[fd97:d1fb:f215:1::7]:80"))

	owned := NewOwnedAddrs(netip.Addr{}, nil, discardLogger())
	t.Cleanup(func() { _ = owned.Remove() })
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, owned.Add(addr))
	}
	assert.Equal(t, want4, source("198.51.100.7:80"), "the IPv4 address, of host scope, is no source")
	assert.Equal(t, want6, source("[fd97:d1fb:f215:1::7]:80"), "the IPv6 address, deprecated, is no source")
}

// An address whose addition fails after its guard went in, as the IPv6 one
// does where lo has IPv6 disabled, takes its guard back out.
func TestOwnedAddrs_FailedAddLeavesNoGuard(t *testing.T) {
	enterNetns(t)
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv6/conf/lo/disable_ipv6", []byte("1"), 0))
	owned := NewOwnedAddrs(netip.Addr{}, nil, discardLogger())
	t.Cleanup(func() { _ = owned.Remove() })
	require.Error(t, owned.Add(ContainerDNSIPv6))
	assert.Empty(t, guardRules(t), "the failed address's guard is gone")
	require.NoError(t, owned.Add(ContainerDNSIPv4))
	assert.Equal(t, map[string]int{"ip input": 4, "ip forward": 1, "arp input": 4}, guardRules(t))
}

// Remove takes each address off before its guard, and an address it cannot
// take off keeps its guard.
func TestOwnedAddrs_RemoveKeepsAGuardWhileItsAddressStays(t *testing.T) {
	enterNetns(t)
	owned := NewOwnedAddrs(netip.Addr{}, nil, discardLogger())
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, owned.Add(addr))
	}
	added := slices.Clone(owned.added)
	t.Cleanup(func() {
		for _, a := range added {
			_ = loopbackAddr(unix.RTM_DELADDR, 0, a.addr, "")
			_ = a.guard.remove()
		}
	})
	// Each address's own guard, as guardRules names it.
	guard := map[netip.Addr]string{ContainerDNSIPv4: "ip input", ContainerDNSIPv6: "ip6 input"}
	guarded := map[netip.Addr]bool{}
	owned.deleteAddr = func(addr netip.Addr) error {
		guarded[addr] = guardRules(t)[guard[addr]] == 4
		if addr == ContainerDNSIPv4 {
			return errors.New("refused")
		}
		return loopbackAddr(unix.RTM_DELADDR, 0, addr, "")
	}
	require.ErrorContains(t, owned.Remove(), "refused; its guard stays")
	assert.Equal(t, map[netip.Addr]bool{ContainerDNSIPv4: true, ContainerDNSIPv6: true}, guarded,
		"each address comes off while its guard is still in")
	assert.Equal(t, map[netip.Addr]string{ContainerDNSIPv4: ownedLabel}, ownedOnLo(t))
	assert.Equal(t, map[string]int{"ip input": 4, "ip forward": 1, "arp input": 4}, guardRules(t),
		"the address left keeps its guard; the one removed takes its guard with it")
}

// With arp_ignore 0, the kernel answers ARP for a local address on every
// link; the IPv4 address's guard keeps it from answering for 169.254.0.53,
// while the link's own address is answered as ever. IPv6 needs no guard
// for this: neighbour discovery answers only for the receiving link's own
// addresses.
func TestOwnedAddrs_NotAdvertised(t *testing.T) {
	enterNetns(t)
	tap := addTunTap(t, "cw0", net.IPv4(10, 56, 0, 1), unix.IFF_TAP)
	addAddr6(t, "cw0", net.ParseIP("fd56::1"))
	ifi, err := net.InterfaceByName("cw0")
	require.NoError(t, err)
	mac, peer := ifi.HardwareAddr, net.HardwareAddr{2, 0, 0, 0, 0, 2}
	arpFor := func(target net.IP, wait time.Duration) bool {
		_, err := tap.Write(arpRequest(peer, net.IPv4(10, 56, 0, 2), target))
		require.NoError(t, err)
		return answered(t, tap, wait, func(f []byte) bool {
			return binary.BigEndian.Uint16(f[12:]) == 0x0806 && len(f) >= 42 &&
				binary.BigEndian.Uint16(f[20:]) == 2 && net.IP(f[28:32]).Equal(target)
		})
	}
	ndFor := func(target net.IP, wait time.Duration) bool {
		_, err := tap.Write(neighborSolicit(mac, peer, net.ParseIP("fd56::2"), net.ParseIP("fd56::1"), target))
		require.NoError(t, err)
		return answered(t, tap, wait, func(f []byte) bool {
			return binary.BigEndian.Uint16(f[12:]) == 0x86dd && len(f) >= 78 && f[20] == unix.IPPROTO_ICMPV6 &&
				f[54] == 136 && net.IP(f[62:78]).Equal(target)
		})
	}

	// The controls: the link's own addresses are answered, and so is the
	// IPv4 address on lo unguarded.
	require.True(t, arpFor(net.IPv4(10, 56, 0, 1), arrives), "ARP for the link's own address")
	require.True(t, ndFor(net.ParseIP("fd56::1"), arrives), "neighbour discovery for the link's own address")
	require.NoError(t, loopbackAddr(unix.RTM_NEWADDR, netlink.Create, ContainerDNSIPv4, ""))
	require.True(t, arpFor(net.IP(ContainerDNSIPv4.AsSlice()), arrives), "ARP for an unguarded address on lo")
	require.NoError(t, loopbackAddr(unix.RTM_DELADDR, 0, ContainerDNSIPv4, ""))

	owned := NewOwnedAddrs(netip.Addr{}, nil, discardLogger())
	t.Cleanup(func() { _ = owned.Remove() })
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, owned.Add(addr))
	}
	assert.False(t, arpFor(net.IP(ContainerDNSIPv4.AsSlice()), absent), "ARP for the guarded IPv4 address")
	assert.False(t, ndFor(net.IP(ContainerDNSIPv6.AsSlice()), absent), "neighbour discovery for the IPv6 address")
	assert.True(t, arpFor(net.IPv4(10, 56, 0, 1), arrives), "ARP for the link's own address, guard or none")
}

// answered reports whether a frame match accepts comes out of tap within
// wait.
func answered(t *testing.T, tap *os.File, wait time.Duration, match func([]byte) bool) bool {
	t.Helper()
	buf := make([]byte, 1600)
	require.NoError(t, tap.SetReadDeadline(time.Now().Add(wait)))
	for {
		n, err := tap.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false
		}
		require.NoError(t, err)
		if n >= 14 && match(buf[:n]) {
			return true
		}
	}
}

// ether is payload in an Ethernet frame from src to dst of the given type.
func ether(dst, src net.HardwareAddr, typ uint16, payload []byte) []byte {
	f := make([]byte, 14, 14+len(payload))
	copy(f, dst)
	copy(f[6:], src)
	binary.BigEndian.PutUint16(f[12:], typ)
	return append(f, payload...)
}

// arpRequest is a broadcast ARP request from mac at ip for target.
func arpRequest(mac net.HardwareAddr, ip, target net.IP) []byte {
	a := make([]byte, 28)
	binary.BigEndian.PutUint16(a[0:], 1)      // Ethernet
	binary.BigEndian.PutUint16(a[2:], 0x0800) // IPv4
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:], 1) // request
	copy(a[8:], mac)
	copy(a[14:], ip.To4())
	copy(a[24:], target.To4())
	return ether(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, mac, 0x0806, a)
}

// neighborSolicit is a neighbour solicitation from mac at src for target,
// sent unicast to dst at dstMAC, with mac as its source link-layer address.
func neighborSolicit(dstMAC, mac net.HardwareAddr, src, dst, target net.IP) []byte {
	b := make([]byte, 40+32)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], 32)
	b[6], b[7] = unix.IPPROTO_ICMPV6, 255 // neighbour discovery needs hop limit 255
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	icmp := b[40:]
	icmp[0] = 135 // neighbour solicitation
	copy(icmp[8:24], target.To16())
	icmp[24], icmp[25] = 1, 1 // source link-layer address, 8 bytes
	copy(icmp[26:], mac)
	binary.BigEndian.PutUint16(icmp[2:], inetChecksum(uint32(len(icmp))+unix.IPPROTO_ICMPV6, b[8:40], icmp))
	return ether(dstMAC, mac, 0x86dd, b)
}

// newBridge creates a Linux bridge named name, up, and removes it at the
// end of the test.
func newBridge(t *testing.T, name string) {
	t.Helper()
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.IFLA_IFNAME, name)
	ae.Nested(unix.IFLA_LINKINFO, func(info *netlink.AttributeEncoder) error {
		info.String(unix.IFLA_INFO_KIND, "bridge")
		return nil
	})
	attrs, err := ae.Encode()
	require.NoError(t, err)
	_, err = rtnetlink(netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_NEWLINK,
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl,
		},
		Data: append(make([]byte, unix.SizeofIfInfomsg), attrs...),
	})
	require.NoError(t, err)
	setLinkUp(t, name)
}

// enslave makes the interface named port a port of the bridge named master.
func enslave(t *testing.T, port, master string) {
	t.Helper()
	p, err := net.InterfaceByName(port)
	require.NoError(t, err)
	m, err := net.InterfaceByName(master)
	require.NoError(t, err)
	ifi := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(ifi[4:], uint32(p.Index))
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(unix.IFLA_MASTER, uint32(m.Index))
	attrs, err := ae.Encode()
	require.NoError(t, err)
	_, err = rtnetlink(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_NEWLINK, Flags: netlink.Request | netlink.Acknowledge},
		Data:   append(ifi, attrs...),
	})
	require.NoError(t, err)
}
