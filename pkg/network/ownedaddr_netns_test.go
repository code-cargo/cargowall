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

// bothGuarded is the guard tables' rules with both addresses added.
var bothGuarded = map[string]int{"ip input": 1, "ip forward": 1, "ip6 input": 1, "ip6 forward": 1}

// The container DNS addresses go on lo, the IPv4 one labelled as cargowall's,
// each with its guard, and come off again, guards and all; one added twice
// is added once, and once removed, none is added.
func TestOwnedAddrs_AddRemove(t *testing.T) {
	enterNetns(t)
	owned := NewOwnedAddrs(netip.Addr{}, discardLogger())
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, owned.Add(addr))
	}
	require.NoError(t, owned.Add(ContainerDNSIPv4), "an address already added is not added again")
	assert.Equal(t, map[netip.Addr]string{ContainerDNSIPv4: ownedLabel, ContainerDNSIPv6: ""}, ownedOnLo(t))
	assert.Equal(t, bothGuarded, guardRules(t))

	require.NoError(t, owned.Remove())
	assert.Empty(t, ownedOnLo(t))
	assert.Empty(t, guardRules(t), "the guards go with the addresses")
	require.NoError(t, owned.Remove(), "a second Remove has nothing to do")
	require.ErrorContains(t, owned.Add(ContainerDNSIPv4), "teardown has begun")
	assert.Empty(t, ownedOnLo(t))
	assert.Empty(t, guardRules(t))
}

// A run killed before its teardown leaves the addresses on lo. Its guards
// die with its sockets where the kernel owns them, and stay where it
// cannot. The next run takes the addresses over, as its own, replaces a
// guard left rather than adding to it, and its teardown removes both.
func TestOwnedAddrs_TakesOverALeftover(t *testing.T) {
	enterNetns(t)
	for _, unowned := range []bool{false, true} {
		killed := NewOwnedAddrs(netip.Addr{}, discardLogger())
		if unowned {
			killed.ownerFlag = 0 // a kernel that cannot own tables
		}
		next := NewOwnedAddrs(netip.Addr{}, discardLogger())
		for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
			require.NoError(t, killed.Add(addr))
		}
		owned := killed.added[0].guard.owned
		require.Equal(t, !unowned && ownsTables(t), owned, "a guard is owned wherever the kernel can own one")
		for _, a := range killed.added {
			require.NoError(t, a.guard.conn.Close(), "the process dies")
		}
		if owned {
			assert.Empty(t, guardRules(t), "an owned guard dies with its socket")
		} else {
			assert.Equal(t, bothGuarded, guardRules(t), "an unowned guard outlives its socket")
		}
		for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
			require.NoError(t, next.Add(addr), "%s: a leftover is cargowall's own", addr)
		}
		assert.Equal(t, bothGuarded, guardRules(t), "unowned %v: a guard left is replaced", unowned)
		require.NoError(t, next.Remove())
		assert.Empty(t, ownedOnLo(t))
		assert.Empty(t, guardRules(t))
	}
}

// An address whose guard cannot be installed is refused, and not added:
// here another live socket owns a table of the guard's name, as a second
// cargowall's would. The other family's guard is a table of its own.
func TestOwnedAddrs_RefusedWithoutItsGuard(t *testing.T) {
	enterNetns(t)
	requireOwnedTables(t)
	other, err := installGuard(ContainerDNSIPv4, nftTableFOwner, discardLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.remove() })
	owned := NewOwnedAddrs(netip.Addr{}, discardLogger())
	t.Cleanup(func() { _ = owned.Remove() })

	err = owned.Add(ContainerDNSIPv4)
	require.ErrorContains(t, err, "its guard cannot be installed")
	require.ErrorIs(t, err, unix.EPERM)
	assert.Empty(t, ownedOnLo(t))
	require.NoError(t, owned.Add(ContainerDNSIPv6))
	assert.Equal(t, map[netip.Addr]string{ContainerDNSIPv6: ""}, ownedOnLo(t))
}

// With no DNS redirect in place, the addresses' guards still keep them from
// every link but lo and the docker bridges. DNS for them arriving on docker0
// or a br-* bridge reaches the proxy's listeners there, over UDP and TCP;
// arriving on the uplink it does not, though without the guard it does.
func TestOwnedAddrs_GuardWithoutRedirect(t *testing.T) {
	enterNetns(t)
	docker0 := addTun(t, "docker0", net.IPv4(10, 54, 0, 1))
	user := addTun(t, "br-test", net.IPv4(10, 55, 0, 1))
	uplink := addTun(t, "cw0", net.IPv4(10, 56, 0, 1))
	for name, addr := range map[string]string{"docker0": "fd54::1", "br-test": "fd55::1", "cw0": "fd56::1"} {
		addAddr6(t, name, net.ParseIP(addr))
	}
	v4, v6 := net.IP(ContainerDNSIPv4.AsSlice()), net.IP(ContainerDNSIPv6.AsSlice())
	type link struct {
		wire      *os.File
		src, src6 net.IP
	}
	bridges := []link{
		{docker0, net.IPv4(10, 54, 0, 2), net.ParseIP("fd54::2")},
		{user, net.IPv4(10, 55, 0, 2), net.ParseIP("fd55::2")},
	}
	off := link{uplink, net.IPv4(10, 56, 0, 2), net.ParseIP("fd56::2")}
	sport := uint16(7000) // a port per TCP handshake: none reuses a half-open one
	// reaches reports whether DNS sent over c to the addresses reaches the
	// listeners: UDP for each family, and a TCP handshake for IPv4.
	reaches := func(c link, l, l6 *net.UDPConn, wait time.Duration) (u4, u6, syn bool) {
		name := c.wire.Name()
		_, err := c.wire.Write(udp4(c.src, v4, 5000, 53, name))
		require.NoError(t, err)
		got, _ := received(t, l, wait)
		_, err = c.wire.Write(udp6(c.src6, v6, 5000, 53, name+"6"))
		require.NoError(t, err)
		got6, _ := received(t, l6, wait)
		sport++
		return got == name, got6 == name+"6", synAcked(t, c.wire, c.src, v4, sport, 53)
	}

	// The control: the addresses on lo, unguarded, are reached from the
	// uplink.
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, loopbackAddr(unix.RTM_NEWADDR, netlink.Create, addr, ""))
	}
	l, l6 := listenUDP(t, containerAddr(ContainerDNSIPv4)), listenUDP(t, containerAddr(ContainerDNSIPv6))
	tcp := listenTCPAt(t, containerAddr(ContainerDNSIPv4))
	u4, u6, syn := reaches(off, l, l6, arrives)
	require.True(t, u4 && u6 && syn, "without the guard the uplink reaches the addresses (udp %v udp6 %v tcp %v)",
		u4, u6, syn)
	l.Close()
	l6.Close()
	tcp.Close()
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, loopbackAddr(unix.RTM_DELADDR, 0, addr, ""))
	}

	owned := NewOwnedAddrs(netip.Addr{}, discardLogger())
	t.Cleanup(func() { _ = owned.Remove() })
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, owned.Add(addr))
	}
	require.Empty(t, redirectRules(t), "no redirect")
	l, l6 = listenUDP(t, containerAddr(ContainerDNSIPv4)), listenUDP(t, containerAddr(ContainerDNSIPv6))
	listenTCPAt(t, containerAddr(ContainerDNSIPv4))
	for _, c := range bridges {
		u4, u6, syn := reaches(c, l, l6, arrives)
		assert.True(t, u4 && u6 && syn, "%s must reach the addresses (udp %v udp6 %v tcp %v)", c.wire.Name(),
			u4, u6, syn)
	}
	u4, u6, syn = reaches(off, l, l6, absent)
	assert.False(t, u4 || u6 || syn, "the uplink must not reach the addresses (udp %v udp6 %v tcp %v)", u4, u6, syn)
}

// An address something else holds is refused, with the reason, and not
// added: the proxy's upstream, an address on another interface or on lo
// without cargowall's label, and one a route more specific than its range's
// generic one sends through a link. The generic routes themselves, a
// link-local /16 on the uplink, as NetworkManager and cloud images add,
// and a ULA /8, hold nothing.
func TestOwnedAddrs_RefusesAHolder(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw1", net.IPv4(10, 57, 0, 1))
	for _, c := range []struct {
		name     string
		addr     netip.Addr
		upstream netip.Addr
		set      func() func() // sets the holder up, returns its undo
		refusal  string        // "" for none
	}{
		{
			name: "the DNS upstream", addr: ContainerDNSIPv4, upstream: ContainerDNSIPv4,
			refusal: "it is the DNS upstream, so the proxy would forward container DNS to itself",
		},
		{
			name: "assigned to another interface", addr: ContainerDNSIPv4,
			set:     func() func() { return setAddr(t, netip.PrefixFrom(ContainerDNSIPv4, 32), "cw1", "") },
			refusal: "it is already assigned to cw1",
		},
		{
			name: "assigned to lo by something else", addr: ContainerDNSIPv4,
			set:     func() func() { return setAddr(t, netip.PrefixFrom(ContainerDNSIPv4, 32), "lo", "lo") },
			refusal: "it is already assigned to lo by something other than cargowall",
		},
		{
			name: "IPv6, assigned to another interface", addr: ContainerDNSIPv6,
			set:     func() func() { return setAddr(t, netip.PrefixFrom(ContainerDNSIPv6, 64), "cw1", "") },
			refusal: "it is already assigned to cw1",
		},
		{
			name: "routed by a /24 through a link", addr: ContainerDNSIPv4,
			set:     func() func() { return addRoute(t, netip.MustParsePrefix("169.254.0.0/24"), "cw1") },
			refusal: "it is routed through cw1 by 169.254.0.0/24",
		},
		{
			name: "routed by a /17 through a link", addr: ContainerDNSIPv4,
			set:     func() func() { return addRoute(t, netip.MustParsePrefix("169.254.0.0/17"), "cw1") },
			refusal: "it is routed through cw1 by 169.254.0.0/17",
		},
		{
			name: "IPv6, its /48 routed through a link", addr: ContainerDNSIPv6,
			set:     func() func() { return addRoute(t, netip.MustParsePrefix("fd97:d1fb:f215::/48"), "cw1") },
			refusal: "it is routed through cw1 by fd97:d1fb:f215::/48",
		},
		{
			name: "the generic link-local /16 on the uplink", addr: ContainerDNSIPv4,
			set: func() func() { return addRoute(t, netip.MustParsePrefix("169.254.0.0/16"), "cw1") },
		},
		{
			name: "a ULA /8 through a link", addr: ContainerDNSIPv6,
			set: func() func() { return addRoute(t, netip.MustParsePrefix("fd00::/8"), "cw1") },
		},
		{
			name: "IPv6, a /47 holding more than the ULA's /48", addr: ContainerDNSIPv6,
			set: func() func() { return addRoute(t, netip.MustParsePrefix("fd97:d1fb:f214::/47"), "cw1") },
		},
	} {
		undo := func() {}
		if c.set != nil {
			undo = c.set()
		}
		before := ownedOnLo(t)
		owned := NewOwnedAddrs(c.upstream, discardLogger())
		err := owned.Add(c.addr)
		if c.refusal == "" {
			require.NoError(t, err, c.name)
			assert.Contains(t, ownedOnLo(t), c.addr, c.name)
		} else {
			require.EqualError(t, err, c.refusal, c.name)
			assert.Equal(t, before, ownedOnLo(t), "%s: a refused address is not added", c.name)
			assert.Empty(t, guardRules(t), "%s: nor guarded", c.name)
		}
		require.NoError(t, owned.Remove(), c.name)
		undo()
	}
}

// The IPv6 container DNS address on lo leaves by no link, so it makes no
// host IPv6: an IPv6 address on a link does.
func TestHostIPv6_NotFromLo(t *testing.T) {
	enterNetns(t)
	owned := NewOwnedAddrs(netip.Addr{}, discardLogger())
	t.Cleanup(func() { _ = owned.Remove() })
	require.NoError(t, owned.Add(ContainerDNSIPv6))
	assert.False(t, HostIPv6(), "::1 and the container DNS address are lo's")
	addTun(t, "cw1", net.IPv4(10, 57, 0, 1))
	addAddr6(t, "cw1", net.ParseIP("fd57::1"))
	assert.True(t, HostIPv6())
}

// Were a container DNS address gone while cargowall runs, container DNS
// sent to it, by daemon.json or by the redirect's DNAT, would be routed off
// the host instead; its guard's forward drop keeps it in, with the redirect
// or without. Without the guard the packet is forwarded, which shows the
// route out is there.
func TestOwnedAddrs_ForwardDrop(t *testing.T) {
	enterNetns(t)
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
	docker0 := addTun(t, "docker0", net.IPv4(10, 54, 0, 1))
	uplink := addTun(t, "cw0", net.IPv4(10, 56, 0, 1))
	// The address routed out of the uplink, as a default route would.
	addRoute(t, netip.MustParsePrefix("169.254.0.0/16"), "cw0")
	src := net.IPv4(10, 54, 0, 2)
	v4 := net.IP(ContainerDNSIPv4.AsSlice())
	send := func(dst net.IP, sport uint16) {
		_, err := docker0.Write(udp4(src, dst, sport, 53, "query"))
		require.NoError(t, err)
	}

	send(v4, 5000)
	require.True(t, forwardedOut(t, uplink, v4, arrives), "without the guard, the packet is forwarded out of cw0")

	owned := NewOwnedAddrs(netip.Addr{}, discardLogger())
	t.Cleanup(func() { _ = owned.Remove() })
	require.NoError(t, owned.Add(ContainerDNSIPv4))
	require.NoError(t, loopbackAddr(unix.RTM_DELADDR, 0, ContainerDNSIPv4, ""), "the address gone from under cargowall")
	send(v4, 5001)
	require.False(t, forwardedOut(t, uplink, v4, absent), "DNS for the address must not leave by cw0")

	r := NewDNSRedirect(discardLogger())
	require.NoError(t, r.Install(RedirectSpec{ContainerIPv4: ContainerDNSIPv4}))
	t.Cleanup(func() { _ = r.Teardown() })
	send(net.IPv4(8, 8, 8, 8), 5002)
	require.False(t, forwardedOut(t, uplink, v4, absent), "nor may DNS DNAT'd to it")
	require.NoError(t, r.Teardown())

	require.NoError(t, owned.Remove())
	send(v4, 5003)
	require.True(t, forwardedOut(t, uplink, v4, arrives), "the guard goes with Remove")
}

// forwardedOut reports whether an IPv4 UDP packet for dst:53 comes out of
// wire within wait.
func forwardedOut(t *testing.T, wire *os.File, dst net.IP, wait time.Duration) bool {
	t.Helper()
	buf := make([]byte, 1500)
	require.NoError(t, wire.SetReadDeadline(time.Now().Add(wait)))
	for {
		n, err := wire.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false
		}
		require.NoError(t, err)
		p := buf[:n]
		if n >= 28 && p[0]>>4 == 4 && p[9] == unix.IPPROTO_UDP && net.IP(p[16:20]).Equal(dst) &&
			binary.BigEndian.Uint16(p[int(p[0]&0x0f)*4+2:]) == 53 {
			return true
		}
	}
}

// guardRules counts the guard tables' rules per family and chain.
func guardRules(t *testing.T) map[string]int {
	t.Helper()
	return tableRules(t, GuardTable)
}

// ownedOnLo is the container DNS addresses on lo, with their labels.
func ownedOnLo(t *testing.T) map[netip.Addr]string {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	out := map[netip.Addr]string{}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		replies, err := rtnetlink(netlink.Message{
			Header: netlink.Header{Type: unix.RTM_GETADDR, Flags: netlink.Request | netlink.Dump},
			Data:   []byte{family, 0, 0, 0, 0, 0, 0, 0},
		})
		require.NoError(t, err)
		for _, m := range replies {
			if int(binary.NativeEndian.Uint32(m.Data[4:8])) != lo.Index {
				continue
			}
			addr, label := ifaddrAttrs(m.Data[unix.SizeofIfAddrmsg:])
			if slices.Contains([]netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6}, addr) {
				out[addr] = label
			}
		}
	}
	return out
}

// setAddr assigns prefix's address to the interface named dev, with label
// for an IPv4 one where given, and returns its removal.
func setAddr(t *testing.T, prefix netip.Prefix, dev, label string) func() {
	t.Helper()
	ifi, err := net.InterfaceByName(dev)
	require.NoError(t, err)
	msg := func(typ netlink.HeaderType, flags netlink.HeaderFlags) netlink.Message {
		ifa := make([]byte, unix.SizeofIfAddrmsg)
		ifa[0], ifa[1] = unix.AF_INET, byte(prefix.Bits())
		if prefix.Addr().Is6() {
			ifa[0], ifa[2] = unix.AF_INET6, unix.IFA_F_NODAD
		}
		binary.NativeEndian.PutUint32(ifa[4:], uint32(ifi.Index))
		ae := netlink.NewAttributeEncoder()
		ae.Bytes(unix.IFA_LOCAL, prefix.Addr().AsSlice())
		ae.Bytes(unix.IFA_ADDRESS, prefix.Addr().AsSlice())
		if label != "" {
			ae.String(unix.IFA_LABEL, label)
		}
		attrs, err := ae.Encode()
		require.NoError(t, err)
		return netlink.Message{
			Header: netlink.Header{Type: typ, Flags: netlink.Request | netlink.Acknowledge | flags},
			Data:   append(ifa, attrs...),
		}
	}
	_, err = rtnetlink(msg(unix.RTM_NEWADDR, netlink.Create|netlink.Excl))
	require.NoError(t, err)
	return func() {
		_, err := rtnetlink(msg(unix.RTM_DELADDR, 0))
		require.NoError(t, err)
	}
}

// addRoute adds a unicast route for prefix through the interface named dev
// to the main table, and returns its removal.
func addRoute(t *testing.T, prefix netip.Prefix, dev string) func() {
	t.Helper()
	ifi, err := net.InterfaceByName(dev)
	require.NoError(t, err)
	msg := func(typ netlink.HeaderType, flags netlink.HeaderFlags) netlink.Message {
		// struct rtmsg: family, dst_len, src_len, tos, table, protocol,
		// scope, type, flags.
		rtm := make([]byte, unix.SizeofRtMsg)
		rtm[0], rtm[1] = unix.AF_INET, byte(prefix.Bits())
		rtm[6] = unix.RT_SCOPE_LINK
		if prefix.Addr().Is6() {
			rtm[0], rtm[6] = unix.AF_INET6, unix.RT_SCOPE_UNIVERSE
		}
		rtm[4], rtm[5], rtm[7] = unix.RT_TABLE_MAIN, unix.RTPROT_STATIC, unix.RTN_UNICAST
		ae := netlink.NewAttributeEncoder()
		ae.Bytes(unix.RTA_DST, prefix.Addr().AsSlice())
		ae.Uint32(unix.RTA_OIF, uint32(ifi.Index))
		attrs, err := ae.Encode()
		require.NoError(t, err)
		return netlink.Message{
			Header: netlink.Header{Type: typ, Flags: netlink.Request | netlink.Acknowledge | flags},
			Data:   append(rtm, attrs...),
		}
	}
	_, err = rtnetlink(msg(unix.RTM_NEWROUTE, netlink.Create|netlink.Excl))
	require.NoError(t, err)
	return func() {
		_, err := rtnetlink(msg(unix.RTM_DELROUTE, 0))
		require.NoError(t, err)
	}
}
