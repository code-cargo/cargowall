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

// The container DNS addresses go on lo, the IPv4 one labelled as cargowall's,
// and come off again; once removed, none is added.
func TestOwnedAddrs_AddRemove(t *testing.T) {
	enterNetns(t)
	owned := NewOwnedAddrs(netip.Addr{}, discardLogger())
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, owned.Add(addr))
	}
	assert.Equal(t, map[netip.Addr]string{ContainerDNSIPv4: ownedLabel, ContainerDNSIPv6: ""}, ownedOnLo(t))

	require.NoError(t, owned.Remove())
	assert.Empty(t, ownedOnLo(t))
	require.NoError(t, owned.Remove(), "a second Remove has nothing to do")
	require.ErrorContains(t, owned.Add(ContainerDNSIPv4), "teardown has begun")
	assert.Empty(t, ownedOnLo(t))
}

// A run killed before its teardown leaves the addresses on lo. The next run
// takes them over, as its own, and its teardown removes them.
func TestOwnedAddrs_TakesOverALeftover(t *testing.T) {
	enterNetns(t)
	killed := NewOwnedAddrs(netip.Addr{}, discardLogger())
	next := NewOwnedAddrs(netip.Addr{}, discardLogger())
	for _, addr := range []netip.Addr{ContainerDNSIPv4, ContainerDNSIPv6} {
		require.NoError(t, killed.Add(addr))
		require.NoError(t, next.Add(addr), "%s: a leftover is cargowall's own", addr)
	}
	require.NoError(t, next.Remove())
	assert.Empty(t, ownedOnLo(t))
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

// TestDNSRedirect_ForwardDrop: were a container listener's address gone
// while the redirect stands, the container DNS DNAT'd to it would be routed
// off the host instead; the forward drop keeps it in. Without the redirect,
// a packet for the address is forwarded, which shows the route out is there.
func TestDNSRedirect_ForwardDrop(t *testing.T) {
	enterNetns(t)
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
	docker0 := addTun(t, "docker0", net.IPv4(10, 54, 0, 1))
	uplink := addTun(t, "cw0", net.IPv4(10, 56, 0, 1))
	// The container listener's address routed out of the uplink, as a
	// default route would.
	addRoute(t, netip.MustParsePrefix("169.254.0.0/16"), "cw0")
	src := net.IPv4(10, 54, 0, 2)
	v4 := net.IP(ContainerDNSIPv4.AsSlice())

	_, err := docker0.Write(udp4(src, v4, 5000, 53, "before"))
	require.NoError(t, err)
	require.True(t, forwardedOut(t, uplink, v4, arrives), "without the redirect, the packet is forwarded out of cw0")

	r := NewDNSRedirect(discardLogger())
	require.NoError(t, r.Install(RedirectSpec{ContainerIPv4: ContainerDNSIPv4}))
	t.Cleanup(func() { _ = r.Teardown() })
	for _, dst := range []net.IP{net.IPv4(8, 8, 8, 8), v4} {
		_, err = docker0.Write(udp4(src, dst, 5001, 53, "after"))
		require.NoError(t, err)
		require.False(t, forwardedOut(t, uplink, v4, absent), "DNS DNAT'd to an address that is gone must not leave by cw0")
	}
	require.NoError(t, r.Teardown())
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
