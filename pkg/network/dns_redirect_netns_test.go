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
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/google/nftables"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The redirect's tests send real packets through it in a private network
// namespace. TUN interfaces stand in for the host's uplink and for docker
// bridges: a packet written to a TUN arrives on its interface as if it came
// off the wire, and what the kernel routes out of one is simply never read.

// enterNetns moves the test's goroutine into a fresh network namespace with
// loopback up. The goroutine stays locked to its thread and never unlocks,
// so the thread exits with the test rather than carrying the namespace back
// into the scheduler's pool. Everything the test does from here (sockets,
// nftables, conntrack) runs in the namespace; subtests would not.
func enterNetns(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for a network namespace and nftables; covered by the sudo test pass")
	}
	runtime.LockOSThread()
	require.NoError(t, unix.Unshare(unix.CLONE_NEWNET))
	// No duplicate address detection, so an IPv6 address is usable as soon
	// as it is added, on every kernel: some run it even on a NOARP TUN, and
	// a tentative address refuses to be bound. The sysctls are this thread's
	// namespace's, and interfaces made from here on take the default.
	for _, conf := range []string{"all", "default"} {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+conf+"/accept_dad", []byte("0"), 0); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			require.NoError(t, err)
		}
	}
	setLinkUp(t, "lo")
}

func setLinkUp(t *testing.T, name string) {
	t.Helper()
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(sock)
	ifr, err := unix.NewIfreq(name)
	require.NoError(t, err)
	require.NoError(t, unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr))
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	require.NoError(t, unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr))
}

// addTun creates TUN interface name holding addr/24, up, and returns the
// file whose writes arrive on it.
func addTun(t *testing.T, name string, addr net.IP) *os.File {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	f := os.NewFile(uintptr(fd), name)
	t.Cleanup(func() { f.Close() })
	ifr, err := unix.NewIfreq(name)
	require.NoError(t, err)
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	require.NoError(t, unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr))

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(sock)
	for _, set := range []struct {
		req uint
		ip  net.IP
	}{{unix.SIOCSIFADDR, addr}, {unix.SIOCSIFNETMASK, net.IPv4(255, 255, 255, 0)}} {
		ifr, err := unix.NewIfreq(name)
		require.NoError(t, err)
		require.NoError(t, ifr.SetInet4Addr(set.ip.To4()))
		require.NoError(t, unix.IoctlIfreq(sock, set.req, ifr))
	}
	setLinkUp(t, name)
	return f
}

// addAddr6 gives interface name the IPv6 address addr/64, usable at once
// since enterNetns turns duplicate address detection off.
func addAddr6(t *testing.T, name string, addr net.IP) {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	require.NoError(t, err)
	sock, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(sock)
	// struct in6_ifreq, which x/sys/unix does not carry.
	req := struct {
		addr      [16]byte
		prefixlen uint32
		ifindex   int32
	}{prefixlen: 64, ifindex: int32(iface.Index)}
	copy(req.addr[:], addr.To16())
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&req)))
	require.Zero(t, errno, "adding %s to %s", addr, name)
}

// udp6 builds an IPv6/UDP packet, with the checksum IPv6 requires.
func udp6(src, dst net.IP, sport, dport uint16, payload string) []byte {
	b := make([]byte, 48+len(payload))
	b[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	b[6] = unix.IPPROTO_UDP
	b[7] = 64 // hop limit
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	udp := b[40:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	copy(udp[8:], payload)
	// The pseudo-header: both addresses, the UDP length, the next header.
	sum := uint32(len(udp)) + unix.IPPROTO_UDP
	for _, words := range [][]byte{b[8:40], udp} {
		for i := 0; i+1 < len(words); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(words[i:]))
		}
		if len(words)%2 == 1 {
			sum += uint32(words[len(words)-1]) << 8
		}
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	check := ^uint16(sum)
	if check == 0 {
		check = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], check)
	return b
}

// udp4 builds an IPv4/UDP packet. A zero UDP checksum means none, which
// IPv4 allows.
func udp4(src, dst net.IP, sport, dport uint16, payload string) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45 // version 4, 5-word header
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64 // TTL
	b[9] = unix.IPPROTO_UDP
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(b[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

// ipNet is network ("udp" or "tcp") for addr's family.
func ipNet(network, addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			return network + "6"
		}
	}
	return network + "4"
}

func listenUDP(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	ua, err := net.ResolveUDPAddr(ipNet("udp", addr), addr)
	require.NoError(t, err)
	c, err := net.ListenUDP(ipNet("udp", addr), ua)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func listenTCPAt(t *testing.T, addr string) *net.TCPListener {
	t.Helper()
	l, err := net.Listen(ipNet("tcp", addr), addr)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	return l.(*net.TCPListener)
}

// connects reports whether a TCP connection to dst lands on l.
func connects(t *testing.T, dst string, l *net.TCPListener) bool {
	t.Helper()
	c, err := net.DialTimeout(ipNet("tcp", dst), dst, absent)
	if err != nil {
		return false
	}
	c.Close()
	require.NoError(t, l.SetDeadline(time.Now().Add(arrives)))
	a, err := l.Accept()
	if err != nil {
		return false
	}
	a.Close()
	return true
}

// received reports what l got within wait, or "" when nothing came, and
// from where.
func received(t *testing.T, l *net.UDPConn, wait time.Duration) (string, *net.UDPAddr) {
	t.Helper()
	require.NoError(t, l.SetReadDeadline(time.Now().Add(wait)))
	buf := make([]byte, 512)
	n, from, err := l.ReadFromUDP(buf)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "", nil
	}
	require.NoError(t, err)
	return string(buf[:n]), from
}

// query sends payload to addr from a fresh socket, marked as the proxy's
// own when marked.
func query(t *testing.T, addr, payload string, marked bool) {
	t.Helper()
	d := net.Dialer{}
	if marked {
		d.Control = MarkDNSProxySocket
	}
	c, err := d.Dial(ipNet("udp", addr), addr)
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte(payload))
	require.NoError(t, err)
}

const (
	arrives = 2 * time.Second        // how long a packet that should land may take
	absent  = 300 * time.Millisecond // how long to watch for one that should not
)

// TestDNSRedirect_Output: DNS this namespace sends leaves for the proxy at
// 127.0.0.1:53, the systemd-resolved stub's included, while the proxy's own
// marked queries and the rest of 127.0.0.0/8 go where they were sent. Those
// hold in either table family; with IPv6 covered, IPv6 DNS likewise leaves
// for [::1]:53, and without it goes where it was sent.
func TestDNSRedirect_Output(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 53, 0, 1))
	addAddr6(t, "cw0", net.ParseIP("fd53::1"))
	proxy := listenUDP(t, "127.0.0.1:53")
	proxyTCP := listenTCPAt(t, "127.0.0.1:53")
	proxy6 := listenUDP(t, "[::1]:53")
	proxy6TCP := listenTCPAt(t, "[::1]:53")

	// Without the redirect a query for an outside resolver leaves by cw0.
	query(t, "10.53.0.2:53", "before", false)
	got, _ := received(t, proxy, absent)
	require.Empty(t, got, "the query reached the proxy with no redirect installed")

	for _, ipv6 := range []bool{false, true} {
		r := NewDNSRedirect(discardLogger())
		require.NoError(t, r.Install(RedirectSpec{IPv6: ipv6}))

		query(t, "10.53.0.2:53", "outside", false)
		got, _ = received(t, proxy, arrives)
		require.Equal(t, "outside", got, "ipv6 %v: UDP DNS for an outside resolver must reach the proxy", ipv6)

		for _, stub := range []string{"127.0.0.53:53", "127.0.0.54:53"} {
			query(t, stub, "stub", false)
			got, _ = received(t, proxy, arrives)
			require.Equal(t, "stub", got, "ipv6 %v: UDP DNS for the resolved stub at %s must reach the proxy", ipv6, stub)
		}

		for _, dst := range []string{"10.53.0.2:53", "127.0.0.53:53", "127.0.0.54:53"} {
			require.True(t, connects(t, dst, proxyTCP), "ipv6 %v: TCP DNS for %s must reach the proxy", ipv6, dst)
		}

		query(t, "10.53.0.2:53", "marked", true)
		got, _ = received(t, proxy, absent)
		require.Empty(t, got, "ipv6 %v: the proxy's own marked query must not be redirected back to it", ipv6)

		query(t, "127.0.0.2:53", "loopback", false)
		got, _ = received(t, proxy, absent)
		require.Empty(t, got, "ipv6 %v: loopback DNS other than the stub must not be redirected", ipv6)

		query(t, "[fd53::2]:53", "outside6", false)
		if ipv6 {
			got, _ = received(t, proxy6, arrives)
			require.Equal(t, "outside6", got, "UDP DNS for an outside IPv6 resolver must reach the proxy at [::1]:53")
			require.True(t, connects(t, "[fd53::2]:53", proxy6TCP), "TCP DNS for an outside IPv6 resolver must reach the proxy")

			query(t, "[fd53::2]:53", "marked6", true)
			got, _ = received(t, proxy6, absent)
			require.Empty(t, got, "the proxy's own marked IPv6 query must not be redirected back to it")
		} else {
			got, _ = received(t, proxy6, absent)
			require.Empty(t, got, "an IPv4-only redirect leaves IPv6 DNS alone")
		}

		require.NoError(t, r.Teardown())
	}
}

// TestDNSRedirect_LinkLocalIPv6: DNS for a link-local resolver never goes
// around the proxy. A socket connected to one is bound to its interface, so
// once DNAT'd to ::1 the kernel cannot route it and the send fails at once;
// an unbound socket's query reaches the proxy.
func TestDNSRedirect_LinkLocalIPv6(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 53, 0, 1))
	addAddr6(t, "cw0", net.ParseIP("fe80::1"))
	proxy6 := listenUDP(t, "[::1]:53")
	install := func() {
		r := NewDNSRedirect(discardLogger())
		require.NoError(t, r.Install(RedirectSpec{IPv6: true}))
		t.Cleanup(func() { _ = r.Teardown() })
	}
	resolver := &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: 53, Zone: "cw0"}

	connected, err := net.DialUDP("udp6", nil, resolver)
	require.NoError(t, err)
	defer connected.Close()
	install()
	_, err = connected.Write([]byte("connected"))
	require.ErrorIs(t, err, unix.ENETUNREACH, "a connected link-local query must fail, not leave")
	got, _ := received(t, proxy6, absent)
	require.Empty(t, got)

	unbound, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	require.NoError(t, err)
	defer unbound.Close()
	_, err = unbound.WriteTo([]byte("unbound"), resolver)
	require.NoError(t, err)
	got, _ = received(t, proxy6, arrives)
	require.Equal(t, "unbound", got, "an unbound link-local query must reach the proxy")
}

// TestDNSRedirect_InputGuard: a sport-53 packet that would open a flow from
// outside is dropped, a reply to the proxy's own upstream query is not, and
// loopback is exempt, in either table family; an inet table guards IPv6 the
// same way.
func TestDNSRedirect_InputGuard(t *testing.T) {
	enterNetns(t)
	local, remote := net.IPv4(10, 53, 0, 1), net.IPv4(10, 53, 0, 2)
	local6, remote6 := net.ParseIP("fd53::1"), net.ParseIP("fd53::2")
	wire := addTun(t, "cw0", local)
	addAddr6(t, "cw0", local6)
	l := listenUDP(t, "10.53.0.1:40000")
	l6 := listenUDP(t, "[fd53::1]:40000")

	// The harness itself delivers before the guard exists.
	_, err := wire.Write(udp4(remote, local, 53, 40000, "before"))
	require.NoError(t, err)
	got, _ := received(t, l, arrives)
	require.Equal(t, "before", got)
	_, err = wire.Write(udp6(remote6, local6, 53, 40000, "before6"))
	require.NoError(t, err)
	got, _ = received(t, l6, arrives)
	require.Equal(t, "before6", got)

	marked := net.ListenConfig{Control: MarkDNSProxySocket}
	src, err := marked.ListenPacket(t.Context(), "udp4", "127.0.0.1:53")
	require.NoError(t, err)
	t.Cleanup(func() { src.Close() })
	lo := listenUDP(t, "127.0.0.1:40001")

	for _, ipv6 := range []bool{false, true} {
		r := NewDNSRedirect(discardLogger())
		require.NoError(t, r.Install(RedirectSpec{IPv6: ipv6}))

		_, err = wire.Write(udp4(net.IPv4(10, 53, 0, 3), local, 53, 40000, "unsolicited"))
		require.NoError(t, err)
		got, _ = received(t, l, absent)
		require.Empty(t, got, "ipv6 %v: an inbound sport-53 packet opening a flow must be dropped", ipv6)

		// The proxy's upstream query: marked, so it leaves by cw0 un-DNAT'd,
		// and the resolver's answer rides the flow it opened.
		upstream, err := marked.ListenPacket(t.Context(), "udp4", "10.53.0.1:0")
		require.NoError(t, err)
		_, err = upstream.WriteTo([]byte("query"), &net.UDPAddr{IP: remote, Port: 53})
		require.NoError(t, err)
		port := uint16(upstream.LocalAddr().(*net.UDPAddr).Port)
		_, err = wire.Write(udp4(remote, local, 53, port, "answer"))
		require.NoError(t, err)
		got, _ = received(t, upstream.(*net.UDPConn), arrives)
		require.Equal(t, "answer", got, "ipv6 %v: a reply to the proxy's own query must pass the guard", ipv6)
		upstream.Close()

		_, err = src.WriteTo([]byte("lo"), lo.LocalAddr())
		require.NoError(t, err)
		got, _ = received(t, lo, arrives)
		require.Equal(t, "lo", got, "ipv6 %v: loopback sport-53 traffic is exempt from the guard", ipv6)

		if ipv6 {
			_, err = wire.Write(udp6(net.ParseIP("fd53::3"), local6, 53, 40000, "unsolicited6"))
			require.NoError(t, err)
			got, _ = received(t, l6, absent)
			require.Empty(t, got, "an inbound IPv6 sport-53 packet opening a flow must be dropped")

			upstream6, err := marked.ListenPacket(t.Context(), "udp6", "[fd53::1]:0")
			require.NoError(t, err)
			_, err = upstream6.WriteTo([]byte("query6"), &net.UDPAddr{IP: remote6, Port: 53})
			require.NoError(t, err)
			port := uint16(upstream6.LocalAddr().(*net.UDPAddr).Port)
			_, err = wire.Write(udp6(remote6, local6, 53, port, "answer6"))
			require.NoError(t, err)
			got, _ = received(t, upstream6.(*net.UDPConn), arrives)
			require.Equal(t, "answer6", got, "a reply to the proxy's own IPv6 query must pass the guard")
			upstream6.Close()
		}

		require.NoError(t, r.Teardown())
	}
}

// TestDNSRedirect_Bridge: DNS a container sends through docker0 or a br-*
// bridge reaches the proxy's listener on the bridge IP with its source kept,
// and DNS arriving on any other interface does not. With IPv6 covered, IPv6
// DNS arriving on a bridge is dropped, wherever it was sent: there is no
// IPv6 listener for it. Here it is sent to a resolver on the host itself,
// which an IPv4-only redirect lets it reach.
func TestDNSRedirect_Bridge(t *testing.T) {
	enterNetns(t)
	bridgeIP := net.IPv4(10, 54, 0, 1)
	resolver := net.IPv4(8, 8, 8, 8)
	docker0 := addTun(t, "docker0", bridgeIP)
	user := addTun(t, "br-test", net.IPv4(10, 55, 0, 1))
	other := addTun(t, "cw0", net.IPv4(10, 56, 0, 1))
	for name, addr := range map[string]string{"docker0": "fd54::1", "br-test": "fd55::1", "cw0": "fd56::1"} {
		addAddr6(t, name, net.ParseIP(addr))
	}
	l := listenUDP(t, "10.54.0.1:53")
	hostResolver6 := listenUDP(t, "[fd56::1]:53")

	for _, ipv6 := range []bool{false, true} {
		r := NewDNSRedirect(discardLogger())
		require.NoError(t, r.Install(RedirectSpec{IPv6: ipv6, BridgeIP: bridgeIP.String()}))

		for _, c := range []struct {
			wire      *os.File
			src, src6 net.IP
		}{
			{docker0, net.IPv4(10, 54, 0, 2), net.ParseIP("fd54::2")},
			{user, net.IPv4(10, 55, 0, 2), net.ParseIP("fd55::2")},
		} {
			_, err := c.wire.Write(udp4(c.src, resolver, 5000, 53, c.wire.Name()))
			require.NoError(t, err)
			got, from := received(t, l, arrives)
			require.Equal(t, c.wire.Name(), got, "ipv6 %v: DNS on %s must reach the bridge listener", ipv6, c.wire.Name())
			require.True(t, from.IP.Equal(c.src), "DNAT must keep the container's source, got %s", from)

			_, err = c.wire.Write(udp6(c.src6, net.ParseIP("fd56::1"), 5000, 53, c.wire.Name()+"6"))
			require.NoError(t, err)
			if ipv6 {
				got, _ = received(t, hostResolver6, absent)
				require.Empty(t, got, "IPv6 DNS on %s must be dropped", c.wire.Name())
			} else {
				got, _ = received(t, hostResolver6, arrives)
				require.Equal(t, c.wire.Name()+"6", got, "an IPv4-only redirect leaves IPv6 container DNS on %s alone",
					c.wire.Name())
			}
		}

		_, err := other.Write(udp4(net.IPv4(10, 56, 0, 2), resolver, 5000, 53, "other"))
		require.NoError(t, err)
		got, _ := received(t, l, absent)
		require.Empty(t, got, "DNS arriving off a docker bridge must not be redirected")
		_, err = other.Write(udp6(net.ParseIP("fd56::2"), net.ParseIP("fd56::1"), 5000, 53, "other6"))
		require.NoError(t, err)
		got, _ = received(t, hostResolver6, arrives)
		require.Equal(t, "other6", got, "ipv6 %v: IPv6 DNS arriving off a docker bridge is no bridge's to drop", ipv6)

		require.NoError(t, r.Teardown())
	}
}

// TestDNSRedirect_AheadOfHostNAT: DNS meets the redirect before the DNAT a
// host nat table applies at dstnat, where Docker's published-port and
// kube-proxy's service DNAT sit, whichever table registered first and
// whichever family the redirect's table is; the proxy's own marked queries
// still get the host's DNAT.
func TestDNSRedirect_AheadOfHostNAT(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 53, 0, 1))
	proxy := listenUDP(t, "127.0.0.1:53")
	service := listenUDP(t, "127.0.0.2:53") // where the host's DNAT sends DNS
	hostNAT := func() func() {
		conn, err := nftables.New()
		require.NoError(t, err)
		table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "hostnat"})
		chain := conn.AddChain(&nftables.Chain{
			Name: "output", Table: table, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest,
		})
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: slices.Concat(
			l4proto(unix.IPPROTO_UDP), port(dstPort, 53), dnat(net.IPv4(127, 0, 0, 2).To4(), 53))})
		require.NoError(t, conn.Flush())
		return func() {
			conn.DelTable(table)
			require.NoError(t, conn.Flush())
		}
	}

	for _, ipv6 := range []bool{false, true} {
		for _, hostFirst := range []bool{true, false} {
			var dropHost func()
			if hostFirst {
				dropHost = hostNAT()
			}
			r := NewDNSRedirect(discardLogger())
			require.NoError(t, r.Install(RedirectSpec{IPv6: ipv6}))
			if !hostFirst {
				dropHost = hostNAT()
			}

			query(t, "10.53.0.2:53", "job", false)
			got, _ := received(t, proxy, arrives)
			require.Equal(t, "job", got, "ipv6 %v, host table first %v: the job's DNS must reach the proxy", ipv6, hostFirst)
			got, _ = received(t, service, absent)
			require.Empty(t, got, "ipv6 %v, host table first %v: the host's DNAT must not win", ipv6, hostFirst)

			query(t, "10.53.0.2:53", "upstream", true)
			got, _ = received(t, service, arrives)
			require.Equal(t, "upstream", got,
				"ipv6 %v, host table first %v: the proxy's own query must get the host's DNAT", ipv6, hostFirst)

			require.NoError(t, r.Teardown())
			dropHost()
		}
	}
}

// TestDNSRedirect_FlushesIPv6Flows: an IPv6 DNS flow is flushed like an
// IPv4 one. Conntrack tracks IPv6 here once the inet table's nat chains hook
// it, so the flow is opened after the install, by a marked query the
// redirect lets leave.
func TestDNSRedirect_FlushesIPv6Flows(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 53, 0, 1))
	addAddr6(t, "cw0", net.ParseIP("fd53::1"))
	r := NewDNSRedirect(discardLogger())
	require.NoError(t, r.Install(RedirectSpec{IPv6: true}))
	t.Cleanup(func() { _ = r.Teardown() })

	dns6 := func() int {
		conn, err := dialCt()
		require.NoError(t, err)
		defer conn.Close()
		tuples, err := dumpTuples(conn, unix.AF_INET6, ctTuple.isDNS)
		require.NoError(t, err)
		return len(tuples)
	}
	query(t, "[fd53::2]:53", "flow6", true)
	require.Equal(t, 1, dns6(), "the marked IPv6 query must leave a flow to flush")
	require.NoError(t, FlushDNSConntrack(discardLogger(), false))
	require.Equal(t, 1, dns6(), "a flush for an IPv4-only redirect must leave IPv6 flows alone")
	require.NoError(t, FlushDNSConntrack(discardLogger(), true))
	require.Zero(t, dns6(), "the flush must delete IPv6 DNS flows")
}

// TestDNSRedirect_InetRefused: a kernel that refuses an inet table, which
// bit 7 of the family byte stands in for, gets the IPv4-only redirect, and
// IPv6Refused says why. A leftover of the other family is still removed.
func TestDNSRedirect_InetRefused(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 53, 0, 1))
	proxy := listenUDP(t, "127.0.0.1:53")
	r := NewDNSRedirect(discardLogger())
	r.inet = 0x80
	require.NoError(t, r.Install(RedirectSpec{IPv6: true}))
	t.Cleanup(func() { _ = r.Teardown() })
	require.Error(t, r.IPv6Refused(), "the refusal must be kept for the caller to report")
	require.Equal(t, map[string]int{"ip output": 8, "ip input": 2}, redirectRules(t))
	query(t, "10.53.0.2:53", "v4", false)
	got, _ := received(t, proxy, arrives)
	require.Equal(t, "v4", got, "the IPv4-only redirect must still redirect")
	require.NoError(t, NewDNSRedirect(discardLogger()).IPv6Refused(), "nothing refused before an install")
	require.NoError(t, removeLeftover(0x80), "a family the kernel lacks has no leftover, and must not fail the install")
}

// TestDNSRedirect_Ownership: the table belongs to the socket that made it.
// No other socket can delete it, a second cargowall in the namespace cannot
// take it over, whichever family either asks for, and closing the socket
// deletes it as surely as teardown.
func TestDNSRedirect_Ownership(t *testing.T) {
	enterNetns(t)
	requireOwnedTables(t)
	logger := discardLogger()
	require.NoError(t, (*DNSRedirect)(nil).Teardown(), "nil is no redirect")

	// A table of this name that no socket owns is replaced, chains and all.
	other, err := nftables.New()
	require.NoError(t, err)
	stale := other.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: RedirectTable})
	other.AddChain(&nftables.Chain{Name: "leftover", Table: stale})
	require.NoError(t, other.Flush())
	r := NewDNSRedirect(logger)
	require.NoError(t, r.Install(RedirectSpec{BridgeIP: "10.54.0.1"}))
	want := map[string]int{"ip output": 8, "ip input": 2, "ip prerouting": 4}
	require.Equal(t, want, redirectRules(t), "setup must replace an unowned table, not add to it")

	for _, ipv6 := range []bool{false, true} {
		err = NewDNSRedirect(logger).Install(RedirectSpec{IPv6: ipv6})
		require.ErrorIs(t, err, unix.EPERM, "ipv6 %v: a second setup must not take over a live redirect", ipv6)
		require.ErrorContains(t, err, "another process owns the table")
	}
	other.DelTable(stale)
	require.ErrorIs(t, other.Flush(), unix.EPERM, "another socket must not delete the table")
	other.FlushRuleset()
	_ = other.Flush()
	require.Equal(t, want, redirectRules(t), "nothing another socket did may touch the table")

	require.Error(t, NewDNSRedirect(logger).Install(RedirectSpec{BridgeIP: "fd00::1"}), "an IPv6 bridge IP is refused")
	require.Error(t, r.Install(RedirectSpec{}), "an installed redirect is not installed twice")

	require.NoError(t, r.Teardown())
	require.Empty(t, redirectRules(t), "teardown must remove the table")
	require.NoError(t, r.Teardown(), "a second teardown is a no-op")
	require.Error(t, r.Install(RedirectSpec{}), "a torn-down redirect is not installed again")
	require.Empty(t, redirectRules(t))

	// Teardown registered ahead of the install, as startup does, and run
	// first by a forced shutdown: the install that follows must not leave a
	// table no undo will remove.
	early := NewDNSRedirect(logger)
	require.NoError(t, early.Teardown(), "nothing installed, nothing to remove")
	require.Error(t, early.Install(RedirectSpec{}))
	require.Empty(t, redirectRules(t))

	// The socket closing without a teardown, as when the process dies.
	for _, ipv6 := range []bool{false, true} {
		r = NewDNSRedirect(logger)
		require.NoError(t, r.Install(RedirectSpec{IPv6: ipv6}))
		require.NotEmpty(t, redirectRules(t))
		require.NoError(t, r.conn.Close())
		require.Empty(t, redirectRules(t), "ipv6 %v: the kernel must delete the table with the socket that owns it", ipv6)
	}
}

// TestDNSRedirect_FamilySwitch: a leftover of the other family, from a run
// that did or did not cover IPv6, goes with the install, so the host never
// carries two redirects; an inet table holds both families' rules.
func TestDNSRedirect_FamilySwitch(t *testing.T) {
	enterNetns(t)
	logger := discardLogger()
	for _, c := range []struct {
		from, to bool
		want     map[string]int
	}{
		{false, true, map[string]int{"inet output": 10, "inet input": 2}},
		{true, false, map[string]int{"ip output": 8, "ip input": 2}},
	} {
		leftover := refusedOwner(logger) // unowned, so it outlives its socket
		require.NoError(t, leftover.Install(RedirectSpec{IPv6: c.from}))
		require.NoError(t, leftover.conn.Close())
		require.NotEmpty(t, redirectRules(t))

		r := NewDNSRedirect(logger)
		require.NoError(t, r.Install(RedirectSpec{IPv6: c.to}))
		require.Equal(t, c.want, redirectRules(t), "from ipv6 %v to %v: the leftover must go", c.from, c.to)
		require.NoError(t, r.Teardown())
		require.Empty(t, redirectRules(t))
	}
}

// TestDNSRedirect_Unowned: a kernel that refuses the owner flag, as those
// before 5.12 do, gets the table unowned. It is the same redirect, but it
// outlives a socket that closes without a teardown, the next install
// replaces it, and another process can delete it.
func TestDNSRedirect_Unowned(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 53, 0, 1))
	proxy := listenUDP(t, "127.0.0.1:53")
	logger := discardLogger()
	want := map[string]int{"ip output": 8, "ip input": 2}

	r := refusedOwner(logger)
	require.NoError(t, r.Install(RedirectSpec{}), "a refused owner flag must fall back to an unowned table")
	require.False(t, r.owned)
	require.Equal(t, want, redirectRules(t))
	query(t, "10.53.0.2:53", "unowned", false)
	got, _ := received(t, proxy, arrives)
	require.Equal(t, "unowned", got, "an unowned table redirects the same")

	// Dying without a teardown leaves it; the next run replaces it.
	require.NoError(t, r.conn.Close())
	require.Equal(t, want, redirectRules(t), "nothing deletes an unowned table with its socket")
	next := refusedOwner(logger)
	require.NoError(t, next.Install(RedirectSpec{}))
	require.Equal(t, want, redirectRules(t), "the next install must replace the leftover, not add to it")
	require.NoError(t, next.Teardown())
	require.Empty(t, redirectRules(t))

	// Teardown deletes the table of the family it installed: nothing else
	// removes an unowned one.
	dual := refusedOwner(logger)
	require.NoError(t, dual.Install(RedirectSpec{IPv6: true}))
	require.Equal(t, map[string]int{"inet output": 10, "inet input": 2}, redirectRules(t))
	require.NoError(t, dual.Teardown())
	require.Empty(t, redirectRules(t), "teardown must remove an unowned inet table")

	// Deleted by another process: DNS went around the proxy from then on,
	// and teardown says so rather than reporting a clean removal.
	r = refusedOwner(logger)
	require.NoError(t, r.Install(RedirectSpec{IPv6: true}))
	other, err := nftables.New()
	require.NoError(t, err)
	other.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: RedirectTable})
	require.NoError(t, other.Flush(), "an unowned table is anyone's to delete")
	require.ErrorContains(t, r.Teardown(), "table inet cargowall was already gone at teardown")
	require.Empty(t, redirectRules(t))
}

// holderEnv makes the test binary, run by TestDNSRedirect_DiesWithProcess,
// a process that installs the redirect and waits to be killed.
const holderEnv = "CARGOWALL_TEST_REDIRECT_HOLDER"

func TestDNSRedirect_Holder(t *testing.T) {
	if os.Getenv(holderEnv) != "1" {
		t.Skip("the redirect-holding child of TestDNSRedirect_DiesWithProcess")
	}
	r := NewDNSRedirect(discardLogger())
	if err := r.Install(RedirectSpec{IPv6: true}); err != nil {
		fmt.Println("setup:", err)
		os.Exit(1)
	}
	fmt.Println("installed")
	time.Sleep(time.Minute)
	// An unreachable redirect would let a GC finalize its socket, deleting
	// the table before the parent's kill.
	runtime.KeepAlive(r)
}

// TestDNSRedirect_DiesWithProcess: a process killed outright, with no
// chance to tear anything down, takes its redirect with it.
func TestDNSRedirect_DiesWithProcess(t *testing.T) {
	enterNetns(t)
	requireOwnedTables(t)
	// Started from this goroutine's thread, so in its namespace.
	child := exec.Command(os.Args[0], "-test.run=^TestDNSRedirect_Holder$")
	child.Env = append(os.Environ(), holderEnv+"=1")
	out, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	line, err := bufio.NewReader(out).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "installed\n", line)
	require.NotEmpty(t, redirectRules(t))

	require.NoError(t, child.Process.Signal(unix.SIGKILL))
	_ = child.Wait()
	require.Empty(t, redirectRules(t), "the redirect must not outlive its process")
}

// refusedOwner is a redirect whose owner flag the kernel refuses, as a
// kernel before 5.12 refuses NFT_TABLE_F_OWNER: bit 31 is no table flag.
func refusedOwner(logger *slog.Logger) *DNSRedirect {
	r := NewDNSRedirect(logger)
	r.ownerFlag = 1 << 31
	return r
}

// requireOwnedTables skips a test of what table ownership guarantees on a
// kernel that cannot own tables (before 5.12), where the redirect goes in
// unowned instead.
func requireOwnedTables(t *testing.T) {
	t.Helper()
	r := NewDNSRedirect(discardLogger())
	require.NoError(t, r.Install(RedirectSpec{}))
	owned := r.owned
	require.NoError(t, r.Teardown())
	if !owned {
		t.Skip("this kernel cannot own nftables tables (5.12)")
	}
}

// redirectRules counts the redirect tables' rules per family and chain
// ("ip output"), read back by google/nftables rather than by the code that
// wrote them.
func redirectRules(t *testing.T) map[string]int {
	t.Helper()
	conn, err := nftables.New()
	require.NoError(t, err)
	out := map[string]int{}
	for family, name := range map[nftables.TableFamily]string{
		nftables.TableFamilyIPv4: "ip", nftables.TableFamilyINet: "inet",
	} {
		chains, err := conn.ListChainsOfTableFamily(family)
		require.NoError(t, err)
		for _, c := range chains {
			if c.Table.Name != RedirectTable {
				continue
			}
			rules, err := conn.GetRules(c.Table, c)
			require.NoError(t, err)
			out[name+" "+c.Name] = len(rules)
		}
	}
	return out
}
