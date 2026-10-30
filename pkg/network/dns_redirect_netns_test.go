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
	"os"
	"runtime"
	"testing"
	"time"

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

func listenUDP(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp4", addr)
	require.NoError(t, err)
	c, err := net.ListenUDP("udp4", ua)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
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
	c, err := d.Dial("udp4", addr)
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
// marked queries and the rest of 127.0.0.0/8 go where they were sent.
func TestDNSRedirect_Output(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 53, 0, 1))
	proxy := listenUDP(t, "127.0.0.1:53")
	proxyTCP, err := net.Listen("tcp4", "127.0.0.1:53")
	require.NoError(t, err)
	t.Cleanup(func() { proxyTCP.Close() })

	// Without the redirect a query for an outside resolver leaves by cw0.
	query(t, "10.53.0.2:53", "before", false)
	got, _ := received(t, proxy, absent)
	require.Empty(t, got, "the query reached the proxy with no redirect installed")

	require.NoError(t, SetupDNSRedirect(discardLogger(), ""))
	t.Cleanup(func() { _ = TeardownDNSRedirect(discardLogger()) })

	query(t, "10.53.0.2:53", "outside", false)
	got, _ = received(t, proxy, arrives)
	require.Equal(t, "outside", got, "UDP DNS for an outside resolver must reach the proxy")

	query(t, "127.0.0.53:53", "stub", false)
	got, _ = received(t, proxy, arrives)
	require.Equal(t, "stub", got, "UDP DNS for the resolved stub must reach the proxy")

	for _, dst := range []string{"10.53.0.2:53", "127.0.0.53:53"} {
		c, err := net.DialTimeout("tcp4", dst, arrives)
		require.NoError(t, err, "TCP DNS for %s must reach the proxy", dst)
		c.Close()
		require.NoError(t, proxyTCP.(*net.TCPListener).SetDeadline(time.Now().Add(arrives)))
		a, err := proxyTCP.Accept()
		require.NoError(t, err, "the proxy's TCP listener did not get the %s connection", dst)
		a.Close()
	}

	query(t, "10.53.0.2:53", "marked", true)
	got, _ = received(t, proxy, absent)
	require.Empty(t, got, "the proxy's own marked query must not be redirected back to it")

	query(t, "127.0.0.2:53", "loopback", false)
	got, _ = received(t, proxy, absent)
	require.Empty(t, got, "loopback DNS other than the stub must not be redirected")
}

// TestDNSRedirect_InputGuard: a sport-53 packet that would open a flow from
// outside is dropped, a reply to the proxy's own upstream query is not, and
// loopback is exempt.
func TestDNSRedirect_InputGuard(t *testing.T) {
	enterNetns(t)
	local, remote := net.IPv4(10, 53, 0, 1), net.IPv4(10, 53, 0, 2)
	wire := addTun(t, "cw0", local)
	l := listenUDP(t, "10.53.0.1:40000")

	// The harness itself delivers before the guard exists.
	_, err := wire.Write(udp4(remote, local, 53, 40000, "before"))
	require.NoError(t, err)
	got, _ := received(t, l, arrives)
	require.Equal(t, "before", got)

	require.NoError(t, SetupDNSRedirect(discardLogger(), ""))
	t.Cleanup(func() { _ = TeardownDNSRedirect(discardLogger()) })

	_, err = wire.Write(udp4(net.IPv4(10, 53, 0, 3), local, 53, 40000, "unsolicited"))
	require.NoError(t, err)
	got, _ = received(t, l, absent)
	require.Empty(t, got, "an inbound sport-53 packet opening a flow must be dropped")

	// The proxy's upstream query: marked, so it leaves by cw0 un-DNAT'd,
	// and the resolver's answer rides the flow it opened.
	marked := net.ListenConfig{Control: MarkDNSProxySocket}
	upstream, err := marked.ListenPacket(t.Context(), "udp4", "10.53.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { upstream.Close() })
	_, err = upstream.WriteTo([]byte("query"), &net.UDPAddr{IP: remote, Port: 53})
	require.NoError(t, err)
	port := uint16(upstream.LocalAddr().(*net.UDPAddr).Port)
	_, err = wire.Write(udp4(remote, local, 53, port, "answer"))
	require.NoError(t, err)
	got, _ = received(t, upstream.(*net.UDPConn), arrives)
	require.Equal(t, "answer", got, "a reply to the proxy's own query must pass the guard")

	src, err := marked.ListenPacket(t.Context(), "udp4", "127.0.0.1:53")
	require.NoError(t, err)
	t.Cleanup(func() { src.Close() })
	lo := listenUDP(t, "127.0.0.1:40001")
	_, err = src.WriteTo([]byte("lo"), lo.LocalAddr())
	require.NoError(t, err)
	got, _ = received(t, lo, arrives)
	require.Equal(t, "lo", got, "loopback sport-53 traffic is exempt from the guard")
}

// TestDNSRedirect_Bridge: DNS a container sends through docker0 or a br-*
// bridge reaches the proxy's listener on the bridge IP with its source kept,
// and DNS arriving on any other interface does not.
func TestDNSRedirect_Bridge(t *testing.T) {
	enterNetns(t)
	bridgeIP := net.IPv4(10, 54, 0, 1)
	resolver := net.IPv4(8, 8, 8, 8)
	docker0 := addTun(t, "docker0", bridgeIP)
	user := addTun(t, "br-test", net.IPv4(10, 55, 0, 1))
	other := addTun(t, "cw0", net.IPv4(10, 56, 0, 1))
	l := listenUDP(t, "10.54.0.1:53")

	require.NoError(t, SetupDNSRedirect(discardLogger(), bridgeIP.String()))
	t.Cleanup(func() { _ = TeardownDNSRedirect(discardLogger()) })

	for _, c := range []struct {
		wire *os.File
		src  net.IP
	}{{docker0, net.IPv4(10, 54, 0, 2)}, {user, net.IPv4(10, 55, 0, 2)}} {
		_, err := c.wire.Write(udp4(c.src, resolver, 5000, 53, c.wire.Name()))
		require.NoError(t, err)
		got, from := received(t, l, arrives)
		require.Equal(t, c.wire.Name(), got, "DNS on %s must reach the bridge listener", c.wire.Name())
		require.True(t, from.IP.Equal(c.src), "DNAT must keep the container's source, got %s", from)
	}

	_, err := other.Write(udp4(net.IPv4(10, 56, 0, 2), resolver, 5000, 53, "other"))
	require.NoError(t, err)
	got, _ := received(t, l, absent)
	require.Empty(t, got, "DNS arriving off a docker bridge must not be redirected")
}

// TestDNSRedirect_ReplaceAndTeardown: setup replaces whatever table an
// earlier run left rather than adding to it, and teardown removes the table
// and is a quiet no-op when there is none.
func TestDNSRedirect_ReplaceAndTeardown(t *testing.T) {
	enterNetns(t)
	logger := discardLogger()
	require.NoError(t, TeardownDNSRedirect(logger), "teardown with nothing installed")

	chainRules := func() map[string]int {
		conn, err := nftables.New()
		require.NoError(t, err)
		table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: RedirectTable}
		chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
		require.NoError(t, err)
		out := map[string]int{}
		for _, c := range chains {
			if c.Table.Name != RedirectTable {
				continue
			}
			rules, err := conn.GetRules(table, c)
			require.NoError(t, err)
			out[c.Name] = len(rules)
		}
		return out
	}

	require.NoError(t, SetupDNSRedirect(logger, "10.54.0.1"))
	require.NoError(t, SetupDNSRedirect(logger, "10.54.0.1"))
	require.Equal(t, map[string]int{"output": 6, "input": 2, "prerouting": 4}, chainRules(),
		"a second setup must replace the table, not add to it")

	require.NoError(t, SetupDNSRedirect(logger, ""))
	require.Equal(t, map[string]int{"output": 6, "input": 2}, chainRules(),
		"setup without a bridge must not keep an earlier run's bridge chain")

	require.Error(t, SetupDNSRedirect(logger, "fd00::1"), "an IPv6 bridge IP is refused")
	require.Equal(t, map[string]int{"output": 6, "input": 2}, chainRules(),
		"a refused setup leaves the table as it was")

	require.NoError(t, TeardownDNSRedirect(logger))
	require.Empty(t, chainRules(), "teardown must remove the table")
	require.NoError(t, TeardownDNSRedirect(logger), "a second teardown is a no-op")
}
