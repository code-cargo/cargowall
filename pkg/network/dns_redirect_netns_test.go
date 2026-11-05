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
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The redirect's tests send real packets through it in a private network
// namespace. TUN interfaces stand in for the host's uplink and for docker
// bridges: a packet written to a TUN arrives on its interface as if it came
// off the wire, and what the kernel routes out of one can be read back.

const (
	arrives = 2 * time.Second        // how long a packet that should land may take
	absent  = 300 * time.Millisecond // how long to watch for one that should not
)

// enterNetns moves the test's goroutine into a fresh network namespace with
// loopback up. The goroutine stays locked to its thread and never unlocks,
// so the thread exits with the test rather than carrying the namespace back
// into the scheduler's pool. Everything the test does from here (sockets,
// and the iptables it runs, which forks from this thread) happens in the
// namespace; subtests would not.
func enterNetns(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for a network namespace and iptables; covered by the sudo test pass")
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
// file whose writes arrive on it and whose reads are what the kernel routes
// out of it. The file is nonblocking, made once the interface is attached,
// so the runtime's poller serves it and a read can time out.
func addTun(t *testing.T, name string, addr net.IP) *os.File {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	require.NoError(t, err)
	ifr, err := unix.NewIfreq(name)
	if err == nil {
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err != nil {
		unix.Close(fd)
		require.NoError(t, err)
	}
	f := os.NewFile(uintptr(fd), name)
	t.Cleanup(func() { f.Close() })

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
	binary.BigEndian.PutUint16(b[10:], inetChecksum(0, b[:20]))
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

// tcp4SYN builds an IPv4/TCP SYN with both checksums: unlike UDP's, TCP's
// is not optional, and the kernel checks it on a packet arriving off a
// TUN.
func tcp4SYN(src, dst net.IP, sport, dport uint16) []byte {
	b := make([]byte, 40)
	b[0] = 0x45 // version 4, 5-word header
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64 // TTL
	b[9] = unix.IPPROTO_TCP
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	binary.BigEndian.PutUint16(b[10:], inetChecksum(0, b[:20]))
	tcp := b[20:]
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], 1)                // sequence number
	tcp[12] = 5 << 4                                      // 5-word header
	tcp[13] = 0x02                                        // SYN
	binary.BigEndian.PutUint16(tcp[14:], 0xffff)          // window
	pseudo := uint32(unix.IPPROTO_TCP) + uint32(len(tcp)) // and both addresses
	binary.BigEndian.PutUint16(tcp[16:], inetChecksum(pseudo, b[12:20], tcp))
	return b
}

// inetChecksum is the internet checksum (RFC 1071) of words, which it sums
// as one run of bytes, folded onto sum: a pseudo-header's length and
// protocol, for a transport checksum. Only the last of words may be of odd
// length, as a payload can be; its last byte is padded with zero.
func inetChecksum(sum uint32, words ...[]byte) uint16 {
	for _, w := range words {
		for i := 0; i+1 < len(w); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(w[i:]))
		}
		if len(w)%2 == 1 {
			sum += uint32(w[len(w)-1]) << 8
		}
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// routedOut reads what the kernel routes out of wire until an IPv4 packet of
// proto from src:sport to dst:dport turns up, and returns its transport
// segment, or nil when none does within arrives.
func routedOut(t *testing.T, wire *os.File, proto byte, src, dst net.IP, sport, dport uint16) []byte {
	t.Helper()
	buf := make([]byte, 1500)
	require.NoError(t, wire.SetReadDeadline(time.Now().Add(arrives)))
	for {
		n, err := wire.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		require.NoError(t, err)
		p := buf[:n]
		if n < 20 || p[0]>>4 != 4 || p[9] != proto || n < int(p[0]&0x0f)*4+8 {
			continue // not IPv4 of proto: the IPv6 the interface sends of its own accord
		}
		l4 := p[int(p[0]&0x0f)*4:]
		if net.IP(p[12:16]).Equal(src) && net.IP(p[16:20]).Equal(dst) &&
			binary.BigEndian.Uint16(l4[0:]) == sport && binary.BigEndian.Uint16(l4[2:]) == dport {
			return l4
		}
	}
}

// synAcked sends a TCP SYN from src:sport to dst:dport in on wire, and
// reports whether a SYN-ACK from dst:dport comes back out of it: a listener
// took the SYN, under whatever DNAT the reply undoes.
func synAcked(t *testing.T, wire *os.File, src, dst net.IP, sport, dport uint16) bool {
	t.Helper()
	_, err := wire.Write(tcp4SYN(src, dst, sport, dport))
	require.NoError(t, err)
	tcp := routedOut(t, wire, unix.IPPROTO_TCP, dst, src, dport, sport)
	return len(tcp) > 13 && tcp[13]&0x12 == 0x12
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

func listenTCP(t *testing.T, addr string) *net.TCPListener {
	t.Helper()
	l, err := net.Listen("tcp4", addr)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	return l.(*net.TCPListener)
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
// own upstream query when marked.
func query(t *testing.T, addr, payload string, marked bool) {
	t.Helper()
	d := net.Dialer{}
	if marked {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var sErr error
			if err := c.Control(func(fd uintptr) {
				sErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, DNSProxyFWMark)
			}); err != nil {
				return err
			}
			return sErr
		}
	}
	c, err := d.Dial("udp4", addr)
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte(payload))
	require.NoError(t, err)
}

// natDNATs is the DNAT rules iptables lists in chain of the nat table.
func natDNATs(t *testing.T, chain string) []string {
	t.Helper()
	out, err := exec.Command("iptables", "-t", "nat", "-S", chain).CombinedOutput()
	require.NoError(t, err, "%s", out)
	var rules []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "DNAT") {
			rules = append(rules, line)
		}
	}
	return rules
}

// TestDNSRedirect_Output: DNS this namespace sends leaves for the proxy at
// 127.0.0.1:53, while the proxy's own marked queries and the rest of
// 127.0.0.0/8 go where they were sent, until the teardown.
func TestDNSRedirect_Output(t *testing.T) {
	enterNetns(t)
	addTun(t, "cw0", net.IPv4(10, 53, 0, 1))
	proxy := listenUDP(t, "127.0.0.1:53")
	resolver := listenUDP(t, "127.0.0.2:53")

	logger := discardLogger()
	require.NoError(t, SetupDNSRedirect(logger))
	t.Cleanup(func() { _ = TeardownDNSRedirect(logger) }) // a failure below skips the Teardown

	query(t, "10.53.0.2:53", "outside", false)
	got, _ := received(t, proxy, arrives)
	require.Equal(t, "outside", got, "DNS for an outside resolver must reach the proxy")

	query(t, "10.53.0.2:53", "marked", true)
	got, _ = received(t, proxy, absent)
	require.Empty(t, got, "the proxy's own marked query must not be redirected back to it")

	query(t, "127.0.0.2:53", "loopback", false)
	got, _ = received(t, resolver, arrives)
	require.Equal(t, "loopback", got, "loopback DNS must go where it was sent")

	require.NoError(t, TeardownDNSRedirect(logger))
	require.Empty(t, natDNATs(t, "OUTPUT"), "the teardown must remove every rule")
	query(t, "10.53.0.2:53", "after", false)
	got, _ = received(t, proxy, absent)
	require.Empty(t, got, "DNS must not reach the proxy once the redirect is torn down")
}

// TestDNSRedirect_ContainerBridges: DNS arriving on docker0 for a resolver
// outside docker0's subnet, private or public, and DNS arriving on a br-*
// bridge for a public resolver, reaches the proxy's listener on the docker0
// address with the container's source kept, and its answer leaves as if
// from the resolver the container asked. DNS for docker0's own subnet, for a
// private resolver from a br-* bridge, or arriving on any other interface is
// left alone, and the teardown removes the redirect.
func TestDNSRedirect_ContainerBridges(t *testing.T) {
	enterNetns(t)
	public := net.IPv4(8, 8, 8, 8)
	cluster := net.IPv4(10, 96, 0, 10) // a private resolver, as a pod's cluster DNS is
	docker0 := addTun(t, "docker0", net.IPv4(10, 54, 0, 1))
	user := addTun(t, "br-test", net.IPv4(10, 55, 0, 1))
	other := addTun(t, "cw0", net.IPv4(10, 56, 0, 1))
	bridge := &net.IPNet{IP: net.IPv4(10, 54, 0, 1).To4(), Mask: net.CIDRMask(24, 32)}
	l := listenUDP(t, "10.54.0.1:53")
	listenTCP(t, "10.54.0.1:53")

	_, err := docker0.Write(udp4(net.IPv4(10, 54, 0, 2), public, 4000, 53, "before"))
	require.NoError(t, err)
	got, _ := received(t, l, absent)
	require.Empty(t, got, "container DNS for an outside resolver reached the listener with no redirect installed")

	logger := discardLogger()
	require.NoError(t, SetupContainerDNSRedirect(bridge, logger))
	t.Cleanup(func() { _ = TeardownContainerDNSRedirect(bridge, logger) }) // a failure below skips the Teardown
	require.Len(t, natDNATs(t, "PREROUTING"), 4, "a UDP and a TCP rule for each of docker0 and br-+")

	sport := uint16(6000) // a port per TCP handshake: none reuses a half-open one
	for _, c := range []struct {
		wire       *os.File
		src        net.IP
		redirected []net.IP // the listener answers, as these
		alone      []net.IP // not redirected
	}{
		// docker0's gateway is the listener itself, reached with no DNAT:
		// what a container asks when Docker points it at cargowall.
		{
			docker0, net.IPv4(10, 54, 0, 2),
			[]net.IP{public, cluster, net.IPv4(10, 54, 0, 1)},
			[]net.IP{net.IPv4(10, 54, 0, 53)},
		},
		{
			user, net.IPv4(10, 55, 0, 2),
			[]net.IP{public},
			[]net.IP{cluster, net.IPv4(10, 55, 0, 53), net.IPv4(10, 55, 0, 1)},
		},
	} {
		name := c.wire.Name()
		for _, dst := range c.redirected {
			_, err := c.wire.Write(udp4(c.src, dst, 5000, 53, name))
			require.NoError(t, err)
			got, from := received(t, l, arrives)
			require.Equal(t, name, got, "DNS on %s for %s must reach the bridge listener", name, dst)
			require.True(t, from.IP.Equal(c.src), "DNAT must keep the container's source, got %s", from)

			_, err = l.WriteToUDP([]byte("answer"), from)
			require.NoError(t, err)
			reply := routedOut(t, c.wire, unix.IPPROTO_UDP, dst, c.src, 53, 5000)
			require.NotNil(t, reply, "the answer to %s's query must leave %s as if from %s:53", c.src, name, dst)
			require.Equal(t, "answer", string(reply[8:]))
		}
		for _, dst := range c.alone {
			_, err := c.wire.Write(udp4(c.src, dst, 5000, 53, name))
			require.NoError(t, err)
			got, _ := received(t, l, absent)
			require.Empty(t, got, "DNS on %s for %s must not be redirected", name, dst)
		}
		sport++
		require.True(t, synAcked(t, c.wire, c.src, public, sport, 53),
			"TCP DNS on %s must reach the bridge listener", name)
	}

	_, err = other.Write(udp4(net.IPv4(10, 56, 0, 2), public, 5000, 53, "other"))
	require.NoError(t, err)
	got, _ = received(t, l, absent)
	require.Empty(t, got, "DNS arriving off a docker bridge must not be redirected")

	require.NoError(t, TeardownContainerDNSRedirect(bridge, logger))
	require.Empty(t, natDNATs(t, "PREROUTING"), "the teardown must remove every rule")
	// A fresh source port: the flow above keeps its DNAT for as long as
	// conntrack remembers it.
	_, err = docker0.Write(udp4(net.IPv4(10, 54, 0, 2), public, 5001, 53, "after"))
	require.NoError(t, err)
	got, _ = received(t, l, absent)
	require.Empty(t, got, "container DNS must not reach the listener once the redirect is torn down")
}

// TestDNSRedirect_BridgedDNSLeftAlone: with br_netfilter running iptables on
// bridged frames, as on every Kubernetes node, DNS one container sends
// another on the same bridge (a compose service, a kind node) still reaches
// it, on docker0 and on a br-* bridge, while DNS sent to the bridge for a
// public resolver is redirected. TAPs stand in for the containers' veths:
// a frame written to one enters the bridge as from that container.
func TestDNSRedirect_BridgedDNSLeftAlone(t *testing.T) {
	enterNetns(t)
	enableBridgeNetfilter(t)
	bridge := &net.IPNet{IP: net.IPv4(10, 54, 0, 1).To4(), Mask: net.CIDRMask(24, 32)}
	macA := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}
	macB := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b}

	type side struct {
		bridge     string
		gw, a, b   net.IP
		tapA, tapB *os.File
	}
	sides := []side{
		{bridge: "docker0", gw: net.IPv4(10, 54, 0, 1), a: net.IPv4(10, 54, 0, 2), b: net.IPv4(10, 54, 0, 53)},
		{bridge: "br-test", gw: net.IPv4(10, 55, 0, 1), a: net.IPv4(10, 55, 0, 2), b: net.IPv4(10, 55, 0, 53)},
	}
	for i := range sides {
		s := &sides[i]
		s.tapA = addTap(t, s.bridge+"-a")
		s.tapB = addTap(t, s.bridge+"-b")
		addBridge(t, s.bridge, s.gw, s.bridge+"-a", s.bridge+"-b")
	}
	l := listenUDP(t, "10.54.0.1:53")

	logger := discardLogger()
	require.NoError(t, SetupContainerDNSRedirect(bridge, logger))
	t.Cleanup(func() { _ = TeardownContainerDNSRedirect(bridge, logger) })

	for _, s := range sides {
		iface, err := net.InterfaceByName(s.bridge)
		require.NoError(t, err)

		_, err = s.tapA.Write(ether(macB, macA, udp4(s.a, s.b, 5000, 53, "bridged")))
		require.NoError(t, err)
		got, _ := received(t, l, absent)
		require.Empty(t, got, "DNS from one container to another on %s must not be redirected", s.bridge)
		require.NotNil(t, bridgedOut(t, s.tapB, s.a, s.b, "bridged"),
			"DNS from one container to another on %s must reach it", s.bridge)

		_, err = s.tapA.Write(ether(iface.HardwareAddr, macA, udp4(s.a, net.IPv4(8, 8, 8, 8), 5001, 53, "routed")))
		require.NoError(t, err)
		got, _ = received(t, l, arrives)
		require.Equal(t, "routed", got, "DNS on %s for a public resolver must reach the bridge listener", s.bridge)
	}
}

// enableBridgeNetfilter loads br_netfilter and turns on its iptables pass
// for bridged IPv4 in this namespace. The module stays loaded: removing it
// with modprobe -r also removes the bridge module, which no bridge device
// pins, and that deletes every bridge on the host, docker0 included.
func enableBridgeNetfilter(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("modprobe", "br_netfilter").CombinedOutput(); err != nil {
		t.Skipf("br_netfilter unavailable: %v: %s", err, out)
	}
	// Net sysctls are the writing thread's namespace's.
	require.NoError(t, os.WriteFile("/proc/sys/net/bridge/bridge-nf-call-iptables", []byte("1"), 0))
}

// addTap creates TAP interface name, up and with no address, and returns
// the file whose writes arrive on it as Ethernet frames and whose reads are
// the frames the kernel sends out of it.
func addTap(t *testing.T, name string) *os.File {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	require.NoError(t, err)
	ifr, err := unix.NewIfreq(name)
	if err == nil {
		ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err != nil {
		unix.Close(fd)
		require.NoError(t, err)
	}
	f := os.NewFile(uintptr(fd), name)
	t.Cleanup(func() { f.Close() })
	setLinkUp(t, name)
	return f
}

// addBridge creates bridge name holding addr/24, enslaves ports to it, and
// brings it up.
func addBridge(t *testing.T, name string, addr net.IP, ports ...string) {
	t.Helper()
	ip := func(args ...string) {
		out, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "ip %v: %s", args, out)
	}
	ip("link", "add", "name", name, "type", "bridge")
	ip("addr", "add", addr.String()+"/24", "dev", name)
	for _, port := range ports {
		ip("link", "set", port, "master", name)
	}
	ip("link", "set", name, "up")
}

// ether frames an IPv4 packet for dst from src.
func ether(dst, src net.HardwareAddr, packet []byte) []byte {
	b := make([]byte, 14, 14+len(packet))
	copy(b[0:6], dst)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	return append(b, packet...)
}

// bridgedOut reads frames out of wire until an IPv4/UDP one from src to dst
// carrying payload turns up, and returns it, or nil when none does within
// arrives.
func bridgedOut(t *testing.T, wire *os.File, src, dst net.IP, payload string) []byte {
	t.Helper()
	buf := make([]byte, 1514)
	require.NoError(t, wire.SetReadDeadline(time.Now().Add(arrives)))
	for {
		n, err := wire.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		require.NoError(t, err)
		f := buf[:n]
		if n < 14+28 || binary.BigEndian.Uint16(f[12:]) != 0x0800 {
			continue // not IPv4: the IPv6 the interfaces send of their own accord
		}
		p := f[14:]
		if p[9] == unix.IPPROTO_UDP && net.IP(p[12:16]).Equal(src) && net.IP(p[16:20]).Equal(dst) &&
			strings.HasSuffix(string(p), payload) {
			return f
		}
	}
}
