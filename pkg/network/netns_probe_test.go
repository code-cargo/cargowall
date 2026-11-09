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

// Probes for the namespace tests: the packets they write to TUN and TAP
// interfaces, and the listeners and checks that tell whether one landed.

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

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
	check := inetChecksum(uint32(len(udp))+unix.IPPROTO_UDP, b[8:40], udp)
	if check == 0 {
		check = 0xffff // zero is no checksum, which IPv6 refuses
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

// synAcked sends a TCP SYN from src:sport to dst:dport in on wire, and
// reports whether a SYN-ACK from dst:dport comes back out of it: a listener
// took the SYN, under whatever DNAT the reply undoes.
func synAcked(t *testing.T, wire *os.File, src, dst net.IP, sport, dport uint16) bool {
	t.Helper()
	_, err := wire.Write(tcp4SYN(src, dst, sport, dport))
	require.NoError(t, err)
	buf := make([]byte, 1500)
	require.NoError(t, wire.SetReadDeadline(time.Now().Add(arrives)))
	for {
		n, err := wire.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false
		}
		require.NoError(t, err)
		p := buf[:n]
		if n < 20 || p[0]>>4 != 4 || p[9] != unix.IPPROTO_TCP || n < int(p[0]&0x0f)*4+20 {
			continue // not IPv4 TCP: the IPv6 the interface sends of its own accord
		}
		tcp := p[int(p[0]&0x0f)*4:]
		if net.IP(p[12:16]).Equal(dst) && net.IP(p[16:20]).Equal(src) &&
			binary.BigEndian.Uint16(tcp[0:]) == dport && binary.BigEndian.Uint16(tcp[2:]) == sport &&
			tcp[13]&0x12 == 0x12 {
			return true
		}
	}
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

// resentUntil writes pkt to wire, again every resend, until l gets want or
// wait runs out, and reports what l got as received does. An IPv6 packet
// written to a TUN or TAP can find no input route while other network
// namespaces come and go (Ip6InNoRoutes, and an ICMPv6 unreachable back:
// about 1 in 80 under ip netns add/del churn, never for IPv4 or for a
// socket's own sends), so one that should land gets more than one try.
// Anything else l reads is skipped: an earlier probe's extra copy can come
// late. So a probe sent to the same listener again takes a payload of its
// own, or the earlier one's extra copy would answer for it.
func resentUntil(t *testing.T, wire *os.File, pkt []byte, l *net.UDPConn, want string,
	wait time.Duration,
) (string, *net.UDPAddr) {
	t.Helper()
	for end := time.Now().Add(wait); time.Now().Before(end); {
		_, err := wire.Write(pkt)
		require.NoError(t, err)
		again := time.Now().Add(min(resend, time.Until(end)))
		for time.Now().Before(again) {
			if got, from := received(t, l, time.Until(again)); got == want {
				return got, from
			}
		}
	}
	return "", nil
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
	// How long resentUntil waits on one copy before it sends another: past
	// absent, so a packet that should not land is still sent once, and long
	// enough that a copy that is only slow, not lost, rarely gets a twin
	// for a later check to read.
	resend = time.Second
)
