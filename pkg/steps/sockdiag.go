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

package steps

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// sockdiag resolves a local socket's kernel cookie from its source address,
// via NETLINK_SOCK_DIAG. The DNS proxy uses this to attribute a query to
// the step whose process sent it: source address → cookie → map_sock_step.
//
// A dump (filtered client-side by source) is used instead of an exact
// 4-tuple lookup deliberately: the iptables REDIRECT that steers DNS to the
// proxy rewrites the packet, not the client socket, so the client's socket
// still names the ORIGINAL resolver as its peer — the proxy-side 4-tuple
// doesn't exist in the client's socket table.

// inetDiagSockID mirrors struct inet_diag_sockid (ports/addrs big-endian).
type inetDiagSockID struct {
	SPort  [2]byte
	DPort  [2]byte
	Src    [16]byte
	Dst    [16]byte
	If     uint32
	Cookie [2]uint32
}

// inetDiagReqV2 mirrors struct inet_diag_req_v2.
type inetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       inetDiagSockID
}

// Responses are struct inet_diag_msg: 4 header bytes, then the sock id
// (ports big-endian at 4..8, src at 8..24, dst at 24..40, ifindex at
// 40..44, cookie at 44..52), then counters — parsed by offset below and
// pinned against SO_COOKIE in TestLookupSocketCookie_*.
const (
	sizeofInetDiagReqV2 = 56
	sizeofInetDiagMsg   = 72
)

// lookupSocketCookie dumps the kernel's socket table for (family, proto)
// and returns the cookie of the socket bound to srcIP:srcPort. Ephemeral
// ports make the match unique in practice; the first hit wins.
func lookupSocketCookie(family, proto uint8, srcIP net.IP, srcPort uint16) (uint64, bool) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, false
	}
	defer unix.Close(fd)

	// Bound every recv: this runs on the DNS query path, and a lost
	// NLMSG_DONE (e.g. ENOBUFS under memory pressure) would otherwise block
	// the handler goroutine forever. A timeout fails soft to "not found",
	// which the caller already treats as ordinal 0 (untagged).
	tv := unix.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return 0, false
	}

	req := inetDiagReqV2{
		Family:   family,
		Protocol: proto,
		States:   ^uint32(0),
	}
	buf := make([]byte, unix.NLMSG_HDRLEN+sizeofInetDiagReqV2)
	binary.NativeEndian.PutUint32(buf[0:4], uint32(len(buf)))
	binary.NativeEndian.PutUint16(buf[4:6], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(buf[8:12], 1)  // seq
	binary.NativeEndian.PutUint32(buf[12:16], 0) // pid
	p := buf[unix.NLMSG_HDRLEN:]
	p[0], p[1], p[2], p[3] = req.Family, req.Protocol, req.Ext, req.Pad
	binary.NativeEndian.PutUint32(p[4:8], req.States)
	// ID stays zero for a dump.

	if err := unix.Sendto(fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, false
	}

	var want [16]byte
	if ip4 := srcIP.To4(); ip4 != nil && family == unix.AF_INET {
		copy(want[:4], ip4)
	} else {
		copy(want[:], srcIP.To16())
	}

	rb := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, rb, 0)
		if err != nil || n <= 0 {
			return 0, false
		}
		msgs, err := syscall.ParseNetlinkMessage(rb[:n])
		if err != nil {
			return 0, false
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE, unix.NLMSG_ERROR:
				return 0, false
			}
			if len(m.Data) < sizeofInetDiagMsg {
				continue
			}
			d := m.Data
			sport := uint16(d[4])<<8 | uint16(d[5]) // big-endian in the sock id
			var src [16]byte
			copy(src[:], d[8:24])
			if sport != srcPort || src != want {
				continue
			}
			cookieLo := binary.NativeEndian.Uint32(d[44:48])
			cookieHi := binary.NativeEndian.Uint32(d[48:52])
			return uint64(cookieLo) | uint64(cookieHi)<<32, true
		}
	}
}

// StepForClient resolves the step ordinal of the process owning the local
// socket behind addr (a DNS client seen by the proxy). Returns 0 when the
// socket can't be found or carries no tag — callers treat 0 as untagged.
func (t *Tracker) StepForClient(addr net.Addr) uint32 {
	var ip net.IP
	var port int
	var proto uint8
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, port, proto = a.IP, a.Port, unix.IPPROTO_UDP
	case *net.TCPAddr:
		ip, port, proto = a.IP, a.Port, unix.IPPROTO_TCP
	default:
		return 0
	}
	family := uint8(unix.AF_INET6)
	if ip.To4() != nil {
		family = unix.AF_INET
	}
	cookie, ok := lookupSocketCookie(family, proto, ip, uint16(port))
	if !ok {
		return 0
	}
	var ordinal uint32
	if err := t.sockMap.Lookup(cookie, &ordinal); err != nil {
		return 0
	}
	return ordinal
}
