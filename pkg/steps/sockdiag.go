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
	"fmt"
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
// ports make the match unique in practice; the first hit wins. A non-nil
// error means the dump itself failed (netlink unavailable — e.g. a kernel
// without CONFIG_INET_DIAG — send/recv failure, timeout), as opposed to a
// clean dump with no matching socket, so the caller can surface systemic
// breakage instead of conflating it with "socket not found".
//
// An unconnected client (bare sendto, e.g. dig or dnspython — glibc/musl/Go
// resolvers all connect) is auto-bound to the wildcard address, so the
// table shows 0.0.0.0/:: where the wire carried the routed source. Such a
// socket is accepted by port alone, but only when the dump completes with
// exactly one wildcard candidate — misattribution is worse than none.
// (A dual-stack [::]:port socket sending v4-mapped traffic lands in the
// AF_INET6 table while a v4 query prompts an AF_INET dump; out of scope —
// per-family sockets are what the unconnected tools actually use.)
func lookupSocketCookie(family, proto uint8, srcIP net.IP, srcPort uint16) (uint64, bool, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, false, fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	// Bound every recv: this runs on the DNS query path, and a lost
	// NLMSG_DONE (e.g. ENOBUFS under memory pressure) would otherwise block
	// the handler goroutine forever. A timeout fails soft to "not found",
	// which the caller already treats as ordinal 0 (untagged).
	tv := unix.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return 0, false, fmt.Errorf("set recv timeout: %w", err)
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
		return 0, false, fmt.Errorf("netlink send: %w", err)
	}

	var want [16]byte
	if ip4 := srcIP.To4(); ip4 != nil && family == unix.AF_INET {
		copy(want[:4], ip4)
	} else {
		copy(want[:], srcIP.To16())
	}

	// Wildcard-bound fallback candidate (see the function comment). A
	// bound-then-connected socket gets a concrete source from the route,
	// so an all-zero source reliably means unconnected.
	var wildCookie uint64
	wildCount := 0

	rb := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, rb, 0)
		if err != nil {
			return 0, false, fmt.Errorf("netlink recv: %w", err)
		}
		if n <= 0 {
			return 0, false, fmt.Errorf("netlink recv: empty read")
		}
		msgs, err := syscall.ParseNetlinkMessage(rb[:n])
		if err != nil {
			return 0, false, fmt.Errorf("netlink parse: %w", err)
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				if wildCount == 1 {
					return wildCookie, true, nil
				}
				return 0, false, nil
			case unix.NLMSG_ERROR:
				// nlmsgerr carries a negated errno in its first 4 bytes;
				// EOPNOTSUPP here is the CONFIG_INET_DIAG-less kernel.
				if len(m.Data) >= 4 {
					if errno := int32(binary.NativeEndian.Uint32(m.Data[0:4])); errno < 0 {
						return 0, false, fmt.Errorf("netlink error: %w", syscall.Errno(-errno))
					}
				}
				return 0, false, fmt.Errorf("netlink error response")
			}
			if len(m.Data) < sizeofInetDiagMsg {
				continue
			}
			d := m.Data
			sport := uint16(d[4])<<8 | uint16(d[5]) // big-endian in the sock id
			if sport != srcPort {
				continue
			}
			var src [16]byte
			copy(src[:], d[8:24])
			cookieLo := binary.NativeEndian.Uint32(d[44:48])
			cookieHi := binary.NativeEndian.Uint32(d[48:52])
			cookie := uint64(cookieLo) | uint64(cookieHi)<<32
			if src == want {
				return cookie, true, nil
			}
			if src == [16]byte{} {
				wildCookie = cookie
				wildCount++
			}
		}
	}
}

// stepCacheTTL bounds reuse of a client-address resolution. A cookie is
// stable for its socket's lifetime; the risk is the ephemeral (ip, port)
// being reused by a NEW socket inside the window, which the size of the
// ephemeral range makes unlikely within seconds even under churn. Kept
// short regardless: the cache exists to shed query floods (many blocked
// queries from one client socket), not for steady-state savings.
const stepCacheTTL = 2 * time.Second

// stepCacheCap bounds the cache map — a flood of one-query client sockets
// would otherwise grow it without limit. Reset-on-full is crude, but the
// cache is purely a load shed and repopulates immediately.
const stepCacheCap = 4096

// diagConcurrency bounds simultaneous socket-table dumps (each can hold a
// resolver handler goroutine for up to the 500ms recv timeout).
const diagConcurrency = 4

type stepCacheKey struct {
	ip    [16]byte
	port  uint16
	proto uint8
}

type stepCacheEntry struct {
	ordinal uint32
	expires time.Time
}

// StepForClient resolves the step ordinal of the process owning the local
// socket behind addr (a DNS client seen by the proxy). Returns 0 when the
// socket can't be found or carries no tag — callers treat 0 as untagged.
//
// The blocked-query path is adversarial by definition (query floods are
// what filtering exists for), so the netlink dump is guarded twice: a
// short-TTL cache absorbs repeat queries from the same client socket, and
// a semaphore sheds excess concurrent dumps to untagged (uncached, so a
// quieter moment can still resolve that client) rather than stacking them
// under the resolver's handler goroutines.
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

	var key stepCacheKey
	copy(key.ip[:], ip.To16())
	key.port = uint16(port)
	key.proto = proto

	now := time.Now()
	t.stepCacheMu.Lock()
	if e, ok := t.stepCache[key]; ok && now.Before(e.expires) {
		t.stepCacheMu.Unlock()
		return e.ordinal
	}
	t.stepCacheMu.Unlock()

	select {
	case t.diagSem <- struct{}{}:
	default:
		return 0
	}
	defer func() { <-t.diagSem }()

	var ordinal uint32
	cookie, found, err := lookupSocketCookie(family, proto, ip, uint16(port))
	switch {
	case err != nil:
		// One warning for the run: a systemically broken lookup (e.g. a
		// kernel without CONFIG_INET_DIAG) must be distinguishable in the
		// logs from the routine no-match path.
		t.diagWarnOnce.Do(func() {
			t.logger.Warn("Step attribution: socket-cookie lookup failed; DNS events will be untagged",
				"error", err)
		})
	case found:
		if lerr := t.sockMap.Lookup(cookie, &ordinal); lerr != nil {
			ordinal = 0
		}
	}

	// Cache negative results too — unattributable floods are the hot case.
	t.stepCacheMu.Lock()
	if len(t.stepCache) >= stepCacheCap {
		clear(t.stepCache)
	}
	t.stepCache[key] = stepCacheEntry{ordinal: ordinal, expires: now.Add(stepCacheTTL)}
	t.stepCacheMu.Unlock()
	return ordinal
}
