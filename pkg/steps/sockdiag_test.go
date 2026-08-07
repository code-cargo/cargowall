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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The diag lookup must return exactly the cookie the kernel assigned to the
// socket (cross-checked via SO_COOKIE), keyed only by source address — the
// same view the DNS proxy has of a redirected client.
func TestLookupSocketCookie_UDP(t *testing.T) {
	// A connected UDP socket, like a stub resolver client.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
	require.NoError(t, err)
	defer conn.Close()

	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	var wantCookie uint64
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		wantCookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}))
	require.NoError(t, sockErr)

	local := conn.LocalAddr().(*net.UDPAddr)
	cookie, ok, err := lookupSocketCookie(unix.AF_INET, unix.IPPROTO_UDP, local.IP, uint16(local.Port))
	require.NoError(t, err)
	require.True(t, ok, "socket must be found by source address")
	assert.Equal(t, wantCookie, cookie)
}

func TestLookupSocketCookie_TCP(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	raw, err := conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	var wantCookie uint64
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		wantCookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}))
	require.NoError(t, sockErr)

	local := conn.LocalAddr().(*net.TCPAddr)
	cookie, ok, err := lookupSocketCookie(unix.AF_INET, unix.IPPROTO_TCP, local.IP, uint16(local.Port))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, wantCookie, cookie)
}

func TestLookupSocketCookie_NotFound(t *testing.T) {
	// Port 1 with no socket bound: dump completes cleanly without a match,
	// which must NOT surface as an error (errors mean the dump itself broke).
	_, ok, err := lookupSocketCookie(unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), 1)
	require.NoError(t, err)
	assert.False(t, ok)
}

// A bare-sendto client (dig-style, never connected) is auto-bound to the
// wildcard address, so the kernel table shows 0.0.0.0 where the proxy saw
// the routed source. The unique-wildcard fallback must still resolve it to
// exactly the kernel-assigned cookie.
func TestLookupSocketCookie_UnconnectedUDPWildcard(t *testing.T) {
	conn, err := net.ListenUDP("udp4", nil)
	require.NoError(t, err)
	defer conn.Close()

	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	var wantCookie uint64
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		wantCookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}))
	require.NoError(t, sockErr)

	// Look up by the proxy's view — a concrete source IP that can never
	// equal the socket's wildcard bind address, forcing the fallback.
	local := conn.LocalAddr().(*net.UDPAddr)
	cookie, ok, err := lookupSocketCookie(unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), uint16(local.Port))
	require.NoError(t, err)
	require.True(t, ok, "wildcard-bound socket must be found by port")
	assert.Equal(t, wantCookie, cookie)
}
