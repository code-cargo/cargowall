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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/events"
)

// dumpAndMatch is one table dump plus one pure match. A dump failure fails
// the test: these tests pin resolution behavior, not error handling.
func dumpAndMatch(t *testing.T, family, proto uint8, ip net.IP, port uint16) (uint64, matchKind) {
	t.Helper()
	rows, err := dumpSocketTable(family, proto)
	require.NoError(t, err)
	return matchCookie(rows, port, wantBytes(family, ip))
}

// soCookie reads the kernel-assigned SO_COOKIE the dump must reproduce.
func soCookie(t *testing.T, c interface {
	SyscallConn() (syscall.RawConn, error)
},
) uint64 {
	t.Helper()
	raw, err := c.SyscallConn()
	require.NoError(t, err)
	var cookie uint64
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		cookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}))
	require.NoError(t, sockErr)
	return cookie
}

// fdCookie reads SO_COOKIE from a raw fd.
func fdCookie(t *testing.T, fd int) uint64 {
	t.Helper()
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)
	return cookie
}

// dualStackConn creates an AF_INET6 V6ONLY=0 UDP socket connected to
// ::ffff:127.0.0.1:dstPort — a socket that lives only in the v6 table while
// its traffic is v4. Returns the fd and its auto-bound port.
func dualStackConn(t *testing.T, dstPort int) (int, uint16) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	require.NoError(t, unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0))
	require.NoError(t, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1))

	var sa unix.SockaddrInet6
	sa.Port = dstPort
	copy(sa.Addr[:], net.IPv4(127, 0, 0, 1).To16()) // ::ffff:127.0.0.1
	require.NoError(t, unix.Connect(fd, &sa))

	local, err := unix.Getsockname(fd)
	require.NoError(t, err)
	return fd, uint16(local.(*unix.SockaddrInet6).Port)
}

// The dump+match must return exactly the cookie the kernel assigned to the
// socket (cross-checked via SO_COOKIE), keyed only by source address — the
// same view the DNS proxy has of a redirected client.
func TestDumpSocketTable_UDP(t *testing.T) {
	// A connected UDP socket, like a stub resolver client.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
	require.NoError(t, err)
	defer conn.Close()

	local := conn.LocalAddr().(*net.UDPAddr)
	cookie, kind := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, local.IP, uint16(local.Port))
	require.Equal(t, matchExact, kind, "socket must be found by source address")
	assert.Equal(t, soCookie(t, conn), cookie)
}

func TestDumpSocketTable_TCP(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	local := conn.LocalAddr().(*net.TCPAddr)
	cookie, kind := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_TCP, local.IP, uint16(local.Port))
	require.Equal(t, matchExact, kind)
	assert.Equal(t, soCookie(t, conn.(*net.TCPConn)), cookie)
}

func TestDumpSocketTable_NotFound(t *testing.T) {
	// Port 1 with no socket bound: dump completes cleanly without a match,
	// which must NOT surface as an error (errors mean the dump itself broke).
	_, kind := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), 1)
	assert.Equal(t, matchNone, kind)
}

// A live loopback listener (the DNS proxy), a connected client that has
// SENT a datagram the listener already received, and the lookup running
// while the client is parked in recv — exactly what the refusal path sees,
// since attribution runs before the REFUSED write. TestDumpSocketTable_UDP
// covers connect-without-traffic; this pins that a socket with traffic
// through it stays visible to the dump.
func TestDumpSocketTable_UDP_AfterSend(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer srv.Close()

	conn, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("query"))
	require.NoError(t, err)
	require.NoError(t, srv.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, _, err = srv.ReadFromUDP(make([]byte, 64))
	require.NoError(t, err)

	local := conn.LocalAddr().(*net.UDPAddr)
	cookie, kind := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, local.IP, uint16(local.Port))
	require.Equal(t, matchExact, kind, "socket with sent traffic must be found by source address")
	assert.Equal(t, soCookie(t, conn), cookie)
}

// TestHelperUDPClient is not a test: it is the child half of
// TestDumpSocketTable_ChildProcessSocket, re-exec'd from the test binary.
// It dials the target, sends one datagram, and stays alive (blocked in read)
// until killed — a mid-query resolver client in another process.
func TestHelperUDPClient(t *testing.T) {
	target := os.Getenv("SOCKDIAG_CHILD_TARGET")
	if target == "" {
		t.Skip("helper process for TestDumpSocketTable_ChildProcessSocket")
	}
	conn, err := net.Dial("udp4", target)
	if err != nil {
		fmt.Println("ERR", err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("query")); err != nil {
		fmt.Println("ERR", err)
		return
	}
	_, _ = conn.Read(make([]byte, 64)) // parked until the parent kills us
}

// The dump must resolve sockets it does not own: the DNS proxy's clients
// are other processes' resolver sockets, while every other test here dumps
// a same-process socket. The child is the test binary re-exec'd into
// TestHelperUDPClient.
func TestDumpSocketTable_ChildProcessSocket(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer srv.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperUDPClient")
	cmd.Env = append(os.Environ(), "SOCKDIAG_CHILD_TARGET="+srv.LocalAddr().String())
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	require.NoError(t, srv.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, clientAddr, err := srv.ReadFromUDP(make([]byte, 64))
	require.NoError(t, err, "child must send its datagram")

	cookie, kind := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, clientAddr.IP, uint16(clientAddr.Port))
	require.Equal(t, matchExact, kind, "another process's live client socket must be found by source address")
	assert.NotZero(t, cookie)
}

// An AF_INET6 V6ONLY=0 socket connected to a v4-mapped destination lives in
// the v6 table with a ::ffff:a.b.c.d source. The v6-table dump keyed by the
// v4-mapped want must find it — the second table lookupCookie consults for
// an IPv4 client.
func TestDumpSocketTable_DualStackV4Mapped(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer srv.Close()

	fd, port := dualStackConn(t, srv.LocalAddr().(*net.UDPAddr).Port)

	// The v4 table misses it...
	_, kind := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), port)
	assert.Equal(t, matchNone, kind, "a dual-stack socket is not in the AF_INET table")

	// ...and the v6 table resolves it via the v4-mapped want.
	cookie, kind := dumpAndMatch(t, unix.AF_INET6, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), port)
	require.Equal(t, matchExact, kind, "the AF_INET6 table must resolve the v4-mapped source")
	assert.Equal(t, fdCookie(t, fd), cookie)
}

// A bare-sendto client (dig-style, never connected) is auto-bound to the
// wildcard address, so the kernel table shows 0.0.0.0 where the proxy saw
// the routed source. The unique-wildcard fallback must still resolve it to
// exactly the kernel-assigned cookie.
func TestDumpSocketTable_UnconnectedUDPWildcard(t *testing.T) {
	conn, err := net.ListenUDP("udp4", nil)
	require.NoError(t, err)
	defer conn.Close()

	// Look up by the proxy's view — a concrete source IP that can never
	// equal the socket's wildcard bind address, forcing the fallback.
	local := conn.LocalAddr().(*net.UDPAddr)
	cookie, kind := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), uint16(local.Port))
	require.Equal(t, matchWildcard, kind, "wildcard-bound socket must be found by port")
	assert.Equal(t, soCookie(t, conn), cookie)
}

// newTestResolver builds the resolver without BPF: nil maps, so found
// sockets resolve as untagged.
func newTestResolver() *clientResolver {
	return newClientResolver(nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// matchCookie is the pure half of the lookup: exact source beats wildcard,
// a lone wildcard is matchable by port, competing wildcards decline.
func TestMatchCookie(t *testing.T) {
	exact := wantBytes(unix.AF_INET, net.IPv4(127, 0, 0, 1))
	rows := []sockRow{
		{sport: 10, src: exact, cookie: 1},
		{sport: 10, cookie: 2}, // wildcard on the same port must not shadow the exact hit
		{sport: 11, cookie: 3},
		{sport: 12, cookie: 4},
		{sport: 12, cookie: 5},
	}

	cookie, kind := matchCookie(rows, 10, exact)
	assert.Equal(t, matchExact, kind)
	assert.Equal(t, uint64(1), cookie, "exact source match wins over a wildcard candidate")

	cookie, kind = matchCookie(rows, 11, exact)
	assert.Equal(t, matchWildcard, kind)
	assert.Equal(t, uint64(3), cookie, "a unique wildcard resolves by port")

	_, kind = matchCookie(rows, 12, exact)
	assert.Equal(t, matchAmbiguous, kind, "two wildcard candidates decline rather than guess")

	_, kind = matchCookie(rows, 13, exact)
	assert.Equal(t, matchNone, kind)
}

// A burst wider than the old per-lookup semaphore must resolve every
// client: the batcher coalesces concurrent lookups into shared dumps
// instead of shedding the excess to an unresolved result.
func TestDiagBatcher_Burst(t *testing.T) {
	const clients = 12
	conns := make([]*net.UDPConn, clients)
	for i := range conns {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
		require.NoError(t, err)
		defer conn.Close()
		conns[i] = conn
	}

	b := newDiagBatcher()
	defer b.close()
	table := diagTable{family: unix.AF_INET, proto: unix.IPPROTO_UDP}
	var wg sync.WaitGroup
	kinds := make([]matchKind, clients)
	errs := make([]error, clients)
	sheds := make([]bool, clients)
	for i, conn := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, shed, err := b.rows(table)
			errs[i], sheds[i] = err, shed
			if err != nil || shed {
				return
			}
			local := conn.LocalAddr().(*net.UDPAddr)
			_, kinds[i] = matchCookie(rows, uint16(local.Port), wantBytes(unix.AF_INET, local.IP))
		}()
	}
	wg.Wait()

	for i := range conns {
		require.NoError(t, errs[i], "client %d", i)
		assert.False(t, sheds[i], "client %d must not be shed under a %d-wide burst", i, clients)
		assert.Equal(t, matchExact, kinds[i], "client %d must be resolved", i)
	}
}

// After close, lookups shed instead of dumping, and no drainer survives.
func TestDiagBatcher_Close(t *testing.T) {
	b := newDiagBatcher()
	table := diagTable{family: unix.AF_INET, proto: unix.IPPROTO_UDP}
	_, shed, err := b.rows(table)
	require.NoError(t, err)
	require.False(t, shed)

	b.close()
	_, shed, err = b.rows(table)
	require.NoError(t, err)
	assert.True(t, shed, "a closed batcher sheds instead of dumping")
}

// lookupCookie ranks an exact source match in ANY table above a wildcard:
// a dual-stack socket's exact v4-mapped entry in the v6 table must win over
// an unrelated wildcard sharing the port in the v4 table.
func TestLookupCookie_ExactBeatsCrossTableWildcard(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer srv.Close()

	fd, port := dualStackConn(t, srv.LocalAddr().(*net.UDPAddr).Port)

	// An unrelated v4 wildcard socket on the SAME port (SO_REUSEADDR on
	// both sides makes the shared bind legal).
	wildFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(wildFd)
	require.NoError(t, unix.SetsockoptInt(wildFd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1))
	require.NoError(t, unix.Bind(wildFd, &unix.SockaddrInet4{Port: int(port)}))

	r := newTestResolver()
	defer r.close()
	cookie, status, err := r.lookupCookie(unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), port)
	require.NoError(t, err)
	require.Equal(t, cookieHit, status)
	assert.Equal(t, fdCookie(t, fd), cookie,
		"the v6-table exact match must win; the v4 wildcard is a different socket")
}

// The full cross-table ranking on synthetic rows via the batcher's dump
// seam: exact in any table beats wildcard anywhere; an earlier table's
// wildcard beats a later one's; a unique wildcard beats ambiguity.
func TestLookupCookie_RankingSynthetic(t *testing.T) {
	exact4 := wantBytes(unix.AF_INET, net.IPv4(127, 0, 0, 1))
	exact6 := wantBytes(unix.AF_INET6, net.IPv4(127, 0, 0, 1))
	const port = 40000
	cases := []struct {
		name       string
		v4, v6     []sockRow
		wantCookie uint64
		wantStatus cookieStatus
	}{
		{"v4 exact wins", []sockRow{{sport: port, src: exact4, cookie: 1}}, nil, 1, cookieHit},
		{
			"v6 exact beats v4 wildcard",
			[]sockRow{{sport: port, cookie: 2}},
			[]sockRow{{sport: port, src: exact6, cookie: 3}},
			3, cookieHit,
		},
		{
			"v4 wildcard beats v6 wildcard",
			[]sockRow{{sport: port, cookie: 4}},
			[]sockRow{{sport: port, cookie: 5}},
			4, cookieHit,
		},
		{"v6 wildcard when v4 empty", nil, []sockRow{{sport: port, cookie: 6}}, 6, cookieHit},
		{
			"unique wildcard beats ambiguity in the other table",
			[]sockRow{{sport: port, cookie: 7}, {sport: port, cookie: 8}},
			[]sockRow{{sport: port, cookie: 9}},
			9, cookieHit,
		},
		{
			"ambiguous only",
			[]sockRow{{sport: port, cookie: 7}, {sport: port, cookie: 8}},
			nil, 0, cookieAmbiguous,
		},
		{"not found", nil, nil, 0, cookieNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestResolver()
			defer r.close()
			r.diag.dump = func(table diagTable) ([]sockRow, error) {
				if table.family == unix.AF_INET {
					return tc.v4, nil
				}
				return tc.v6, nil
			}
			cookie, status, err := r.lookupCookie(unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), port)
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.wantCookie, cookie)
		})
	}
}

// stepForClient outcome taxonomy: each distinct failure mode must be
// tellable apart on the result — none may collapse into a silent 0.
func TestStepForClient_Outcomes(t *testing.T) {
	t.Run("dump error", func(t *testing.T) {
		r := newTestResolver()
		defer r.close()
		boom := errors.New("boom")
		r.diag.dump = func(diagTable) ([]sockRow, error) { return nil, boom }
		attr := r.stepForClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001})
		assert.Equal(t, events.StepAttrDumpError, attr.Outcome)

		// Cached with the TTL: the repeat query must not dump again.
		calls := 0
		r.diag.dump = func(diagTable) ([]sockRow, error) { calls++; return nil, boom }
		attr = r.stepForClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001})
		assert.Equal(t, events.StepAttrDumpError, attr.Outcome)
		assert.Zero(t, calls, "dump errors are cached, not retried per query")
	})

	t.Run("unsupported addr", func(t *testing.T) {
		r := newTestResolver()
		attr := r.stepForClient(&net.UnixAddr{Name: "/tmp/x", Net: "unix"})
		assert.Equal(t, events.StepAttrUnsupported, attr.Outcome)
		assert.Zero(t, attr.Ordinal)
	})

	t.Run("not found", func(t *testing.T) {
		r := newTestResolver()
		// Port 1 with no socket bound: clean dump, no match.
		attr := r.stepForClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
		assert.Equal(t, events.StepAttrNotFound, attr.Outcome)
	})

	t.Run("found but untagged", func(t *testing.T) {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
		require.NoError(t, err)
		defer conn.Close()

		r := newTestResolver()
		attr := r.stepForClient(conn.LocalAddr())
		assert.Equal(t, events.StepAttrUntagged, attr.Outcome, "nil sockMap resolves found sockets as untagged")
		assert.Zero(t, attr.Ordinal)
	})

	t.Run("ambiguous wildcard", func(t *testing.T) {
		// Two unconnected sockets sharing one port via SO_REUSEPORT: both are
		// wildcard candidates, so the lookup must decline rather than guess.
		fds := make([]int, 2)
		var port int
		for i := range fds {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			require.NoError(t, err)
			defer unix.Close(fd)
			require.NoError(t, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1))
			require.NoError(t, unix.Bind(fd, &unix.SockaddrInet4{Port: port}))
			if i == 0 {
				sn, err := unix.Getsockname(fd)
				require.NoError(t, err)
				port = sn.(*unix.SockaddrInet4).Port
			}
			fds[i] = fd
		}

		r := newTestResolver()
		attr := r.stepForClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		assert.Equal(t, events.StepAttrAmbiguous, attr.Outcome)
		assert.Zero(t, attr.Ordinal)
	})

	t.Run("dual-stack retry", func(t *testing.T) {
		_, port := dualStackConn(t, 53535)

		r := newTestResolver()
		attr := r.stepForClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		assert.Equal(t, events.StepAttrUntagged, attr.Outcome,
			"a clean v4 miss must consult the v6 table and find the dual-stack socket (untagged ≠ not_found)")
	})

	t.Run("cache returns the full result", func(t *testing.T) {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
		require.NoError(t, err)
		local := conn.LocalAddr().(*net.UDPAddr)

		r := newTestResolver()
		first := r.stepForClient(local)
		require.Equal(t, events.StepAttrUntagged, first.Outcome)
		conn.Close()
		// Within the TTL the closed socket still resolves from cache,
		// outcome included.
		second := r.stepForClient(&net.UDPAddr{IP: local.IP, Port: local.Port})
		assert.Equal(t, first, second)
	})
}

// The production join, end to end minus the BPF programs: seeded
// map_sock_step/map_sock_pid equivalents must yield StepAttrOK with the
// ordinal AND the owner's pid/comm — the owner-naming half is what tells a
// reader who an unattributed client was. Needs CAP_BPF to create maps, so
// it skips unprivileged and runs in the sudo'd CI lane (and Lima).
func TestStepForClient_SeededMaps(t *testing.T) {
	newMap := func() *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Type:       ebpf.LRUHash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: 8,
		})
		if err != nil {
			t.Skipf("creating BPF map (needs CAP_BPF; covered by the sudo test lane): %v", err)
		}
		return m
	}
	sockMap := newMap()
	defer sockMap.Close()
	pidMap := newMap()
	defer pidMap.Close()

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
	require.NoError(t, err)
	defer conn.Close()
	cookie := soCookie(t, conn)

	require.NoError(t, sockMap.Put(cookie, uint32(7)))
	require.NoError(t, pidMap.Put(cookie, uint32(os.Getpid())))

	r := newClientResolver(sockMap, pidMap, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer r.close()
	attr := r.stepForClient(conn.LocalAddr())
	assert.Equal(t, events.StepAttrOK, attr.Outcome)
	assert.Equal(t, uint32(7), attr.Ordinal)
	assert.Equal(t, uint32(os.Getpid()), attr.PID)
	assert.Equal(t, readComm(os.Getpid()), attr.Process)
}
