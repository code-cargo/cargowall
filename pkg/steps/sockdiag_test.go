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

// dumpAndMatch is the production lookup as the tests exercise it — one
// table dump, one pure match. A dump failure fails the test: these tests
// pin resolution behavior, not error handling.
func dumpAndMatch(t *testing.T, family, proto uint8, ip net.IP, port uint16) (cookie uint64, found, ambiguous bool) {
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

// The dump+match must return exactly the cookie the kernel assigned to the
// socket (cross-checked via SO_COOKIE), keyed only by source address — the
// same view the DNS proxy has of a redirected client.
func TestDumpSocketTable_UDP(t *testing.T) {
	// A connected UDP socket, like a stub resolver client.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
	require.NoError(t, err)
	defer conn.Close()

	local := conn.LocalAddr().(*net.UDPAddr)
	cookie, found, _ := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, local.IP, uint16(local.Port))
	require.True(t, found, "socket must be found by source address")
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
	cookie, found, _ := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_TCP, local.IP, uint16(local.Port))
	require.True(t, found)
	assert.Equal(t, soCookie(t, conn.(*net.TCPConn)), cookie)
}

func TestDumpSocketTable_NotFound(t *testing.T) {
	// Port 1 with no socket bound: dump completes cleanly without a match,
	// which must NOT surface as an error (errors mean the dump itself broke).
	_, found, ambiguous := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), 1)
	assert.False(t, found)
	assert.False(t, ambiguous)
}

// The production shape behind issue #110: a live loopback listener (the DNS
// proxy), a connected client that has SENT a datagram the listener already
// received, and the lookup running while the client is parked in recv —
// exactly what StepForClient sees when it runs before the REFUSED write.
// TestDumpSocketTable_UDP covers connect-without-traffic; this pins that a
// socket with traffic through it stays visible to the dump.
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
	cookie, found, _ := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, local.IP, uint16(local.Port))
	require.True(t, found, "socket with sent traffic must be found by source address")
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

// The dump must resolve sockets it does not own: the DNS proxy's clients are
// other processes' resolver sockets (glibc in apt methods, curl, …), while
// every other test here dumps a same-process socket. The child is the test
// binary re-exec'd into TestHelperUDPClient.
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

	cookie, found, _ := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, clientAddr.IP, uint16(clientAddr.Port))
	require.True(t, found, "another process's live client socket must be found by source address")
	assert.NotZero(t, cookie)
}

// The documented dual-stack gap (issue #110 suspect 1): an AF_INET6
// V6ONLY=0 socket connected to a v4-mapped destination lives in the v6
// table with a ::ffff:a.b.c.d source. The v6-table dump keyed by the
// v4-mapped want must find it — this is the second lookup StepForClient
// issues after a clean AF_INET miss.
func TestDumpSocketTable_DualStackV4Mapped(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer srv.Close()
	srvPort := srv.LocalAddr().(*net.UDPAddr).Port

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	require.NoError(t, unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0))

	var sa unix.SockaddrInet6
	sa.Port = srvPort
	copy(sa.Addr[:], net.IPv4(127, 0, 0, 1).To16()) // ::ffff:127.0.0.1
	require.NoError(t, unix.Connect(fd, &sa))

	local, err := unix.Getsockname(fd)
	require.NoError(t, err)
	port := uint16(local.(*unix.SockaddrInet6).Port)
	wantCookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)

	// The v4 table misses it...
	_, found, _ := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), port)
	assert.False(t, found, "a dual-stack socket is not in the AF_INET table")

	// ...and the v6 table resolves it via the v4-mapped want.
	cookie, found, _ := dumpAndMatch(t, unix.AF_INET6, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), port)
	require.True(t, found, "the AF_INET6 table must resolve the v4-mapped source")
	assert.Equal(t, wantCookie, cookie)
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
	cookie, found, _ := dumpAndMatch(t, unix.AF_INET, unix.IPPROTO_UDP, net.IPv4(127, 0, 0, 1), uint16(local.Port))
	require.True(t, found, "wildcard-bound socket must be found by port")
	assert.Equal(t, soCookie(t, conn), cookie)
}

// newDiagTracker builds the minimal Tracker the sock_diag path needs — no
// BPF: sockMap/pidMap stay nil, so found sockets resolve as untagged.
func newDiagTracker() *Tracker {
	return &Tracker{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		stepCache: make(map[stepCacheKey]stepCacheEntry),
		diag:      newDiagBatcher(),
	}
}

// matchCookie is the pure half of the lookup: exact source beats wildcard,
// a lone wildcard is accepted by port, competing wildcards decline.
func TestMatchCookie(t *testing.T) {
	exact := wantBytes(unix.AF_INET, net.IPv4(127, 0, 0, 1))
	rows := []sockRow{
		{sport: 10, src: exact, cookie: 1},
		{sport: 10, cookie: 2}, // wildcard on the same port must not shadow the exact hit
		{sport: 11, cookie: 3},
		{sport: 12, cookie: 4},
		{sport: 12, cookie: 5},
	}

	cookie, found, ambiguous := matchCookie(rows, 10, exact)
	assert.True(t, found)
	assert.False(t, ambiguous)
	assert.Equal(t, uint64(1), cookie, "exact source match wins over a wildcard candidate")

	cookie, found, ambiguous = matchCookie(rows, 11, exact)
	assert.True(t, found)
	assert.False(t, ambiguous)
	assert.Equal(t, uint64(3), cookie, "a unique wildcard resolves by port")

	_, found, ambiguous = matchCookie(rows, 12, exact)
	assert.False(t, found)
	assert.True(t, ambiguous, "two wildcard candidates decline rather than guess")

	_, found, ambiguous = matchCookie(rows, 13, exact)
	assert.False(t, found)
	assert.False(t, ambiguous)
}

// A burst wider than the old semaphore (4) must resolve every client: the
// batcher coalesces concurrent lookups into shared dumps instead of
// shedding the excess to untagged — the failure mode that zeroed 5 of the
// 9 apt sockets in the issue #110 runs.
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
	founds := make([]bool, clients)
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
			_, founds[i], _ = matchCookie(rows, uint16(local.Port), wantBytes(unix.AF_INET, local.IP))
		}()
	}
	wg.Wait()

	for i := range conns {
		require.NoError(t, errs[i], "client %d", i)
		assert.False(t, sheds[i], "client %d must not be shed under a %d-wide burst", i, clients)
		assert.True(t, founds[i], "client %d must be resolved", i)
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

// StepForClient outcome taxonomy: each distinct failure mode must be
// tellable apart on the result — they were previously all a silent 0.
func TestStepForClient_Outcomes(t *testing.T) {
	t.Run("unsupported addr", func(t *testing.T) {
		tr := newDiagTracker()
		cs := tr.StepForClient(&net.UnixAddr{Name: "/tmp/x", Net: "unix"})
		assert.Equal(t, events.StepAttrUnsupported, cs.Outcome)
		assert.Zero(t, cs.Ordinal)
	})

	t.Run("not found", func(t *testing.T) {
		tr := newDiagTracker()
		// Port 1 with no socket bound: clean dump, no match.
		cs := tr.StepForClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
		assert.Equal(t, events.StepAttrNotFound, cs.Outcome)
	})

	t.Run("found but untagged", func(t *testing.T) {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
		require.NoError(t, err)
		defer conn.Close()

		tr := newDiagTracker()
		cs := tr.StepForClient(conn.LocalAddr())
		assert.Equal(t, events.StepAttrUntagged, cs.Outcome, "nil sockMap resolves found sockets as untagged")
		assert.Zero(t, cs.Ordinal)
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

		tr := newDiagTracker()
		cs := tr.StepForClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		assert.Equal(t, events.StepAttrAmbiguous, cs.Outcome)
		assert.Zero(t, cs.Ordinal)
	})

	t.Run("dual-stack retry", func(t *testing.T) {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		require.NoError(t, err)
		defer unix.Close(fd)
		require.NoError(t, unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0))
		var sa unix.SockaddrInet6
		sa.Port = 53535
		copy(sa.Addr[:], net.IPv4(127, 0, 0, 1).To16())
		require.NoError(t, unix.Connect(fd, &sa))
		sn, err := unix.Getsockname(fd)
		require.NoError(t, err)
		port := sn.(*unix.SockaddrInet6).Port

		tr := newDiagTracker()
		cs := tr.StepForClient(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		assert.Equal(t, events.StepAttrUntagged, cs.Outcome,
			"a clean v4 miss must retry the v6 table and find the dual-stack socket (untagged ≠ not_found)")
	})

	t.Run("cache returns the full result", func(t *testing.T) {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53535})
		require.NoError(t, err)
		local := conn.LocalAddr().(*net.UDPAddr)

		tr := newDiagTracker()
		first := tr.StepForClient(local)
		require.Equal(t, events.StepAttrUntagged, first.Outcome)
		conn.Close()
		// Within the TTL the closed socket still resolves from cache,
		// outcome included.
		second := tr.StepForClient(&net.UDPAddr{IP: local.IP, Port: local.Port})
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

	tr := newDiagTracker()
	tr.sockMap = sockMap
	tr.pidMap = pidMap
	cs := tr.StepForClient(conn.LocalAddr())
	assert.Equal(t, events.StepAttrOK, cs.Outcome)
	assert.Equal(t, uint32(7), cs.Ordinal)
	assert.Equal(t, uint32(os.Getpid()), cs.PID)
	assert.Equal(t, readComm(os.Getpid()), cs.Process)
}
