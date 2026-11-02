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

	install(t, "")

	query(t, "10.53.0.2:53", "outside", false)
	got, _ = received(t, proxy, arrives)
	require.Equal(t, "outside", got, "UDP DNS for an outside resolver must reach the proxy")

	for _, stub := range []string{"127.0.0.53:53", "127.0.0.54:53"} {
		query(t, stub, "stub", false)
		got, _ = received(t, proxy, arrives)
		require.Equal(t, "stub", got, "UDP DNS for the resolved stub at %s must reach the proxy", stub)
	}

	for _, dst := range []string{"10.53.0.2:53", "127.0.0.53:53", "127.0.0.54:53"} {
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

	install(t, "")

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

	install(t, bridgeIP.String())

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

// TestDNSRedirect_AheadOfHostNAT: DNS meets the redirect before the DNAT a
// host nat table applies at dstnat, where Docker's published-port and
// kube-proxy's service DNAT sit, whichever table registered first; the
// proxy's own marked queries still get the host's DNAT.
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

	for _, hostFirst := range []bool{true, false} {
		var dropHost func()
		if hostFirst {
			dropHost = hostNAT()
		}
		r := NewDNSRedirect(discardLogger())
		require.NoError(t, r.Install(""))
		if !hostFirst {
			dropHost = hostNAT()
		}

		query(t, "10.53.0.2:53", "job", false)
		got, _ := received(t, proxy, arrives)
		require.Equal(t, "job", got, "host table first: %v: the job's DNS must reach the proxy", hostFirst)
		got, _ = received(t, service, absent)
		require.Empty(t, got, "host table first: %v: the host's DNAT must not win", hostFirst)

		query(t, "10.53.0.2:53", "upstream", true)
		got, _ = received(t, service, arrives)
		require.Equal(t, "upstream", got, "host table first: %v: the proxy's own query must get the host's DNAT", hostFirst)

		require.NoError(t, r.Teardown())
		dropHost()
	}
}

// TestDNSRedirect_Ownership: the table belongs to the socket that made it.
// No other socket can delete it, a second cargowall in the namespace cannot
// take it over, and closing the socket deletes it as surely as teardown.
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
	require.NoError(t, r.Install("10.54.0.1"))
	want := map[string]int{"output": 8, "input": 2, "prerouting": 4}
	require.Equal(t, want, redirectRules(t), "setup must replace an unowned table, not add to it")

	err = NewDNSRedirect(logger).Install("")
	require.ErrorIs(t, err, unix.EPERM, "a second setup must not take over a live redirect")
	require.ErrorContains(t, err, "another process owns the table")
	other.DelTable(stale)
	require.ErrorIs(t, other.Flush(), unix.EPERM, "another socket must not delete the table")
	other.FlushRuleset()
	_ = other.Flush()
	require.Equal(t, want, redirectRules(t), "nothing another socket did may touch the table")

	require.Error(t, NewDNSRedirect(logger).Install("fd00::1"), "an IPv6 bridge IP is refused")
	require.Error(t, r.Install(""), "an installed redirect is not installed twice")

	require.NoError(t, r.Teardown())
	require.Empty(t, redirectRules(t), "teardown must remove the table")
	require.NoError(t, r.Teardown(), "a second teardown is a no-op")
	require.Error(t, r.Install(""), "a torn-down redirect is not installed again")
	require.Empty(t, redirectRules(t))

	// Teardown registered ahead of the install, as startup does, and run
	// first by a forced shutdown: the install that follows must not leave a
	// table no undo will remove.
	early := NewDNSRedirect(logger)
	require.NoError(t, early.Teardown(), "nothing installed, nothing to remove")
	require.Error(t, early.Install(""))
	require.Empty(t, redirectRules(t))

	// The socket closing without a teardown, as when the process dies.
	r = NewDNSRedirect(logger)
	require.NoError(t, r.Install(""))
	require.Equal(t, map[string]int{"output": 8, "input": 2}, redirectRules(t))
	require.NoError(t, r.conn.Close())
	require.Empty(t, redirectRules(t), "the kernel must delete the table with the socket that owns it")
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
	want := map[string]int{"output": 8, "input": 2}

	r := refusedOwner(logger)
	require.NoError(t, r.Install(""), "a refused owner flag must fall back to an unowned table")
	require.False(t, r.owned)
	require.Equal(t, want, redirectRules(t))
	query(t, "10.53.0.2:53", "unowned", false)
	got, _ := received(t, proxy, arrives)
	require.Equal(t, "unowned", got, "an unowned table redirects the same")

	// Dying without a teardown leaves it; the next run replaces it.
	require.NoError(t, r.conn.Close())
	require.Equal(t, want, redirectRules(t), "nothing deletes an unowned table with its socket")
	next := refusedOwner(logger)
	require.NoError(t, next.Install(""))
	require.Equal(t, want, redirectRules(t), "the next install must replace the leftover, not add to it")
	require.NoError(t, next.Teardown())
	require.Empty(t, redirectRules(t))

	// Deleted by another process: DNS went around the proxy from then on,
	// and teardown says so rather than reporting a clean removal.
	r = refusedOwner(logger)
	require.NoError(t, r.Install(""))
	other, err := nftables.New()
	require.NoError(t, err)
	other.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: RedirectTable})
	require.NoError(t, other.Flush(), "an unowned table is anyone's to delete")
	require.ErrorContains(t, r.Teardown(), "another process deleted it during the run")
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
	if err := r.Install(""); err != nil {
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
	require.NoError(t, r.Install(""))
	owned := r.owned
	require.NoError(t, r.Teardown())
	if !owned {
		t.Skip("this kernel cannot own nftables tables (5.12)")
	}
}

// install sets up the redirect for the rest of the test.
func install(t *testing.T, bridgeIP string) {
	t.Helper()
	r := NewDNSRedirect(discardLogger())
	require.NoError(t, r.Install(bridgeIP))
	t.Cleanup(func() { _ = r.Teardown() })
}

// redirectRules counts the redirect table's rules per chain, read back by
// google/nftables rather than by the code that wrote them.
func redirectRules(t *testing.T) map[string]int {
	t.Helper()
	conn, err := nftables.New()
	require.NoError(t, err)
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	require.NoError(t, err)
	out := map[string]int{}
	for _, c := range chains {
		if c.Table.Name != RedirectTable {
			continue
		}
		rules, err := conn.GetRules(c.Table, c)
		require.NoError(t, err)
		out[c.Name] = len(rules)
	}
	return out
}
