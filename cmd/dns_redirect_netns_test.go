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

package cmd

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/firewall"
	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// Root-only tests, run in a network namespace of their own (the sudo test
// pass selects them by the Netns suffix).

// startDNSRedirect's wiring, from startDockerDNS on, against a real proxy
// and the kernel's nf_tables. The container listeners go on cargowall's own
// addresses on lo once the proxy holds its primary, and the bridges' DNS of
// both families is DNAT'd to them, over UDP and TCP from docker0 and br-*.
// An address refused, here the IPv4 one for being the proxy's upstream, is
// not added and gets no rule for its family, and the redirect is recorded as
// applied for the host alone. The teardown takes the addresses off again.
func TestStartDNSRedirect_ContainerListenersNetns(t *testing.T) {
	netns := newNetns(t)
	logger := slog.New(slog.DiscardHandler)
	for _, refused := range []bool{false, true} {
		t.Run(map[bool]string{false: "added", true: "refused"}[refused], func(t *testing.T) {
			// Each case's cleanups run on its own goroutine, which is in
			// the namespace, before the next case: the proxy, the table and
			// the addresses never outlive a failed one.
			enterNetns(t, netns)
			cmd := &StartCmd{DNSRedirect: true, DockerDNSInterception: true, DNSUpstream: "192.0.2.1:53"}
			if refused {
				cmd.DNSUpstream = "169.254.0.53:53"
			}
			srv := dns.NewServer(config.NewConfigManager(), new(firewall.MockFirewall), cmd.DNSUpstream, "127.0.0.1:53", logger)
			addIPv6Listener(cmd, srv)
			teardowns := &teardownList{}
			d, removeAddrs := startDockerDNS(cmd, srv, podenv.Dockerd{}, teardowns, logger)
			t.Cleanup(removeAddrs)
			t.Cleanup(startProxyIn(t, netns, srv))

			r, undo := startDNSRedirect(srv, d, teardowns, logger)
			t.Cleanup(undo)
			require.True(t, r.isActive())
			assert.Equal(t, !refused, onLo(t, network.ContainerDNSIPv4))
			assert.True(t, onLo(t, network.ContainerDNSIPv6))
			assert.NotEmpty(t, redirectChainRules(t, "output"), "the host's DNS is redirected either way")
			dnats := map[string]int{}
			for _, rule := range redirectChainRules(t, "prerouting") {
				for _, addr := range []netip.Addr{network.ContainerDNSIPv4, network.ContainerDNSIPv6} {
					if dnatsTo(rule, net.IP(addr.AsSlice())) {
						dnats[addr.String()]++
					}
				}
			}
			want := map[string]int{"169.254.0.53": 4, "fd97:d1fb:f215::53": 4} // docker0 and br-*, UDP and TCP
			if refused {
				delete(want, "169.254.0.53")
				assert.Equal(t, dnsRedirectHost, r.applied)
				assert.ErrorContains(t, r.err, "container DNS is not redirected: the proxy cannot listen on 169.254.0.53:53: "+
					"it is the DNS upstream, so the proxy would forward container DNS to itself")
			} else {
				require.NoError(t, r.err)
			}
			assert.Equal(t, want, dnats, "a DNAT to each container listener the proxy holds, and none to one it does not")

			undo()
			removeAddrs()
			assert.False(t, onLo(t, network.ContainerDNSIPv4), "the teardown takes the addresses off")
			assert.False(t, onLo(t, network.ContainerDNSIPv6), "the teardown takes the addresses off")
		})
	}
}

// A second cargowall in the namespace cannot hold the primary, so its Start
// fails before it adds the container addresses, and its teardown, which
// removes only what it added, leaves the first's in place.
func TestStartDockerDNS_SecondInstanceNetns(t *testing.T) {
	netns := newNetns(t)
	logger := slog.New(slog.DiscardHandler)
	cmd := &StartCmd{DockerDNSInterception: true, DNSUpstream: "192.0.2.1:53"}
	first := dns.NewServer(config.NewConfigManager(), new(firewall.MockFirewall), cmd.DNSUpstream, "127.0.0.1:53", logger)
	_, removeFirst := startDockerDNS(cmd, first, podenv.Dockerd{}, &teardownList{}, logger)
	t.Cleanup(removeFirst)
	t.Cleanup(startProxyIn(t, netns, first))
	require.True(t, onLo(t, network.ContainerDNSIPv4))

	second := dns.NewServer(config.NewConfigManager(), new(firewall.MockFirewall), cmd.DNSUpstream, "127.0.0.1:53", logger)
	_, removeSecond := startDockerDNS(cmd, second, podenv.Dockerd{}, &teardownList{}, logger)
	require.ErrorContains(t, second.Start(t.Context()), "127.0.0.1:53", "the second proxy cannot hold the primary")
	removeSecond()
	assert.True(t, onLo(t, network.ContainerDNSIPv4), "the second's teardown must leave the first's addresses")
	assert.True(t, onLo(t, network.ContainerDNSIPv6), "the second's teardown must leave the first's addresses")
}

// Docker DNS interception without the DNS redirect: the container DNS
// addresses still come with their guards, whose tables the teardown takes
// off with the addresses, and there is no redirect table.
func TestStartDockerDNS_GuardedWithoutRedirectNetns(t *testing.T) {
	netns := newNetns(t)
	logger := slog.New(slog.DiscardHandler)
	cmd := &StartCmd{DockerDNSInterception: true, DNSUpstream: "192.0.2.1:53"}
	srv := dns.NewServer(config.NewConfigManager(), new(firewall.MockFirewall), cmd.DNSUpstream, "127.0.0.1:53", logger)
	d, removeAddrs := startDockerDNS(cmd, srv, podenv.Dockerd{}, &teardownList{}, logger)
	t.Cleanup(removeAddrs)
	t.Cleanup(startProxyIn(t, netns, srv))

	require.True(t, d.serving())
	assert.True(t, onLo(t, network.ContainerDNSIPv4))
	assert.True(t, onLo(t, network.ContainerDNSIPv6))
	assert.Equal(t, map[string]int{"ip input": 1, "ip forward": 1, "ip6 input": 1, "ip6 forward": 1},
		tableRuleCounts(t, network.GuardTable), "each address guarded, the redirect or none")
	assert.Empty(t, tableRuleCounts(t, network.RedirectTable), "no redirect")

	removeAddrs()
	assert.False(t, onLo(t, network.ContainerDNSIPv4))
	assert.Empty(t, tableRuleCounts(t, network.GuardTable), "the guards go with the addresses")
}

// newNetns moves the test's goroutine into a network namespace of its own,
// with loopback up, and returns it for others to enter. Locked for good:
// the thread exits with the test, and the namespace with it, rather than
// going back to the scheduler's pool.
func newNetns(t *testing.T) *os.File {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for a network namespace and nftables; covered by the sudo test pass")
	}
	runtime.LockOSThread()
	require.NoError(t, unix.Unshare(unix.CLONE_NEWNET))
	setLoopbackUp(t)
	netns, err := os.Open("/proc/thread-self/ns/net")
	require.NoError(t, err)
	t.Cleanup(func() { netns.Close() })
	return netns
}

// onLo reports whether addr is on lo.
func onLo(t *testing.T, addr netip.Addr) bool {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	addrs, err := lo.Addrs()
	require.NoError(t, err)
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(net.IP(addr.AsSlice())) {
			return true
		}
	}
	return false
}

// enterNetns moves the calling goroutine into the network namespace netns,
// on a thread locked to it for good: the thread exits with the goroutine
// rather than carrying the namespace back into the scheduler's pool.
func enterNetns(t *testing.T, netns *os.File) {
	t.Helper()
	runtime.LockOSThread()
	require.NoError(t, unix.Setns(int(netns.Fd()), unix.CLONE_NEWNET))
}

// setLoopbackUp brings this thread's namespace's loopback up, which gives
// it 127.0.0.0/8 and ::1.
func setLoopbackUp(t *testing.T) {
	t.Helper()
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(sock)
	ifr, err := unix.NewIfreq("lo")
	require.NoError(t, err)
	require.NoError(t, unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr))
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	require.NoError(t, unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr))
}

// startProxyIn starts srv in the network namespace netns and returns once
// it has bound its listeners, and a func that stops it. Start binds on its
// goroutine's thread, which the scheduler picks, so the goroutine locks one
// and moves it into the namespace first, as enterNetns does: it cannot fail
// the test from there.
func startProxyIn(t *testing.T, netns *os.File, srv *dns.Server) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // for good: the thread is the namespace's now, and exits with the goroutine
		if err := unix.Setns(int(netns.Fd()), unix.CLONE_NEWNET); err != nil {
			errCh <- err
			return
		}
		errCh <- srv.Start(ctx)
	}()
	select {
	case err := <-errCh:
		cancel()
		require.FailNow(t, "the proxy did not start", "%v", err)
	case <-srv.Ready():
	}
	return func() {
		cancel()
		require.NoError(t, <-errCh)
	}
}

// redirectChainRules is the rules of the redirect table's chain name, of
// either family, read back by google/nftables rather than by the code that
// wrote them; nil when there is no such chain.
func redirectChainRules(t *testing.T, name string) []*nftables.Rule {
	t.Helper()
	conn, err := nftables.New()
	require.NoError(t, err)
	for _, family := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyINet} {
		chains, err := conn.ListChainsOfTableFamily(family)
		require.NoError(t, err)
		for _, c := range chains {
			if c.Table.Name == network.RedirectTable && c.Name == name {
				rules, err := conn.GetRules(c.Table, c)
				require.NoError(t, err)
				return rules
			}
		}
	}
	return nil
}

// tableRuleCounts counts the rules of the tables named table per family
// and chain ("ip6 input").
func tableRuleCounts(t *testing.T, table string) map[string]int {
	t.Helper()
	conn, err := nftables.New()
	require.NoError(t, err)
	out := map[string]int{}
	for family, name := range map[nftables.TableFamily]string{
		nftables.TableFamilyIPv4: "ip", nftables.TableFamilyIPv6: "ip6", nftables.TableFamilyINet: "inet",
	} {
		chains, err := conn.ListChainsOfTableFamily(family)
		require.NoError(t, err)
		for _, c := range chains {
			if c.Table.Name == table {
				rules, err := conn.GetRules(c.Table, c)
				require.NoError(t, err)
				out[name+" "+c.Name] = len(rules)
			}
		}
	}
	return out
}

// dnatsTo reports whether rule DNATs to addr.
func dnatsTo(rule *nftables.Rule, addr net.IP) bool {
	var target, nat bool
	for _, e := range rule.Exprs {
		switch e := e.(type) {
		case *expr.Immediate:
			target = target || net.IP(e.Data).Equal(addr)
		case *expr.NAT:
			nat = e.Type == expr.NATTypeDestNAT
		}
	}
	return target && nat
}
