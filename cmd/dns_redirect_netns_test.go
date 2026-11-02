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
)

// Root-only tests, run in a network namespace of their own (the sudo test
// pass selects them by the Netns suffix).

// startDNSRedirect's wiring against a real proxy and the kernel's nf_tables:
// a bridge listener the proxy holds gets the bridge DNAT, over UDP and TCP
// from docker0 and br-*, and one another process holds gets no bridge rule
// at all, and is recorded as the redirect applied for the host alone. The
// bridge address is a loopback one, which the namespace holds as a docker
// bridge's would be held.
func TestStartDNSRedirect_BridgeListenerNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a network namespace and nftables; covered by the sudo test pass")
	}
	// Locked for good: the thread exits with the test, and the namespace
	// with it, rather than going back to the scheduler's pool.
	runtime.LockOSThread()
	require.NoError(t, unix.Unshare(unix.CLONE_NEWNET))
	setLoopbackUp(t)
	netns, err := os.Open("/proc/thread-self/ns/net")
	require.NoError(t, err)
	t.Cleanup(func() { netns.Close() })

	const bridgeIP = "127.0.0.2"
	logger := slog.New(slog.DiscardHandler)
	for _, held := range []bool{false, true} {
		var holder net.PacketConn
		if held {
			holder, err = net.ListenPacket("udp4", bridgeIP+":53")
			require.NoError(t, err)
		}
		srv := dns.NewServer(config.NewConfigManager(), new(firewall.MockFirewall), "192.0.2.1:53", "127.0.0.1:53", logger)
		addIPv6Listener(&StartCmd{DNSRedirect: true}, srv)
		d := &dockerDNS{bridgeIP: bridgeIP, proxy: srv, logger: logger}
		srv.AddContainerListenAddr(d.listenAddr())
		stop := startProxyIn(t, netns, srv)

		r, undo := startDNSRedirect(srv, d, &teardownList{}, logger)
		require.True(t, r.isActive())
		assert.NotEmpty(t, redirectChainRules(t, "output"), "held %v: the host's DNS is redirected either way", held)
		prerouting := redirectChainRules(t, "prerouting")
		if held {
			assert.Empty(t, prerouting, "no bridge rule may name an address another process holds, nor drop in its place")
			assert.Equal(t, dnsRedirectHost, r.applied)
			assert.ErrorContains(t, r.err, "container DNS is not redirected: another process holds 127.0.0.2:53")
		} else {
			require.NoError(t, r.err)
			var dnats int
			for _, rule := range prerouting {
				if dnatsTo(rule, net.ParseIP(bridgeIP).To4()) {
					dnats++
				}
			}
			assert.Equal(t, 4, dnats, "a DNAT to the bridge listener for docker0 and br-*, UDP and TCP")
		}
		undo()
		stop()
		if holder != nil {
			holder.Close()
		}
	}
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
// and moves it into the namespace first.
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
