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

package dns

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

func TestListenProtos(t *testing.T) {
	for addr, want := range map[string][]string{
		"127.0.0.1:53":   {"udp4", "tcp4"},
		"172.17.0.1:53":  {"udp4", "tcp4"},
		"[::1]:53":       {"udp6", "tcp6"},
		"[fd00::1]:53":   {"udp6", "tcp6"},
		"not an address": {"udp4", "tcp4"},
	} {
		assert.Equal(t, want, listenProtos(addr), addr)
	}
}

// freeLoopback6Port is a port free on [::1] for UDP, or a skip where
// loopback has no IPv6.
func freeLoopback6Port(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// startServer runs a server with filtering on and no rules, so every query
// is refused at once without an upstream, and returns its Start error, nil
// once it is serving.
func startServer(t *testing.T, s *Server) error {
	t.Helper()
	s.EnableQueryFiltering(true)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(ctx) }()
	select {
	case err := <-errCh:
		cancel()
		return err
	case <-time.After(200 * time.Millisecond):
	}
	t.Cleanup(func() {
		cancel()
		<-errCh
	})
	return nil
}

func newListenTestServer() *Server {
	return NewServer(config.NewConfigManager(), new(firewall.MockFirewall), "192.0.2.1:53", "127.0.0.1:0",
		slog.New(slog.DiscardHandler))
}

// A redirect listener added twice is bound once: a second bind of the same
// address could only fail, and would fail Start.
func TestAddRedirectListenAddr_Once(t *testing.T) {
	s := newListenTestServer()
	s.AddRedirectListenAddr("[::1]:53")
	s.AddRedirectListenAddr("[::1]:53")
	assert.Equal(t, []string{"[::1]:53"}, s.additionalAddrs)
	assert.Equal(t, []string{"[::1]:53"}, s.requiredAddrs)
}

// The redirect's IPv6 listener binds over IPv6 and answers there.
func TestStart_RedirectListenerServesIPv6(t *testing.T) {
	addr := net.JoinHostPort("::1", strconv.Itoa(freeLoopback6Port(t)))
	s := newListenTestServer()
	s.AddRedirectListenAddr(addr)
	require.NoError(t, startServer(t, s))

	for _, proto := range []string{"udp6", "tcp6"} {
		c := &dns.Client{Net: proto, Timeout: 2 * time.Second}
		reply, _, err := c.Exchange(new(dns.Msg).SetQuestion("blocked.example.", dns.TypeA), addr)
		require.NoError(t, err, "%s: the proxy must answer on %s", proto, addr)
		assert.Equal(t, dns.RcodeRefused, reply.Rcode, proto)
	}
}

// DNS redirected to a port cargowall does not hold goes to whatever does, so
// a redirect listener that cannot bind fails Start, as the primary does. A
// plain secondary listener only logs.
func TestStart_RedirectListenerMustBind(t *testing.T) {
	port := freeLoopback6Port(t)
	addr := net.JoinHostPort("::1", strconv.Itoa(port))
	held, err := net.ListenPacket("udp6", addr)
	require.NoError(t, err)
	t.Cleanup(func() { held.Close() })

	s := newListenTestServer()
	s.AddRedirectListenAddr(addr)
	err = startServer(t, s)
	require.Error(t, err, "a redirect listener that cannot bind must fail Start")
	assert.ErrorContains(t, err, "failed to listen on "+addr+"/udp6")

	s = newListenTestServer()
	s.AddListenAddr(addr)
	assert.NoError(t, startServer(t, s), "a plain secondary listener that cannot bind only logs")
}
