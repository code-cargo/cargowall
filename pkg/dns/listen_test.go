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

// freePort is a port free on host for UDP, or a skip where host is not
// one to listen on here, as [::1] is not where loopback has no IPv6.
func freePort(t *testing.T, host string) int {
	t.Helper()
	addr := net.JoinHostPort(host, "0")
	c, err := net.ListenPacket(listenProtos(addr)[0], addr)
	if err != nil {
		t.Skipf("cannot listen on %s here: %v", host, err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// optionalListeners are the ways an optional listener is added: the
// redirect's IPv6 one, and the docker bridge's, container-serving, here on
// a loopback address of its own.
var optionalListeners = []struct {
	name, host string
	add        func(*Server, string)
}{
	{"ipv6", "::1", (*Server).AddOptionalListenAddr},
	{"container", "127.0.0.2", (*Server).AddContainerListenAddr},
}

// startServer runs a server with filtering on and no rules, so every query
// is refused at once without an upstream, and returns its Start error, nil
// once it has bound its listeners.
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
	case <-s.Ready():
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

// An optional listener added twice is bound once: a second bind of the
// same address could only fail.
func TestAddOptionalListenAddr_Once(t *testing.T) {
	s := newListenTestServer()
	s.AddOptionalListenAddr("[::1]:53")
	s.AddOptionalListenAddr("[::1]:53")
	assert.Equal(t, []string{"[::1]:53"}, s.additionalAddrs)
	assert.Equal(t, []string{"[::1]:53"}, s.optionalAddrs)
}

// An optional listener binds over its address's family and answers there,
// and the docker bridge's stays container-serving.
func TestStart_OptionalListenerServes(t *testing.T) {
	for _, o := range optionalListeners {
		t.Run(o.name, func(t *testing.T) {
			addr := net.JoinHostPort(o.host, strconv.Itoa(freePort(t, o.host)))
			s := newListenTestServer()
			o.add(s, addr)
			require.NoError(t, startServer(t, s))
			require.NoError(t, s.BindError(addr))

			for _, proto := range listenProtos(addr) {
				c := &dns.Client{Net: proto, Timeout: 2 * time.Second}
				reply, _, err := c.Exchange(new(dns.Msg).SetQuestion("blocked.example.", dns.TypeA), addr)
				require.NoError(t, err, "%s: the proxy must answer on %s", proto, addr)
				assert.Equal(t, dns.RcodeRefused, reply.Rcode, proto)
			}
			if o.name == "container" {
				assert.Equal(t, attributeContainerIP, s.listenerModes[o.host])
			}
		})
	}
}

// An optional listener whose UDP or TCP half is held by another process
// binds neither: the proxy still starts, BindError says why, and the half it
// could have held is left free, so nothing sent there meets a proxy that is
// only half there.
func TestStart_OptionalListenerBindsWholeOrNot(t *testing.T) {
	for _, o := range optionalListeners {
		for i := range 2 {
			addr := net.JoinHostPort(o.host, "0")
			held, other := listenProtos(addr)[i], listenProtos(addr)[1-i]
			t.Run(o.name+"/"+held, func(t *testing.T) {
				addr := net.JoinHostPort(o.host, strconv.Itoa(freePort(t, o.host)))
				if i == 0 {
					c, err := net.ListenPacket(held, addr)
					require.NoError(t, err)
					t.Cleanup(func() { c.Close() })
				} else {
					l, err := net.Listen(held, addr)
					require.NoError(t, err)
					t.Cleanup(func() { l.Close() })
				}

				s := newListenTestServer()
				o.add(s, addr)
				require.NoError(t, startServer(t, s), "an optional listener that cannot bind must not fail Start")
				require.ErrorContains(t, s.BindError(addr), held)

				if i == 0 {
					l, err := net.Listen(other, addr)
					require.NoError(t, err, "the proxy must not keep the TCP half")
					l.Close()
				} else {
					c, err := net.ListenPacket(other, addr)
					require.NoError(t, err, "the proxy must not keep the UDP half")
					c.Close()
				}
			})
		}
	}
}

// Ready closes once however often Start runs, and a Server not built by
// NewServer has one too.
func TestReady_ClosesOnce(t *testing.T) {
	s := newListenTestServer()
	for range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.Start(ctx) }()
		<-s.Ready()
		cancel()
		require.NoError(t, <-done)
	}
	assert.NotNil(t, (&Server{}).Ready())
}
