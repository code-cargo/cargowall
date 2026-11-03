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
	"errors"
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

// additionalListeners are the ways a listener beside the primary is added:
// the redirect's IPv6 one, and a container listener, container-serving,
// here on a loopback address of its own.
var additionalListeners = []struct {
	name, host string
	add        func(*Server, string)
}{
	{"ipv6", "::1", (*Server).AddListenAddr},
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

// A listener added twice is bound once, and the primary's address is not
// added beside it: a second bind of the same address could only fail. A
// host serves listeners of one attribution mode, the primary's that of the
// host sockdiag path, so a listener of the other mode there is not added,
// and leaves the mode it would have reclassified alone. BindError says so
// for an address it did not add.
func TestAddListenAddr_Once(t *testing.T) {
	s := newListenTestServer()
	s.AddListenAddr("[::1]:53")
	s.AddContainerListenAddr("[::1]:53")   // a duplicate
	s.AddContainerListenAddr("[::1]:5353") // the host already serves the sockdiag path
	s.AddContainerListenAddr("127.0.0.1:53")
	s.AddListenAddr("127.0.0.1:0") // the primary
	s.AddContainerListenAddr("127.0.0.2:53")
	s.AddContainerListenAddr("127.0.0.2:53")
	s.AddListenAddr("127.0.0.2:5353") // the host already serves containers
	s.AddListenAddr("not an address")
	assert.Equal(t, []string{"[::1]:53", "127.0.0.2:53"}, s.additionalAddrs)
	assert.Equal(t, map[string]listenerAttribution{"127.0.0.2": attributeContainerIP}, s.listenerModes)

	for _, addr := range []string{"[::1]:5353", "127.0.0.1:53", "127.0.0.2:5353", "not an address", "192.0.2.9:53"} {
		require.ErrorIs(t, s.BindError(addr), errNotAdded, addr)
	}
	assert.NoError(t, s.BindError("127.0.0.1:0"), "the primary is bound once Ready closes")
}

// The primary binds over UDP and TCP both or neither too, and either half
// held by another process fails Start, naming it, with nothing left bound.
func TestStart_PrimaryBindsWholeOrFails(t *testing.T) {
	for i, held := range listenProtos("127.0.0.1:0") {
		t.Run(held, func(t *testing.T) {
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t, "127.0.0.1")))
			other := listenProtos(addr)[1-i]
			holdHalf(t, held, addr)

			s := NewServer(config.NewConfigManager(), new(firewall.MockFirewall), "192.0.2.1:53", addr,
				slog.New(slog.DiscardHandler))
			require.ErrorContains(t, startServer(t, s), held)
			requireFree(t, other, addr)
		})
	}
}

// holdHalf binds addr over proto, as another process holding that half.
func holdHalf(t *testing.T, proto, addr string) {
	t.Helper()
	if proto == "udp4" || proto == "udp6" {
		c, err := net.ListenPacket(proto, addr)
		require.NoError(t, err)
		t.Cleanup(func() { c.Close() })
		return
	}
	l, err := net.Listen(proto, addr)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
}

// requireFree fails unless addr can be bound over proto: the proxy did not
// keep that half.
func requireFree(t *testing.T, proto, addr string) {
	t.Helper()
	if proto == "udp4" || proto == "udp6" {
		c, err := net.ListenPacket(proto, addr)
		require.NoError(t, err, "the proxy must not keep the UDP half")
		c.Close()
		return
	}
	l, err := net.Listen(proto, addr)
	require.NoError(t, err, "the proxy must not keep the TCP half")
	l.Close()
}

// A listener beside the primary binds over its address's family and
// answers there, and a container listener stays container-serving.
func TestStart_AdditionalListenerServes(t *testing.T) {
	for _, o := range additionalListeners {
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

// A listener beside the primary whose UDP or TCP half is held by another
// process binds neither: the proxy still starts, BindError says why, and the
// half it could have held is left free, so nothing sent there meets a proxy
// that is only half there.
func TestStart_AdditionalListenerBindsWholeOrNot(t *testing.T) {
	for _, o := range additionalListeners {
		for i, held := range listenProtos(net.JoinHostPort(o.host, "0")) {
			t.Run(o.name+"/"+held, func(t *testing.T) {
				addr := net.JoinHostPort(o.host, strconv.Itoa(freePort(t, o.host)))
				other := listenProtos(addr)[1-i]
				holdHalf(t, held, addr)

				s := newListenTestServer()
				o.add(s, addr)
				require.NoError(t, startServer(t, s), "a listener beside the primary that cannot bind must not fail Start")
				require.ErrorContains(t, s.BindError(addr), held)
				requireFree(t, other, addr)
			})
		}
	}
}

// A listener's preparation runs once the primary is bound and before the
// listener binds; its failure is the listener's BindError, the listener is
// not bound, and the proxy still starts. Where the primary cannot bind,
// nothing is prepared: the second proxy in a namespace touches nothing.
func TestPrepareListenAddr(t *testing.T) {
	primary := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t, "127.0.0.1")))
	addr := net.JoinHostPort("127.0.0.2", strconv.Itoa(freePort(t, "127.0.0.2")))
	refused := errors.New("refused")
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "refused"}[fail], func(t *testing.T) {
			s := NewServer(config.NewConfigManager(), new(firewall.MockFirewall), "192.0.2.1:53", primary,
				slog.New(slog.DiscardHandler))
			s.AddContainerListenAddr(addr)
			// What the preparation found, on Start's goroutine: whether the
			// primary was held and the listener's address still free.
			var prepared, primaryHeld, addrFree bool
			s.PrepareListenAddr(addr, func() error {
				prepared = true
				if c, err := net.ListenPacket("udp4", primary); err == nil {
					c.Close()
				} else {
					primaryHeld = true
				}
				if c, err := net.ListenPacket("udp4", addr); err == nil {
					addrFree = true
					c.Close()
				}
				if fail {
					return refused
				}
				return nil
			})
			require.NoError(t, startServer(t, s))
			require.True(t, prepared)
			assert.True(t, primaryHeld, "the primary must be bound before the preparation")
			assert.True(t, addrFree, "the listener must bind only after its preparation")
			if fail {
				require.ErrorIs(t, s.BindError(addr), refused)
				requireFree(t, "udp4", addr)
				requireFree(t, "tcp4", addr)
			} else {
				require.NoError(t, s.BindError(addr))
			}
		})
	}

	holdHalf(t, "udp4", primary)
	s := NewServer(config.NewConfigManager(), new(firewall.MockFirewall), "192.0.2.1:53", primary,
		slog.New(slog.DiscardHandler))
	s.AddContainerListenAddr(addr)
	prepared := false
	s.PrepareListenAddr(addr, func() error { prepared = true; return nil })
	require.ErrorContains(t, startServer(t, s), primary)
	assert.False(t, prepared, "a proxy without its primary must prepare nothing")
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
