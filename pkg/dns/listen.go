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
	"fmt"
	"net"
	"slices"

	"github.com/miekg/dns"
)

// Optional listeners, which the DNS redirect sends IPv6 DNS to, and the
// networks a listener binds.

// AddOptionalListenAddr adds an address the proxy listens on if it can,
// attributed via the host sockdiag path: the DNS redirect's [::1]:53, which
// IPv6 DNS is sent to only once it is known to be bound. It binds over UDP
// and TCP both or neither, so nothing redirected there finds half of it
// held by another process. A failure is logged at Debug and left to
// BindError: what it costs is the caller's call. Call before Start.
func (s *Server) AddOptionalListenAddr(addr string) {
	if slices.Contains(s.optionalAddrs, addr) {
		return // bound once: a second listener on it could only fail
	}
	s.AddListenAddr(addr)
	s.optionalAddrs = append(s.optionalAddrs, addr)
}

// Ready is closed once Start has bound its listeners. A primary that cannot
// bind ends Start with its error instead, and Ready stays open.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// BindError is why an optional listener did not bind, nil when it did.
// Valid once Ready is closed.
func (s *Server) BindError(addr string) error { return s.bindErrs[addr] }

// listenBoth binds addr over UDP and TCP and serves both, or binds neither.
func (s *Server) listenBoth(ctx context.Context, lc *net.ListenConfig, addr string) error {
	protos := listenProtos(addr)
	pc, err := lc.ListenPacket(ctx, protos[0], addr)
	if err != nil {
		return fmt.Errorf("%s: %w", protos[0], err)
	}
	ln, err := lc.Listen(ctx, protos[1], addr)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("%s: %w", protos[1], err)
	}
	s.serveOn(addr, protos[0], pc, nil)
	s.serveOn(addr, protos[1], nil, ln)
	return nil
}

// serveOn serves DNS on a bound conn, pc for UDP or ln for TCP, in the
// background, and keeps it for Start's shutdown.
func (s *Server) serveOn(addr, proto string, pc net.PacketConn, ln net.Listener) {
	server := &dns.Server{
		Addr:       addr,
		Net:        proto,
		Handler:    dns.HandlerFunc(s.handleDNSQuery),
		PacketConn: pc,
		Listener:   ln,
		NotifyStartedFunc: func() {
			s.logger.Debug("DNS server is now listening", "addr", addr, "proto", proto)
		},
	}
	s.servers = append(s.servers, server)
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			s.logger.Error("DNS server error", "error", err, "addr", addr)
		}
	}()
}

// listenProtos are the networks a listener on addr binds: IPv6 for an IPv6
// address, IPv4 otherwise.
func listenProtos(addr string) []string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			return []string{"udp6", "tcp6"}
		}
	}
	return []string{"udp4", "tcp4"}
}
