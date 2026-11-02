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
	"fmt"
	"net"
	"slices"

	"github.com/miekg/dns"
)

// The listeners beside the primary, which the DNS redirect sends IPv6 and
// container DNS to, and the networks a listener binds.

// AddListenAddr adds an address the proxy listens on beside the primary, if
// it can, attributed via the host sockdiag path unless AddContainerListenAddr
// adds it: the DNS redirect's [::1]:53, which IPv6 DNS is sent to only once
// it is known to be bound, and likewise the docker bridge's. It binds over
// UDP and TCP both or neither, so nothing sent there finds half of it held
// by another process. A failure is logged at Debug and left to BindError:
// what it costs is the caller's call. Call before Start.
func (s *Server) AddListenAddr(addr string) { s.addListenAddr(addr, attributeHostSockdiag) }

// addListenAddr adds a listener at addr whose queries are attributed by
// mode, and reports whether it did. An address is added once, and the
// primary's not at all: a second listener on one could only fail. A host
// serves listeners of one mode only, the primary's that of the host
// sockdiag path: the mode is the listener host's (attributionMode), so a
// listener of the other one would reclassify every query the host's
// listeners already get.
func (s *Server) addListenAddr(addr string, mode listenerAttribution) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || addr == s.listenAddr || slices.Contains(s.additionalAddrs, addr) {
		return false
	}
	for _, a := range append([]string{s.listenAddr}, s.additionalAddrs...) {
		if h, _, _ := net.SplitHostPort(a); h == host && s.listenerModes[h] != mode {
			return false
		}
	}
	s.additionalAddrs = append(s.additionalAddrs, addr)
	if mode != attributeHostSockdiag {
		s.listenerModes[host] = mode
	}
	return true
}

// errNotAdded is BindError's answer for an address no listener was added
// at.
var errNotAdded = errors.New("no listener was added at that address")

// Ready is closed once Start has bound its listeners. A primary that cannot
// bind ends Start with its error instead, and Ready stays open.
func (s *Server) Ready() <-chan struct{} { return s.readyCh() }

// readyCh is Ready's channel, made on first use so that a Server not built
// by NewServer has one too.
func (s *Server) readyCh() chan struct{} {
	s.readyOnce.Do(func() { s.ready = make(chan struct{}) })
	return s.ready
}

// BindError is why the listener at addr did not bind, nil when it did, and
// errNotAdded when none was added there (addListenAddr). Valid once Ready is
// closed, by when the primary has bound.
func (s *Server) BindError(addr string) error {
	switch {
	case addr == s.listenAddr:
		return nil
	case !slices.Contains(s.additionalAddrs, addr):
		return errNotAdded
	}
	return s.bindErrs[addr]
}

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

// shutdownServers stops every server Start bound. Shutdown refuses until
// ActivateAndServe has marked a server started ("server not started", the
// only error it returns without a deadline), and then it does NOT close the
// conn we bound: close it directly, or a cancel that lands right after Ready
// leaves the :53 socket and its serve goroutine behind.
func (s *Server) shutdownServers() {
	for _, srv := range s.servers {
		if srv.Shutdown() == nil {
			continue
		}
		if srv.PacketConn != nil {
			_ = srv.PacketConn.Close()
		}
		if srv.Listener != nil {
			_ = srv.Listener.Close()
		}
	}
	s.servers = nil
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
