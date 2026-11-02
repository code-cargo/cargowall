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
	"net"
	"slices"
)

// Listeners the DNS redirect sends queries to, and the networks a listener
// binds.

// AddRedirectListenAddr adds an address the DNS redirect sends queries to,
// such as [::1]:53 for IPv6, attributed via the host sockdiag path. Like the
// primary address, it must bind or Start fails: DNS redirected to a port
// cargowall does not hold goes to whatever does.
func (s *Server) AddRedirectListenAddr(addr string) {
	if slices.Contains(s.requiredAddrs, addr) {
		return // bound once: a second listener on it could only fail
	}
	s.AddListenAddr(addr)
	s.requiredAddrs = append(s.requiredAddrs, addr)
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
