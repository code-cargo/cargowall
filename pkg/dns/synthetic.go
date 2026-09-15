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
	"os"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// Names systemd-resolved synthesizes locally (#126): the underscore set, the
// machine's own hostname (s.machineNames, seeded at Start), and the RFC 6761
// localhost family (localhost, localhost.localdomain, anything beneath
// either). The proxy relays them to the stub on its marked client and
// writes resolved's answer back, uncached. The underscore set and the
// machine names — a fixed handful — get L4 enforcement and attribution
// like any upstream answer (#129): a rule naming "_gateway" opens the
// gateway's address on its ports, a deny closes it, and with no rule the
// connection is attributed to the name rather than a bare IP. They mint no
// L7 identity evidence (localAlias). The localhost family is relayed only:
// loopback is auto-allowed, and tracking arbitrary "*.localhost" aliases
// would grow hostnameIPs without bound.
var (
	syntheticNames = []string{"_gateway", "_outbound", "_localdnsstub", "_localdnsproxy"}
	localhostRoots = []string{"localhost", "localhost.localdomain"}
)

// Injection points for tests: the stub address and the machine hostname.
var (
	resolvedStubAddr = "127.0.0.53:53"
	machineHostname  = os.Hostname
)

// seedMachineNames records the forms resolved synthesizes for the machine's
// own hostname — the configured name, its first label when it carries a
// domain, and the mDNS form "<label>.local" — so they resolve under the
// redirect even where /etc/hosts does not pin them (sudo's "unable to
// resolve host" otherwise). Three names at most.
func (s *Server) seedMachineNames() {
	h, err := machineHostname()
	if err != nil || h == "" {
		return
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	first, _, cut := strings.Cut(h, ".")
	if first == "" {
		return
	}
	s.machineNames = []string{h}
	if cut {
		s.machineNames = append(s.machineNames, first)
	}
	s.machineNames = append(s.machineNames, first+".local")
}

// serveSynthetic answers a synthetic-name query — host listeners, IN class —
// reporting whether it wrote a response. A stub that does not answer sends
// the query down the ordinary path: /run/systemd/resolve outlives a stopped
// resolved (RuntimeDirectoryPreserve=yes), so presence proves nothing, and
// the connection-refused round trip on loopback is the cheapest true probe.
func (s *Server) serveSynthetic(w dns.ResponseWriter, r *dns.Msg) bool {
	if len(r.Question) == 0 || r.Question[0].Qclass != dns.ClassINET || !s.hostListener(w) {
		return false
	}
	name, expanded, ok := syntheticQuery(r.Question[0].Name, s.config.IsHostSearchSuffix)
	enforce := ok && slices.Contains(syntheticNames, name)
	if !ok {
		if full := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, ".")); slices.Contains(s.machineNames, full) {
			name, ok, enforce = full, true, true
		}
	}
	if !ok {
		return false
	}

	m := new(dns.Msg)
	if expanded {
		// NXDOMAIN, not REFUSED: REFUSED on a multi-label attempt aborts
		// c-ares' search before the bare name. Not relayed: the stub would
		// query upstream unmarked and the DNAT would bring it back here.
		m.SetRcode(r, dns.RcodeNameError)
		m.Authoritative = true
		w.WriteMsg(m)
		return true
	}

	resp, _, err := s.client.Exchange(r, resolvedStubAddr)
	if err != nil {
		s.logger.Debug("systemd-resolved stub unreachable; synthetic name takes the ordinary path",
			"name", name, "error", err)
		return false
	}
	resp.Id = r.Id
	if enforce && resp.Rcode == dns.RcodeSuccess {
		s.enforceDNSResponse(name, resp, 0)
	}
	w.WriteMsg(resp)
	return true
}

// localAlias reports whether the proxy answers name from resolved's local
// state. Such a name is an address alias, never a name a peer presents —
// "_gateway" is whatever the routing table says — so enforceDNSResponse
// mints no forward-resolution evidence for it and registerL7 therefore
// scopes nothing (SCOPE IFF BOUND): an all-ports allow stays L4, and HTTP
// to the host agent carrying "Host: 192.168.127.1" is not an L7 miss.
func (s *Server) localAlias(name string) bool {
	return slices.Contains(syntheticNames, name) || slices.Contains(s.machineNames, name)
}

// hostListener reports whether the query arrived on a listener created for
// host-netns clients rather than via AddContainerListenAddr.
func (s *Server) hostListener(w dns.ResponseWriter) bool {
	return s.attributionMode(w) == attributeHostSockdiag
}

// syntheticQuery classifies a wire-form query name: a localhost-family name,
// a bare underscore name, its search-expanded form (first label synthetic,
// remainder a host search suffix per isHostSuffix), or neither.
func syntheticQuery(qname string, isHostSuffix func(string) bool) (name string, expanded, ok bool) {
	full := strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, root := range localhostRoots {
		if full == root || strings.HasSuffix(full, "."+root) {
			return full, false, true
		}
	}
	first, rest, hasRest := strings.Cut(full, ".")
	if !slices.Contains(syntheticNames, first) {
		return "", false, false
	}
	if !hasRest {
		return first, false, true
	}
	if isHostSuffix(rest) {
		return first, true, true
	}
	return "", false, false
}
