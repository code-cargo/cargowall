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
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// Names systemd-resolved synthesizes locally (#126): the underscore set, and
// the RFC 6761 localhost family (localhost, localhost.localdomain, anything
// beneath either). The proxy relays them to the stub on its marked client
// and writes resolved's answer back uncached and unenforced: it never feeds
// hostnameIPs or the firewall.
var (
	syntheticNames = []string{"_gateway", "_outbound", "_localdnsstub", "_localdnsproxy"}
	localhostRoots = []string{"localhost", "localhost.localdomain"}
)

// resolvedStubAddr is a var so tests can point the relay at a fake stub.
var resolvedStubAddr = "127.0.0.53:53"

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
	w.WriteMsg(resp)
	return true
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
