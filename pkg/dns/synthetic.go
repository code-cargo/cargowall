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
// writes resolved's answer back, uncached. See lookupSynthetic for which of
// them are enforced.
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
// resolve host" otherwise). Deduplicated; three names at most.
func (s *Server) seedMachineNames() {
	h, err := machineHostname()
	if err != nil {
		return
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	first, _, cut := strings.Cut(h, ".")
	if first == "" {
		return
	}
	add := func(n string) {
		if !slices.Contains(s.machineNames, n) {
			s.machineNames = append(s.machineNames, n)
		}
	}
	add(h)
	if cut {
		add(first)
	}
	add(first + ".local")
}

// lookupSynthetic classifies a wire-form query name (trailing dot). ok:
// the proxy answers this name itself. expanded: the search-expanded form of
// an underscore name, answered NXDOMAIN — never relayed, never enforced.
// enforce: the answer gets L4 enforcement and attribution like an upstream
// one (#129) — the underscore set and the machine's own names, a fixed
// handful. The localhost family is relayed only: any label under .localhost
// is accepted, and tracking each alias would grow hostnameIPs without bound.
// Machine names take no search expansion: a real host's expanded form is
// the name that resolves, so "runner.lan" stays on the ordinary path.
func (s *Server) lookupSynthetic(qname string) (name string, expanded, enforce, ok bool) {
	full := strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, root := range localhostRoots {
		if full == root || strings.HasSuffix(full, "."+root) {
			return full, false, false, true
		}
	}
	if slices.Contains(s.machineNames, full) {
		return full, false, true, true
	}
	first, rest, hasRest := strings.Cut(full, ".")
	if !slices.Contains(syntheticNames, first) {
		return "", false, false, false
	}
	if !hasRest {
		return first, false, true, true
	}
	if s.config.IsHostSearchSuffix(rest) {
		return first, true, false, true
	}
	return "", false, false, false
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
	name, expanded, enforce, ok := s.lookupSynthetic(r.Question[0].Name)
	if !ok {
		return false
	}

	if expanded {
		// NXDOMAIN, not REFUSED: REFUSED on a multi-label attempt aborts
		// c-ares' search before the bare name. Not relayed: the stub would
		// query upstream unmarked and the DNAT would bring it back here.
		m := new(dns.Msg)
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
		s.enforceDNSResponse(name, resp, 0, false)
	}
	w.WriteMsg(resp)
	return true
}

// hostListener reports whether the query arrived on a listener created for
// host-netns clients rather than via AddContainerListenAddr.
func (s *Server) hostListener(w dns.ResponseWriter) bool {
	return s.attributionMode(w) == attributeHostSockdiag
}
