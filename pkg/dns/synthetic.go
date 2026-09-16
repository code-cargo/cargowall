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

// aliasClass is what kind of name the proxy has in hand: an ordinary one, or
// one of the kinds it answers from resolved's local state (#126, #129).
type aliasClass int

const (
	// notAlias: the ordinary path.
	notAlias aliasClass = iota
	// trackedAlias: _gateway, _outbound and the machine's own names —
	// relayed, L4-enforced and attributed like an upstream answer, minting
	// no L7 evidence. A real routed address a rule may name.
	trackedAlias
	// untrackedAlias: the stub's loopback listeners and the localhost
	// family — relayed, recorded nowhere. Loopback the relay itself depends
	// on, and any label under .localhost is accepted, so tracking would
	// grow hostnameIPs without bound.
	untrackedAlias
	// expandedAlias: <alias>.<search>, the form a stub resolver tries before
	// the name itself — NXDOMAIN, recorded nowhere. Never relayed: the stub
	// would query upstream unmarked and the DNAT would bring it back here.
	expandedAlias
)

var (
	enforcedNames  = []string{"_gateway", "_outbound"}
	relayOnlyNames = []string{"_localdnsstub", "_localdnsproxy"}
	localhostRoots = []string{"localhost", "localhost.localdomain"}
)

// Injection points for tests: the stub address and the machine hostname.
var (
	resolvedStubAddr = "127.0.0.53:53"
	machineHostname  = os.Hostname
)

// machineHostnames returns the forms resolved synthesizes for the machine's
// own hostname: the configured name and, when it carries a domain, its
// first label (else ""). Read per lookup — gethostname is a trivial syscall
// — so a hostnamectl set-hostname mid-run is honoured. The mDNS
// "<label>.local" form is deliberately absent: resolved renames it on
// conflict, and a .local query it does not synthesize is multicast to the
// LAN, whose answer is not local state. A hostname in the localhost family
// yields nothing; that family is handled on its own terms.
func machineHostnames() (full, label string) {
	h, err := machineHostname()
	if err != nil {
		return "", ""
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	first, _, cut := strings.Cut(h, ".")
	if first == "" || isLocalhostName(h) {
		return "", ""
	}
	if cut {
		return h, first
	}
	return h, ""
}

// isLocalhostName reports an RFC 6761 localhost-family name.
func isLocalhostName(name string) bool {
	for _, root := range localhostRoots {
		if name == root || strings.HasSuffix(name, "."+root) {
			return true
		}
	}
	return false
}

// lookupSynthetic classifies a wire-form query name (trailing dot),
// returning the alias it names — for expandedAlias, the bare alias — and
// its class. Checked in place against the fixed sets; nothing is built per
// query.
func (s *Server) lookupSynthetic(qname string) (string, aliasClass) {
	full := strings.ToLower(strings.TrimSuffix(qname, "."))
	if isLocalhostName(full) || slices.Contains(relayOnlyNames, full) {
		return full, untrackedAlias
	}
	// "" means absent for both host (gethostname failed) and label (a
	// single-label hostname); neither may match the root query, which
	// trims to "".
	host, label := machineHostnames()
	if slices.Contains(enforcedNames, full) || (host != "" && full == host) || (label != "" && full == label) {
		return full, trackedAlias
	}
	for _, n := range enforcedNames {
		if s.expandedFrom(full, n) {
			return n, expandedAlias
		}
	}
	for _, n := range relayOnlyNames {
		if s.expandedFrom(full, n) {
			return n, expandedAlias
		}
	}
	if host != "" && s.expandedFrom(full, host) {
		return host, expandedAlias
	}
	if label != "" && s.expandedFrom(full, label) {
		return label, expandedAlias
	}
	return "", notAlias
}

// expandedFrom reports whether full is base plus one of the host's own
// search suffixes.
func (s *Server) expandedFrom(full, base string) bool {
	rest, ok := strings.CutPrefix(full, base)
	return ok && len(rest) > 1 && rest[0] == '.' && s.config.IsHostSearchSuffix(rest[1:])
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
	name, class := s.lookupSynthetic(r.Question[0].Name)
	switch class {
	case notAlias:
		return false
	case expandedAlias:
		// NXDOMAIN, not REFUSED: REFUSED on a multi-label attempt aborts
		// c-ares' search before the bare name.
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
	if class == trackedAlias && resp.Rcode == dns.RcodeSuccess {
		s.enforceDNSResponse(name, resp, 0, localAnswer)
	}
	w.WriteMsg(resp)
	return true
}

// RecordSystemCacheAnswer applies one startup pre-population answer — the
// IPs a rule hostname currently resolves to through the system resolver, the
// IPs live processes are already using — under the same policy as the
// proxy's own answers. A wire name is mapped for attribution and mints
// forward-resolution evidence: a FORWARD lookup of a rule name, the same
// evidence class as the proxy's answers, and what lets an IP be L7-scoped at
// all (RegisterL7Identity scopes iff bound). A tracked alias is mapped
// without evidence. Anything else is recorded nowhere, so the
// tracked-hostname replay can never write a loopback listener.
func (s *Server) RecordSystemCacheAnswer(hostname string, ips []string) {
	_, class := s.lookupSynthetic(hostname)
	if class != notAlias && class != trackedAlias {
		return
	}
	for _, ip := range ips {
		s.config.UpdateDNSMapping(hostname, ip)
		if class == notAlias {
			s.config.RecordForwardResolution(hostname, ip)
		}
	}
}

// hostListener reports whether the query arrived on a listener created for
// host-netns clients rather than via AddContainerListenAddr.
func (s *Server) hostListener(w dns.ResponseWriter) bool {
	return s.attributionMode(w) == attributeHostSockdiag
}
