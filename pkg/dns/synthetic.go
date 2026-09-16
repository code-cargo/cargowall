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

// answerSource says where a DNS answer came from, for enforceDNSResponse's
// L7 evidence: only an answer that came off the wire, for a name a peer can
// present, may mint forward-resolution evidence.
type answerSource int

const (
	// wireAnswer: an upstream answer, or a CNAME pre-resolve of one.
	wireAnswer answerSource = iota
	// localAnswer: relayed from resolved's own state — an address alias, not
	// an identity. Scoping its address against it would make every flow
	// there an L7 miss.
	localAnswer
)

// Names systemd-resolved synthesizes locally (#126), relayed to the stub on
// the marked client and written back uncached. Which of them are enforced
// is decided in lookupSynthetic.
var (
	// enforcedNames are real routed addresses a rule may name (#129): the
	// default gateway and the machine's outbound address.
	enforcedNames = []string{"_gateway", "_outbound"}
	// relayOnlyNames resolve to the loopback listeners the proxy's own relay
	// and startup cache peek depend on: relayed, never tracked, never written.
	relayOnlyNames = []string{"_localdnsstub", "_localdnsproxy"}
	localhostRoots = []string{"localhost", "localhost.localdomain"}
)

// Injection points for tests: the stub address and the machine hostname.
var (
	resolvedStubAddr = "127.0.0.53:53"
	machineHostname  = os.Hostname
)

// machineNames returns the forms resolved synthesizes for the machine's own
// hostname: the configured name and, when it carries a domain, its first
// label. Read per lookup — gethostname is a trivial syscall — so a
// hostnamectl set-hostname mid-run is honoured. The mDNS "<label>.local"
// form is deliberately absent: resolved renames it on conflict, and a
// .local query it does not synthesize is multicast to the LAN, whose answer
// is not local state. A hostname in the localhost family yields nothing;
// that family is handled on its own terms.
func machineNames() []string {
	h, err := machineHostname()
	if err != nil {
		return nil
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	first, _, cut := strings.Cut(h, ".")
	if first == "" || isLocalhostName(h) {
		return nil
	}
	if cut {
		return []string{h, first}
	}
	return []string{h}
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

// lookupSynthetic classifies a wire-form query name (trailing dot). ok:
// the proxy answers this name itself. expanded: the search-expanded form a
// stub resolver tries before the name itself, answered NXDOMAIN — never
// relayed, never enforced. enforce: the answer gets L4 enforcement and
// attribution like an upstream one (#129) — enforcedNames and the machine's
// own names, a fixed handful. The localhost family and relayOnlyNames are
// relayed only: they are loopback, and any label under .localhost is
// accepted, so tracking them would grow hostnameIPs without bound.
func (s *Server) lookupSynthetic(qname string) (name string, expanded, enforce, ok bool) {
	full := strings.ToLower(strings.TrimSuffix(qname, "."))
	if isLocalhostName(full) || slices.Contains(relayOnlyNames, full) {
		return full, false, false, true
	}
	enforced := append(machineNames(), enforcedNames...)
	if slices.Contains(enforced, full) {
		return full, false, true, true
	}
	for _, n := range append(enforced, relayOnlyNames...) {
		if rest, found := strings.CutPrefix(full, n+"."); found && s.config.IsHostSearchSuffix(rest) {
			return n, true, false, true
		}
	}
	return "", false, false, false
}

// AliasClass is how a caller that resolves rule names outside the proxy —
// startup pre-population through the system resolver — must treat a name
// the proxy answers from resolved's local state.
type AliasClass int

const (
	// NotAlias is a wire name: map it and mint forward-resolution evidence.
	NotAlias AliasClass = iota
	// TrackedAlias is an enforced synthetic name (_gateway, _outbound, the
	// machine's own names): map it for attribution, mint no evidence.
	TrackedAlias
	// UntrackedAlias is a loopback listener or a localhost-family name:
	// never tracked, never written — nothing to record at all.
	UntrackedAlias
)

// ClassifyAlias classifies name for a caller outside the proxy's own relay.
func (s *Server) ClassifyAlias(name string) AliasClass {
	_, expanded, enforce, ok := s.lookupSynthetic(name)
	switch {
	case !ok:
		return NotAlias
	case enforce && !expanded:
		return TrackedAlias
	default:
		return UntrackedAlias
	}
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
		s.enforceDNSResponse(name, resp, 0, localAnswer)
	}
	w.WriteMsg(resp)
	return true
}

// hostListener reports whether the query arrived on a listener created for
// host-netns clients rather than via AddContainerListenAddr.
func (s *Server) hostListener(w dns.ResponseWriter) bool {
	return s.attributionMode(w) == attributeHostSockdiag
}
