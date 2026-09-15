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
	"bufio"
	"os"
	"slices"
	"strings"

	"github.com/miekg/dns"

	cargowallNet "github.com/code-cargo/cargowall/pkg/network"
)

// syntheticNames are the names systemd-resolved synthesizes locally (#126).
// The proxy relays them to the stub on its marked client and writes
// resolved's answer back uncached and unenforced: it never feeds
// hostnameIPs or the firewall.
var syntheticNames = []string{"_gateway", "_outbound", "_localdnsstub", "_localdnsproxy"}

// Injection points for tests.
var (
	resolvedStubAddr = "127.0.0.53:53"
	resolvConfPath   = "/etc/resolv.conf"
	resolvedRunning  = cargowallNet.SystemdResolvedRunning
)

// serveSynthetic answers a synthetic-name query — host listeners, IN class,
// resolved running (probed per hit) — reporting whether it wrote a response.
func (s *Server) serveSynthetic(w dns.ResponseWriter, r *dns.Msg) bool {
	if len(r.Question) == 0 || r.Question[0].Qclass != dns.ClassINET || !s.hostListener(w) {
		return false
	}
	name, expanded, ok := syntheticQuery(r.Question[0].Name)
	if !ok {
		return false
	}
	if running, err := resolvedRunning(); err != nil || !running {
		if err != nil {
			s.logger.Debug("systemd-resolved probe failed; synthetic name takes the ordinary path",
				"name", name, "error", err)
		}
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
		s.logger.Warn("systemd-resolved stub query failed", "name", name, "error", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return true
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

// syntheticQuery classifies a wire-form query name: a bare synthetic name,
// its search-expanded form (first label synthetic, remainder a suffix on the
// host's resolv.conf search list), or neither. resolv.conf is read only
// after the first label matches.
func syntheticQuery(qname string) (name string, expanded, ok bool) {
	full := strings.ToLower(strings.TrimSuffix(qname, "."))
	first, rest, hasRest := strings.Cut(full, ".")
	if !slices.Contains(syntheticNames, first) {
		return "", false, false
	}
	if !hasRest {
		return first, false, true
	}
	if slices.Contains(hostSearchDomains(resolvConfPath), rest) {
		return first, true, true
	}
	return "", false, false
}

// hostSearchDomains reads resolv.conf's search list: the last "search" or
// "domain" directive wins, as glibc reads it; unreadable yields nil.
func hostSearchDomains(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var domains []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || (fields[0] != "search" && fields[0] != "domain") {
			continue
		}
		domains = domains[:0]
		for _, d := range fields[1:] {
			if strings.HasPrefix(d, "#") || strings.HasPrefix(d, ";") {
				break
			}
			domains = append(domains, strings.ToLower(strings.TrimSuffix(d, ".")))
		}
	}
	return domains
}
