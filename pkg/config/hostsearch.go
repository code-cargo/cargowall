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

package config

import (
	"log/slog"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Host search domains (#127).
//
// A stub resolver expands a name with fewer dots than ndots through the
// host's resolv.conf search list before trying it as-is, so on a host with
// "search corp.lan" the first query on the wire for "myservice" is
// "myservice.corp.lan" — and for a real host that expanded form is the name
// that exists. The gate judged it as asked: no rule for the expanded form,
// REFUSED. glibc and Go move on to the bare name; c-ares ends its search on
// a REFUSED multi-label attempt, so for Node dns.resolve*, grpcio and any
// curl or gRPC build on c-ares the rule "myservice" never took effect.
//
// The host list is a third suffix source for stripping, beside the
// Kubernetes defaults and the operator's search-domains, so
// "myservice.corp.lan" is matched as "myservice". Stripping only: it never
// joins the search-domain BYPASS (HasSearchDomainSuffix), which lets
// unmatched names through and stays operator-configured, since resolv.conf
// is DHCP-written. Held outside cm.config so a policy load does not wipe it.

// SetHostSearchDomains replaces the host search list. Normalized like the
// operator list (lowercase, leading dot, deduplicated). Single-label
// suffixes are kept — "lan", "home", "internal" are what search lists carry
// — but a suffix that is itself a public suffix (".com", ".co.uk",
// ".github.io") is skipped with a warning: stripping it would let rule
// "foo" match "foo.com".
func (cm *Manager) SetHostSearchDomains(domains []string, logger *slog.Logger) {
	kept := make([]string, 0, len(domains))
	for _, raw := range domains {
		d := strings.ToLower(strings.TrimSpace(raw))
		d = strings.TrimSuffix(d, ".")
		d = strings.TrimPrefix(d, ".")
		if d == "" {
			continue
		}
		if isPublicSuffix(d) {
			logger.Warn("Ignoring host search domain that is a public suffix", "domain", raw)
			continue
		}
		kept = append(kept, "."+d)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.hostSearchDomains = mergeNormalizedSearchDomains(nil, kept)
}

// HostSearchDomains returns the host search list in effect.
func (cm *Manager) HostSearchDomains() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return append([]string(nil), cm.hostSearchDomains...)
}

// isPublicSuffix reports whether a bare (no leading dot) suffix is a public
// suffix. The PSL's default rule makes every unknown single label its own
// public suffix, which is exactly what a private search domain looks like,
// so a single label counts only when the PSL knows it as an ICANN suffix.
func isPublicSuffix(bare string) bool {
	ps, icann := publicsuffix.PublicSuffix(bare)
	if ps != bare {
		return false
	}
	return icann || strings.Contains(bare, ".")
}
