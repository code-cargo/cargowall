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

package config

import (
	"log/slog"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// The host's resolv.conf search list is a strip-only suffix source (#127):
// "myservice.corp.lan" is judged as "myservice", but no name is let through
// for ending in a host suffix — resolv.conf is DHCP-written, so it never
// joins the operator's search-domain bypass. Held outside cm.config so a
// policy load leaves it alone.

// SetHostSearchDomains replaces the host search list: lowercased, leading
// dot, deduplicated, public suffixes dropped with a warning.
func (cm *Manager) SetHostSearchDomains(domains []string, logger *slog.Logger) {
	kept := make([]string, 0, len(domains))
	for _, raw := range domains {
		d := strings.ToLower(strings.TrimSpace(raw))
		d = strings.TrimPrefix(strings.TrimSuffix(d, "."), ".")
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

// IsHostSearchSuffix reports whether a bare suffix ("corp.lan") is on the
// host search list, under the same normalization the list was stored with.
func (cm *Manager) IsHostSearchSuffix(suffix string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return slices.Contains(cm.hostSearchDomains, "."+strings.ToLower(strings.Trim(suffix, ".")))
}

// isPublicSuffix reports whether a bare suffix is a public suffix. Stripping
// one would let rule "foo" match "foo.com". The PSL's default rule makes
// every unknown single label its own suffix — which is what a private search
// domain like "lan" looks like — so a single label counts only when the PSL
// knows it as an ICANN suffix.
func isPublicSuffix(bare string) bool {
	ps, icann := publicsuffix.PublicSuffix(bare)
	if ps != bare {
		return false
	}
	return icann || strings.Contains(bare, ".")
}
