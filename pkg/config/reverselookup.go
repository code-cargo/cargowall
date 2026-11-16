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
)

// ReverseLookupName reports whether name is, or is under, in-addr.arpa or
// ip6.arpa: a lookup of an address's name, never a host to allow. A
// hostname pattern under either counts too. Other .arpa names, such as
// home.arpa or ipv4only.arpa, don't.
func ReverseLookupName(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, zone := range []string{"in-addr.arpa", "ip6.arpa"} {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

// dropReverseLookupHosts returns rules without each hostname allow rule for
// a reverse-lookup name (ReverseLookupName), warning once for each. Such a
// rule would allow every name and query type under it, not one reverse
// lookup, and none is needed: query filtering answers the reverse lookup of
// an address the run allows. A deny rule stays, since dropping it could
// only widen what is allowed.
func dropReverseLookupHosts(rules []Rule) []Rule {
	return slices.DeleteFunc(slices.Clone(rules), func(rule Rule) bool {
		if rule.Type != RuleTypeHostname || rule.Action == ActionDeny || !ReverseLookupName(rule.Value) {
			return false
		}
		slog.Warn("A hostname rule for a reverse-lookup name is dropped: a reverse lookup is answered for an "+
			"address the run allows; allow the address instead",
			"value", rule.Value, "action", rule.Action, "ports", rule.Ports)
		return true
	})
}

// dropReverseZoneSearchDomains returns domains without each search domain
// that is, or is under, a reverse-lookup zone (ReverseLookupName), warning
// once for each. A reverse-lookup name is decided by the address it asks
// about, never by a search domain, so such an entry could never take
// effect; dropping it, rather than refusing the policy, keeps one stray
// entry from failing a whole policy's load.
func dropReverseZoneSearchDomains(domains []string) []string {
	return slices.DeleteFunc(slices.Clone(domains), func(d string) bool {
		if !ReverseLookupName(d) {
			return false
		}
		slog.Warn("A search domain under a reverse-lookup zone is dropped: reverse-lookup names are decided by "+
			"the address they ask about", "domain", d)
		return true
	})
}
