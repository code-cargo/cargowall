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
	"net"
	"slices"
)

// dropUnspecifiedHosts returns rules without each CIDR rule that names only
// the unspecified address (0.0.0.0/32, ::/128, or the IPv4-mapped
// ::ffff:0.0.0.0/128) and carries ports, warning once for each. A port entry
// keyed on the zero address is the any-destination wildcard, so such a rule's
// ports would apply to every destination rather than to the one address it
// names, and dropping it narrows nothing: no packet's destination is the
// zero address. Without ports the rule only matches packets sent to the zero
// address itself, so it stays, and the firewall leaves it out
// (firewall/unspecified.go).
func dropUnspecifiedHosts(rules []Rule) []Rule {
	return slices.DeleteFunc(slices.Clone(rules), func(rule Rule) bool {
		if rule.Type != RuleTypeCIDR || len(rule.Ports) == 0 || !isUnspecifiedHost(rule.Value) {
			return false
		}
		slog.Warn("Dropping a rule for the unspecified address with ports: no destination is the unspecified "+
			"address; use 0.0.0.0/0 or ::/0 to cover every destination",
			"value", rule.Value, "action", rule.Action, "ports", rule.Ports)
		return true
	})
}

// isUnspecifiedHost reports whether value is a single-address CIDR for the
// unspecified address. Rule values are CIDRs by now: normalizeRules promoted
// bare IPs.
func isUnspecifiedHost(value string) bool {
	ip, ipnet, err := net.ParseCIDR(value)
	if err != nil {
		return false
	}
	ones, bits := ipnet.Mask.Size()
	return ones == bits && ip.IsUnspecified()
}
