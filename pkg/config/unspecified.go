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

// dropUnspecifiedNetworks returns rules without each CIDR rule that carries
// ports and whose network is the unspecified address at a prefix of 1 or more,
// warning once for each. A port entry is keyed on the network address, so a
// host route at 0.0.0.0 or ::, and a port-scoped subnet whose network is the
// zero address at any prefix but /0, key their ports where the
// any-destination wildcard keeps its own (firewall/unspecified.go). Such a
// rule can never mean the one address or network it names; /0 is the real
// wildcard and stays. Dropping the rest narrows nothing: no packet's
// destination is the zero address, and a port-scoped subnet matches nothing
// inside itself in this release anyway.
func dropUnspecifiedNetworks(rules []Rule) []Rule {
	return slices.DeleteFunc(slices.Clone(rules), func(rule Rule) bool {
		if rule.Type != RuleTypeCIDR || len(rule.Ports) == 0 || !isUnspecifiedNetwork(rule.Value) {
			return false
		}
		slog.Warn("Dropping a rule for the unspecified address with ports: no destination is the unspecified "+
			"address or a network based at it; use 0.0.0.0/0 or ::/0 to cover every destination",
			"value", rule.Value, "action", rule.Action, "ports", rule.Ports)
		return true
	})
}

// isUnspecifiedNetwork reports whether value is a CIDR whose network address is
// the unspecified address at a prefix of 1 or more (so /0, the real wildcard,
// is excluded). Rule values are CIDRs by now: normalizeRules promoted bare IPs.
func isUnspecifiedNetwork(value string) bool {
	ip, ipnet, err := net.ParseCIDR(value)
	if err != nil {
		return false
	}
	ones, _ := ipnet.Mask.Size()
	return ones >= 1 && ip.IsUnspecified()
}
