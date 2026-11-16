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
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/code-cargo/cargowall/pkg/config"
)

// reverseNameVerdict decides a query for domain when domain is a
// reverse-lookup name (config.ReverseLookupName), and reports whether it is
// one. Only the address gate or the default action decides such a name: a
// PTR query of canonical shape (isValidReverseDNS) for an address the run
// knows (reverseQueryKnown) is allowed; any other is refused when a deny
// rule matches it, and otherwise follows the default action. No allow rule,
// step rule, CNAME allowance or search domain allows it, since none names
// an address, and any would allow every name and query type under it.
func (s *Server) reverseNameVerdict(domain string, qtype uint16) (allowed, decided bool) {
	if !config.ReverseLookupName(domain) {
		return false, false
	}
	if qtype == dns.TypePTR && isValidReverseDNS(domain) && s.reverseQueryKnown(domain) {
		return true, true
	}
	if s.config.MatchHostnameRule(domain).HasDeny() {
		return false, true
	}
	return s.config.GetDefaultAction() == config.ActionAllow, true
}

// reverseQueryKnown reports whether domain, a canonical PTR name (see
// isValidReverseDNS), asks about an address the run already knows, the only
// reverse lookups query filtering answers on their shape alone: a local
// address (config.LocalAddress), or one the config manager knows
// (KnownAddress). A reverse lookup of any other address is judged like any
// other name.
func (s *Server) reverseQueryKnown(domain string) bool {
	addr, ok := reverseQueryAddr(domain)
	if !ok {
		return false
	}
	return config.LocalAddress(addr) || s.config.KnownAddress(addr)
}

// reverseQueryAddr returns the address a canonical PTR name asks about: an
// IPv4 address for in-addr.arpa, an IPv6 one for ip6.arpa, unmapped when
// that is an IPv4-mapped address.
func reverseQueryAddr(domain string) (netip.Addr, bool) {
	lower := strings.ToLower(strings.TrimSuffix(domain, "."))
	if !isValidReverseDNS(lower) {
		return netip.Addr{}, false
	}
	if rest, ok := strings.CutSuffix(lower, ".in-addr.arpa"); ok {
		labels := strings.Split(rest, ".")
		var b [4]byte
		for i, l := range labels {
			n, err := strconv.ParseUint(l, 10, 8)
			if err != nil {
				return netip.Addr{}, false
			}
			b[3-i] = byte(n)
		}
		return netip.AddrFrom4(b), true
	}
	rest, _ := strings.CutSuffix(lower, ".ip6.arpa")
	labels := strings.Split(rest, ".")
	var b [16]byte
	for i, l := range labels {
		n, err := strconv.ParseUint(l, 16, 8)
		if err != nil {
			return netip.Addr{}, false
		}
		// labels[0] is the lowest nibble of the last byte.
		nibble := 31 - i
		if nibble%2 == 0 {
			b[nibble/2] |= byte(n) << 4
		} else {
			b[nibble/2] |= byte(n)
		}
	}
	return netip.AddrFrom16(b).Unmap(), true
}
