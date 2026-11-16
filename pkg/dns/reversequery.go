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
)

// reverseQueryKnown reports whether domain, a canonical PTR name (see
// isValidReverseDNS), asks about an address the run already knows, the only
// reverse lookups query filtering answers on their shape alone: a local
// address (localAddress), or one the config manager knows (KnownAddress). A
// reverse lookup of any other address is judged like any other name.
func (s *Server) reverseQueryKnown(domain string) bool {
	addr, ok := reverseQueryAddr(domain)
	if !ok {
		return false
	}
	return localAddress(addr) || s.config.KnownAddress(addr)
}

// sharedAddressSpace is 100.64.0.0/10 (RFC 6598), as used for carrier-grade
// NAT and cluster networks.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// localAddress reports whether addr is private, loopback, link-local,
// unique-local or in the shared address space: the ranges whose reverse
// zones resolvers serve locally (RFC 6303, RFC 7793).
func localAddress(addr netip.Addr) bool {
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		sharedAddressSpace.Contains(addr.Unmap())
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
