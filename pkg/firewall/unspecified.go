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

package firewall

import (
	"net"
)

// A port entry keyed on the zero address is the any-destination wildcard:
// 0.0.0.0/0 and ::/0 with ports write their port entries at the zero address
// (UpdateAllowlistTC), and the verdict reads them there after any rule lookup.
// A host entry keys its ports on its address, and a subnet keys its on its
// network address, so any rule whose address or network is the zero address
// keys its ports where the wildcard's are. No such host or network is a real
// destination: the writers refuse it, and the loaders drop it.

// refuseUnspecifiedLocked reports whether ip is the unspecified address (IPv4,
// IPv6, or IPv4-mapped IPv6), which the writers must not key port entries on,
// and logs a warning the first time each address is refused. Must be called
// with f.mu held.
func (f *FirewallImpl) refuseUnspecifiedLocked(ip net.IP, ipStr string) bool {
	if !ip.IsUnspecified() {
		return false
	}
	if f.unspecifiedWarned == nil {
		f.unspecifiedWarned = make(map[string]struct{})
	}
	if _, warned := f.unspecifiedWarned[ipStr]; !warned {
		f.unspecifiedWarned[ipStr] = struct{}{}
		f.logger.Warn("Not installing the unspecified address as a destination: a port entry keyed on "+
			"the zero address is the entry for every destination", "ip", ipStr)
	}
	return true
}

// isZeroV6 reports whether ip6's 16 bytes are all zero.
func isZeroV6(ip6 net.IP) bool {
	return net.IP(ip6).Equal(net.IPv6unspecified)
}
