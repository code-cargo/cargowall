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
// 0.0.0.0/0 and ::/0 with ports are written at the zero address with
// host_bits 0 (addWildcardPortsV4/V6), which is also how a host entry keys its
// ports. So the host writers must not install the unspecified address, and
// refusing it loses nothing: it is never a packet's destination.

// refuseUnspecifiedLocked reports whether ip is the unspecified address (IPv4,
// IPv6, or IPv4-mapped IPv6), which the host writers must not install, and
// logs a warning the first time each address is refused. Must be called with
// f.mu held.
func (f *FirewallImpl) refuseUnspecifiedLocked(policy uint32, ip net.IP, ipStr string) bool {
	if !ip.IsUnspecified() {
		return false
	}
	if f.unspecifiedWarned == nil {
		f.unspecifiedWarned = make(map[string]struct{})
	}
	if _, warned := f.unspecifiedWarned[ipStr]; !warned {
		f.unspecifiedWarned[ipStr] = struct{}{}
		f.logger.Warn("Not installing the unspecified address as a destination: a port entry keyed on "+
			"the zero address is the entry for every destination", "ip", ipStr, "policy", policy)
	}
	return true
}
