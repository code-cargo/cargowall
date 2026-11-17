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
	"net"
	"net/netip"
)

// sharedAddressSpace is 100.64.0.0/10 (RFC 6598), as used for carrier-grade
// NAT and cluster networks.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// LocalAddress reports whether addr is private, loopback, link-local,
// unique-local or in the shared address space: the ranges whose reverse
// zones resolvers serve locally (RFC 6303, RFC 7793). An IPv4-mapped
// address counts as its IPv4 address.
func LocalAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || sharedAddressSpace.Contains(addr)
}

// KnownAddress reports whether addr is an address the run already knows:
// one with a name, which a DNS answer, a CNAME chain from an allowed name,
// or a confirmed reverse lookup gave it, or one inside an allow rule's
// CIDR, the job's or a step's.
func (cm *Manager) KnownAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	ip := net.IP(addr.AsSlice())
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.ipNamedLocked(addr.String()) {
		return true
	}
	for _, r := range cm.resolvedRules {
		if r.Type == RuleTypeCIDR && r.Action == ActionAllow && r.IPNet != nil && r.IPNet.Contains(ip) {
			return true
		}
	}
	for _, sp := range cm.steps {
		for _, r := range sp.rules {
			if r.Type == RuleTypeCIDR && r.Action == ActionAllow && r.IPNet != nil && r.IPNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ipNamedLocked reports whether ip has a name: an entry in the IP-to-hostname
// map, or a place among any tracked name's cached addresses. Must be called
// with cm.mu held.
func (cm *Manager) ipNamedLocked(ip string) bool {
	if _, named := cm.ipToHostname[ip]; named {
		return true
	}
	for _, ips := range cm.hostnameCache {
		for _, cached := range ips {
			if cached.String() == ip {
				return true
			}
		}
	}
	return false
}
