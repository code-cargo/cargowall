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
	"encoding/binary"
	"net"

	"github.com/code-cargo/cargowall/bpf"
)

// What a policy's rules decide about a packet, as rules_v4 in verdict.h
// returns it.
type ruleResult int

const (
	ruleNone ruleResult = iota
	ruleAllow
	ruleDeny
)

func resultOf(action uint8) ruleResult {
	if action == 1 {
		return ruleAllow
	}
	return ruleDeny
}

// Allows reports what the rule maps decide for a packet to ip on port and
// proto from a socket judged by step policy, as the hooks' verdict does
// (verdict_allowed_v4 and _v6 in verdict.h). See the Firewall interface.
func (f *FirewallImpl) Allows(policy uint32, ip net.IP, port uint16, proto uint8) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	r := f.rulesLocked(bpf.PolicyJob, ip, port, proto)
	if r == ruleNone && policy != bpf.PolicyJob && f.rulesLocked(policy, ip, port, proto) == ruleAllow {
		return true
	}
	if r == ruleNone {
		var action uint8
		return f.defaultActionMap.Lookup(uint32(0), &action) == nil && action == 1
	}
	return r == ruleAllow
}

// rulesLocked is what policy's rules decide about a packet to ip on port and
// proto, as rules_v4 and rules_v6 read the maps: the longest LPM match; for
// a port-specific one, its port entry under the matched rule's network
// address; then the wildcard port entry. Must be called with f.mu held.
func (f *FirewallImpl) rulesLocked(policy uint32, ip net.IP, port uint16, proto uint8) ruleResult {
	var lpm bpf.TcBpfLpmVal
	var pv bpf.TcBpfPortVal
	if ip4 := ip.To4(); ip4 != nil {
		key := bpf.RuleKey(policy, 32, binary.NativeEndian.Uint32(ip4))
		if f.cidrsMap.Lookup(&key, &lpm) == nil {
			if lpm.PortSpecific == 0 {
				return resultOf(lpm.Action)
			}
			network := binary.NativeEndian.Uint32(ip4.Mask(net.CIDRMask(32-int(lpm.HostBits), 32)))
			pkey := bpf.RulePortKey(policy, network, port, proto, lpm.HostBits)
			if f.portsMap.Lookup(&pkey, &pv) == nil {
				return resultOf(pv.Action)
			}
		}
		wildcard := bpf.RulePortKey(policy, 0, port, proto, 0)
		if f.portsMap.Lookup(&wildcard, &pv) == nil {
			return resultOf(pv.Action)
		}
		return ruleNone
	}
	ip6 := ip.To16()
	if ip6 == nil {
		return ruleNone
	}
	var addr [16]byte
	copy(addr[:], ip6)
	key := bpf.RuleKeyV6(policy, 128, addr)
	if f.cidrsV6Map.Lookup(&key, &lpm) == nil {
		if lpm.PortSpecific == 0 {
			return resultOf(lpm.Action)
		}
		var network [16]byte
		copy(network[:], ip6.Mask(net.CIDRMask(128-int(lpm.HostBits), 128)))
		pkey := bpf.RulePortKeyV6(policy, network, port, proto, lpm.HostBits)
		if f.portsV6Map.Lookup(&pkey, &pv) == nil {
			return resultOf(pv.Action)
		}
	}
	wildcard := bpf.RulePortKeyV6(policy, [16]byte{}, port, proto, 0)
	if f.portsV6Map.Lookup(&wildcard, &pv) == nil {
		return resultOf(pv.Action)
	}
	return ruleNone
}
