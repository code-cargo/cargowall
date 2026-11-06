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

package bpf

// Keys of the rule maps (map_cidrs, map_ports and their v6 twins), which
// hold rules by policy as well as by address: see the rule policies in
// verdict.h. Every writer builds its keys here, so the prefix length always
// counts the policy field.

// PolicyJob is the job's own rules, POLICY_JOB in verdict.h.
const PolicyJob uint32 = 0

// RulePolicyBits is the policy field's share of a rule LPM key's prefix
// length, RULE_POLICY_BITS in verdict.h: every lookup matches it whole.
const RulePolicyBits = 32

// RuleKey is the map_cidrs key of policy's rule over ip (network byte
// order, as the packet carries it) with the given prefix length.
func RuleKey(policy, prefixLen, ip uint32) TcBpfRuleKey {
	return TcBpfRuleKey{Prefixlen: RulePolicyBits + prefixLen, Policy: policy, Ip: ip}
}

// RuleKeyV6 is the map_cidrs_v6 key of policy's rule over ip with the given
// prefix length.
func RuleKeyV6(policy, prefixLen uint32, ip [16]byte) TcBpfRuleKeyV6 {
	return TcBpfRuleKeyV6{Prefixlen: RulePolicyBits + prefixLen, Policy: policy, Ip: ip}
}

// RulePortKey is the map_ports key of policy's port entry for a rule over
// the network address ip leaving hostBits open (0 and 0 for the wildcard
// entry).
func RulePortKey(policy, ip uint32, port uint16, proto, hostBits uint8) TcBpfRulePortKey {
	return TcBpfRulePortKey{Policy: policy, Ip: ip, Port: port, Proto: proto, HostBits: hostBits}
}

// RulePortKeyV6 is the map_ports_v6 key of policy's port entry, as in
// RulePortKey.
func RulePortKeyV6(policy uint32, ip [16]byte, port uint16, proto, hostBits uint8) TcBpfRulePortKeyV6 {
	return TcBpfRulePortKeyV6{Policy: policy, Ip: ip, Port: port, Proto: proto, HostBits: hostBits}
}
