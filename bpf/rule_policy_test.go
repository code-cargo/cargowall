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

import (
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

// otherPolicy is a policy id beside the job's, for rules both hooks must
// never see while they judge under the job's.
const otherPolicy uint32 = 7

// TestRulePoliciesAreIsolated: the rule maps hold rules by policy, and an
// entry under one policy must never answer a lookup made under another. The
// other policy's entries here would each allow every probe if they leaked
// into the job's lookup: a 0.0.0.0/0 and ::/0 all-ports allow, a host
// route, wildcard ports, and a port entry under the very network address
// and host_bits of the job's own port-specific rule. Both hooks judge every
// probe, and must agree.
func TestRulePoliciesAreIsolated(t *testing.T) {
	requireBPF(t)
	tcObjs := loadBPFObjects(t)
	originObjs := loadOriginObjectsSharing(t, tcObjs)

	require.NoError(t, tcObjs.MapDefaultAction.Put(uint32(0), uint8(0)))
	require.NoError(t, tcObjs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, originObjs.MapOriginConfig.Put(uint32(0), uint8(originModeEnforce)))

	allowAll := TcBpfLpmVal{Action: 1}
	portAllow := TcBpfPortVal{Action: 1}

	// The job's own rules: 10.1.2.3 on TCP 443 only.
	require.NoError(t, tcObjs.MapCidrs.Put(RuleKey(PolicyJob, 32, ipToU32("10.1.2.3")),
		TcBpfLpmVal{Action: 1, PortSpecific: 1}))
	require.NoError(t, tcObjs.MapPorts.Put(RulePortKey(PolicyJob, ipToU32("10.1.2.3"), 443, ipprotoTCP, 0), portAllow))

	// Another policy's, which allow everything.
	require.NoError(t, tcObjs.MapCidrs.Put(RuleKey(otherPolicy, 0, 0), TcBpfLpmVal{Action: 1, HostBits: 32}))
	require.NoError(t, tcObjs.MapCidrs.Put(RuleKey(otherPolicy, 32, ipToU32("93.184.216.34")), allowAll))
	require.NoError(t, tcObjs.MapPorts.Put(RulePortKey(otherPolicy, 0, 8443, ipprotoTCP, 0), portAllow))
	require.NoError(t, tcObjs.MapPorts.Put(RulePortKey(otherPolicy, 0, 53, ipprotoUDP, 0), portAllow))
	require.NoError(t, tcObjs.MapPorts.Put(RulePortKey(otherPolicy, ipToU32("10.1.2.3"), 8080, ipprotoTCP, 0), portAllow))
	require.NoError(t, tcObjs.MapCidrsV6.Put(RuleKeyV6(otherPolicy, 0, [16]byte{}), TcBpfLpmVal{Action: 1, HostBits: 128}))
	require.NoError(t, tcObjs.MapPortsV6.Put(RulePortKeyV6(otherPolicy, [16]byte{}, 443, ipprotoTCP, 0), portAllow))

	cases := []struct {
		name   string
		packet []byte
		allow  bool
	}{
		{"job's port-specific rule, its port", craftIPv4TCP(t, "10.1.2.3", 443), true},
		{"job's port-specific rule, another policy's port", craftIPv4TCP(t, "10.1.2.3", 8080), false},
		{"another policy's host route", craftIPv4TCP(t, "93.184.216.34", 80), false},
		{"another policy's 0.0.0.0/0", craftIPv4TCP(t, "198.51.100.9", 22), false},
		{"another policy's wildcard TCP port", craftIPv4TCP(t, "198.51.100.9", 8443), false},
		{"another policy's wildcard UDP port", craftIPv4UDP(t, "198.51.100.9", 53), false},
		{"another policy's ::/0 and wildcard port", craftIPv6TCP(t, "2001:db8::1", 443), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tcRet, _, err := tcObjs.CwTcEgress.Test(tc.packet)
			require.NoError(t, err)
			cgRet, _, err := originObjs.CwCgEgress.Test(tc.packet)
			require.NoError(t, err)
			require.Equal(t, tc.allow, tcRet == tcActOK, "cw_tc_egress (ret %d)", tcRet)
			require.Equal(t, tc.allow, cgRet == 1, "cw_cg_egress (ret %d)", cgRet)
		})
	}
}

// TestRuleKeyPrefixCountsPolicy pins the key layout every writer relies on,
// with the kernel's own longest-prefix match: a rule's prefix covers the
// addresses under it within its policy, and no prefix, /0 included, reaches
// past the policy field into another policy's lookups.
func TestRuleKeyPrefixCountsPolicy(t *testing.T) {
	objs := loadBPFObjects(t)

	subnet := TcBpfLpmVal{Action: 1, HostBits: 8}
	require.NoError(t, objs.MapCidrs.Put(RuleKey(PolicyJob, 24, ipToU32("10.1.0.0")), subnet))
	everything := TcBpfLpmVal{Action: 0, HostBits: 32}
	require.NoError(t, objs.MapCidrs.Put(RuleKey(otherPolicy, 0, 0), everything))

	var got TcBpfLpmVal
	require.NoError(t, objs.MapCidrs.Lookup(RuleKey(PolicyJob, 32, ipToU32("10.1.0.200")), &got))
	require.Equal(t, subnet, got, "a /24 covers its addresses")
	require.NoError(t, objs.MapCidrs.Lookup(RuleKey(otherPolicy, 32, ipToU32("10.1.0.200")), &got))
	require.Equal(t, everything, got, "the other policy's /0 is its own longest match")
	err := objs.MapCidrs.Lookup(RuleKey(PolicyJob, 32, ipToU32("192.0.2.1")), &got)
	require.True(t, errors.Is(err, ebpf.ErrKeyNotExist), "another policy's /0 must not match the job's lookup: %v", err)
	err = objs.MapCidrs.Lookup(RuleKey(otherPolicy+1, 32, ipToU32("10.1.0.200")), &got)
	require.True(t, errors.Is(err, ebpf.ErrKeyNotExist), "no policy's rule matches a third's lookup: %v", err)

	subnet6 := TcBpfLpmVal{Action: 1, HostBits: 80}
	require.NoError(t, objs.MapCidrsV6.Put(RuleKeyV6(PolicyJob, 48, [16]byte(net.ParseIP("2001:db8:5::").To16())), subnet6))
	require.NoError(t, objs.MapCidrsV6.Put(RuleKeyV6(otherPolicy, 0, [16]byte{}), everything))
	var got6 TcBpfLpmVal
	require.NoError(t, objs.MapCidrsV6.Lookup(RuleKeyV6(PolicyJob, 128, [16]byte(net.ParseIP("2001:db8:5:1::7").To16())), &got6))
	require.Equal(t, subnet6, got6, "a /48 covers its addresses")
	err = objs.MapCidrsV6.Lookup(RuleKeyV6(PolicyJob, 128, [16]byte(net.ParseIP("2001:db8:6::1").To16())), &got6)
	require.True(t, errors.Is(err, ebpf.ErrKeyNotExist), "another policy's ::/0 must not match the job's lookup: %v", err)
}
