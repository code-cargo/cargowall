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
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

// TestVerdictParityWithTcEgress is the anti-drift guard for phase 3b: the
// enforcing cgroup hook and the TC backstop share verdict.h, and this proves
// they actually agree. A divergence between the primary hook and its
// backstop is a security bug, so every tuple must produce the same
// allow/deny from both — despite different parse paths (TC starts at the
// Ethernet header, cgroup at L3) and inverted action constants.
//
// It runs twice, with the step-rules gate off and on: with no step bound to
// a policy the step tier finds none, so the gate alone must change no
// verdict.
func TestVerdictParityWithTcEgress(t *testing.T) {
	requireBPF(t)
	off := verdictParity(t, false)
	on := verdictParity(t, true)
	require.Equal(t, off, on, "the step-rules gate alone changed a verdict")
}

// verdictParity runs the parity cases with the step-rules gate as asked and
// returns each case's verdict.
func verdictParity(t *testing.T, stepRules bool) map[string]bool {
	t.Helper()
	tcObjs := loadBPFObjectsStepRules(t, stepRules)
	originObjs := loadOriginObjectsSharing(t, tcObjs)

	// One policy, written once, read by both programs through the shared maps.
	require.NoError(t, tcObjs.MapDefaultAction.Put(uint32(0), uint8(0)))
	require.NoError(t, tcObjs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, tcObjs.MapCidrs.Put(
		RuleKey(PolicyJob, 24, ipToU32("140.82.114.0")),
		TcBpfLpmVal{Action: 1},
	))
	require.NoError(t, tcObjs.MapCidrs.Put(
		RuleKey(PolicyJob, 32, ipToU32("10.1.2.3")),
		TcBpfLpmVal{Action: 1, PortSpecific: 1},
	))
	require.NoError(t, tcObjs.MapPorts.Put(
		RulePortKey(PolicyJob, ipToU32("10.1.2.3"), 8443, ipprotoTCP, 0),
		TcBpfPortVal{Action: 1},
	))
	// Port-specific subnets, keyed as the firewall writes them: the verdict
	// masks the destination down to the matched rule's network address.
	require.NoError(t, tcObjs.MapCidrs.Put(
		RuleKey(PolicyJob, 16, ipToU32("10.2.0.0")),
		TcBpfLpmVal{Action: 1, PortSpecific: 1, HostBits: 16},
	))
	require.NoError(t, tcObjs.MapPorts.Put(
		RulePortKey(PolicyJob, ipToU32("10.2.0.0"), 8443, ipprotoTCP, 16),
		TcBpfPortVal{Action: 1},
	))
	subnet6 := RuleKeyV6(PolicyJob, 48, [16]byte{})
	copy(subnet6.Ip[:], net.ParseIP("2001:db8:5::").To16())
	require.NoError(t, tcObjs.MapCidrsV6.Put(subnet6, TcBpfLpmVal{Action: 1, PortSpecific: 1, HostBits: 80}))
	port6 := RulePortKeyV6(PolicyJob, subnet6.Ip, 8443, ipprotoTCP, 80)
	require.NoError(t, tcObjs.MapPortsV6.Put(port6, TcBpfPortVal{Action: 1}))
	require.NoError(t, originObjs.MapOriginConfig.Put(uint32(0), uint8(originModeEnforce)))

	cases := []struct {
		name   string
		packet []byte
	}{
		// Decision coverage: the rule lookup itself.
		{"allowed /24 member", craftIPv4TCP(t, "140.82.114.3", 443)},
		{"outside the /24", craftIPv4TCP(t, "140.82.115.3", 443)},
		{"port-specific allowed port", craftIPv4TCP(t, "10.1.2.3", 8443)},
		{"port-specific other port", craftIPv4TCP(t, "10.1.2.3", 443)},
		{"port-specific subnet member, allowed port", craftIPv4TCP(t, "10.2.200.7", 8443)},
		{"port-specific subnet member, other port", craftIPv4TCP(t, "10.2.200.7", 443)},
		{"IPv6 port-specific subnet member, allowed port", craftIPv6TCP(t, "2001:db8:5:1::7", 8443)},
		{"IPv6 port-specific subnet member, other port", craftIPv6TCP(t, "2001:db8:5:1::7", 443)},
		{"unmatched, default deny", craftIPv4TCP(t, "93.184.216.34", 80)},

		// Parse coverage: the two hooks keep SEPARATE parsers (TC starts at
		// the Ethernet header, the cgroup hook at L3), and the shared
		// verdict helper only guarantees the decision. Parse drift is
		// therefore the likelier split, and comments claiming "same
		// discipline as tcbpf" are not a contract — these are. Each case is
		// an edge where a parser could disagree about the tuple it feeds
		// into the decision.
		{"IPv4 header with options", craftIPv4WithOptionsTCP(t, "140.82.114.3", 443)},
		{"IPv4 first fragment", craftIPv4FirstFragment(t, "140.82.114.3", 443)},
		{"IPv4 non-first fragment (no L4 header)", craftIPv4NonFirstFragment(t, "140.82.114.3")},
		{"IPv4 non-first fragment, denied dst", craftIPv4NonFirstFragment(t, "93.184.216.34")},
		{"IPv4 invalid IHL", craftInvalidIHLIPv4(t)},
		{"IPv4 truncated TCP", craftTruncatedTCP(t)},
		{"IPv4 UDP allowed", craftIPv4UDP(t, "140.82.114.3", 443)},
		{"IPv4 UDP denied", craftIPv4UDP(t, "93.184.216.34", 53)},
		{"IPv4 established ACK, denied dst", craftIPv4TCPWithFlags(t, "93.184.216.34", 443, 0x10)},
		{"IPv6 allowed", craftIPv6TCP(t, "2606:4700::1", 443)},
		{"IPv6 denied", craftIPv6TCP(t, "2001:db8::1", 443)},
		{"IPv6 behind hop-by-hop ext header", craftIPv6ExtHdrTCP(t, "2606:4700::1", 443, ipprotoHopOpts)},
		{"IPv6 behind routing ext header", craftIPv6ExtHdrTCP(t, "2001:db8::1", 443, ipprotoRouting)},
		{"IPv6 UDP denied", craftIPv6UDP(t, "2001:db8::1", 9999)},
		{"IPv6 multicast", craftIPv6Multicast(t)},
		{"IPv6 ICMPv6 NDP", craftICMPv6NDP(t)},
		{"IPv6 fragmented ICMPv6 non-first", craftIPv6FragmentedICMPv6(t, false)},
		{"ARP (non-IP)", craftARP(t)},
	}

	verdicts := make(map[string]bool, len(cases))
	for _, tc := range cases {
		t.Run(fmt.Sprintf("step rules %v/%s", stepRules, tc.name), func(t *testing.T) {
			tcRet, _, err := tcObjs.CwTcEgress.Test(tc.packet)
			require.NoError(t, err)
			cgRet, _, err := originObjs.CwCgEgress.Test(tc.packet)
			require.NoError(t, err)

			// TC: 0 = pass, 2 = drop. cgroup: 1 = pass, 0 = drop.
			tcAllowed := tcRet == tcActOK
			cgAllowed := cgRet == 1
			require.Equal(t, tcAllowed, cgAllowed,
				"cw_tc_egress and cw_cg_egress disagree (tc=%d cgroup=%d)", tcRet, cgRet)
			verdicts[tc.name] = tcAllowed
		})
	}
	return verdicts
}

// loadOriginObjectsSharing loads the origin collection against the tcbpf
// collection's rule and step-policy maps, built with tcbpf's step-rules
// gate — the same wiring pkg/origin uses in production, which also pins
// that the two collections' map specs stay compatible (a shape or size
// drift fails the load here).
func loadOriginObjectsSharing(t *testing.T, tcObjs *TcBpfObjects) *OriginBpfObjects {
	t.Helper()
	spec, err := LoadOriginBpf()
	require.NoError(t, err)
	require.NoError(t, SetStepRules(spec, tcObjs.StepRules()))
	var objs OriginBpfObjects
	require.NoError(t, spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"map_cidrs":          tcObjs.MapCidrs,
			"map_ports":          tcObjs.MapPorts,
			"map_cidrs_v6":       tcObjs.MapCidrsV6,
			"map_ports_v6":       tcObjs.MapPortsV6,
			"map_default_action": tcObjs.MapDefaultAction,
			"map_audit_mode":     tcObjs.MapAuditMode,
			"map_sock_step":      tcObjs.MapSockStep,
			"map_step_policy":    tcObjs.MapStepPolicy,
		},
	}), "origin collection must load against the tcbpf rule maps")
	t.Cleanup(func() { objs.Close() })
	return &objs
}
