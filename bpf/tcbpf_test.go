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
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

// bpfAvailable is set by TestMain to indicate whether BPF is available.
var bpfAvailable bool

func TestMain(m *testing.M) {
	if err := rlimit.RemoveMemlock(); err != nil {
		// BPF not available — tests will skip individually with visible output
		log.Printf("BPF not available (run with sudo for full test coverage): %v", err)
		bpfAvailable = false
	} else {
		bpfAvailable = true
	}
	os.Exit(m.Run())
}

// requireBPF skips the test with a visible message if BPF is not available.
func requireBPF(t *testing.T) {
	t.Helper()
	if !bpfAvailable {
		t.Skip("BPF not available (requires root/CAP_BPF)")
	}
}

const (
	// TC action codes
	tcActOK   = 0
	tcActShot = 2

	// Ethernet protocols
	ethPIP     = 0x0800
	ethPIPv6   = 0x86DD
	ethP8021Q  = 0x8100
	ethP8021AD = 0x88A8

	// IP protocols
	ipprotoICMP     = 1
	ipprotoTCP      = 6
	ipprotoUDP      = 17
	ipprotoICMPv6   = 58
	ipprotoHopOpts  = 0
	ipprotoRouting  = 43
	ipprotoFrag     = 44
	ipprotoDstOpts  = 60
	ipprotoMobility = 135
)

func loadBPFObjects(t *testing.T) *TcBpfObjects {
	t.Helper()
	requireBPF(t)
	var objs TcBpfObjects
	if err := LoadTcBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loading objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// Test cases for tc_egress program using BPF_PROG_TEST_RUN
func TestTcEgress(t *testing.T) {
	objs := loadBPFObjects(t)

	// Set up test rules
	setupTestRules(t, objs)

	tests := []struct {
		name    string
		packet  []byte
		wantRet uint32
	}{
		// Basic IPv4 tests
		{
			name:    "IPv4 TCP to allowed host",
			packet:  craftIPv4TCP(t, "140.82.114.3", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 TCP to blocked host",
			packet:  craftIPv4TCP(t, "93.184.216.34", 80),
			wantRet: tcActShot,
		},
		{
			name:    "IPv4 UDP to allowed host",
			packet:  craftIPv4UDP(t, "140.82.114.3", 53),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 UDP to blocked host",
			packet:  craftIPv4UDP(t, "93.184.216.34", 53),
			wantRet: tcActShot,
		},

		// IPv4 Fragmentation tests
		{
			name:    "IPv4 first fragment to allowed host",
			packet:  craftIPv4FirstFragment(t, "140.82.114.3", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 first fragment to blocked host",
			packet:  craftIPv4FirstFragment(t, "93.184.216.34", 80),
			wantRet: tcActShot,
		},
		{
			name:    "IPv4 non-first fragment to allowed host",
			packet:  craftIPv4NonFirstFragment(t, "140.82.114.3"),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 non-first fragment to blocked host",
			packet:  craftIPv4NonFirstFragment(t, "93.184.216.34"),
			wantRet: tcActShot,
		},

		// TCP flag variants
		{
			name:    "IPv4 TCP ACK only to allowed host",
			packet:  craftIPv4TCPWithFlags(t, "140.82.114.3", 443, 0x10),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 TCP SYN+ACK to allowed host",
			packet:  craftIPv4TCPWithFlags(t, "140.82.114.3", 443, 0x12),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 TCP RST to allowed host",
			packet:  craftIPv4TCPWithFlags(t, "140.82.114.3", 443, 0x04),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 TCP FIN to allowed host",
			packet:  craftIPv4TCPWithFlags(t, "140.82.114.3", 443, 0x01),
			wantRet: tcActOK,
		},

		// IPv4 with IP options (IHL > 5)
		{
			name:    "IPv4 with IP options to allowed host",
			packet:  craftIPv4WithOptionsTCP(t, "140.82.114.3", 443),
			wantRet: tcActOK,
		},

		// VLAN handling
		{
			name:    "VLAN tagged to allowed host",
			packet:  craftVLANIPv4(t, "140.82.114.3", 443),
			wantRet: tcActOK,
		},
		{
			name:    "VLAN tagged to blocked host",
			packet:  craftVLANIPv4(t, "93.184.216.34", 80),
			wantRet: tcActShot,
		},
		{
			name:    "QinQ double VLAN to blocked host",
			packet:  craftQinQIPv4(t, "93.184.216.34", 80),
			wantRet: tcActShot,
		},
		{
			name:    "QinQ double VLAN to allowed host",
			packet:  craftQinQIPv4(t, "140.82.114.3", 443),
			wantRet: tcActOK,
		},
		{
			name:    "QinQ double VLAN IPv6 to allowed host",
			packet:  craftQinQIPv6(t, "2606:4700::1", 443),
			wantRet: tcActOK,
		},
		{
			name:    "QinQ double VLAN IPv6 to blocked host",
			packet:  craftQinQIPv6(t, "2001:db8::1", 80),
			wantRet: tcActShot,
		},

		// Basic IPv6 tests
		{
			name:    "IPv6 direct TCP",
			packet:  craftIPv6TCP(t, "2606:4700::1", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 TCP to blocked host",
			packet:  craftIPv6TCP(t, "2001:db8::1", 80),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 UDP to allowed host",
			packet:  craftIPv6UDP(t, "2606:4700::1", 53),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 UDP to blocked host",
			packet:  craftIPv6UDP(t, "2001:db8::1", 53),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 TCP ACK only to allowed host",
			packet:  craftIPv6TCPWithFlags(t, "2606:4700::1", 443, 0x10),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 TCP SYN+ACK to allowed host",
			packet:  craftIPv6TCPWithFlags(t, "2606:4700::1", 443, 0x12),
			wantRet: tcActOK,
		},

		// IPv6 extension headers
		{
			name:    "IPv6 with Hop-by-Hop then TCP",
			packet:  craftIPv6ExtHdrTCP(t, "2606:4700::1", 443, ipprotoHopOpts),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 with Routing header then TCP",
			packet:  craftIPv6ExtHdrTCP(t, "2606:4700::1", 443, ipprotoRouting),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 with Destination Options then TCP",
			packet:  craftIPv6ExtHdrTCP(t, "2606:4700::1", 443, ipprotoDstOpts),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 with Mobility header then TCP",
			packet:  craftIPv6ExtHdrTCP(t, "2606:4700::1", 443, ipprotoMobility),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 with HopByHop + Routing + TCP chain",
			packet:  craftIPv6MultiExtHdrTCP(t, "2606:4700::1", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 with HopByHop + Routing + TCP chain to blocked host",
			packet:  craftIPv6MultiExtHdrTCP(t, "2001:db8::1", 80),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 fragmented ICMPv6 first fragment",
			packet:  craftIPv6FragmentedICMPv6(t, true),
			wantRet: tcActOK, // ICMPv6 should be allowed even after fragment header
		},
		{
			name:    "IPv6 fragmented ICMPv6 non-first fragment",
			packet:  craftIPv6FragmentedICMPv6(t, false),
			wantRet: tcActOK, // Non-first fragments of ICMPv6 should also be allowed
		},
		{
			name:    "IPv6 fragmented TCP first fragment to allowed host",
			packet:  craftIPv6FragmentedTCP(t, "2606:4700::1", 443, true),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 fragmented TCP non-first fragment to allowed host",
			packet:  craftIPv6FragmentedTCP(t, "2606:4700::1", 443, false),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 fragmented TCP first fragment to blocked host",
			packet:  craftIPv6FragmentedTCP(t, "2001:db8::1", 80, true),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 fragmented TCP non-first fragment to blocked host",
			packet:  craftIPv6FragmentedTCP(t, "2001:db8::1", 80, false),
			wantRet: tcActShot,
		},

		{
			name:    "IPv4 ICMP allowed via CIDR allow rule",
			packet:  craftIPv4ICMP(t, "140.82.114.3"),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 ICMP blocked outside allowed CIDR (default deny)",
			packet:  craftIPv4ICMP(t, "93.184.216.34"),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 GRE blocked",
			packet:  craftIPv6Proto(t, "2606:4700::1", 47),
			wantRet: tcActShot,
		},

		// VLAN handling - IPv6
		{
			name:    "VLAN tagged IPv6 to allowed host",
			packet:  craftVLANIPv6(t, "2606:4700::1", 443),
			wantRet: tcActOK,
		},
		{
			name:    "VLAN tagged IPv6 to blocked host",
			packet:  craftVLANIPv6(t, "2001:db8::1", 80),
			wantRet: tcActShot,
		},

		// Malformed packets (should block)
		// Note: truncated ethernet header (<14 bytes) can't be tested via BPF_PROG_TEST_RUN
		// because the kernel requires minimum ETH_HLEN (14) bytes.
		{
			name:    "Truncated IP header",
			packet:  craftTruncatedIPv4(t),
			wantRet: tcActShot,
		},
		{
			name:    "Invalid IHL",
			packet:  craftInvalidIHLIPv4(t),
			wantRet: tcActShot,
		},
		{
			name:    "Truncated TCP header",
			packet:  craftTruncatedTCP(t),
			wantRet: tcActShot,
		},
		{
			name:    "Truncated UDP header",
			packet:  craftTruncatedUDP(t),
			wantRet: tcActShot,
		},
		{
			name:    "Truncated IPv6 header",
			packet:  craftTruncatedIPv6(t),
			wantRet: tcActShot,
		},
		{
			name:    "Truncated IPv6 TCP header",
			packet:  craftTruncatedIPv6TCP(t),
			wantRet: tcActShot,
		},
		{
			name:    "Truncated IPv6 extension header",
			packet:  craftTruncatedIPv6ExtHdr(t),
			wantRet: tcActShot,
		},
		{
			name:    "Truncated IPv6 fragment header",
			packet:  craftTruncatedIPv6FragHdr(t),
			wantRet: tcActShot,
		},
		{
			name:    "Truncated VLAN header",
			packet:  craftEthHeader(ethP8021Q), // 14 bytes, no VLAN payload
			wantRet: tcActShot,
		},
		{
			name:    "Truncated QinQ inner VLAN",
			packet:  append(craftEthHeader(ethP8021AD), craftVLANHeader(ethP8021Q, 200)...),
			wantRet: tcActShot,
		},
		{
			name:    "Truncated IPv6 UDP header",
			packet:  craftTruncatedIPv6UDP(t),
			wantRet: tcActShot,
		},

		// IPv6 extension header + fragment header chain
		{
			name:    "IPv6 HopByHop + Fragment header chain to allowed host",
			packet:  craftIPv6ExtHdrThenFragmentedTCP(t, "2606:4700::1", 443, true),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 HopByHop + Fragment header chain to blocked host",
			packet:  craftIPv6ExtHdrThenFragmentedTCP(t, "2001:db8::1", 80, true),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 HopByHop + Fragment non-first fragment to allowed host",
			packet:  craftIPv6ExtHdrThenFragmentedTCP(t, "2606:4700::1", 443, false),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 HopByHop + Fragment non-first fragment to blocked host",
			packet:  craftIPv6ExtHdrThenFragmentedTCP(t, "2001:db8::1", 80, false),
			wantRet: tcActShot,
		},

		// Non-SYN TCP to blocked host (blocked without event submission)
		{
			name:    "IPv4 TCP ACK to blocked host",
			packet:  craftIPv4TCPWithFlags(t, "93.184.216.34", 80, 0x10),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 TCP ACK to blocked host",
			packet:  craftIPv6TCPWithFlags(t, "2001:db8::1", 80, 0x10),
			wantRet: tcActShot,
		},

		// Passthrough traffic (always allowed)
		{
			name:    "ARP packet",
			packet:  craftARP(t),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 multicast",
			packet:  craftIPv6Multicast(t),
			wantRet: tcActOK,
		},
		{
			name:    "ICMPv6 NDP",
			packet:  craftICMPv6NDP(t),
			wantRet: tcActOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.TcEgress.Test(tt.packet)
			require.NoError(t, err, "test run failed")
			require.Equal(t, tt.wantRet, ret, "unexpected return value")
		})
	}
}

func TestTcEgressAuditMode(t *testing.T) {
	objs := loadBPFObjects(t)

	setupTestRules(t, objs)

	// Enable audit mode
	var auditKey uint32 = 0
	var auditVal uint8 = 1
	err := objs.MapAuditMode.Update(&auditKey, &auditVal, ebpf.UpdateAny)
	require.NoError(t, err)

	tests := []struct {
		name    string
		packet  []byte
		wantRet uint32
	}{
		{
			name:    "Blocked IPv4 TCP passes in audit mode",
			packet:  craftIPv4TCP(t, "93.184.216.34", 80),
			wantRet: tcActOK,
		},
		{
			name:    "Blocked IPv6 TCP passes in audit mode",
			packet:  craftIPv6TCP(t, "2001:db8::1", 80),
			wantRet: tcActOK,
		},
		{
			name:    "Blocked ICMP passes in audit mode",
			packet:  craftIPv4ICMP(t, "93.184.216.34"),
			wantRet: tcActOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.TcEgress.Test(tt.packet)
			require.NoError(t, err, "test run failed")
			require.Equal(t, tt.wantRet, ret, "unexpected return value")
		})
	}
}

func TestTcIngress(t *testing.T) {
	objs := loadBPFObjects(t)

	// Ingress should always allow traffic
	packet := craftIPv4TCP(t, "93.184.216.34", 80)
	ret, _, err := objs.TcIngress.Test(packet)
	require.NoError(t, err)
	require.Equal(t, uint32(tcActOK), ret, "ingress should always allow")
}

func TestTcEgressDefaultAllow(t *testing.T) {
	objs := loadBPFObjects(t)

	// Set default action to allow
	var defKey uint32 = 0
	var defVal uint8 = 1 // allow
	err := objs.MapDefaultAction.Update(&defKey, &defVal, ebpf.UpdateAny)
	require.NoError(t, err)

	tests := []struct {
		name    string
		packet  []byte
		wantRet uint32
	}{
		{
			name:    "IPv4 TCP to unknown host should be allowed",
			packet:  craftIPv4TCP(t, "8.8.8.8", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 UDP to unknown host should be allowed",
			packet:  craftIPv4UDP(t, "1.1.1.1", 53),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 TCP to unknown host should be allowed",
			packet:  craftIPv6TCP(t, "2001:4860:4860::8888", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 UDP to unknown host should be allowed",
			packet:  craftIPv6UDP(t, "2001:4860:4860::8888", 53),
			wantRet: tcActOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.TcEgress.Test(tt.packet)
			require.NoError(t, err, "test run failed")
			require.Equal(t, tt.wantRet, ret, "unexpected return value")
		})
	}
}

func TestTcEgressExplicitDeny(t *testing.T) {
	objs := loadBPFObjects(t)

	// Set default action to deny
	var defKey uint32 = 0
	var defVal uint8 = 0 // deny
	err := objs.MapDefaultAction.Update(&defKey, &defVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv4 allow rule for 140.82.114.0/24
	key4Allow := TcBpfLpmKey{
		Prefixlen: 24,
		Ip:        ipToU32("140.82.114.0"),
	}
	allowVal := TcBpfLpmVal{
		Action:       1, // allow
		PortSpecific: 0,
	}
	err = objs.MapCidrs.Update(&key4Allow, &allowVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv4 explicit deny rule for 10.0.0.0/24
	key4Deny := TcBpfLpmKey{
		Prefixlen: 24,
		Ip:        ipToU32("10.0.0.0"),
	}
	denyVal := TcBpfLpmVal{
		Action:       0, // explicit deny
		PortSpecific: 0,
	}
	err = objs.MapCidrs.Update(&key4Deny, &denyVal, ebpf.UpdateAny)
	require.NoError(t, err)

	tests := []struct {
		name    string
		packet  []byte
		wantRet uint32
	}{
		{
			name:    "Explicit deny rule blocks traffic",
			packet:  craftIPv4TCP(t, "10.0.0.1", 443),
			wantRet: tcActShot,
		},
		{
			name:    "Allow rule permits traffic",
			packet:  craftIPv4TCP(t, "140.82.114.3", 443),
			wantRet: tcActOK,
		},
		{
			name:    "No rule falls to default deny",
			packet:  craftIPv4TCP(t, "8.8.8.8", 443),
			wantRet: tcActShot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.TcEgress.Test(tt.packet)
			require.NoError(t, err, "test run failed")
			require.Equal(t, tt.wantRet, ret, "unexpected return value")
		})
	}
}

func TestTcEgressDefaultAllowWithDeny(t *testing.T) {
	objs := loadBPFObjects(t)

	// Set default action to allow
	var defKey uint32 = 0
	var defVal uint8 = 1 // allow
	err := objs.MapDefaultAction.Update(&defKey, &defVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv4 explicit deny rule for 10.0.0.0/24
	key4Deny := TcBpfLpmKey{
		Prefixlen: 24,
		Ip:        ipToU32("10.0.0.0"),
	}
	denyVal := TcBpfLpmVal{
		Action:       0, // explicit deny
		PortSpecific: 0,
	}
	err = objs.MapCidrs.Update(&key4Deny, &denyVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv6 explicit deny rule for 2001:db8::/32
	key6Deny := TcBpfLpmKeyV6{
		Prefixlen: 32,
	}
	ip6 := net.ParseIP("2001:db8::")
	copy(key6Deny.Ip[:], ip6.To16())
	err = objs.MapCidrsV6.Update(&key6Deny, &denyVal, ebpf.UpdateAny)
	require.NoError(t, err)

	tests := []struct {
		name    string
		packet  []byte
		wantRet uint32
	}{
		{
			name:    "IPv4 deny rule overrides default allow",
			packet:  craftIPv4TCP(t, "10.0.0.1", 443),
			wantRet: tcActShot,
		},
		{
			name:    "IPv4 no rule falls to default allow",
			packet:  craftIPv4TCP(t, "8.8.8.8", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 deny rule overrides default allow",
			packet:  craftIPv6TCP(t, "2001:db8::1", 80),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 no rule falls to default allow",
			packet:  craftIPv6TCP(t, "2001:4860:4860::8888", 443),
			wantRet: tcActOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.TcEgress.Test(tt.packet)
			require.NoError(t, err, "test run failed")
			require.Equal(t, tt.wantRet, ret, "unexpected return value")
		})
	}
}

func TestTcEgressPortSpecificRules(t *testing.T) {
	objs := loadBPFObjects(t)

	setupPortSpecificRules(t, objs)

	tests := []struct {
		name    string
		packet  []byte
		wantRet uint32
	}{
		// IPv4 port-specific tests
		{
			name:    "IPv4 TCP to port-specific host on allowed port",
			packet:  craftIPv4TCP(t, "10.0.0.1", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 TCP to port-specific host on blocked port",
			packet:  craftIPv4TCP(t, "10.0.0.1", 80),
			wantRet: tcActShot,
		},
		{
			name:    "IPv4 UDP to port-specific host on allowed port",
			packet:  craftIPv4UDP(t, "10.0.0.1", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 TCP using wildcard port rule",
			packet:  craftIPv4TCP(t, "192.168.1.1", 8080),
			wantRet: tcActOK,
		},
		{
			name:    "IPv4 TCP not matching any port rule",
			packet:  craftIPv4TCP(t, "192.168.1.1", 9999),
			wantRet: tcActShot,
		},

		// IPv6 port-specific tests
		{
			name:    "IPv6 TCP to port-specific host on allowed port",
			packet:  craftIPv6TCP(t, "2001:db8:1::1", 443),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 TCP to port-specific host on blocked port",
			packet:  craftIPv6TCP(t, "2001:db8:1::1", 80),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 TCP using wildcard port rule",
			packet:  craftIPv6TCP(t, "2001:db8:2::1", 8080),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 TCP not matching any port rule",
			packet:  craftIPv6TCP(t, "2001:db8:2::1", 9999),
			wantRet: tcActShot,
		},

		// Port-specific CIDR with wildcard port fallback
		// These IPs match the LPM CIDR (port_specific=1) but have no specific IP:port entry,
		// so they fall back to the wildcard 0.0.0.0:8080 / [::]:8080 rule.
		{
			name:    "IPv4 TCP to port-specific host falling back to wildcard port",
			packet:  craftIPv4TCP(t, "10.0.0.99", 8080),
			wantRet: tcActOK,
		},
		{
			name:    "IPv6 TCP to port-specific host falling back to wildcard port",
			packet:  craftIPv6TCP(t, "2001:db8:1::99", 8080),
			wantRet: tcActOK,
		},

		// Port-specific deny tests (action=0 in port map)
		{
			name:    "IPv4 TCP to port-specific host on denied port",
			packet:  craftIPv4TCP(t, "10.0.0.1", 22),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 TCP to port-specific host on denied port",
			packet:  craftIPv6TCP(t, "2001:db8:1::1", 22),
			wantRet: tcActShot,
		},

		// Wildcard port deny after CIDR match (Gap 3):
		// IP matches port_specific CIDR, no specific IP:port entry,
		// falls back to wildcard 0.0.0.0:9090 / [::]:9090 which has action=0 (deny).
		{
			name:    "IPv4 TCP port-specific CIDR falling back to wildcard port deny",
			packet:  craftIPv4TCP(t, "10.0.0.99", 9090),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 TCP port-specific CIDR falling back to wildcard port deny",
			packet:  craftIPv6TCP(t, "2001:db8:1::99", 9090),
			wantRet: tcActShot,
		},

		// Wildcard port deny with no CIDR match (Gap 4):
		// IP does NOT match any CIDR, falls to wildcard 0.0.0.0:9090 / [::]:9090
		// which has action=0 (deny). Distinct from "no wildcard at all → default deny".
		{
			name:    "IPv4 TCP no CIDR match with wildcard port deny",
			packet:  craftIPv4TCP(t, "192.168.1.1", 9090),
			wantRet: tcActShot,
		},
		{
			name:    "IPv6 TCP no CIDR match with wildcard port deny",
			packet:  craftIPv6TCP(t, "2001:db8:2::1", 9090),
			wantRet: tcActShot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.TcEgress.Test(tt.packet)
			require.NoError(t, err, "test run failed")
			require.Equal(t, tt.wantRet, ret, "unexpected return value")
		})
	}
}

func TestTcEgressProtocolEnforcement(t *testing.T) {
	objs := loadBPFObjects(t)

	// Set default deny
	var defKey uint32 = 0
	var defVal uint8 = 0
	err := objs.MapDefaultAction.Update(&defKey, &defVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add 10.0.0.0/24 with port_specific=1
	key4 := TcBpfLpmKey{Prefixlen: 24, Ip: ipToU32("10.0.0.0")}
	val := TcBpfLpmVal{Action: 1, PortSpecific: 1}
	err = objs.MapCidrs.Update(&key4, &val, ebpf.UpdateAny)
	require.NoError(t, err)

	// Allow 10.0.0.1:443 TCP ONLY (no UDP entry)
	portVal := TcBpfPortVal{Action: 1}
	portKey := TcBpfPortKey{Ip: ipToU32("10.0.0.1"), Port: 443, Proto: ipprotoTCP}
	err = objs.MapPorts.Update(&portKey, &portVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Allow 10.0.0.1:53 UDP ONLY (no TCP entry)
	portKey2 := TcBpfPortKey{Ip: ipToU32("10.0.0.1"), Port: 53, Proto: ipprotoUDP}
	err = objs.MapPorts.Update(&portKey2, &portVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Allow 10.0.0.2 ICMP ONLY (port=0, proto=1, no TCP/UDP entries)
	portKeyICMP := TcBpfPortKey{Ip: ipToU32("10.0.0.2"), Port: 0, Proto: ipprotoICMP}
	err = objs.MapPorts.Update(&portKeyICMP, &portVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv6 2001:db8:1::/48 with port_specific=1
	key6 := TcBpfLpmKeyV6{Prefixlen: 48}
	ip6 := net.ParseIP("2001:db8:1::")
	copy(key6.Ip[:], ip6.To16())
	err = objs.MapCidrsV6.Update(&key6, &val, ebpf.UpdateAny)
	require.NoError(t, err)

	// Allow [2001:db8:1::1]:443 TCP ONLY
	portKey6 := TcBpfPortKeyV6{Port: 443, Proto: ipprotoTCP}
	ip6Addr := net.ParseIP("2001:db8:1::1")
	copy(portKey6.Ip[:], ip6Addr.To16())
	err = objs.MapPortsV6.Update(&portKey6, &portVal, ebpf.UpdateAny)
	require.NoError(t, err)

	tests := []struct {
		name    string
		packet  []byte
		wantRet uint32
	}{
		// IPv4 TCP-only port
		{"IPv4 TCP to TCP-only port allowed", craftIPv4TCP(t, "10.0.0.1", 443), tcActOK},
		{"IPv4 UDP to TCP-only port blocked", craftIPv4UDP(t, "10.0.0.1", 443), tcActShot},
		// IPv4 UDP-only port
		{"IPv4 UDP to UDP-only port allowed", craftIPv4UDP(t, "10.0.0.1", 53), tcActOK},
		{"IPv4 TCP to UDP-only port blocked", craftIPv4TCP(t, "10.0.0.1", 53), tcActShot},
		// IPv4 ICMP only (proto field in port_key discriminates)
		{"IPv4 ICMP to ICMP-allowed host allowed", craftIPv4ICMP(t, "10.0.0.2"), tcActOK},
		{"IPv4 TCP to ICMP-only host blocked", craftIPv4TCP(t, "10.0.0.2", 443), tcActShot},
		{"IPv4 ICMP to TCP-only host blocked", craftIPv4ICMP(t, "10.0.0.1"), tcActShot},
		// IPv6 TCP-only port
		{"IPv6 TCP to TCP-only port allowed", craftIPv6TCP(t, "2001:db8:1::1", 443), tcActOK},
		{"IPv6 UDP to TCP-only port blocked", craftIPv6UDP(t, "2001:db8:1::1", 443), tcActShot},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.TcEgress.Test(tt.packet)
			require.NoError(t, err)
			require.Equal(t, tt.wantRet, ret)
		})
	}
}

func TestCgroupProgramsLoad(t *testing.T) {
	objs := loadBPFObjects(t)

	require.NotNil(t, objs.CgConnect4, "cg_connect4 program should be loaded")
	require.NotNil(t, objs.CgConnect6, "cg_connect6 program should be loaded")
	require.NotNil(t, objs.CgSendmsg4, "cg_sendmsg4 program should be loaded")
	require.NotNil(t, objs.CgSendmsg6, "cg_sendmsg6 program should be loaded")
	require.NotNil(t, objs.MapSockPid, "map_sock_pid should be loaded")

	// Verify program types
	require.Equal(t, ebpf.CGroupSockAddr, objs.CgConnect4.Type(), "cg_connect4 should be CGroupSockAddr type")
	require.Equal(t, ebpf.CGroupSockAddr, objs.CgConnect6.Type(), "cg_connect6 should be CGroupSockAddr type")
	require.Equal(t, ebpf.CGroupSockAddr, objs.CgSendmsg4.Type(), "cg_sendmsg4 should be CGroupSockAddr type")
	require.Equal(t, ebpf.CGroupSockAddr, objs.CgSendmsg6.Type(), "cg_sendmsg6 should be CGroupSockAddr type")

	// Verify map type
	info, err := objs.MapSockPid.Info()
	require.NoError(t, err)
	require.Equal(t, ebpf.LRUHash, info.Type, "map_sock_pid should be LRU_HASH type")
}

func TestMapSockPidReadWrite(t *testing.T) {
	objs := loadBPFObjects(t)

	// Write a cookie→PID mapping
	var cookie uint64 = 12345
	var pid uint32 = 42
	err := objs.MapSockPid.Update(&cookie, &pid, ebpf.UpdateAny)
	require.NoError(t, err)

	// Read it back
	var got uint32
	err = objs.MapSockPid.Lookup(&cookie, &got)
	require.NoError(t, err)
	require.Equal(t, pid, got)

	// Verify a missing key returns an error
	var missingCookie uint64 = 99999
	err = objs.MapSockPid.Lookup(&missingCookie, &got)
	require.Error(t, err, "lookup of missing cookie should fail")

	// Overwrite with a new PID
	var newPid uint32 = 100
	err = objs.MapSockPid.Update(&cookie, &newPid, ebpf.UpdateAny)
	require.NoError(t, err)
	err = objs.MapSockPid.Lookup(&cookie, &got)
	require.NoError(t, err)
	require.Equal(t, newPid, got)

	// Delete and verify it's gone
	err = objs.MapSockPid.Delete(&cookie)
	require.NoError(t, err)
	err = objs.MapSockPid.Lookup(&cookie, &got)
	require.Error(t, err)
}

// bpfBlockedEvent matches the C struct blocked_event for decoding ring buffer records.
type bpfBlockedEvent struct {
	IpVersion uint8
	Allowed   uint8
	Pad1      [2]uint8
	SrcIp     uint32
	DstIp     uint32
	SrcPort   uint16
	DstPort   uint16
	SrcIp6    [16]byte
	DstIp6    [16]byte
	Timestamp uint64
	Pid       uint32
	Pad2      uint32
}

func TestEventPidZeroWhenNoCookieMapping(t *testing.T) {
	objs := loadBPFObjects(t)
	setupTestRules(t, objs)

	// Do NOT populate map_sock_pid — PID should be 0

	rd, err := ringbuf.NewReader(objs.MapEvents)
	require.NoError(t, err)
	defer rd.Close()

	// Send a blocked TCP SYN to trigger an event
	pkt := craftIPv4TCP(t, "93.184.216.34", 80)
	ret, _, err := objs.TcEgress.Test(pkt)
	require.NoError(t, err)
	require.Equal(t, uint32(tcActShot), ret)

	record, err := rd.Read()
	require.NoError(t, err)

	var evt bpfBlockedEvent
	err = binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &evt)
	require.NoError(t, err)

	require.Equal(t, uint8(4), evt.IpVersion)
	require.Equal(t, uint8(0), evt.Allowed)
	require.Equal(t, uint32(0), evt.Pid, "PID should be 0 when no cookie mapping exists")
}

func TestEventPidZeroWhenNoCookieMappingIPv6(t *testing.T) {
	objs := loadBPFObjects(t)
	setupTestRules(t, objs)

	rd, err := ringbuf.NewReader(objs.MapEvents)
	require.NoError(t, err)
	defer rd.Close()

	// Send a blocked IPv6 TCP SYN
	pkt := craftIPv6TCP(t, "2001:db8::1", 80)
	ret, _, err := objs.TcEgress.Test(pkt)
	require.NoError(t, err)
	require.Equal(t, uint32(tcActShot), ret)

	record, err := rd.Read()
	require.NoError(t, err)

	var evt bpfBlockedEvent
	err = binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &evt)
	require.NoError(t, err)

	require.Equal(t, uint8(6), evt.IpVersion, "should be IPv6 event")
	require.Equal(t, uint8(0), evt.Allowed, "should be a blocked event")
	require.Equal(t, uint32(0), evt.Pid, "PID should be 0 when no cookie mapping exists")
	require.Equal(t, uint16(80), evt.DstPort)
}

// setupTestRules configures the BPF maps with test rules.
// Default action: deny
// Allow: 140.82.114.0/24 (GitHub IPs)
// Allow: 2606:4700::/32 (Cloudflare IPv6)
func setupTestRules(t *testing.T, objs *TcBpfObjects) {
	t.Helper()

	// Set default action to deny
	var defKey uint32 = 0
	var defVal uint8 = 0 // deny
	err := objs.MapDefaultAction.Update(&defKey, &defVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv4 allow rule for 140.82.114.0/24
	key4 := TcBpfLpmKey{
		Prefixlen: 24,
		Ip:        ipToU32("140.82.114.0"),
	}
	val := TcBpfLpmVal{
		Action:       1, // allow
		PortSpecific: 0, // all ports
	}
	err = objs.MapCidrs.Update(&key4, &val, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv6 allow rule for 2606:4700::/32
	key6 := TcBpfLpmKeyV6{
		Prefixlen: 32,
	}
	ip6 := net.ParseIP("2606:4700::")
	copy(key6.Ip[:], ip6.To16())
	err = objs.MapCidrsV6.Update(&key6, &val, ebpf.UpdateAny)
	require.NoError(t, err)
}

// ipToU32 converts an IPv4 string to a uint32 matching how BPF reads __be32 fields.
// Uses NativeEndian so the resulting bytes in the map key are in network byte order,
// which is required for LPM trie prefix matching.
func ipToU32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	return binary.NativeEndian.Uint32(ip)
}

// Packet crafting helpers

func craftEthHeader(proto uint16) []byte {
	eth := make([]byte, 14)
	// dst mac
	copy(eth[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	// src mac
	copy(eth[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	// ethertype
	binary.BigEndian.PutUint16(eth[12:14], proto)
	return eth
}

func craftIPv4Header(dstIP string, proto uint8, payloadLen int) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	ip[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(ip[6:8], 0)      // Flags/Fragment offset
	ip[8] = 64                                  // TTL
	ip[9] = proto                               // Protocol
	// Checksum (leave as 0, BPF doesn't validate)
	// Src IP
	srcIP := net.ParseIP("192.168.1.100").To4()
	copy(ip[12:16], srcIP)
	// Dst IP
	dstIPBytes := net.ParseIP(dstIP).To4()
	copy(ip[16:20], dstIPBytes)
	return ip
}

func craftTCPHeader(dstPort uint16, syn bool) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 12345)   // src port
	binary.BigEndian.PutUint16(tcp[2:4], dstPort) // dst port
	binary.BigEndian.PutUint32(tcp[4:8], 0)       // seq
	binary.BigEndian.PutUint32(tcp[8:12], 0)      // ack
	tcp[12] = 0x50                                // data offset = 5 (20 bytes)
	if syn {
		tcp[13] = 0x02 // SYN flag
	}
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	// checksum and urgent pointer left as 0
	return tcp
}

func craftUDPHeader(dstPort uint16) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 12345)   // src port
	binary.BigEndian.PutUint16(udp[2:4], dstPort) // dst port
	binary.BigEndian.PutUint16(udp[4:6], 8)       // length
	// checksum left as 0
	return udp
}

func craftIPv4TCP(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	tcp := craftTCPHeader(dstPort, true)
	ip := craftIPv4Header(dstIP, ipprotoTCP, len(tcp))
	return append(append(eth, ip...), tcp...)
}

func craftIPv4WithOptionsTCP(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	tcp := craftTCPHeader(dstPort, true)
	// Build IPv4 header with IHL=6 (24 bytes: 20 standard + 4 bytes options)
	ip := make([]byte, 24)
	ip[0] = 0x46 // Version 4, IHL 6 (24 bytes)
	ip[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(24+len(tcp)))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(ip[6:8], 0)      // Flags/Fragment offset
	ip[8] = 64                                  // TTL
	ip[9] = ipprotoTCP                          // Protocol
	srcIP := net.ParseIP("192.168.1.100").To4()
	copy(ip[12:16], srcIP)
	dstIPBytes := net.ParseIP(dstIP).To4()
	copy(ip[16:20], dstIPBytes)
	// 4 bytes of NOP options (NOP = 0x01)
	ip[20] = 0x01
	ip[21] = 0x01
	ip[22] = 0x01
	ip[23] = 0x01
	return append(append(eth, ip...), tcp...)
}

func craftIPv4UDP(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	udp := craftUDPHeader(dstPort)
	ip := craftIPv4Header(dstIP, ipprotoUDP, len(udp))
	return append(append(eth, ip...), udp...)
}

func craftVLANHeader(innerProto uint16, vlanID uint16) []byte {
	vlan := make([]byte, 4)
	// TCI: priority (3 bits) + DEI (1 bit) + VLAN ID (12 bits)
	binary.BigEndian.PutUint16(vlan[0:2], vlanID&0x0FFF)
	binary.BigEndian.PutUint16(vlan[2:4], innerProto)
	return vlan
}

func craftVLANIPv4(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethP8021Q)
	vlan := craftVLANHeader(ethPIP, 100)
	tcp := craftTCPHeader(dstPort, true)
	ip := craftIPv4Header(dstIP, ipprotoTCP, len(tcp))
	pkt := append(eth, vlan...)
	pkt = append(pkt, ip...)
	pkt = append(pkt, tcp...)
	return pkt
}

func craftQinQIPv4(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethP8021AD)
	outerVlan := craftVLANHeader(ethP8021Q, 200) // outer VLAN points to inner 802.1Q
	innerVlan := craftVLANHeader(ethPIP, 100)    // inner VLAN points to IPv4
	tcp := craftTCPHeader(dstPort, true)
	ip := craftIPv4Header(dstIP, ipprotoTCP, len(tcp))
	pkt := append(eth, outerVlan...)
	pkt = append(pkt, innerVlan...)
	pkt = append(pkt, ip...)
	pkt = append(pkt, tcp...)
	return pkt
}

func craftQinQIPv6(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethP8021AD)
	outerVlan := craftVLANHeader(ethP8021Q, 200) // outer VLAN points to inner 802.1Q
	innerVlan := craftVLANHeader(ethPIPv6, 100)  // inner VLAN points to IPv6
	tcp := craftTCPHeader(dstPort, true)
	ip6 := craftIPv6Header(dstIP, ipprotoTCP, len(tcp))
	pkt := append(eth, outerVlan...)
	pkt = append(pkt, innerVlan...)
	pkt = append(pkt, ip6...)
	pkt = append(pkt, tcp...)
	return pkt
}

func craftIPv6Header(dstIP string, nextHdr uint8, payloadLen int) []byte {
	ip6 := make([]byte, 40)
	// Version (4) + Traffic Class (8) + Flow Label (20)
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(payloadLen))
	ip6[6] = nextHdr
	ip6[7] = 64 // Hop limit

	// Src IP (fe80::1)
	srcIP := net.ParseIP("fe80::1").To16()
	copy(ip6[8:24], srcIP)

	// Dst IP
	dstIPBytes := net.ParseIP(dstIP).To16()
	copy(ip6[24:40], dstIPBytes)
	return ip6
}

func craftIPv6TCP(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	tcp := craftTCPHeader(dstPort, true)
	ip6 := craftIPv6Header(dstIP, ipprotoTCP, len(tcp))
	return append(append(eth, ip6...), tcp...)
}

// craftIPv6ExtHdr creates a generic IPv6 extension header
// nextHdr: the next protocol
// length: header length in 8-byte units (not counting first 8 bytes)
func craftIPv6ExtHdr(nextHdr uint8, length uint8) []byte {
	size := (int(length) + 1) * 8
	hdr := make([]byte, size)
	hdr[0] = nextHdr
	hdr[1] = length
	return hdr
}

func craftIPv6ExtHdrTCP(t *testing.T, dstIP string, dstPort uint16, extHdrProto uint8) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	tcp := craftTCPHeader(dstPort, true)
	extHdr := craftIPv6ExtHdr(ipprotoTCP, 0) // 8 bytes, next=TCP
	ip6 := craftIPv6Header(dstIP, extHdrProto, len(extHdr)+len(tcp))
	pkt := append(eth, ip6...)
	pkt = append(pkt, extHdr...)
	pkt = append(pkt, tcp...)
	return pkt
}

// craftIPv6FragmentHdr creates an IPv6 fragment header (8 bytes).
// nextHdr: the protocol after the fragment header
// firstFragment: if true, offset=0 MF=1; if false, offset=185 MF=0
func craftIPv6FragmentHdr(nextHdr uint8, firstFragment bool) []byte {
	fragHdr := make([]byte, 8)
	fragHdr[0] = nextHdr
	if firstFragment {
		fragHdr[2] = 0x00
		fragHdr[3] = 0x01 // offset=0, MF=1
	} else {
		fragHdr[2] = 0x05
		fragHdr[3] = 0xC8 // offset=185 (1480 bytes), MF=0
	}
	return fragHdr
}

func craftIPv6FragmentedICMPv6(t *testing.T, firstFragment bool) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	fragHdr := craftIPv6FragmentHdr(ipprotoICMPv6, firstFragment)

	// ICMPv6 data (minimal)
	icmp := make([]byte, 8)
	icmp[0] = 128 // Echo request type

	ip6 := craftIPv6Header("2606:4700::1", ipprotoFrag, len(fragHdr)+len(icmp))
	pkt := append(eth, ip6...)
	pkt = append(pkt, fragHdr...)
	pkt = append(pkt, icmp...)
	return pkt
}

func craftTruncatedIPv4(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	// Only 10 bytes of IP header (needs 20 minimum)
	ip := make([]byte, 10)
	ip[0] = 0x45
	return append(eth, ip...)
}

func craftInvalidIHLIPv4(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	ip := make([]byte, 20)
	ip[0] = 0x42 // Version 4, IHL 2 (8 bytes - invalid, must be >= 5)
	return append(eth, ip...)
}

func craftTruncatedTCP(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	ip := craftIPv4Header("140.82.114.3", ipprotoTCP, 10)
	// Only 10 bytes of TCP (needs 20)
	tcp := make([]byte, 10)
	return append(append(eth, ip...), tcp...)
}

func craftARP(t *testing.T) []byte {
	t.Helper()
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // broadcast
	copy(eth[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(eth[12:14], 0x0806) // ARP

	// Minimal ARP payload
	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)      // Hardware type: Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // Protocol type: IPv4
	arp[4] = 6                                   // Hardware size
	arp[5] = 4                                   // Protocol size
	binary.BigEndian.PutUint16(arp[6:8], 1)      // Opcode: request
	return append(eth, arp...)
}

func craftIPv6Multicast(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	// Multicast destination ff02::1 (all nodes)
	ip6 := craftIPv6Header("ff02::1", ipprotoICMPv6, 8)
	icmp := make([]byte, 8)
	icmp[0] = 128 // Echo request
	return append(append(eth, ip6...), icmp...)
}

func craftICMPv6NDP(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	// Unicast destination with ICMPv6
	ip6 := craftIPv6Header("fe80::1", ipprotoICMPv6, 8)
	icmp := make([]byte, 8)
	icmp[0] = 135 // Neighbor Solicitation
	return append(append(eth, ip6...), icmp...)
}

// addPortV4 inserts an IPv4 port rule for both TCP and UDP.
func addPortV4(t *testing.T, m *ebpf.Map, ip uint32, port uint16, action uint8) {
	t.Helper()
	val := TcBpfPortVal{Action: action}
	for _, proto := range []uint8{ipprotoTCP, ipprotoUDP} {
		key := TcBpfPortKey{Ip: ip, Port: port, Proto: proto}
		require.NoError(t, m.Update(&key, &val, ebpf.UpdateAny))
	}
}

// addPortV6 inserts an IPv6 port rule for both TCP and UDP.
func addPortV6(t *testing.T, m *ebpf.Map, ipStr string, port uint16, action uint8) {
	t.Helper()
	val := TcBpfPortVal{Action: action}
	for _, proto := range []uint8{ipprotoTCP, ipprotoUDP} {
		key := TcBpfPortKeyV6{Port: port, Proto: proto}
		if ipStr != "" {
			ip6 := net.ParseIP(ipStr)
			copy(key.Ip[:], ip6.To16())
		}
		require.NoError(t, m.Update(&key, &val, ebpf.UpdateAny))
	}
}

// setupPortSpecificRules configures the BPF maps with port-specific rules.
// Default action: deny
// IPv4: 10.0.0.0/24 port_specific=1; 10.0.0.1:443 allow; 10.0.0.1:22 deny
// IPv4: wildcard 0.0.0.0:8080 allow; wildcard 0.0.0.0:9090 deny
// IPv6: 2001:db8:1::/48 port_specific=1; [2001:db8:1::1]:443 allow; [2001:db8:1::1]:22 deny
// IPv6: wildcard [::]:8080 allow; wildcard [::]:9090 deny
func setupPortSpecificRules(t *testing.T, objs *TcBpfObjects) {
	t.Helper()

	// Set default action to deny
	var defKey uint32 = 0
	var defVal uint8 = 0 // deny
	err := objs.MapDefaultAction.Update(&defKey, &defVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv4 CIDR 10.0.0.0/24 with port_specific=1
	key4 := TcBpfLpmKey{Prefixlen: 24, Ip: ipToU32("10.0.0.0")}
	val := TcBpfLpmVal{Action: 1, PortSpecific: 1}
	err = objs.MapCidrs.Update(&key4, &val, ebpf.UpdateAny)
	require.NoError(t, err)

	// IPv4 port rules (TCP + UDP for each)
	addPortV4(t, objs.MapPorts, ipToU32("10.0.0.1"), 443, 1) // allow
	addPortV4(t, objs.MapPorts, 0, 8080, 1)                  // wildcard allow
	addPortV4(t, objs.MapPorts, ipToU32("10.0.0.1"), 22, 0)  // deny
	addPortV4(t, objs.MapPorts, 0, 9090, 0)                  // wildcard deny

	// Add IPv6 CIDR 2001:db8:1::/48 with port_specific=1
	key6 := TcBpfLpmKeyV6{Prefixlen: 48}
	ip6 := net.ParseIP("2001:db8:1::")
	copy(key6.Ip[:], ip6.To16())
	err = objs.MapCidrsV6.Update(&key6, &val, ebpf.UpdateAny)
	require.NoError(t, err)

	// IPv6 port rules (TCP + UDP for each)
	addPortV6(t, objs.MapPortsV6, "2001:db8:1::1", 443, 1) // allow
	addPortV6(t, objs.MapPortsV6, "", 8080, 1)             // wildcard allow
	addPortV6(t, objs.MapPortsV6, "2001:db8:1::1", 22, 0)  // deny
	addPortV6(t, objs.MapPortsV6, "", 9090, 0)             // wildcard deny
}

// craftIPv4HeaderWithFragOffset creates an IPv4 header with specified fragment offset
// fragOffset is in 8-byte units, moreFragments indicates MF flag
func craftIPv4HeaderWithFragOffset(dstIP string, proto uint8, payloadLen int, fragOffset uint16, moreFragments bool) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	ip[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234) // ID
	// Flags/Fragment offset: MF in bit 13, offset in bits 0-12
	fragField := fragOffset & 0x1FFF
	if moreFragments {
		fragField |= 0x2000 // Set MF flag
	}
	binary.BigEndian.PutUint16(ip[6:8], fragField)
	ip[8] = 64    // TTL
	ip[9] = proto // Protocol
	// Checksum (leave as 0, BPF doesn't validate)
	// Src IP
	srcIP := net.ParseIP("192.168.1.100").To4()
	copy(ip[12:16], srcIP)
	// Dst IP
	dstIPBytes := net.ParseIP(dstIP).To4()
	copy(ip[16:20], dstIPBytes)
	return ip
}

func craftIPv4FirstFragment(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	tcp := craftTCPHeader(dstPort, true)
	// First fragment: offset=0, MF=1
	ip := craftIPv4HeaderWithFragOffset(dstIP, ipprotoTCP, len(tcp), 0, true)
	return append(append(eth, ip...), tcp...)
}

func craftIPv4NonFirstFragment(t *testing.T, dstIP string) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	// Non-first fragment: offset > 0, no L4 header (just payload)
	payload := make([]byte, 100) // Fragment payload
	// offset=185 (in 8-byte units = 1480 bytes), MF=0
	ip := craftIPv4HeaderWithFragOffset(dstIP, ipprotoTCP, len(payload), 185, false)
	return append(append(eth, ip...), payload...)
}

func craftTCPHeaderWithFlags(dstPort uint16, flags uint8) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 12345)   // src port
	binary.BigEndian.PutUint16(tcp[2:4], dstPort) // dst port
	binary.BigEndian.PutUint32(tcp[4:8], 0)       // seq
	binary.BigEndian.PutUint32(tcp[8:12], 0)      // ack
	tcp[12] = 0x50                                // data offset = 5 (20 bytes)
	tcp[13] = flags                               // TCP flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	// checksum and urgent pointer left as 0
	return tcp
}

func craftIPv4TCPWithFlags(t *testing.T, dstIP string, dstPort uint16, flags uint8) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	tcp := craftTCPHeaderWithFlags(dstPort, flags)
	ip := craftIPv4Header(dstIP, ipprotoTCP, len(tcp))
	return append(append(eth, ip...), tcp...)
}

func craftIPv6UDP(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	udp := craftUDPHeader(dstPort)
	ip6 := craftIPv6Header(dstIP, ipprotoUDP, len(udp))
	return append(append(eth, ip6...), udp...)
}

func craftIPv6TCPWithFlags(t *testing.T, dstIP string, dstPort uint16, flags uint8) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	tcp := craftTCPHeaderWithFlags(dstPort, flags)
	ip6 := craftIPv6Header(dstIP, ipprotoTCP, len(tcp))
	return append(append(eth, ip6...), tcp...)
}

func craftIPv6MultiExtHdrTCP(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	tcp := craftTCPHeader(dstPort, true)
	// Chain: HopByHop -> Routing -> TCP
	routing := craftIPv6ExtHdr(ipprotoTCP, 0)      // 8 bytes, next=TCP
	hopByHop := craftIPv6ExtHdr(ipprotoRouting, 0) // 8 bytes, next=Routing
	ip6 := craftIPv6Header(dstIP, ipprotoHopOpts, len(hopByHop)+len(routing)+len(tcp))
	pkt := append(eth, ip6...)
	pkt = append(pkt, hopByHop...)
	pkt = append(pkt, routing...)
	pkt = append(pkt, tcp...)
	return pkt
}

func craftIPv6FragmentedTCP(t *testing.T, dstIP string, dstPort uint16, firstFragment bool) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	fragHdr := craftIPv6FragmentHdr(ipprotoTCP, firstFragment)

	var payload []byte
	if firstFragment {
		payload = craftTCPHeader(dstPort, true)
	} else {
		payload = make([]byte, 100)
	}

	ip6 := craftIPv6Header(dstIP, ipprotoFrag, len(fragHdr)+len(payload))
	pkt := append(eth, ip6...)
	pkt = append(pkt, fragHdr...)
	pkt = append(pkt, payload...)
	return pkt
}

func craftTruncatedUDP(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	ip := craftIPv4Header("140.82.114.3", ipprotoUDP, 4)
	// Only 4 bytes of UDP (needs 8)
	udp := make([]byte, 4)
	return append(append(eth, ip...), udp...)
}

func craftTruncatedIPv6(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	// Only 20 bytes of IPv6 header (needs 40)
	ip6 := make([]byte, 20)
	ip6[0] = 0x60 // Version 6
	return append(eth, ip6...)
}

func craftTruncatedIPv6TCP(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	ip6 := craftIPv6Header("2606:4700::1", ipprotoTCP, 10)
	// Only 10 bytes of TCP (needs 20)
	tcp := make([]byte, 10)
	return append(append(eth, ip6...), tcp...)
}

func craftTruncatedIPv6ExtHdr(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	// IPv6 header with HopByHop extension but truncated extension header
	ip6 := craftIPv6Header("2606:4700::1", ipprotoHopOpts, 4)
	// Only 1 byte of extension header (needs at least 2 for next/len)
	extHdr := make([]byte, 1)
	return append(append(eth, ip6...), extHdr...)
}

func craftTruncatedIPv6FragHdr(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	// IPv6 header with nexthdr=Fragment but only 4 bytes of fragment header (needs 8)
	ip6 := craftIPv6Header("2606:4700::1", ipprotoFrag, 4)
	fragHdr := make([]byte, 4)
	return append(append(eth, ip6...), fragHdr...)
}

func craftIPv4ICMP(t *testing.T, dstIP string) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIP)
	// Minimal ICMP payload: type(1) + code(1) + checksum(2) + id(2) + seq(2) = 8 bytes
	icmp := make([]byte, 8)
	icmp[0] = 8                                // Echo request
	ip := craftIPv4Header(dstIP, 1, len(icmp)) // proto=1 (ICMP)
	return append(append(eth, ip...), icmp...)
}

func craftIPv6Proto(t *testing.T, dstIP string, proto uint8) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	// Minimal payload for the protocol
	payload := make([]byte, 8)
	ip6 := craftIPv6Header(dstIP, proto, len(payload))
	return append(append(eth, ip6...), payload...)
}

func craftVLANIPv6(t *testing.T, dstIP string, dstPort uint16) []byte {
	t.Helper()
	eth := craftEthHeader(ethP8021Q)
	vlan := craftVLANHeader(ethPIPv6, 100)
	tcp := craftTCPHeader(dstPort, true)
	ip6 := craftIPv6Header(dstIP, ipprotoTCP, len(tcp))
	pkt := append(eth, vlan...)
	pkt = append(pkt, ip6...)
	pkt = append(pkt, tcp...)
	return pkt
}

func craftTruncatedIPv6UDP(t *testing.T) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	ip6 := craftIPv6Header("2606:4700::1", ipprotoUDP, 4)
	// Only 4 bytes of UDP (needs 8)
	udp := make([]byte, 4)
	return append(append(eth, ip6...), udp...)
}

func craftIPv6ExtHdrThenFragmentedTCP(t *testing.T, dstIP string, dstPort uint16, firstFragment bool) []byte {
	t.Helper()
	eth := craftEthHeader(ethPIPv6)
	hopByHop := craftIPv6ExtHdr(ipprotoFrag, 0) // 8 bytes, next=Fragment
	fragHdr := craftIPv6FragmentHdr(ipprotoTCP, firstFragment)

	var payload []byte
	if firstFragment {
		payload = craftTCPHeader(dstPort, true)
	} else {
		payload = make([]byte, 100)
	}

	ip6 := craftIPv6Header(dstIP, ipprotoHopOpts, len(hopByHop)+len(fragHdr)+len(payload))
	pkt := append(eth, ip6...)
	pkt = append(pkt, hopByHop...)
	pkt = append(pkt, fragHdr...)
	pkt = append(pkt, payload...)
	return pkt
}
