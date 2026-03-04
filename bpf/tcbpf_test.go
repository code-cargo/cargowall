//go:build linux

package bpf

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

// TODO: TestMain silently skips all tests when not running as root.
// This means CI will report a pass even when no BPF tests actually run.
// Consider using t.Skip() in individual tests or a build tag instead.
func TestMain(m *testing.M) {
	// Remove MEMLOCK limit for BPF map creation
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("skipping eBPF tests: failed to remove memlock (run with sudo): %v", err)
		os.Exit(0)
	}
	os.Exit(m.Run())
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

		// Blocked protocols (non-TCP/UDP)
		{
			name:    "IPv4 ICMP blocked",
			packet:  craftIPv4ICMP(t, "140.82.114.3"),
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
			packet:  craftIPv4ICMP(t, "140.82.114.3"),
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

	// Add IPv4 rule for 10.0.0.0/24 with port_specific=1
	key4 := TcBpfLpmKey{
		Prefixlen: 24,
		Ip:        ipToU32("10.0.0.0"),
	}
	val := TcBpfLpmVal{
		Action:       1, // allow
		PortSpecific: 1, // check port map
	}
	err = objs.MapCidrs.Update(&key4, &val, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add port rule for 10.0.0.1:443
	portKey := TcBpfPortKey{
		Ip:   ipToU32("10.0.0.1"),
		Port: 443,
	}
	portVal := TcBpfPortVal{
		Action: 1, // allow
	}
	err = objs.MapPorts.Update(&portKey, &portVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add wildcard port rule for 0.0.0.0:8080 (any IP, port 8080)
	wildcardPortKey := TcBpfPortKey{
		Ip:   0,
		Port: 8080,
	}
	err = objs.MapPorts.Update(&wildcardPortKey, &portVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv6 rule for 2001:db8:1::/48 with port_specific=1
	key6 := TcBpfLpmKeyV6{
		Prefixlen: 48,
	}
	ip6 := net.ParseIP("2001:db8:1::")
	copy(key6.Ip[:], ip6.To16())
	err = objs.MapCidrsV6.Update(&key6, &val, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv6 port rule for [2001:db8:1::1]:443
	portKey6 := TcBpfPortKeyV6{
		Port: 443,
	}
	ip6Addr := net.ParseIP("2001:db8:1::1")
	copy(portKey6.Ip[:], ip6Addr.To16())
	err = objs.MapPortsV6.Update(&portKey6, &portVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add wildcard IPv6 port rule for [::]:8080
	wildcardPortKey6 := TcBpfPortKeyV6{
		Port: 8080,
	}
	// Ip is already zeroed
	err = objs.MapPortsV6.Update(&wildcardPortKey6, &portVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add port deny entry for 10.0.0.1:22
	portKeyDeny := TcBpfPortKey{
		Ip:   ipToU32("10.0.0.1"),
		Port: 22,
	}
	portValDeny := TcBpfPortVal{Action: 0}
	err = objs.MapPorts.Update(&portKeyDeny, &portValDeny, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv6 port deny entry for [2001:db8:1::1]:22
	portKey6Deny := TcBpfPortKeyV6{
		Port: 22,
	}
	ip6Deny := net.ParseIP("2001:db8:1::1")
	copy(portKey6Deny.Ip[:], ip6Deny.To16())
	err = objs.MapPortsV6.Update(&portKey6Deny, &portValDeny, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add wildcard port deny for port 9090 (0.0.0.0:9090 → action=0)
	wildcardDenyKey := TcBpfPortKey{Ip: 0, Port: 9090}
	wildcardDenyVal := TcBpfPortVal{Action: 0}
	err = objs.MapPorts.Update(&wildcardDenyKey, &wildcardDenyVal, ebpf.UpdateAny)
	require.NoError(t, err)

	// Add IPv6 wildcard port deny for port 9090 ([::]:9090 → action=0)
	wildcardDenyKey6 := TcBpfPortKeyV6{Port: 9090}
	err = objs.MapPortsV6.Update(&wildcardDenyKey6, &wildcardDenyVal, ebpf.UpdateAny)
	require.NoError(t, err)
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
