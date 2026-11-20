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

package tcmaps

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	tcp443 = []PortProto{{443, ProtoTCP}}
	udp53  = []PortProto{{53, ProtoUDP}}
)

func rule(prefix string, allow bool, ports ...PortProto) Rule {
	return Rule{Prefix: netip.MustParsePrefix(prefix), Allow: allow, Ports: ports, Label: prefix}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// A port-scoped network at the zero address would key its port entries where
// the wildcard's are, so it writes nothing and is noted. Without ports it keys
// none, so its LPM entry is written.
func TestCompile_ZeroNetwork(t *testing.T) {
	m := Compile([]Rule{
		rule("0.0.0.0/8", true, tcp443...),
		rule("::/96", true, tcp443...),
	})
	assert.Empty(t, m.Subnets)
	assert.Empty(t, m.Ports)
	require.Len(t, m.Notes, 2)
	assert.Equal(t, NoteUnspecified, m.Notes[0].Kind)

	m = Compile([]Rule{rule("0.0.0.0/8", true), rule("::/96", true), rule("10.0.0.0/8", true, tcp443...)})
	assert.Len(t, m.Subnets, 3)
	assert.Equal(t, map[PortKey]bool{{addr("10.0.0.0"), tcp443[0]}: true}, m.Ports, "a non-zero subnet keys its network")
}

// A port-scoped 0.0.0.0/0 or ::/0 is the any-destination wildcard.
func TestCompile_Wildcard(t *testing.T) {
	m := Compile([]Rule{rule("0.0.0.0/0", true, udp53...), rule("::/0", false, tcp443...)})
	assert.Empty(t, m.Subnets)
	assert.True(t, m.Allows(addr("192.0.2.1"), udp53[0], false))
	assert.False(t, m.Allows(addr("2001:db8::1"), tcp443[0], true))
	assert.False(t, m.Allows(addr("192.0.2.1"), tcp443[0], false), "the default decides other ports")
}

// A subnet's port entries answer only for its network address.
func TestCompile_SubnetPortsKeyedByNetwork(t *testing.T) {
	m := Compile([]Rule{rule("10.0.0.0/16", true, udp53...)})
	assert.True(t, m.Allows(addr("10.0.0.0"), udp53[0], false))
	assert.False(t, m.Allows(addr("10.0.0.2"), udp53[0], false))
}

// A host's first contribution folds in a covering all-ports entry, so the
// host keeps that entry's verdict on every port, and writes no /32 when its
// value equals the covering one.
func TestCompile_HostFoldsCoveringAllPorts(t *testing.T) {
	m := Compile([]Rule{rule("10.0.0.0/8", true), rule("10.0.0.2/32", true, tcp443...)})
	h := m.Hosts[addr("10.0.0.2")]
	require.NotNil(t, h)
	assert.True(t, h.AllPortsAllow)
	assert.False(t, h.Installed, "its value equals the /8's")
	assert.True(t, m.Allows(addr("10.0.0.2"), PortProto{22, ProtoTCP}, false))

	m = Compile([]Rule{rule("10.0.0.0/8", false), rule("10.0.0.2/32", true, udp53...)})
	assert.True(t, m.Hosts[addr("10.0.0.2")].AllPortsDeny)
	assert.False(t, m.Allows(addr("10.0.0.2"), udp53[0], true), "the deny holds")
	require.Len(t, m.Notes, 1)
	assert.Equal(t, NoteInertPorts, m.Notes[0].Kind)

	// Written before the subnet, the host is the longest match and keeps its
	// own ports.
	m = Compile([]Rule{rule("10.0.0.2/32", true, tcp443...), rule("10.0.0.0/8", true)})
	assert.True(t, m.Hosts[addr("10.0.0.2")].Installed)
	assert.False(t, m.Allows(addr("10.0.0.2"), PortProto{22, ProtoTCP}, false))
}

// Contributions to one host accumulate: an all-ports deny beats an all-ports
// allow in either order, and an all-ports grant makes later port entries
// inert.
func TestHost_Precedence(t *testing.T) {
	for _, order := range [][]bool{{true, false}, {false, true}} {
		m := Compile([]Rule{rule("192.0.2.5/32", order[0]), rule("192.0.2.5/32", order[1])})
		assert.False(t, m.Allows(addr("192.0.2.5"), tcp443[0], true), "%v", order)
	}
	m := Compile([]Rule{rule("192.0.2.5/32", true), rule("192.0.2.5/32", true, tcp443...)})
	assert.Empty(t, m.Ports, "inert under the all-ports allow")
	assert.Empty(t, m.Notes, "the same action is not a conflict")
}

// The v6 program passes ICMPv6 before the maps, so ICMP is stripped from v6
// rules, and a v6 rule naming only ICMP installs nothing.
func TestCompile_V6ICMP(t *testing.T) {
	icmp := PortProto{0, ProtoICMP}
	m := Compile([]Rule{
		rule("2001:db8::/32", true, icmp),
		rule("2001:db8::5/128", true, icmp),
		rule("2001:db8:1::/48", true, icmp, tcp443[0]),
	})
	assert.Equal(t, map[netip.Prefix]LPM{netip.MustParsePrefix("2001:db8:1::/48"): {Allow: true, PortSpecific: true}}, m.Subnets)
	assert.Empty(t, m.Hosts)
	assert.Equal(t, map[PortKey]bool{{addr("2001:db8:1::"), tcp443[0]}: true}, m.Ports)
	assert.Len(t, m.Notes, 2)
}

// A host's own installed entry is its LPM answer, ahead of any subnet.
func TestLookup_HostAheadOfSubnet(t *testing.T) {
	m := Compile([]Rule{rule("192.0.2.0/24", true), rule("192.0.2.9/32", false)})
	e, ok := m.Lookup(addr("192.0.2.9"))
	assert.True(t, ok)
	assert.Equal(t, LPM{Allow: false}, e)
	e, ok = m.Lookup(addr("192.0.2.10"))
	assert.True(t, ok)
	assert.Equal(t, LPM{Allow: true}, e)
	_, ok = m.Lookup(addr("2001:db8::1"))
	assert.False(t, ok, "families don't mix")
}

// StripICMP returns its input unchanged when it holds no ICMP, drops ICMP
// from a mixed list, and reports a list of only ICMP as one to skip.
func TestStripICMP(t *testing.T) {
	filtered, skip := StripICMP(nil)
	assert.Nil(t, filtered)
	assert.False(t, skip)

	filtered, skip = StripICMP([]PortProto{})
	assert.Empty(t, filtered)
	assert.False(t, skip)

	icmp := PortProto{0, ProtoICMP}
	in := []PortProto{icmp, tcp443[0]}
	filtered, skip = StripICMP(in)
	assert.Equal(t, tcp443, filtered)
	assert.False(t, skip)
	assert.Equal(t, []PortProto{icmp, tcp443[0]}, in, "the input is not modified")

	filtered, skip = StripICMP([]PortProto{icmp})
	assert.Empty(t, filtered)
	assert.True(t, skip)
}

// The wildcard is a port-scoped /0, decided from the prefix: a /0 on all
// ports is an ordinary LPM entry, and a port-scoped prefix wider than zero
// bits never writes at the zero address.
func TestCompile_WildcardIsPortScopedSlashZero(t *testing.T) {
	m := Compile([]Rule{rule("0.0.0.0/0", true), rule("::/0", false)})
	assert.Equal(t, map[netip.Prefix]LPM{
		netip.MustParsePrefix("0.0.0.0/0"): {Allow: true},
		netip.MustParsePrefix("::/0"):      {Allow: false},
	}, m.Subnets)
	assert.Empty(t, m.Ports)

	m = Compile([]Rule{rule("128.0.0.0/1", true, udp53...)})
	assert.Equal(t, map[PortKey]bool{{addr("128.0.0.0"), udp53[0]}: true}, m.Ports)
	assert.False(t, m.Allows(addr("192.0.2.1"), udp53[0], false))

	// ICMP on the v6 wildcard is kept: the wildcard path writes every port.
	m = Compile([]Rule{rule("::/0", true, PortProto{0, ProtoICMP}, tcp443[0])})
	assert.Len(t, m.Ports, 2)
	assert.Empty(t, m.Notes)
}
