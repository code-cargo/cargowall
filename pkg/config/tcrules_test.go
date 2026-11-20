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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/tcmaps"
)

var (
	ppICMP   = tcmaps.PortProto{Port: 0, Proto: tcmaps.ProtoICMP}
	ppTCP443 = tcmaps.PortProto{Port: 443, Proto: tcmaps.ProtoTCP}
	ppUDP443 = tcmaps.PortProto{Port: 443, Proto: tcmaps.ProtoUDP}
)

// TCPorts expands each rule port to the entries the program keys: ICMP has
// no port, and ProtocolAll is all three protocols.
func TestTCPorts(t *testing.T) {
	assert.Nil(t, TCPorts(nil))
	assert.Equal(t, []tcmaps.PortProto{ppICMP}, TCPorts([]Port{{Port: 0, Protocol: ProtocolICMP}}))
	assert.Equal(t, []tcmaps.PortProto{ppICMP, ppTCP443, ppUDP443}, TCPorts([]Port{{Port: 443, Protocol: ProtocolAll}}))
	assert.Equal(t, []tcmaps.PortProto{ppICMP, ppTCP443}, TCPorts([]Port{
		{Port: 0, Protocol: ProtocolICMP},
		{Port: 443, Protocol: ProtocolTCP},
	}))
}

// A /0 rule reaches the compile as its prefix; whether it is the wildcard is
// the compile's decision, from the prefix and its ports.
func TestTCRules_SlashZero(t *testing.T) {
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]Rule{
		cidrRule("0.0.0.0/0", ActionAllow, udp53...),
		cidrRule("::/0", ActionDeny),
	}, ActionDeny))
	rules := cm.TCRules()
	require.Len(t, rules, 2)
	assert.Equal(t, netip.MustParsePrefix("0.0.0.0/0"), rules[0].Prefix)
	assert.Equal(t, netip.MustParsePrefix("::/0"), rules[1].Prefix)

	m := tcmaps.Compile(rules)
	assert.True(t, m.Allows(netip.MustParseAddr("192.0.2.1"), tcmaps.PortProto{Port: 53, Proto: tcmaps.ProtoUDP}, false))
	assert.False(t, m.Allows(netip.MustParseAddr("2001:db8::1"), ppTCP443, true))
}
