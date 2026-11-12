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
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
)

// The subnet writers never key a port entry on the zero network, so a
// port-scoped subnet based at 0.0.0.0 or :: (reached only by a path that
// bypasses the load-time drop) writes nothing. Called directly: in this
// release no real path produces such a rule, since the loaders drop it and
// the auto-allows only make /32 host routes.
func TestAddCIDR_ZeroNetworkWithPorts_WritesNothing(t *testing.T) {
	ports := []portProto{{Port: 443, Proto: protoTCP}}
	fw, mocks := newTestFirewall()
	require.NoError(t, fw.addCIDRv4(net.IPv4zero.To4(), 8, 1, ports, "0.0.0.0/8"))
	require.NoError(t, fw.addCIDRv6(net.IPv6unspecified, 96, 1, ports, "::/96"))
	for _, name := range []string{"cidrs", "ports", "cidrsV6", "portsV6"} {
		assert.Empty(t, mocks[name].updates, "map_%s was written", name)
	}

	// A non-zero subnet is unchanged: its port entry and LPM entry are written.
	require.NoError(t, fw.addCIDRv4(net.ParseIP("10.0.0.0").To4(), 8, 1, ports, "10.0.0.0/8"))
	assert.Len(t, mocks["ports"].updates, 1)
	assert.Len(t, mocks["cidrs"].updates, 1)

	// So is a zero network without ports: it keys no port entry, so its LPM
	// entry is written as before.
	require.NoError(t, fw.addCIDRv4(net.IPv4zero.To4(), 8, 1, nil, "0.0.0.0/8"))
	require.NoError(t, fw.addCIDRv6(net.IPv6unspecified, 96, 1, nil, "::/96"))
	assert.Len(t, mocks["cidrs"].updates, 2)
	assert.Len(t, mocks["cidrsV6"].updates, 1)
	assert.Len(t, mocks["ports"].updates, 1)
	assert.Empty(t, mocks["portsV6"].updates)
}

// Each refused address is logged once, however often it comes back. On this
// release the warning is the only signal that a DNS answer naming the zero
// address was refused, since the load-time drop never sees answers.
func TestUnspecifiedHost_WarnsOncePerAddress(t *testing.T) {
	var logs bytes.Buffer
	fw, mocks := newTestFirewall()
	fw.logger = slog.New(slog.NewTextHandler(&logs, nil))
	tcp443 := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	for range 2 {
		for _, addr := range []string{"0.0.0.0", "::ffff:0.0.0.0", "::"} {
			changed, err := fw.AddIP(net.ParseIP(addr), config.ActionAllow, tcp443)
			require.NoError(t, err)
			assert.False(t, changed, addr)
		}
	}
	for _, name := range []string{"cidrs", "ports", "cidrsV6", "portsV6"} {
		assert.Empty(t, mocks[name].updates, "map_%s was written", name)
	}
	out := logs.String()
	assert.Equal(t, 2, strings.Count(out, "level=WARN"), out)
	assert.Equal(t, 1, strings.Count(out, "ip=0.0.0.0"), out)
	assert.Equal(t, 1, strings.Count(out, "ip=::"), out)
}

// RemoveIP leaves the zero address alone even if port state were somehow
// recorded for it, so the any-destination wildcard's entries, which share its
// key, are never deleted.
func TestRemoveIP_ZeroAddress_DeletesNothing(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "::"} {
		fw, mocks := newTestFirewall()
		// Seed state as if an install had slipped through, to show the guard,
		// not the absence of state, is what protects the wildcard's key.
		fw.ipPorts[addr] = &ipPortState{ports: []portProto{{Port: 443, Proto: protoTCP}}}
		require.NoError(t, fw.RemoveIP(net.ParseIP(addr)))
		for _, name := range []string{"cidrs", "ports", "cidrsV6", "portsV6"} {
			assert.Empty(t, mocks[name].deletes, "%s: map_%s deleted a key", addr, name)
		}
		assert.Contains(t, fw.ipPorts, addr, "%s: state untouched", addr)
	}
}
