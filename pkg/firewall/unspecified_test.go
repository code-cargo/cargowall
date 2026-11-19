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
		fw.ipPorts[addr] = &ipPortState{Ports: []portProto{{Port: 443, Proto: protoTCP}}}
		require.NoError(t, fw.RemoveIP(net.ParseIP(addr)))
		for _, name := range []string{"cidrs", "ports", "cidrsV6", "portsV6"} {
			assert.Empty(t, mocks[name].deletes, "%s: map_%s deleted a key", addr, name)
		}
		assert.Contains(t, fw.ipPorts, addr, "%s: state untouched", addr)
	}
}
