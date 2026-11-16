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

package events

import (
	"bytes"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

// refusingFirewall refuses every add as a rule naming an unknown protocol.
type refusingFirewall struct{ calls int }

func (f *refusingFirewall) AddIP(net.IP, config.Action, []config.Port) (bool, error) {
	f.calls++
	return false, config.ErrUnknownProtocol
}

// A blocked packet whose rule the firewall refuses for naming an unknown
// protocol is not late-allowed, and isn't logged per packet: the firewall logs it
// once, and the late allow runs for every blocked packet.
func TestTryLateAllow_UnknownProtocolIsQuietAndNotAllowed(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "job.example.com", Action: config.ActionAllow},
	}, config.ActionDeny))
	fw := &refusingFirewall{}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	for range 3 {
		allowed, _ := tryLateAllow(cm, fw, nil, "job.example.com", "93.184.216.34", 443, unix.IPPROTO_TCP, 0, logger)
		assert.False(t, allowed)
	}
	assert.Equal(t, 3, fw.calls, "asked once per packet, never retried within one")
	assert.NotContains(t, logs.String(), "Late-resolved IP add failed")
}
