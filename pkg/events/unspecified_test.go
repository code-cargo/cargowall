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
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

// A denial whose destination is the unspecified address is never late
// allowed: the firewall installs nothing there, so the retry would not pass.
func TestTryLateAllow_UnspecifiedOpensNothing(t *testing.T) {
	cm := config.NewConfigManager()
	assert.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "zero.example.com", Action: config.ActionAllow},
	}, config.ActionDeny))
	fw := &mockFirewallUpdater{}
	for _, addr := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0"} {
		allowed, _ := tryLateAllow(cm, fw, nil, "zero.example.com", addr, 443, unix.IPPROTO_TCP, newTestLogger())
		assert.False(t, allowed, addr)
	}
	assert.Empty(t, fw.addedIPs)

	allowed, _ := tryLateAllow(cm, fw, nil, "zero.example.com", "93.184.216.34", 443, unix.IPPROTO_TCP, newTestLogger())
	assert.True(t, allowed)
}
