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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordReverseName_NamesAnUnnamedIP(t *testing.T) {
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, ActionDeny))

	assert.True(t, cm.RecordReverseName("Edge-1.CDN.example", "192.0.2.1"))
	assert.Equal(t, "edge-1.cdn.example", cm.LookupHostnameByIP("192.0.2.1"))
}

func TestRecordReverseName_NeverReplacesAForwardName(t *testing.T) {
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, ActionDeny))
	cm.UpdateDNSMapping("builder.example", "192.0.2.1")

	assert.False(t, cm.RecordReverseName("ec2-192-0-2-1.compute-1.amazonaws.com", "192.0.2.1"))
	assert.Equal(t, "builder.example", cm.LookupHostnameByIP("192.0.2.1"))
}

// A tracked name's cached address is named too, though no answer mapped it.
func TestRecordReverseName_NeverReplacesACachedTrackedAddress(t *testing.T) {
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, ActionDeny))
	cm.mu.Lock()
	cm.hostnameCache["builder.example"] = []net.IP{net.ParseIP("192.0.2.1")}
	cm.mu.Unlock()

	assert.False(t, cm.RecordReverseName("ec2-192-0-2-1.compute-1.amazonaws.com", "192.0.2.1"))
	assert.Equal(t, "builder.example", cm.LookupHostnameByIP("192.0.2.1"))
}
