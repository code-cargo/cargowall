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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

// The late-allow writes the job's policy, so it must never open the
// firewall for a name only a step's rules allow: that would hand the step's
// allowance to every step and to untagged traffic. It judges by the job's
// rules alone, and FirewallUpdater has no step write at all.
func TestTryLateAllow_StepOnlyNameWritesNothing(t *testing.T) {
	cm := config.NewConfigManager()
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
		"defaultAction": "deny",
		"rules": [{"type": "hostname", "value": "job.example.com", "action": "allow"}],
		"steps": [{"id": "fetch", "rules": [{"type": "hostname", "value": "step.example.com"}]}]
	}`), 0o600))
	require.NoError(t, cm.LoadConfig(path))
	cm.UpdateDNSMapping("step.example.com", "93.184.216.34")

	fw := &mockFirewallUpdater{}
	allowed, rule := tryLateAllow(cm, fw, nil, "step.example.com", "93.184.216.34", 443, unix.IPPROTO_TCP, newTestLogger())
	assert.False(t, allowed)
	assert.Empty(t, rule)

	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	ReportVerdict(verdictRec(true), cm, nil, auditLogger, fw, nil, newTestLogger())
	assert.Empty(t, fw.addedIPs, "a step-only name opened the job's policy")
	require.Len(t, sink.events, 1)
	assert.Equal(t, EventConnectionBlocked, sink.events[0].EventType)

	// The job's own name still late-allows, through the same path.
	cm.UpdateDNSMapping("job.example.com", "93.184.216.34")
	allowed, _ = tryLateAllow(cm, fw, nil, "job.example.com", "93.184.216.34", 443, unix.IPPROTO_TCP, newTestLogger())
	assert.True(t, allowed)
	assert.Len(t, fw.addedIPs, 1)
}
