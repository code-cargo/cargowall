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
	"net"
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
	allowed, rule := tryLateAllow(cm, fw, nil, "step.example.com", "93.184.216.34", 443, unix.IPPROTO_TCP, 0, newTestLogger())
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
	allowed, _ = tryLateAllow(cm, fw, nil, "job.example.com", "93.184.216.34", 443, unix.IPPROTO_TCP, 0, newTestLogger())
	assert.True(t, allowed)
	assert.Len(t, fw.addedIPs, 1)
}

// stepTierRegistrar is an L7 registrar with the step tier, recording the
// steps it was asked for.
type stepTierRegistrar struct {
	allow bool
	asked []uint32
}

func (r *stepTierRegistrar) RegisterLateAllow(string, net.IP, []config.Port) {}

func (r *stepTierRegistrar) LateAllowStep(ordinal uint32, _ string, _ net.IP, _ uint16, _ uint8) (bool, string) {
	r.asked = append(r.asked, ordinal)
	return r.allow, "step.example.com"
}

// A name the job's rules don't allow is the step tier's, where the
// registrar has one: it opens the address for the step that made the
// connection alone, and the job's policy is written nothing. A name the
// job allows, or denies, is never asked of it.
func TestTryLateAllow_StepTier(t *testing.T) {
	cm := config.NewConfigManager()
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
		"defaultAction": "deny",
		"rules": [
			{"type": "hostname", "value": "job.example.com", "action": "allow"},
			{"type": "hostname", "value": "denied.example.com", "action": "deny"},
			{"type": "hostname", "value": "shared.example.com", "ports": [{"port": 80, "protocol": "tcp"}], "action": "allow"}
		],
		"steps": [{"id": "fetch", "rules": [
			{"type": "hostname", "value": "step.example.com"},
			{"type": "hostname", "value": "shared.example.com", "ports": [{"port": 443, "protocol": "tcp"}]}
		]}]
	}`), 0o600))
	require.NoError(t, cm.LoadConfig(path))
	fw := &mockFirewallUpdater{}
	reg := &stepTierRegistrar{allow: true}
	const ip = "93.184.216.34"

	allowed, rule := tryLateAllow(cm, fw, reg, "step.example.com", ip, 443, unix.IPPROTO_TCP, 7, newTestLogger())
	assert.True(t, allowed)
	assert.Equal(t, "step.example.com", rule)
	assert.Equal(t, []uint32{7}, reg.asked)
	assert.Empty(t, fw.addedIPs, "the job's policy written nothing")

	reg.allow = false
	allowed, _ = tryLateAllow(cm, fw, reg, "step.example.com", ip, 80, unix.IPPROTO_TCP, 7, newTestLogger())
	assert.False(t, allowed, "the step tier's answer")

	for _, name := range []string{"job.example.com", "denied.example.com"} {
		reg.asked = nil
		tryLateAllow(cm, fw, reg, name, ip, 443, unix.IPPROTO_TCP, 7, newTestLogger())
		assert.Empty(t, reg.asked, name)
	}
	reg.asked = nil
	tryLateAllow(cm, fw, reg, "step.example.com", ip, 443, unix.IPPROTO_ICMP, 7, newTestLogger())
	assert.Empty(t, reg.asked, "TCP and UDP alone")

	// A name the job allows on other ports than the blocked one is the
	// step tier's on that one.
	reg.allow, reg.asked = true, nil
	allowed, _ = tryLateAllow(cm, fw, reg, "shared.example.com", ip, 80, unix.IPPROTO_TCP, 7, newTestLogger())
	assert.True(t, allowed, "the job's own port")
	assert.Empty(t, reg.asked)
	allowed, _ = tryLateAllow(cm, fw, reg, "shared.example.com", ip, 443, unix.IPPROTO_TCP, 7, newTestLogger())
	assert.True(t, allowed, "the step's port")
	assert.Equal(t, []uint32{7}, reg.asked)

	// A hook's denial asks it for the step that made the connection, and
	// reports the late-allow the step tier gives.
	reg.allow, reg.asked = true, nil
	cm.UpdateDNSMapping("step.example.com", ip)
	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	ReportVerdict(verdictRec(true), cm, nil, auditLogger, fw, reg, newTestLogger())
	assert.Equal(t, []uint32{7}, reg.asked)
	require.Len(t, sink.events, 1)
	assert.Equal(t, EventConnectionLateAllowed, sink.events[0].EventType)
	assert.Equal(t, uint32(7), sink.events[0].StepOrdinal)

	// A container's is never asked: TC may judge its retry as the job's.
	reg.asked = nil
	ctr := verdictRec(true)
	ctr.Decorate = func(a *AuditEvent) { a.ContainerOrigin, a.ContainerID = true, "c0ffee" }
	ReportVerdict(ctr, cm, nil, auditLogger, fw, reg, newTestLogger())
	assert.Empty(t, reg.asked)
	require.Len(t, sink.events, 2)
	assert.Equal(t, EventConnectionBlocked, sink.events[1].EventType)
	assert.Equal(t, "c0ffee", sink.events[1].ContainerID)
}
