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

package dns

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
)

// orderedRegistrar is a recordingRegistrar that also fails the test when an
// address is scoped after a step install already opened it.
type orderedRegistrar struct {
	recordingRegistrar
	t  *testing.T
	fw *recordingFirewall
}

func (r *orderedRegistrar) ScopeIP(ip net.IP, ports []config.Port) error {
	for _, policy := range []uint32{policyFetch, policyDeploy} {
		if _, open := r.fw.snapshot(policy)[ip.String()]; open {
			r.t.Errorf("%s scoped after its step install opened it", ip)
		}
	}
	return r.recordingRegistrar.ScopeIP(ip, ports)
}

// A step's DNS install is L7-scoped as the job's are: before the address
// opens, on the ports it opens on, by rule or by chain. With L7 off nothing
// is kept for the rewarm.
func TestStepInstall_L7Scoped(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	answer(s, "deploy.example.com", aResponse("deploy.example.com", "10.1.0.60"))
	assert.Empty(t, s.steps.l7.scoped, "nothing kept with L7 off")

	rec := &orderedRegistrar{t: t, fw: fw}
	s.SetL7Registrar(rec)
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.61"))
	answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge61.akamai.example"}, ""))
	answer(s, "edge61.akamai.example", aResponse("edge61.akamai.example", "10.1.0.62"))
	answer(s, "a.cdn-step.example.net", aResponse("a.cdn-step.example.net", "10.1.0.63"))
	assert.Equal(t, map[string]string{
		"10.1.0.61": "tcp/443",   // the rule's ports
		"10.1.0.62": "tcp/443",   // the chain's, inherited
		"10.1.0.63": "all-ports", // a rule on all ports
	}, rec.scopes)
	assert.Contains(t, fw.stepIPs(policyFetch), "10.1.0.61", "and installed")
}

// The tracked-hostname replay flushes every L7 scope before it rebuilds
// them. A step install from after the startup backfill is never backfilled
// again, so the replay scopes it again from the step tier's record, or the
// address would stay open to the step on any name.
func TestStepScopes_RewarmedAfterFlush(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	rec := &recordingRegistrar{}
	s.SetL7Registrar(rec)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	s.ApplyRulesToTrackedHostnames() // the startup backfill: seals via
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.64"))
	answer(s, "deploy.example.com", aResponse("deploy.example.com", "10.1.0.64")) // another step's, on 80
	answer(s, "job.example.com", aResponse("job.example.com", "10.2.0.64"))
	require.Equal(t, "tcp/80", rec.scopes["10.1.0.64"])

	s.ApplyRulesToTrackedHostnames()
	assert.Equal(t, 2, rec.flushes)
	assert.Equal(t, map[string]string{"10.1.0.64": "tcp/443,tcp/80", "10.2.0.64": "all-ports"}, rec.scopes,
		"the steps' scopes come back with the job's, on every step's ports")
}

// StepAllowPorts is the oracle's step tier: the ports a step policy's own
// rule, or else its chain, allows a name on; nothing for another step's
// name, nor for a name the job's rules deny.
func TestStepAllowPorts(t *testing.T) {
	cfg := config.NewConfigManager()
	s := newStepTestServer(t, cfg, newRecordingFirewall())
	loadStepPolicy(t, cfg, stepWritersPolicy)
	answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge65.akamai.example"}, ""))
	for _, c := range []struct {
		policy uint32
		name   string
		ports  []config.Port
		ok     bool
	}{
		{policyFetch, "step.example.com", tcp443, true},
		{policyFetch, "edge65.akamai.example", tcp443, true},
		{policyFetch, "a.cdn-step.example.net", nil, true},
		{policyDeploy, "deploy.example.com", tcp80, true},
		{policyDeploy, "step.example.com", nil, false},
		{policyDeploy, "edge65.akamai.example", nil, false},
		{policyFetch, "x.denied.example.com", nil, false},
		{policyFetch, "ports.example.com", nil, false}, // the job denies it on 443
		{policyFetch, "nothing.example.com", nil, false},
	} {
		ports, ok := s.StepAllowPorts(c.policy, c.name)
		assert.Equal(t, c.ok, ok, "%d %s", c.policy, c.name)
		assert.Equal(t, c.ports, ports, "%d %s", c.policy, c.name)
	}
}

// A step's install re-reports as late-allowed the recent blocks there of the
// steps bound to its policy, on its ports, and no other step's: those stay
// for the job's rules, or their own step's, to open. Until something binds
// steps, a step install re-reports none.
func TestStepInstall_ReconcilesItsStepsBlocks(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	auditPath := filepath.Join(t.TempDir(), "audit.ndjson")
	auditLogger, err := events.NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()
	s.SetAuditLogger(auditLogger)
	blocks := events.NewRecentBlocks(0)
	s.SetRecentBlocks(blocks)

	blockedAt := time.Now().Add(-5 * time.Second)
	block := func(ip string, port uint16, ordinal uint32) {
		blocks.Consume(events.AuditEvent{
			Timestamp: blockedAt, EventType: events.EventConnectionBlocked,
			DstIP: ip, DstPort: port, Protocol: "TCP", StepOrdinal: ordinal,
		})
	}
	block("10.1.0.66", 443, 7) // step ordinal 7, bound to fetch
	block("10.1.0.66", 443, 8) // step ordinal 8, bound to deploy
	block("10.1.0.66", 80, 7)  // fetch's rule names 443 alone
	block("10.1.0.67", 443, 7)

	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.67"))
	assert.Empty(t, readAuditEvents(t, auditPath), "no bindings, no re-report")

	s.SetStepBindings(func(ordinal uint32) (uint32, bool) {
		switch ordinal {
		case 7:
			return policyFetch, true
		case 8:
			return policyDeploy, true
		}
		return 0, false
	})
	fw.stepErr = errors.New("map full")
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.66"))
	assert.Empty(t, readAuditEvents(t, auditPath), "an install that failed opened nothing")
	fw.stepErr = nil
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.66"))
	audited := readAuditEvents(t, auditPath)
	require.Len(t, audited, 1)
	assert.Equal(t, events.EventConnectionLateAllowed, audited[0].EventType)
	assert.Equal(t, uint32(7), audited[0].StepOrdinal)
	assert.Equal(t, uint16(443), audited[0].DstPort)
	assert.Equal(t, "step.example.com", audited[0].MatchedRule)
	assert.True(t, audited[0].Timestamp.Equal(blockedAt))
	assert.Len(t, blocks.TakeMatching("10.1.0.66", nil, nil, false), 2, "deploy's block and fetch's on 80 stay")
}
