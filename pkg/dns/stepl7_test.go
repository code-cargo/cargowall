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
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// A step's DNS install is L7-scoped as the job's are, on the ports it opens
// on, by rule or by chain (the firewall runs the scope between admitting
// and writing: TestAddPolicyIP_ScopesBetweenAdmissionAndWrite). With L7 off
// nothing is kept for the rewarm.
func TestStepInstall_L7Scoped(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	answer(s, "deploy.example.com", aResponse("deploy.example.com", "10.1.0.60"))
	assert.Empty(t, s.steps.l7.scoped, "nothing kept with L7 off")

	rec := &recordingRegistrar{}
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
	fw.failAfterScope = errors.New("map full") // admitted and scoped, then refused
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.66"))
	assert.Empty(t, readAuditEvents(t, auditPath), "an install that failed opened nothing")
	fw.failAfterScope = nil
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

// A port a job CIDR deny holds at the address stays blocked whatever the
// step's rules allow there (the job decides first, and the firewall writes
// the step nothing past it), so a step's install never re-reports a block
// on it.
func TestStepInstall_KeepsJobDeniedBlocks(t *testing.T) {
	cfg := config.NewConfigManager()
	s := newStepTestServer(t, cfg, newRecordingFirewall())
	loadStepPolicy(t, cfg, strings.Replace(stepWritersPolicy, `"rules": [`, `"rules": [
		{"type": "cidr", "value": "10.1.0.68/32", "ports": [{"port": 443, "protocol": "tcp"}], "action": "deny"},
		{"type": "cidr", "value": "10.1.3.0/24", "action": "deny"},`, 1))
	auditPath := filepath.Join(t.TempDir(), "audit.ndjson")
	auditLogger, err := events.NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()
	s.SetAuditLogger(auditLogger)
	blocks := events.NewRecentBlocks(0)
	s.SetRecentBlocks(blocks)
	s.SetStepBindings(func(uint32) (uint32, bool) { return policyFetch, true })
	for _, ip := range []string{"10.1.0.68", "10.1.3.5"} {
		blocks.Consume(events.AuditEvent{
			Timestamp: time.Now(), EventType: events.EventConnectionBlocked,
			DstIP: ip, DstPort: 443, Protocol: "TCP", StepOrdinal: 7,
		})
	}
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.68", "10.1.3.5"))
	assert.Empty(t, readAuditEvents(t, auditPath))
}

// failingRegistrar is a registrar whose scope map is full.
type failingRegistrar struct{ recordingRegistrar }

func (r *failingRegistrar) ScopeIP(net.IP, []config.Port) error {
	return errors.New("update: argument list too long")
}

// An install the step budget refuses scopes nothing and is recorded
// nowhere, however many arrive: refused attempts can't fill the scope map
// that admitted installs need.
func TestStepInstall_RefusedScopesNothing(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	fw.stepErr = firewall.ErrStepBudget
	s := newStepTestServer(t, cfg, fw)
	rec := &recordingRegistrar{}
	s.SetL7Registrar(rec)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	for i := range 200 {
		name := fmt.Sprintf("h%d.cdn-step.example.net", i)
		answer(s, name, aResponse(name, fmt.Sprintf("10.4.%d.%d", i/250, i%250+1)))
	}
	assert.Empty(t, rec.scopes, "no scope for a refused install")
	assert.Empty(t, s.steps.l7.scoped, "no record of one either")
}

// A step install whose address the scope map won't take is withheld, never
// open unscoped, with a rate-limited Warn.
func TestStepInstall_WithheldWithoutScope(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	var logs bytes.Buffer
	s := newStepTestServer(t, cfg, fw)
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	s.SetL7Registrar(&failingRegistrar{})
	loadStepPolicy(t, cfg, stepWritersPolicy)
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.69"))
	answer(s, "deploy.example.com", aResponse("deploy.example.com", "10.1.0.70"))
	assert.Empty(t, fw.stepIPs(policyFetch), "withheld")
	assert.Empty(t, fw.stepIPs(policyDeploy), "withheld")
	assert.Empty(t, s.steps.l7.scoped)
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("Step rule install withheld")), "one Warn a minute")
	assert.Contains(t, logs.String(), "step=fetch")
}

// An install the firewall withholds whole, the gate under a job CIDR deny
// say, opened nothing: it is recorded nowhere and re-reports nothing.
func TestStepInstall_WithheldWholeRecordsNothing(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	fw.withhold = true
	s := newStepTestServer(t, cfg, fw)
	s.SetL7Registrar(&recordingRegistrar{})
	loadStepPolicy(t, cfg, stepWritersPolicy)
	auditPath := filepath.Join(t.TempDir(), "audit.ndjson")
	auditLogger, err := events.NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()
	s.SetAuditLogger(auditLogger)
	blocks := events.NewRecentBlocks(0)
	s.SetRecentBlocks(blocks)
	s.SetStepBindings(func(uint32) (uint32, bool) { return policyFetch, true })
	blocks.Consume(events.AuditEvent{
		Timestamp: time.Now(), EventType: events.EventConnectionBlocked,
		DstIP: "10.1.0.71", DstPort: 443, Protocol: "TCP", StepOrdinal: 7,
	})
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.71"))
	assert.Empty(t, s.steps.l7.scoped)
	assert.Empty(t, readAuditEvents(t, auditPath))
}

// cappedRegistrar is a recordingRegistrar over a scope map of capacity
// addresses, which refuses a new one past it as the kernel's does.
type cappedRegistrar struct {
	recordingRegistrar
	capacity int
}

func (r *cappedRegistrar) ScopeIP(ip net.IP, ports []config.Port) error {
	if _, held := r.scopes[ip.String()]; !held && len(r.scopes) >= r.capacity {
		return errors.New("update: argument list too long")
	}
	return r.recordingRegistrar.ScopeIP(ip, ports)
}

// The steps' scopes stay within their share of the scope map, however many
// step installs arrive, admitted or admitted and then refused by the map,
// so the job's own destinations always find room: a job install past them
// is still scoped. A step install out of scope room is withheld.
func TestStepScopes_StayInTheStepsShare(t *testing.T) {
	for _, failAfter := range []bool{false, true} {
		t.Run(fmt.Sprintf("refused after the scope %v", failAfter), func(t *testing.T) {
			cfg := config.NewConfigManager()
			fw := newRecordingFirewall()
			if failAfter {
				fw.failAfterScope = fmt.Errorf("%w: map full", firewall.ErrStepBudget)
			}
			s := newStepTestServer(t, cfg, fw)
			s.steps.l7.share = 3
			rec := &cappedRegistrar{capacity: 5}
			s.SetL7Registrar(rec)
			loadStepPolicy(t, cfg, strings.Replace(stepWritersPolicy, `"rules": [`,
				`"rules": [{"type": "hostname", "value": "*.job-cdn.example.net", "action": "allow"},`, 1))
			for i := range 10 {
				name := fmt.Sprintf("h%d.cdn-step.example.net", i)
				answer(s, name, aResponse(name, fmt.Sprintf("10.5.0.%d", i+1)))
			}
			assert.Len(t, rec.scopes, 3, "the steps' share")
			assert.LessOrEqual(t, len(fw.stepIPs(policyFetch)), 3, "a step install out of scope room never opens")
			for i := range 2 {
				name := fmt.Sprintf("j%d.job-cdn.example.net", i)
				answer(s, name, aResponse(name, fmt.Sprintf("10.6.0.%d", i+1)))
				assert.Contains(t, rec.scopes, fmt.Sprintf("10.6.0.%d", i+1), "the job's destination is scoped")
			}
		})
	}
}

// The rewarm scopes a step's address again under the latest name bound to
// it, whose evidence that install refreshed, not the first, whose evidence
// ages out first. An address no name can be bound to again is withdrawn:
// its step entries are taken out, never left open unscoped.
func TestStepScopes_RebindOrWithdraw(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	rec := &recordingRegistrar{}
	s.SetL7Registrar(rec)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	s.ApplyRulesToTrackedHostnames() // the startup backfill: seals via
	answer(s, "a.cdn-step.example.net", aResponse("a.cdn-step.example.net", "10.1.0.90"))
	answer(s, "c.cdn-step.example.net", aResponse("c.cdn-step.example.net", "10.1.0.91"))
	for i := range 8200 { // evict both names' evidence
		cfg.RecordForwardResolution(fmt.Sprintf("other%d.example.org", i), "192.0.2.1")
	}
	answer(s, "b.cdn-step.example.net", aResponse("b.cdn-step.example.net", "10.1.0.90"))

	s.ApplyRulesToTrackedHostnames()
	assert.Equal(t, "all-ports", rec.scopes["10.1.0.90"], "scoped again under b")
	assert.Contains(t, fw.stepIPs(policyFetch), "10.1.0.90")
	assert.NotContains(t, rec.scopes, "10.1.0.91", "c's evidence is gone")
	assert.NotContains(t, fw.stepIPs(policyFetch), "10.1.0.91", "so its install is withdrawn")
	assert.Contains(t, fw.removed, "10.1.0.91")
}

// The rewarm scopes again only what a step that holds the address still
// allows by the recorded name; the rest is dropped from the record.
func TestStepScopes_PrunedWhenNoStepAllows(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	rec := &recordingRegistrar{}
	s.SetL7Registrar(rec)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	s.ApplyRulesToTrackedHostnames()
	answer(s, "deploy.example.com", aResponse("deploy.example.com", "10.1.0.92"))
	loadStepPolicy(t, cfg, `{"defaultAction": "deny", "rules": [],
		"steps": [{"id": "deploy", "rules": [{"type": "hostname", "value": "other.example.com"}]}]}`)
	s.ApplyRulesToTrackedHostnames()
	assert.NotContains(t, rec.scopes, "10.1.0.92")
	assert.Empty(t, s.steps.l7.scoped)
}

// A scope the registrar fails to write is no charge to the steps' share,
// and a flush gives back the charges of what the rewarm doesn't scope
// again: neither can wear the share down.
func TestStepScopes_ShareGivenBack(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	s.steps.l7.share = 1
	rec := &cappedRegistrar{capacity: 0} // a full map, until it isn't
	s.SetL7Registrar(rec)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	s.ApplyRulesToTrackedHostnames()
	for i := range 3 {
		name := fmt.Sprintf("f%d.cdn-step.example.net", i)
		answer(s, name, aResponse(name, fmt.Sprintf("10.7.0.%d", i+1)))
	}
	rec.capacity = 100
	answer(s, "deploy.example.com", aResponse("deploy.example.com", "10.7.1.1"))
	require.Contains(t, rec.scopes, "10.7.1.1", "the failed scopes took no share")

	loadStepPolicy(t, cfg, `{"defaultAction": "deny", "rules": [],
		"steps": [{"id": "fetch", "rules": [{"type": "hostname", "value": "step.example.com"}]}]}`)
	s.ApplyRulesToTrackedHostnames() // deploy's address is pruned with its rule
	answer(s, "step.example.com", aResponse("step.example.com", "10.7.1.2"))
	assert.Contains(t, rec.scopes, "10.7.1.2", "the pruned address's share came back")
}
