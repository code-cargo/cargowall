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
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
)

// bindStep binds ordinal to policy, as the step binder's lookup does.
func bindStep(s *Server, binds map[uint32]uint32) {
	s.SetStepBindings(func(ordinal uint32) (uint32, bool) {
		p, ok := binds[ordinal]
		return p, ok
	})
}

// The event pipeline's step tier opens an address for a bound step whose
// own rules allow a name the proxy answered it for, under that step's
// policy alone, and says whether the retry passes. Nothing for an unbound
// step, a name with no evidence for the address (a reverse lookup's), or a
// name another step's rules allow.
func TestLateAllowStep(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	ip := net.ParseIP("10.1.0.120")
	tcp := uint8(unix.IPPROTO_TCP)

	ok, _ := s.LateAllowStep(7, "step.example.com", ip, 443, tcp)
	assert.False(t, ok, "no bindings yet")
	bindStep(s, map[uint32]uint32{7: policyFetch, 8: policyDeploy})
	ok, _ = s.LateAllowStep(7, "step.example.com", ip, 443, tcp)
	assert.False(t, ok, "no forward resolution put the name to the address")
	assert.Empty(t, fw.stepIPs(policyFetch))

	cfg.RecordForwardResolution("step.example.com", ip.String())
	ok, _ = s.LateAllowStep(9, "step.example.com", ip, 443, tcp)
	assert.False(t, ok, "an unbound step")
	ok, _ = s.LateAllowStep(8, "step.example.com", ip, 443, tcp)
	assert.False(t, ok, "another step's name")
	assert.Empty(t, fw.stepIPs(policyDeploy))

	ok, rule := s.LateAllowStep(7, "Step.Example.COM", ip, 443, tcp)
	assert.True(t, ok)
	assert.Equal(t, "step.example.com", rule)
	assert.Equal(t, tcp443, fw.stepIPs(policyFetch)[ip.String()], "installed under the step's policy")
	assert.False(t, fw.jobAllows(ip.String()), "and never the job's")
	ok, _ = s.LateAllowStep(7, "step.example.com", ip, 80, tcp)
	assert.False(t, ok, "the rule's ports alone")
}

// A step's blocks from before its binding are re-reported as late-allowed
// once it is bound, where its policy now lets them through: under the name
// the address maps to, by the step's rule for it, or by the step where its
// rules allow the address by no name. Its other blocks, and other steps',
// stay.
func TestReconcileBoundStep(t *testing.T) {
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

	blockedAt := time.Now().Add(-3 * time.Second)
	block := func(ip string, port uint16, ordinal uint32) {
		blocks.Consume(events.AuditEvent{
			Timestamp: blockedAt, EventType: events.EventConnectionBlocked,
			DstIP: ip, DstPort: port, Protocol: "TCP", StepOrdinal: ordinal,
		})
	}
	cfg.UpdateDNSMapping("step.example.com", "10.1.0.121")
	for _, ip := range []string{"10.1.0.121", "10.1.0.122"} {
		_, err := fw.AddPolicyIP(policyFetch, net.ParseIP(ip), tcp443, nil)
		require.NoError(t, err)
	}
	block("10.1.0.121", 443, 7) // fetch's, its rule now opens
	block("10.1.0.122", 443, 7) // fetch's, at an address no name maps to
	block("10.1.0.121", 80, 7)  // fetch's, on a port its rule doesn't name
	block("10.1.0.121", 443, 8) // another step's

	// fetch's, expired
	blocks.Consume(events.AuditEvent{
		Timestamp: time.Now().Add(-time.Hour), EventType: events.EventConnectionBlocked,
		DstIP: "10.1.0.122", DstPort: 8443, Protocol: "TCP", StepOrdinal: 7,
	})
	_, err = fw.AddPolicyIP(policyFetch, net.ParseIP("10.1.0.122"), []config.Port{{Port: 8443, Protocol: config.ProtocolTCP}}, nil)
	require.NoError(t, err)

	s.ReconcileBoundStep(7, policyFetch, "fetch")
	audited := readAuditEvents(t, auditPath)
	require.Len(t, audited, 2)
	byIP := map[string]events.AuditEvent{}
	for _, e := range audited {
		assert.Equal(t, events.EventConnectionLateAllowed, e.EventType)
		assert.Equal(t, uint32(7), e.StepOrdinal)
		assert.True(t, e.Timestamp.Equal(blockedAt), "dated at the attempt")
		byIP[e.DstIP] = e
	}
	assert.Equal(t, "step.example.com", byIP["10.1.0.121"].DstHostname)
	assert.Equal(t, "step.example.com", byIP["10.1.0.121"].MatchedRule)
	assert.Equal(t, "step fetch", byIP["10.1.0.122"].MatchedRule)
	assert.Len(t, blocks.TakeMatching("10.1.0.121", nil, nil, false), 2, "fetch's on 80 and the other step's stay")
}
