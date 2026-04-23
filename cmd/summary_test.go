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

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pb/cargowall/v1/data"
	"github.com/code-cargo/cargowall/pkg/events"
)

func makeEvent(t *testing.T, eventType events.AuditEventType, hostname, ip, process string, port uint16, ts time.Time) events.AuditEvent {
	t.Helper()
	return events.AuditEvent{
		Timestamp:   ts,
		EventType:   eventType,
		DstHostname: hostname,
		DstIP:       ip,
		DstPort:     port,
		Process:     process,
	}
}

// --- deduplicateStepEvents ---

func TestSummary_DeduplicateStepEvents_NoEvents(t *testing.T) {
	stepEvents := []StepEvents{
		{Step: GitHubStep{Name: "build"}, Events: nil},
	}
	deduplicateStepEvents(stepEvents)
	assert.Empty(t, stepEvents[0].Events)
}

func TestSummary_DeduplicateStepEvents_AllUnique(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, ts),
				makeEvent(t, events.EventConnectionBlocked, "b.com", "2.2.2.2", "curl", 443, ts),
				makeEvent(t, events.EventConnectionAllowed, "c.com", "3.3.3.3", "wget", 80, ts),
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	assert.Len(t, stepEvents[0].Events, 3)
}

func TestSummary_DeduplicateStepEvents_Duplicates(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, ts),
				makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, ts.Add(time.Second)),
				makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, ts.Add(2*time.Second)),
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	require.Len(t, stepEvents[0].Events, 1)
	assert.Equal(t, ts, stepEvents[0].Events[0].Timestamp, "should keep the first occurrence")
}

func TestSummary_DeduplicateStepEvents_UsesHostnameFallsBackToIP(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				// Has hostname → keyed by hostname
				makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, ts),
				// Same IP, no hostname → keyed by IP, different from above
				makeEvent(t, events.EventConnectionBlocked, "", "1.1.1.1", "curl", 443, ts.Add(time.Second)),
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	assert.Len(t, stepEvents[0].Events, 2, "hostname vs IP-only should be distinct keys")
}

func TestSummary_DeduplicateStepEvents_AcrossStepsIndependent(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ev := makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, ts)

	stepEvents := []StepEvents{
		{Step: GitHubStep{Name: "step1"}, Events: []events.AuditEvent{ev, ev}},
		{Step: GitHubStep{Name: "step2"}, Events: []events.AuditEvent{ev, ev}},
	}
	deduplicateStepEvents(stepEvents)
	assert.Len(t, stepEvents[0].Events, 1, "step1 deduped independently")
	assert.Len(t, stepEvents[1].Events, 1, "step2 deduped independently")
}

func TestSummary_DeduplicateStepEvents_DifferentPortsKept(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, ts),
				makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 80, ts),
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	assert.Len(t, stepEvents[0].Events, 2, "different ports should be separate entries")
}

// Same (process, dest, port) over different L4 protocols must survive
// dedup so the UI doesn't collapse a TCP and a UDP observation into one row
// (and silently pick whichever protocol won the map write).
func TestSummary_DeduplicateStepEvents_DifferentProtocolsKept(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				{Timestamp: ts, EventType: events.EventConnectionBlocked, DstHostname: "a.com", DstIP: "1.1.1.1", DstPort: 53, Process: "dig", Protocol: "TCP"},
				{Timestamp: ts, EventType: events.EventConnectionBlocked, DstHostname: "a.com", DstIP: "1.1.1.1", DstPort: 53, Process: "dig", Protocol: "UDP"},
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	assert.Len(t, stepEvents[0].Events, 2, "TCP and UDP observations on the same dest:port must remain separate")
}

// --- correlateEventsToSteps ---

func TestSummary_CorrelateEventsToSteps_EventInStep(t *testing.T) {
	cmd := &SummaryCmd{}
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "build", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
	}
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, base.Add(5*time.Second)),
	}
	result := cmd.correlateEventsToSteps(evts, steps)
	require.Len(t, result, 1)
	assert.Len(t, result[0].Events, 1)
	assert.Equal(t, "build", result[0].Step.Name)
}

func TestSummary_CorrelateEventsToSteps_EventOutsideAllSteps(t *testing.T) {
	cmd := &SummaryCmd{}
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "build", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
	}
	// Event well after the step ends (beyond the 1s extension)
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, base.Add(30*time.Second)),
	}
	result := cmd.correlateEventsToSteps(evts, steps)
	require.Len(t, result, 2, "original step + Unknown Step")
	assert.Empty(t, result[0].Events)
	assert.Equal(t, "Unknown Step (events outside step boundaries)", result[1].Step.Name)
	assert.Len(t, result[1].Events, 1)
}

func TestSummary_CorrelateEventsToSteps_CompletedAtZeroInferred(t *testing.T) {
	cmd := &SummaryCmd{}
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "step1", Number: 1, StartedAt: base, CompletedAt: time.Time{}},
		{Name: "step2", Number: 2, StartedAt: base.Add(10 * time.Second), CompletedAt: base.Add(20 * time.Second)},
	}
	// Event in step1's inferred window (before step2 starts)
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, base.Add(5*time.Second)),
	}
	result := cmd.correlateEventsToSteps(evts, steps)
	require.Len(t, result, 2)
	assert.Len(t, result[0].Events, 1, "event should be in step1 with inferred CompletedAt")
}

func TestSummary_CorrelateEventsToSteps_LastStepZeroCompletedAt(t *testing.T) {
	cmd := &SummaryCmd{}
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "step1", Number: 1, StartedAt: base, CompletedAt: time.Time{}},
	}
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, base.Add(5*time.Second)),
	}
	result := cmd.correlateEventsToSteps(evts, steps)
	require.Len(t, result, 1)
	assert.Len(t, result[0].Events, 1, "last step with zero CompletedAt extended to cover events")
}

func TestSummary_CorrelateEventsToSteps_OneSecondExtension(t *testing.T) {
	cmd := &SummaryCmd{}
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "build", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
	}
	// Event at completedAt + 500ms — within the 1s extension
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, base.Add(10*time.Second+500*time.Millisecond)),
	}
	result := cmd.correlateEventsToSteps(evts, steps)
	require.Len(t, result, 1)
	assert.Len(t, result[0].Events, 1, "1s extension should capture sub-second events")
}

func TestSummary_CorrelateEventsToSteps_ExtensionCappedAtNextStep(t *testing.T) {
	cmd := &SummaryCmd{}
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "step1", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
		{Name: "step2", Number: 2, StartedAt: base.Add(10 * time.Second), CompletedAt: base.Add(20 * time.Second)},
	}
	// Event exactly at step2's start — should go to step2, not step1's extension
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, base.Add(10*time.Second)),
	}
	result := cmd.correlateEventsToSteps(evts, steps)
	require.Len(t, result, 2)
	// step1's extension is capped at step2's start, so event at exactly step2's start goes to step2
	assert.Empty(t, result[0].Events, "step1 should not steal event at step2's boundary")
	assert.Len(t, result[1].Events, 1, "event should be in step2")
}

func TestSummary_CorrelateEventsToSteps_EmptyEvents(t *testing.T) {
	cmd := &SummaryCmd{}
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "step1", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
		{Name: "step2", Number: 2, StartedAt: base.Add(10 * time.Second), CompletedAt: base.Add(20 * time.Second)},
	}
	result := cmd.correlateEventsToSteps(nil, steps)
	require.Len(t, result, 2, "all steps returned even with no events")
	assert.Empty(t, result[0].Events)
	assert.Empty(t, result[1].Events)
}

func TestSummary_CorrelateEventsToSteps_MultipleEventsInStep(t *testing.T) {
	cmd := &SummaryCmd{}
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "build", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
	}
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionBlocked, "a.com", "1.1.1.1", "curl", 443, base.Add(1*time.Second)),
		makeEvent(t, events.EventConnectionAllowed, "b.com", "2.2.2.2", "wget", 80, base.Add(3*time.Second)),
		makeEvent(t, events.EventDNSBlocked, "c.com", "", "", 0, base.Add(5*time.Second)),
	}
	result := cmd.correlateEventsToSteps(evts, steps)
	require.Len(t, result, 1)
	assert.Len(t, result[0].Events, 3)
}

// --- readAuditLog ---

func writeJSONL(t *testing.T, dir string, lines []string) string {
	t.Helper()
	path := filepath.Join(dir, "audit.jsonl")
	content := ""
	for _, line := range lines {
		content += line + "\n"
	}
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestSummary_ReadAuditLog_ValidEvents(t *testing.T) {
	dir := t.TempDir()
	ev1, _ := json.Marshal(events.AuditEvent{EventType: events.EventConnectionBlocked, DstHostname: "a.com", DstPort: 443})
	ev2, _ := json.Marshal(events.AuditEvent{EventType: events.EventConnectionAllowed, DstHostname: "b.com", DstPort: 80})
	path := writeJSONL(t, dir, []string{string(ev1), string(ev2)})

	cmd := &SummaryCmd{AuditLog: path}
	result, err := cmd.readAuditLog()
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, events.EventConnectionBlocked, result[0].EventType)
	assert.Equal(t, "a.com", result[0].DstHostname)
	assert.Equal(t, events.EventConnectionAllowed, result[1].EventType)
	assert.Equal(t, "b.com", result[1].DstHostname)
}

func TestSummary_ReadAuditLog_MalformedLineSkipped(t *testing.T) {
	dir := t.TempDir()
	ev1, _ := json.Marshal(events.AuditEvent{EventType: events.EventConnectionBlocked, DstHostname: "a.com"})
	ev2, _ := json.Marshal(events.AuditEvent{EventType: events.EventConnectionAllowed, DstHostname: "b.com"})
	path := writeJSONL(t, dir, []string{string(ev1), "not valid json{{{", string(ev2)})

	cmd := &SummaryCmd{AuditLog: path}
	result, err := cmd.readAuditLog()
	require.NoError(t, err)
	require.Len(t, result, 2, "malformed line should be skipped")
	assert.Equal(t, "a.com", result[0].DstHostname)
	assert.Equal(t, "b.com", result[1].DstHostname)
}

func TestSummary_ReadAuditLog_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o644))

	cmd := &SummaryCmd{AuditLog: path}
	result, err := cmd.readAuditLog()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestSummary_ReadAuditLog_NonExistentFile(t *testing.T) {
	cmd := &SummaryCmd{AuditLog: "/nonexistent/path/audit.jsonl"}
	_, err := cmd.readAuditLog()
	assert.Error(t, err)
}

// --- eventDestination ---

func TestSummary_EventDestination_HostnameWithPort(t *testing.T) {
	cmd := &SummaryCmd{}
	event := events.AuditEvent{
		EventType:   events.EventConnectionBlocked,
		DstHostname: "example.com",
		DstIP:       "1.2.3.4",
		DstPort:     443,
	}
	assert.Equal(t, "example.com:443", cmd.eventDestination(event))
}

func TestSummary_EventDestination_IPOnlyWithPort(t *testing.T) {
	cmd := &SummaryCmd{}
	event := events.AuditEvent{
		EventType: events.EventConnectionBlocked,
		DstIP:     "1.2.3.4",
		DstPort:   443,
	}
	assert.Equal(t, "1.2.3.4:443", cmd.eventDestination(event))
}

func TestSummary_EventDestination_HostnameWithoutPort(t *testing.T) {
	cmd := &SummaryCmd{}
	event := events.AuditEvent{
		EventType:   events.EventDNSBlocked,
		DstHostname: "example.com",
	}
	assert.Equal(t, "example.com", cmd.eventDestination(event))
}

func TestSummary_EventDestination_ProtocolBlockedHostname(t *testing.T) {
	cmd := &SummaryCmd{}
	event := events.AuditEvent{
		EventType:   events.EventProtocolBlocked,
		DstHostname: "example.com",
		DstIP:       "1.2.3.4",
		Protocol:    "ICMP",
	}
	assert.Equal(t, "example.com (ICMP)", cmd.eventDestination(event))
}

func TestSummary_EventDestination_ProtocolBlockedIPFallback(t *testing.T) {
	cmd := &SummaryCmd{}
	event := events.AuditEvent{
		EventType: events.EventProtocolBlocked,
		DstIP:     "1.2.3.4",
		Protocol:  "GRE",
	}
	assert.Equal(t, "1.2.3.4 (GRE)", cmd.eventDestination(event))
}

// --- eventTypeLabel ---

// --- computeSummary ---

func TestSummary_ComputeSummary_EnforceMode(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionAllowed, "a.com", "1.1.1.1", "curl", 443, ts),
		makeEvent(t, events.EventConnectionAllowed, "b.com", "2.2.2.2", "curl", 80, ts),
		makeEvent(t, events.EventConnectionBlocked, "c.com", "3.3.3.3", "curl", 443, ts),
		makeEvent(t, events.EventDNSBlocked, "d.com", "", "", 0, ts),
	}

	summary := computeSummary(evts, data.CargoWallMode_CARGO_WALL_MODE_ENFORCE)

	assert.Equal(t, uint32(4), summary.TotalConnections)
	assert.Equal(t, uint32(2), summary.AllowedConnections)
	assert.Equal(t, uint32(2), summary.DeniedConnections, "enforce mode should count blocked as denied")
	assert.Equal(t, uint32(0), summary.WouldDenyConnections, "enforce mode should have zero would_deny")
	assert.Equal(t, uint32(4), summary.UniqueHostnames)
	assert.Equal(t, uint32(0), summary.AutoAllowedConnections)
}

func TestSummary_ComputeSummary_AuditMode(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionAllowed, "a.com", "1.1.1.1", "curl", 443, ts),
		makeEvent(t, events.EventConnectionBlocked, "b.com", "2.2.2.2", "curl", 443, ts),
		makeEvent(t, events.EventDNSBlocked, "c.com", "", "", 0, ts),
		makeEvent(t, events.EventProtocolBlocked, "d.com", "4.4.4.4", "curl", 0, ts),
	}

	summary := computeSummary(evts, data.CargoWallMode_CARGO_WALL_MODE_AUDIT)

	assert.Equal(t, uint32(4), summary.TotalConnections)
	assert.Equal(t, uint32(1), summary.AllowedConnections)
	assert.Equal(t, uint32(0), summary.DeniedConnections, "audit mode should have zero denied")
	assert.Equal(t, uint32(3), summary.WouldDenyConnections, "audit mode should count blocked as would_deny")
	assert.Equal(t, uint32(4), summary.UniqueHostnames)
}

func TestSummary_ComputeSummary_NoEvents(t *testing.T) {
	summary := computeSummary(nil, data.CargoWallMode_CARGO_WALL_MODE_ENFORCE)

	assert.Equal(t, uint32(0), summary.TotalConnections)
	assert.Equal(t, uint32(0), summary.AllowedConnections)
	assert.Equal(t, uint32(0), summary.DeniedConnections)
	assert.Equal(t, uint32(0), summary.WouldDenyConnections)
	assert.Equal(t, uint32(0), summary.UniqueHostnames)
}

func TestSummary_ComputeSummary_AllAllowed(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionAllowed, "a.com", "1.1.1.1", "curl", 443, ts),
		makeEvent(t, events.EventConnectionAllowed, "b.com", "2.2.2.2", "curl", 80, ts),
	}

	// With no blocked events, audit vs enforce shouldn't matter
	summaryAudit := computeSummary(evts, data.CargoWallMode_CARGO_WALL_MODE_AUDIT)
	summaryEnforce := computeSummary(evts, data.CargoWallMode_CARGO_WALL_MODE_ENFORCE)

	assert.Equal(t, uint32(2), summaryAudit.TotalConnections)
	assert.Equal(t, uint32(2), summaryAudit.AllowedConnections)
	assert.Equal(t, uint32(0), summaryAudit.DeniedConnections)
	assert.Equal(t, uint32(0), summaryAudit.WouldDenyConnections)

	assert.Equal(t, uint32(2), summaryEnforce.TotalConnections)
	assert.Equal(t, uint32(2), summaryEnforce.AllowedConnections)
	assert.Equal(t, uint32(0), summaryEnforce.DeniedConnections)
	assert.Equal(t, uint32(0), summaryEnforce.WouldDenyConnections)
}

func TestSummary_ComputeSummary_AutoAllowed(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	autoEvent := makeEvent(t, events.EventConnectionAllowed, "dns.server", "8.8.8.8", "dns", 53, ts)
	autoEvent.AutoAllowedType = "dns"
	evts := []events.AuditEvent{
		autoEvent,
		makeEvent(t, events.EventConnectionAllowed, "github.com", "1.1.1.1", "curl", 443, ts),
		makeEvent(t, events.EventConnectionBlocked, "evil.com", "6.6.6.6", "curl", 443, ts),
	}

	summary := computeSummary(evts, data.CargoWallMode_CARGO_WALL_MODE_ENFORCE)

	assert.Equal(t, uint32(3), summary.TotalConnections)
	assert.Equal(t, uint32(2), summary.AllowedConnections)
	assert.Equal(t, uint32(1), summary.AutoAllowedConnections)
	assert.Equal(t, uint32(1), summary.DeniedConnections)
}

// TestSummary_ComputeSummary_LateAllowedCountsAsAllowed verifies the audit-log
// fidelity fix: a connection_late_allowed event represents an allow decision
// (BPF dropped the SYN, but a late hostname resolution opened the firewall),
// so it must be counted with allowed connections — not denied/would-deny.
func TestSummary_ComputeSummary_LateAllowedCountsAsAllowed(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionAllowed, "a.com", "1.1.1.1", "curl", 443, ts),
		makeEvent(t, events.EventConnectionLateAllowed, "b.com", "2.2.2.2", "curl", 443, ts),
		makeEvent(t, events.EventConnectionBlocked, "c.com", "3.3.3.3", "curl", 443, ts),
	}

	summary := computeSummary(evts, data.CargoWallMode_CARGO_WALL_MODE_ENFORCE)

	assert.Equal(t, uint32(3), summary.TotalConnections)
	assert.Equal(t, uint32(2), summary.AllowedConnections, "late-allowed must count as allowed")
	assert.Equal(t, uint32(1), summary.DeniedConnections, "late-allowed must NOT count as denied")
	assert.Equal(t, uint32(0), summary.WouldDenyConnections, "late-allowed must NOT count as would-deny")
}

// TestSummary_AuditEventToProto_LateAllowed makes sure late-allowed events
// land in the API proto with the right action (allow) and category (connection).
func TestSummary_AuditEventToProto_LateAllowed(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ev := makeEvent(t, events.EventConnectionLateAllowed, "example.com", "1.2.3.4", "curl", 443, ts)
	ev.MatchedRule = "example.com"

	proto := auditEventToProto(ev)

	assert.Equal(t, data.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW, proto.Action)
	assert.Equal(t, data.CargoWallEventCategory_CARGO_WALL_EVENT_CATEGORY_CONNECTION, proto.Category)
	require.NotNil(t, proto.MatchedRule)
	assert.Equal(t, "example.com", *proto.MatchedRule)
}

func TestSummary_ComputeSummary_UnspecifiedModeFallsBackToEnforce(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	evts := []events.AuditEvent{
		makeEvent(t, events.EventConnectionAllowed, "a.com", "1.1.1.1", "curl", 443, ts),
		makeEvent(t, events.EventConnectionBlocked, "b.com", "2.2.2.2", "curl", 443, ts),
		makeEvent(t, events.EventDNSBlocked, "c.com", "", "", 0, ts),
	}

	summary := computeSummary(evts, data.CargoWallMode_CARGO_WALL_MODE_UNSPECIFIED)

	assert.Equal(t, uint32(3), summary.TotalConnections)
	assert.Equal(t, uint32(1), summary.AllowedConnections)
	assert.Equal(t, uint32(2), summary.DeniedConnections, "unspecified mode should fall back to enforce (blocked counted as denied)")
	assert.Equal(t, uint32(0), summary.WouldDenyConnections, "unspecified mode should have zero would_deny")
	assert.Equal(t, uint32(3), summary.UniqueHostnames)
}

func TestSummary_AuditEventToProto_AutoAllowedType(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("dns", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "", "8.8.8.8", "dns", 53, ts)
		ev.AutoAllowedType = "dns"
		proto := auditEventToProto(ev)
		require.NotNil(t, proto.AutoAllowedType)
		assert.Equal(t, data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_DNS, *proto.AutoAllowedType)
	})

	t.Run("azure_infrastructure", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "", "169.254.169.254", "curl", 80, ts)
		ev.AutoAllowedType = "azure_infrastructure"
		proto := auditEventToProto(ev)
		require.NotNil(t, proto.AutoAllowedType)
		assert.Equal(t, data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_AZURE_INFRASTRUCTURE, *proto.AutoAllowedType)
	})

	t.Run("github_service", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "github.com", "1.1.1.1", "curl", 443, ts)
		ev.AutoAllowedType = "github_service"
		proto := auditEventToProto(ev)
		require.NotNil(t, proto.AutoAllowedType)
		assert.Equal(t, data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_GITHUB_SERVICE, *proto.AutoAllowedType)
	})

	t.Run("codecargo_service", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "api.codecargo.io", "1.2.3.4", "curl", 443, ts)
		ev.AutoAllowedType = "codecargo_service"
		proto := auditEventToProto(ev)
		require.NotNil(t, proto.AutoAllowedType)
		assert.Equal(t, data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_CODECARGO_SERVICE, *proto.AutoAllowedType)
	})

	t.Run("empty_not_set", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "github.com", "1.1.1.1", "curl", 443, ts)
		proto := auditEventToProto(ev)
		assert.Nil(t, proto.AutoAllowedType)
	})

	t.Run("unrecognized_not_set", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "unknown.com", "1.1.1.1", "curl", 443, ts)
		ev.AutoAllowedType = "some_future_type"
		proto := auditEventToProto(ev)
		assert.Nil(t, proto.AutoAllowedType, "unrecognized auto_allowed_type should leave field unset, not UNSPECIFIED")
	})
}

func TestSummary_EventTypeLabel(t *testing.T) {
	cmd := &SummaryCmd{}

	tests := []struct {
		name      string
		eventType events.AuditEventType
		want      string
	}{
		{"ConnectionBlocked", events.EventConnectionBlocked, "Connection"},
		{"ConnectionAllowed", events.EventConnectionAllowed, "Connection"},
		{"ProtocolBlocked", events.EventProtocolBlocked, "Protocol"},
		{"DNSBlocked", events.EventDNSBlocked, "DNS"},
		{"UnknownType", events.AuditEventType("something_else"), "something_else"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cmd.eventTypeLabel(tt.eventType))
		})
	}
}

// --- generateSummary condensed/full output ---

func buildTestStepEvents(t *testing.T) ([]StepEvents, []events.AuditEvent) {
	t.Helper()
	ts := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	blocked := makeEvent(t, events.EventConnectionBlocked, "evil.com", "6.6.6.6", "curl", 443, ts)
	blocked.WouldDeny = true
	allowed := makeEvent(t, events.EventConnectionAllowed, "good.com", "1.1.1.1", "wget", 80, ts.Add(time.Second))
	stepEvents := []StepEvents{
		{
			Step:   GitHubStep{Name: "build", Number: 1, StartedAt: ts, CompletedAt: ts.Add(10 * time.Second)},
			Events: []events.AuditEvent{blocked, allowed},
		},
	}
	existing := []events.AuditEvent{
		{EventType: events.EventExistingConnection, DstIP: "10.0.0.1", DstHostname: "internal.svc"},
	}
	return stepEvents, existing
}

func TestSummary_GenerateSummary_CondensedWithLink(t *testing.T) {
	stepEvents, existing := buildTestStepEvents(t)
	var buf bytes.Buffer
	cmd := &SummaryCmd{output: &buf}

	cmd.generateSummary(stepEvents, existing, false, "https://app.codecargo.io/run/123")

	out := buf.String()
	// Header present
	assert.Contains(t, out, "## CargoWall (Enforce Mode)")
	// CTA link present
	assert.Contains(t, out, "[View full details on CodeCargo](https://app.codecargo.io/run/123)")
	// Summary table and detailed sections skipped
	assert.NotContains(t, out, "### Summary")
	assert.NotContains(t, out, "### Events by Step")
	assert.NotContains(t, out, "### Pre-Existing Connections")
	assert.NotContains(t, out, "### Recommended Allowlist")
}

func TestSummary_GenerateSummary_FullWithoutLink(t *testing.T) {
	stepEvents, existing := buildTestStepEvents(t)
	var buf bytes.Buffer
	cmd := &SummaryCmd{output: &buf}

	cmd.generateSummary(stepEvents, existing, false, "")

	out := buf.String()
	// Detailed sections present
	assert.Contains(t, out, "### Events by Step")
	assert.Contains(t, out, "### Pre-Existing Connections")
	// No CTA link
	assert.NotContains(t, out, "[View full details on CodeCargo]")
	// No parenthetical link in header
	assert.NotContains(t, out, "[view on CodeCargo]")
}

func TestSummary_GenerateSummary_CondensedAuditMode(t *testing.T) {
	ts := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	blocked := makeEvent(t, events.EventConnectionBlocked, "evil.com", "6.6.6.6", "curl", 443, ts)
	blocked.WouldDeny = true
	stepEvents := []StepEvents{
		{
			Step:   GitHubStep{Name: "build", Number: 1, StartedAt: ts, CompletedAt: ts.Add(10 * time.Second)},
			Events: []events.AuditEvent{blocked},
		},
	}
	var buf bytes.Buffer
	cmd := &SummaryCmd{output: &buf}

	cmd.generateSummary(stepEvents, nil, true, "https://app.codecargo.io/run/456")

	out := buf.String()
	// Audit mode header and banner
	assert.Contains(t, out, "## CargoWall (Audit Mode - No Blocking)")
	assert.Contains(t, out, "Running in audit mode")
	// CTA link
	assert.Contains(t, out, "[View full details on CodeCargo](https://app.codecargo.io/run/456)")
	// Summary table and detailed sections skipped
	assert.NotContains(t, out, "### Summary")
	assert.NotContains(t, out, "### Recommended Allowlist Additions")
}
