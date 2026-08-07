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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	cargowallv1 "github.com/code-cargo/cargowall/pb/cargowall/v1"
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

// A CNAME-derived connection is attributed to its origin hostname (chain[0]),
// so a chain-bearing event and a plain direct connection to the same origin
// share a dedup key. First-seen wins, so when the chainless direct hit sorts
// first the chain must be backfilled onto it rather than dropped (issue #77).
func TestSummary_DeduplicateStepEvents_ChainBackfilledFromLaterDuplicate(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	chain := []string{"auth.docker.io", "auth.docker.io.cdn.cloudflare.net"}
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				// First-seen: plain direct connection, no chain.
				{Timestamp: ts, EventType: events.EventConnectionAllowed, DstHostname: "auth.docker.io", DstIP: "1.1.1.1", DstPort: 443, Protocol: "TCP", Process: "curl"},
				// Later duplicate (same key): CNAME-derived, carries the chain.
				{Timestamp: ts.Add(time.Second), EventType: events.EventConnectionAllowed, DstHostname: "auth.docker.io", DstIP: "2.2.2.2", DstPort: 443, Protocol: "TCP", Process: "curl", CNAMEChain: chain},
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	require.Len(t, stepEvents[0].Events, 1, "same origin collapses to one row")
	assert.Equal(t, chain, stepEvents[0].Events[0].CNAMEChain, "chain backfilled from the later duplicate")
	assert.Equal(t, ts, stepEvents[0].Events[0].Timestamp, "representative is still the first-seen event")
}

// The backfill is unconditional on EventType — the Log*Blocked paths also
// emit chains (e.g. a derived connection blocked on a non-inherited port is
// attributed to the origin with its chain), so a chain carried by a later
// blocked duplicate must be preserved too.
func TestSummary_DeduplicateStepEvents_ChainBackfilledOnBlockedEvent(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	chain := []string{"auth.docker.io", "auth.docker.io.cdn.cloudflare.net"}
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				{Timestamp: ts, EventType: events.EventConnectionBlocked, DstHostname: "auth.docker.io", DstIP: "1.1.1.1", DstPort: 25, Protocol: "TCP", Process: "curl"},
				{Timestamp: ts.Add(time.Second), EventType: events.EventConnectionBlocked, DstHostname: "auth.docker.io", DstIP: "2.2.2.2", DstPort: 25, Protocol: "TCP", Process: "curl", CNAMEChain: chain},
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	require.Len(t, stepEvents[0].Events, 1)
	assert.Equal(t, chain, stepEvents[0].Events[0].CNAMEChain, "chain backfilled onto a blocked representative")
}

// If the representative already carries a chain, a later chainless duplicate
// must not clobber it.
func TestSummary_DeduplicateStepEvents_ChainNotOverwritten(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	chain := []string{"auth.docker.io", "auth.docker.io.cdn.cloudflare.net"}
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				{Timestamp: ts, EventType: events.EventConnectionAllowed, DstHostname: "auth.docker.io", DstIP: "2.2.2.2", DstPort: 443, Protocol: "TCP", Process: "curl", CNAMEChain: chain},
				{Timestamp: ts.Add(time.Second), EventType: events.EventConnectionAllowed, DstHostname: "auth.docker.io", DstIP: "1.1.1.1", DstPort: 443, Protocol: "TCP", Process: "curl"},
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	require.Len(t, stepEvents[0].Events, 1)
	assert.Equal(t, chain, stepEvents[0].Events[0].CNAMEChain, "retained chain must be preserved")
}

// auto_allowed_type is per-IP (CIDR pass of GetAutoAllowedType) while the
// dedup key ignores DstIP when a hostname is set, so round-robin DNS can
// produce same-key duplicates where only a later one carries the type — it
// must be backfilled when the representative lacks it, but never overwritten.
func TestSummary_DeduplicateStepEvents_AutoAllowedTypeBackfilled(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	stepEvents := []StepEvents{
		{
			Step: GitHubStep{Name: "build"},
			Events: []events.AuditEvent{
				// First-seen: resolved IP outside any auto-allowed range.
				{Timestamp: ts, EventType: events.EventConnectionAllowed, DstHostname: "a.com", DstIP: "1.1.1.1", DstPort: 443, Protocol: "TCP", Process: "curl"},
				// Later duplicate: resolved IP inside an auto-allowed range.
				{Timestamp: ts.Add(time.Second), EventType: events.EventConnectionAllowed, DstHostname: "a.com", DstIP: "2.2.2.2", DstPort: 443, Protocol: "TCP", Process: "curl", AutoAllowedType: "dns"},
				// Third duplicate: a different type must not overwrite.
				{Timestamp: ts.Add(2 * time.Second), EventType: events.EventConnectionAllowed, DstHostname: "a.com", DstIP: "3.3.3.3", DstPort: 443, Protocol: "TCP", Process: "curl", AutoAllowedType: "github_service"},
			},
		},
	}
	deduplicateStepEvents(stepEvents)
	require.Len(t, stepEvents[0].Events, 1)
	assert.Equal(t, "dns", stepEvents[0].Events[0].AutoAllowedType, "missing auto_allowed_type backfilled from the first duplicate that carries one, later values don't overwrite")
	assert.Equal(t, ts, stepEvents[0].Events[0].Timestamp, "representative is still the first-seen event")
}

// --- Run: empty-network paths ---

// runSummary executes a full SummaryCmd.Run against an audit log written
// from the given events, returning the rendered output.
func runSummary(t *testing.T, evts []events.AuditEvent) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.Create(path)
	require.NoError(t, err)
	enc := json.NewEncoder(f)
	for _, ev := range evts {
		require.NoError(t, enc.Encode(ev))
	}
	require.NoError(t, f.Close())

	var buf bytes.Buffer
	cmd := &SummaryCmd{AuditLog: path, Steps: "[]", output: &buf}
	require.NoError(t, cmd.Run())
	return buf.String()
}

func TestSummary_Run_EmptyLogPrintsNoEventsMessage(t *testing.T) {
	out := runSummary(t, nil)
	assert.Contains(t, out, "No network events were logged during this workflow run.")
}

// With step attribution on, the audit log always contains step_boundary
// rows; a job with zero network activity must still take the concise
// "no events" path rather than rendering a full summary of zeros.
func TestSummary_Run_BoundaryOnlyLogPrintsNoEventsMessage(t *testing.T) {
	out := runSummary(t, []events.AuditEvent{
		{Timestamp: time.Now(), EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/a.sh"},
		{Timestamp: time.Now(), EventType: events.EventStepBoundary, PID: 11, StepOrdinal: 2, Process: "bash -e /tmp/b.sh"},
	})
	assert.Contains(t, out, "No network events were logged during this workflow run.")
	assert.NotContains(t, out, "Events by Step")
}

func TestSummary_Run_BoundariesRenderAsAttributionNotEntries(t *testing.T) {
	base := time.Now()
	out := runSummary(t, []events.AuditEvent{
		{Timestamp: base, EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/a.sh"},
		{Timestamp: base, EventType: events.EventConnectionBlocked, SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: 443, Protocol: "TCP", Process: "curl", Blocked: true, StepOrdinal: 1},
	})
	assert.Contains(t, out, "1.2.3.4", "the connection event renders")
	assert.Contains(t, out, "### Step Attribution", "boundaries render as the attribution table")
	assert.Contains(t, out, "| #1 | - | `bash -e /tmp/a.sh` |", "ordinal→process mapping row (no GitHub name with empty steps)")
	assert.Contains(t, out, "| #1 |\n", "connection row carries its causal step label")
	assert.Contains(t, out, "#### Step: \"#1\"", "events grouped under the causal ordinal")
	assert.Contains(t, out, "Grouped causally", "causal grouping is announced")
	// The boundary must not appear as a connection entry (its process would
	// otherwise show up as a destination-less table row).
	assert.NotContains(t, out, "| connection", "no boundary-derived entry rows")
}

// Headings and the Step column must agree: with attribution present, events
// group by causal ordinal (named via the boundary-timestamp→step-window
// mapping), and untagged traffic lands in labeled buckets rather than
// polluting whichever step it raced into. Raw event counts render next to
// unique counts so retries don't read as missing math.
func TestSummary_Run_CausalGroupingAndCounts(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.Create(path)
	require.NoError(t, err)
	enc := json.NewEncoder(f)
	evts := []events.AuditEvent{
		{Timestamp: base.Add(1 * time.Second), EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/build.sh"},
		// Three retries of one blocked connection, causally step 1 — but the
		// last retry lands inside step 2's temporal window.
		{Timestamp: base.Add(2 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "9.9.9.9", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 1, Blocked: true},
		{Timestamp: base.Add(3 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "9.9.9.9", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 1, Blocked: true},
		{Timestamp: base.Add(11 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "9.9.9.9", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 1, Blocked: true},
		// Untagged daemon-mediated traffic during step 1's window.
		{Timestamp: base.Add(4 * time.Second), EventType: events.EventConnectionAllowed, DstHostname: "registry.example", DstIP: "5.5.5.5", DstPort: 443, Protocol: "TCP", Process: "dockerd"},
	}
	for _, ev := range evts {
		require.NoError(t, enc.Encode(ev))
	}
	require.NoError(t, f.Close())

	steps := `[{"name":"build","number":1,"started_at":"2025-01-01T10:00:00Z","completed_at":"2025-01-01T10:00:10Z"},` +
		`{"name":"deploy","number":2,"started_at":"2025-01-01T10:00:10Z","completed_at":"2025-01-01T10:00:20Z"}]`
	var buf bytes.Buffer
	cmdSum := &SummaryCmd{AuditLog: path, Steps: steps, output: &buf}
	require.NoError(t, cmdSum.Run())
	out := buf.String()

	// Ordinal 1 resolved to "build" via the boundary timestamp.
	assert.Contains(t, out, `#### Step: "#1 — build"`)
	assert.Contains(t, out, "| #1 | build | `bash -e /tmp/build.sh` |")
	// All three retries live under build — none leak into deploy's window
	// bucket — and dedup to one row while the counts show both numbers.
	assert.NotContains(t, out, `"deploy"`)
	assert.Contains(t, out, "| Connections blocked | 1 | 3 |")
	// Untagged dockerd traffic lands in the labeled docker bucket, not a
	// generic unattributed dump and not a step it raced into.
	assert.Contains(t, out, "Docker-mediated (daemon-created sockets")
	assert.NotContains(t, out, "Unattributed (no socket tag")
}

// Step names and process strings are user-controlled; a pipe or newline
// must not add phantom table columns or break rows, and a backtick must
// not terminate the process code span.
func TestSummary_Run_MarkdownCellsEscaped(t *testing.T) {
	base := time.Now()
	out := runSummary(t, []events.AuditEvent{
		{Timestamp: base, EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/a|b`c.sh"},
		{Timestamp: base, EventType: events.EventConnectionBlocked, DstIP: "9.9.9.9", DstPort: 443, Protocol: "TCP", Process: "cu|rl", Blocked: true, StepOrdinal: 1},
	})
	assert.Contains(t, out, `cu\|rl`, "pipe in process escaped in entries table")
	assert.Contains(t, out, "`bash -e /tmp/a\\|b'c.sh`", "attribution process cell escapes pipes and neutralizes backticks")
	assert.NotContains(t, out, "| cu|rl |", "raw pipe must not survive into a cell")
}

func TestSummary_StepOrdinalLabel(t *testing.T) {
	assert.Equal(t, "-", stepOrdinalLabel(events.StepOrdinalNone))
	assert.Equal(t, "runner", stepOrdinalLabel(events.StepOrdinalRunner))
	assert.Equal(t, "pre", stepOrdinalLabel(events.StepOrdinalPreDaemon))
	assert.Equal(t, "#12", stepOrdinalLabel(12))
}

// The SaaS payload keeps the full GitHub step scaffold (timeline intact,
// empty steps included) but assigns events by ordinal→name, with untagged
// traffic in the same labeled buckets as the rendered summary — never in a
// step it merely raced into.
// Locks the "never drift" invariant the shared classifier exists for: for
// one event set, the rendered grouping and the SaaS push grouping must
// route every event to the same destination — same bucket label for
// bucketed traffic, same GitHub step for resolved ordinals. Layout differs
// by design (render collapses and labels "#N — name"; push keeps the step
// scaffold), so this compares destinations, not shapes.
func TestSummary_RenderAndPushGroupingsAgree(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "Set up job", Number: 1, StartedAt: base.Add(-20 * time.Second)},
		{Name: "build", Number: 2, StartedAt: base},
		{Name: "deploy", Number: 3, StartedAt: base.Add(10 * time.Second)},
	}
	ordinalSteps := map[uint32]int{1: 1, 2: 2}
	evts := []events.AuditEvent{
		{Timestamp: base.Add(1 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "1.1.1.1", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 1},
		{Timestamp: base.Add(11 * time.Second), EventType: events.EventConnectionAllowed, DstHostname: "api.example", DstIP: "2.2.2.2", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 2},
		{Timestamp: base.Add(2 * time.Second), EventType: events.EventConnectionAllowed, DstHostname: "registry.example", DstIP: "3.3.3.3", DstPort: 443, Protocol: "TCP", Process: "dockerd"},
		{Timestamp: base.Add(3 * time.Second), EventType: events.EventConnectionAllowed, DstIP: "4.4.4.4", DstPort: 443, Protocol: "TCP", Process: "python3", AutoAllowedType: "cloud_metadata"},
		{Timestamp: base.Add(4 * time.Second), EventType: events.EventConnectionAllowed, DstIP: "5.5.5.5", DstPort: 443, Protocol: "TCP", Process: "Runner.Worker", StepOrdinal: events.StepOrdinalRunner},
		{Timestamp: base.Add(5 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "6.6.6.6", DstPort: 443, Protocol: "TCP", Process: "leftover", StepOrdinal: events.StepOrdinalPreDaemon},
		// Tagged but unresolved (no boundary mapped this ordinal).
		{Timestamp: base.Add(6 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "7.7.7.7", DstPort: 443, Protocol: "TCP", Process: "orphan", StepOrdinal: 99},
	}

	// destination(group label) per event IP, for each presenter. Render
	// labels resolved steps "#N — name"; normalize to the GitHub name so
	// the two are comparable.
	dest := func(groups []StepEvents, render bool) map[string]string {
		out := map[string]string{}
		for _, g := range groups {
			label := g.Step.Name
			if render {
				if _, after, found := strings.Cut(label, " — "); found {
					label = after
				}
			}
			for _, ev := range g.Events {
				out[ev.DstIP] = label
			}
		}
		return out
	}

	renderDest := dest(causalGroups(evts, steps, ordinalSteps), true)
	pushDest := dest(buildCausalPushGroups(evts, steps, ordinalSteps), false)

	require.Len(t, renderDest, len(evts), "every event lands somewhere in the render grouping")
	assert.Equal(t, pushDest, renderDest, "render and push must route every event identically")

	// Spot-check the actual destinations, so an agreeing-but-wrong mapping
	// can't pass.
	assert.Equal(t, "build", renderDest["1.1.1.1"])
	assert.Equal(t, "deploy", renderDest["2.2.2.2"])
	assert.Equal(t, bucketDocker, renderDest["3.3.3.3"])
	assert.Equal(t, bucketAutoInfra, renderDest["4.4.4.4"])
	assert.Equal(t, bucketRunner, renderDest["5.5.5.5"])
	assert.Equal(t, bucketPreDaemon, renderDest["6.6.6.6"])
	assert.Equal(t, "#99", renderDest["7.7.7.7"])
}

func TestSummary_BuildCausalPushGroups(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "Set up job", Number: 1, StartedAt: base.Add(-20 * time.Second)},
		{Name: "build", Number: 2, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
		{Name: "deploy", Number: 3, StartedAt: base.Add(10 * time.Second)},
	}
	ordinalSteps := map[uint32]int{1: 1} // ordinal 1 → steps[1] ("build")
	regular := []events.AuditEvent{
		// Causally build's, though its timestamp sits in deploy's window.
		{Timestamp: base.Add(11 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "9.9.9.9", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 1},
		{Timestamp: base.Add(2 * time.Second), EventType: events.EventConnectionAllowed, DstHostname: "registry.example", DstIP: "5.5.5.5", DstPort: 443, Protocol: "TCP", Process: "dockerd"},
		{Timestamp: base.Add(3 * time.Second), EventType: events.EventConnectionAllowed, DstIP: "6.6.6.6", DstPort: 443, Protocol: "TCP", Process: "Runner.Worker", StepOrdinal: events.StepOrdinalRunner},
	}

	groups := buildCausalPushGroups(regular, steps, ordinalSteps)

	require.GreaterOrEqual(t, len(groups), 5)
	assert.Equal(t, "Set up job", groups[0].Step.Name)
	assert.Empty(t, groups[0].Events, "pre-attach scaffold step ships empty, preserving the timeline")
	assert.Equal(t, "build", groups[1].Step.Name)
	require.Len(t, groups[1].Events, 1, "event assigned by ordinal, not by time window")
	assert.Equal(t, "9.9.9.9", groups[1].Events[0].DstIP)
	assert.Empty(t, groups[2].Events, "deploy gets nothing despite the timestamp landing in its window")

	labels := make(map[string]int)
	for i, g := range groups {
		labels[g.Step.Name] = i
	}
	require.Contains(t, labels, bucketDocker)
	assert.Len(t, groups[labels[bucketDocker]].Events, 1)
	require.Contains(t, labels, bucketRunner)
	assert.Len(t, groups[labels[bucketRunner]].Events, 1)
}

// GitHub's API reports step timings at second granularity, so back-to-back
// cheap steps tie on StartedAt; monotonic assignment must still give each
// boundary its own step INDEX — resolving to distinct steps that happen to
// share nothing but their start second (and would collide if keyed by name).
func TestSummary_ResolveOrdinalSteps_SameSecondSteps(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "setup", Number: 1, StartedAt: base.Add(-10 * time.Second)},
		{Name: "fast-a", Number: 2, StartedAt: base},
		{Name: "fast-b", Number: 3, StartedAt: base}, // same second as fast-a
		{Name: "fast-c", Number: 4, StartedAt: base},
	}
	boundaries := []events.AuditEvent{
		{EventType: events.EventStepBoundary, StepOrdinal: 1, Timestamp: base.Add(100 * time.Millisecond)},
		{EventType: events.EventStepBoundary, StepOrdinal: 2, Timestamp: base.Add(400 * time.Millisecond)},
		{EventType: events.EventStepBoundary, StepOrdinal: 3, Timestamp: base.Add(700 * time.Millisecond)},
	}
	idx := resolveOrdinalSteps(boundaries, steps)
	assert.Equal(t, 1, idx[1])
	assert.Equal(t, 2, idx[2])
	assert.Equal(t, 3, idx[3])
	assert.Equal(t, "fast-a", ordinalStepName(steps, idx, 1))
	assert.Equal(t, "fast-b", ordinalStepName(steps, idx, 2))
	assert.Equal(t, "fast-c", ordinalStepName(steps, idx, 3))
}

// A boundary can land a fraction before its own step's rounded-down start
// (or the step list can lag); the next unassigned step is the right match.
func TestSummary_ResolveOrdinalSteps_BoundaryBeforeRecordedStart(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "build", Number: 1, StartedAt: base},
		{Name: "deploy", Number: 2, StartedAt: base.Add(10 * time.Second)},
	}
	boundaries := []events.AuditEvent{
		{EventType: events.EventStepBoundary, StepOrdinal: 1, Timestamp: base.Add(time.Second)},
		// Fires 200ms before deploy's recorded start.
		{EventType: events.EventStepBoundary, StepOrdinal: 2, Timestamp: base.Add(10*time.Second - 200*time.Millisecond)},
	}
	idx := resolveOrdinalSteps(boundaries, steps)
	assert.Equal(t, "build", ordinalStepName(steps, idx, 1))
	assert.Equal(t, "deploy", ordinalStepName(steps, idx, 2))
}

// Two steps sharing a name (unnamed "Run" steps are common) must remain
// distinct groups: keying on the step index keeps their events apart,
// where the earlier name-keyed grouping collapsed them into the first.
func TestSummary_BuildCausalPushGroups_DuplicateStepNames(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "Run", Number: 1, StartedAt: base},
		{Name: "Run", Number: 2, StartedAt: base.Add(10 * time.Second)},
	}
	ordinalSteps := map[uint32]int{1: 0, 2: 1}
	regular := []events.AuditEvent{
		{Timestamp: base.Add(1 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "1.1.1.1", DstPort: 443, Protocol: "TCP", Process: "a", StepOrdinal: 1},
		{Timestamp: base.Add(11 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "2.2.2.2", DstPort: 443, Protocol: "TCP", Process: "b", StepOrdinal: 2},
	}
	groups := buildCausalPushGroups(regular, steps, ordinalSteps)
	require.Len(t, groups, 2)
	require.Len(t, groups[0].Events, 1, "first Run keeps only its own event")
	assert.Equal(t, "1.1.1.1", groups[0].Events[0].DstIP)
	require.Len(t, groups[1].Events, 1, "second Run is a distinct group despite the shared name")
	assert.Equal(t, "2.2.2.2", groups[1].Events[0].DstIP)
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

// A missing audit log is NOT an error: the action omits --audit-log under
// audit-summary:false, and the SaaS push (job record, mode, status, version,
// downgrade) must still happen with zero events.
func TestSummary_ReadAuditLog_NonExistentFile(t *testing.T) {
	cmd := &SummaryCmd{AuditLog: "/nonexistent/path/audit.jsonl"}
	auditEvents, err := cmd.readAuditLog()
	require.NoError(t, err, "absent audit log must not block the summary run")
	assert.Empty(t, auditEvents)
}

// TestSummary_Run_MissingAuditLogStillPushes is the end-to-end guard for the
// audit-summary:false configuration: with no audit log on disk, Run must
// still push the job record — carrying the effective mode and any downgrade
// record — rather than erroring out before pushToApi.
func TestSummary_Run_MissingAuditLogStillPushes(t *testing.T) {
	_, downgradePath := redirectStateFiles(t)
	d := &cargowallv1.CargoWallDowngrade{
		Type:         data.CargoWallDowngradeType_CARGO_WALL_DOWNGRADE_TYPE_AUDIT_FALLBACK,
		FailureClass: data.CargoWallFetchFailureClass_CARGO_WALL_FETCH_FAILURE_CLASS_TRANSPORT,
		Detail:       "downgraded to audit mode: policy could not be retrieved",
	}
	payload, err := protojson.Marshal(d)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(downgradePath, payload, 0o644))

	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id": "job-1", "workflow_run_url": "https://app.codecargo.io/run/1"}`))
	}))
	t.Cleanup(srv.Close)

	c := &SummaryCmd{
		AuditLog: filepath.Join(t.TempDir(), "never-written.ndjson"),
		Steps:    "[]",
		ApiUrl:   srv.URL,
		Token:    "test-token",
		JobName:  "build",
		Mode:     "audit",
		output:   io.Discard,
	}
	require.NoError(t, c.Run())

	require.NotNil(t, got, "the push must reach the API despite the missing audit log")
	assert.Equal(t, "CARGO_WALL_MODE_AUDIT", got["mode"])
	dg, ok := got["downgrade"].(map[string]any)
	require.True(t, ok, "downgrade record must ride along on a zero-event push")
	assert.Equal(t, "CARGO_WALL_DOWNGRADE_TYPE_AUDIT_FALLBACK", dg["type"])
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

	t.Run("gitlab_service", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "gitlab.com", "1.1.1.1", "curl", 443, ts)
		ev.AutoAllowedType = "gitlab_service"
		proto := auditEventToProto(ev)
		require.NotNil(t, proto.AutoAllowedType)
		assert.Equal(t, data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_GITLAB_SERVICE, *proto.AutoAllowedType)
	})

	t.Run("codecargo_service", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "api.codecargo.io", "1.2.3.4", "curl", 443, ts)
		ev.AutoAllowedType = "codecargo_service"
		proto := auditEventToProto(ev)
		require.NotNil(t, proto.AutoAllowedType)
		assert.Equal(t, data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_CODECARGO_SERVICE, *proto.AutoAllowedType)
	})

	t.Run("cloud_metadata", func(t *testing.T) {
		ev := makeEvent(t, events.EventConnectionAllowed, "", "169.254.169.254", "curl", 80, ts)
		ev.AutoAllowedType = "cloud_metadata"
		proto := auditEventToProto(ev)
		require.NotNil(t, proto.AutoAllowedType)
		assert.Equal(t, data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_CLOUD_METADATA, *proto.AutoAllowedType)
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

	cmd.generateSummary(summaryData{groups: stepEvents, existingConn: existing, workflowRunLink: "https://app.codecargo.io/run/123"})

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

	cmd.generateSummary(summaryData{groups: stepEvents, existingConn: existing})

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

	cmd.generateSummary(summaryData{groups: stepEvents, auditMode: true, workflowRunLink: "https://app.codecargo.io/run/456"})

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

// TestPushToApi_IgnoresUnknownResponseField confirms an additive field in the
// action-job response doesn't break workflow-URL extraction (the response-side
// counterpart to the policy forward-compat tests).
func TestPushToApi_IgnoresUnknownResponseField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/cargowall/v1/action/job", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"job_id": "job-1",
			"workflow_run_url": "https://app.codecargo.io/run/789",
			"future_field": {"enabled": true}
		}`))
	}))
	t.Cleanup(srv.Close)

	c := &SummaryCmd{ApiUrl: srv.URL, Token: "test-token", JobName: "build"}
	url, err := c.pushToApi(nil, nil)
	require.NoError(t, err, "unknown response fields must not break URL extraction")
	assert.Equal(t, "https://app.codecargo.io/run/789", url)
}

// TestPushToApi_ReportsVersion confirms the agent version (#92) rides along on
// the job push as a top-level field, and is omitted entirely when unset rather
// than sent empty.
func TestPushToApi_ReportsVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{name: "set", version: "v1.2.3"},
		{name: "unset", version: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/api/cargowall/v1/action/job", r.URL.Path)
				assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"job_id": "job-1"}`))
			}))
			t.Cleanup(srv.Close)

			c := &SummaryCmd{ApiUrl: srv.URL, Token: "test-token", JobName: "build", Version: tc.version}
			_, err := c.pushToApi(nil, nil)
			require.NoError(t, err)

			if tc.version == "" {
				assert.NotContains(t, got, "version", "version must be omitted when unset")
				return
			}
			assert.Equal(t, tc.version, got["version"])
			// Version belongs on the request, not nested in the stats summary.
			if summary, ok := got["summary"].(map[string]any); ok {
				assert.NotContains(t, summary, "version")
			}
		})
	}
}

// TestPushToApi_ReportsDowngrade confirms the structured downgrade record
// written by `cargowall start` rides along on the job push with its type,
// failure class, status, and human-readable detail intact — and is omitted
// entirely when the run executed at its requested posture (no state file).
func TestPushToApi_ReportsDowngrade(t *testing.T) {
	status := uint32(503)
	tests := []struct {
		name      string
		downgrade *cargowallv1.CargoWallDowngrade
	}{
		{name: "downgraded", downgrade: &cargowallv1.CargoWallDowngrade{
			Type:         data.CargoWallDowngradeType_CARGO_WALL_DOWNGRADE_TYPE_AUDIT_FALLBACK,
			FailureClass: data.CargoWallFetchFailureClass_CARGO_WALL_FETCH_FAILURE_CLASS_SERVER,
			HttpStatus:   &status,
			Detail:       "downgraded to audit mode: policy could not be retrieved",
		}},
		{name: "not downgraded", downgrade: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, downgradePath := redirectStateFiles(t)
			if tc.downgrade != nil {
				payload, merr := protojson.Marshal(tc.downgrade)
				require.NoError(t, merr)
				require.NoError(t, os.WriteFile(downgradePath, payload, 0o644))
			}

			var got map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"job_id": "job-1"}`))
			}))
			t.Cleanup(srv.Close)

			c := &SummaryCmd{ApiUrl: srv.URL, Token: "test-token", JobName: "build", Mode: "audit"}
			_, err := c.pushToApi(nil, nil)
			require.NoError(t, err)

			if tc.downgrade == nil {
				assert.NotContains(t, got, "downgrade", "downgrade must be omitted when the run was not downgraded")
				return
			}
			d, ok := got["downgrade"].(map[string]any)
			require.True(t, ok, "downgrade must be a structured object, got %T", got["downgrade"])
			assert.Equal(t, "CARGO_WALL_DOWNGRADE_TYPE_AUDIT_FALLBACK", d["type"])
			assert.Equal(t, "CARGO_WALL_FETCH_FAILURE_CLASS_SERVER", d["failure_class"])
			assert.Equal(t, float64(503), d["http_status"])
			assert.Equal(t, tc.downgrade.Detail, d["detail"])
		})
	}
}

// Blocked events superseded by a later connection_late_allowed for the same
// (dst_ip, dst_port, protocol) must be dropped so they aren't pushed to the
// SaaS as denies (#83): the daemon emits the late-allowed record when the
// firewall opens for an IP after its connections were already blocked.
func TestReconcileLateAllowedBlocks(t *testing.T) {
	base := time.Date(2026, 7, 16, 3, 57, 0, 0, time.UTC)
	conn := func(eventType events.AuditEventType, ip string, port uint16, protocol string, ts time.Time) events.AuditEvent {
		return events.AuditEvent{
			Timestamp: ts,
			EventType: eventType,
			DstIP:     ip,
			DstPort:   port,
			Protocol:  protocol,
			Process:   "MainThread",
		}
	}

	input := []events.AuditEvent{
		// Retries blocked before the firewall caught up — all superseded by
		// the late-allowed record dated at the last retry.
		conn(events.EventConnectionBlocked, "20.209.113.193", 443, "TCP", base),
		conn(events.EventConnectionBlocked, "20.209.113.193", 443, "TCP", base.Add(5*time.Second)),
		conn(events.EventConnectionBlocked, "20.209.113.193", 443, "TCP", base.Add(17*time.Second)),
		conn(events.EventConnectionLateAllowed, "20.209.113.193", 443, "TCP", base.Add(17*time.Second)),
		// Same IP, different port: no late-allow for this tuple — kept.
		conn(events.EventConnectionBlocked, "20.209.113.193", 80, "TCP", base.Add(2*time.Second)),
		// Same tuple but blocked AFTER the late-allow: blocked again — kept.
		conn(events.EventConnectionBlocked, "20.209.113.193", 443, "TCP", base.Add(30*time.Second)),
		// Unrelated destination with no late-allow — kept.
		conn(events.EventConnectionBlocked, "203.0.113.9", 443, "TCP", base),
		// Non-blocked events always pass through.
		conn(events.EventConnectionAllowed, "20.209.178.193", 443, "TCP", base.Add(35*time.Second)),
	}

	got := reconcileLateAllowedBlocks(input)

	var blockedIPs []string
	lateAllowed := 0
	for _, e := range got {
		switch e.EventType {
		case events.EventConnectionBlocked:
			blockedIPs = append(blockedIPs, e.DstIP)
		case events.EventConnectionLateAllowed:
			lateAllowed++
		}
	}
	assert.Equal(t, 1, lateAllowed, "the late-allowed record itself is kept")
	assert.Len(t, got, 5)
	require.Len(t, blockedIPs, 3)
	assert.ElementsMatch(t, []string{"20.209.113.193", "20.209.113.193", "203.0.113.9"}, blockedIPs)
}

// With no late-allowed events the audit stream passes through untouched.
func TestReconcileLateAllowedBlocks_NoLateAllows(t *testing.T) {
	input := []events.AuditEvent{
		makeEvent(t, events.EventConnectionBlocked, "", "203.0.113.9", "curl", 443, time.Now()),
		makeEvent(t, events.EventConnectionAllowed, "github.com", "140.82.116.3", "git", 443, time.Now()),
	}
	got := reconcileLateAllowedBlocks(input)
	assert.Equal(t, input, got)
}
