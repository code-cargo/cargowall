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

// Tests for the causal step attribution layer (summary_attribution.go):
// ordinal->step resolution, causal grouping for render and SaaS push, and
// the attribution table. Mirrors the production split; generic summary
// pipeline tests live in summary_test.go.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/events"
)

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

	// Ordinal 1 resolved to "build" via the boundary timestamp, and the
	// heading carries the resolved step's time range like temporal
	// grouping's headings do.
	assert.Contains(t, out, `#### Step: "#1 - build" (10:00:00 - 10:00:10)`)
	assert.Contains(t, out, "| #1 | build | `bash -e /tmp/build.sh` |")
	// All three retries live under build — none leak into deploy's window
	// bucket — and dedup to one row while the counts show both numbers.
	assert.NotContains(t, out, `"deploy"`)
	assert.Contains(t, out, "| Connections blocked | 1 | 3 |")
	// Untagged dockerd traffic lands in the labeled docker bucket, not a
	// generic unattributed dump and not a step it raced into.
	assert.Contains(t, out, "Docker daemon")
	assert.NotContains(t, out, `#### Step: "`+bucketUnknown)
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
		// Untagged container-origin traffic; the dockerd process name proves
		// ContainerOrigin outranks the docker bucket in both presenters.
		{Timestamp: base.Add(7 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "8.8.8.8", DstPort: 443, Protocol: "TCP", Process: "dockerd", ContainerOrigin: true},
		// Untagged-outcome DNS block (issue #114): the render side only emits
		// buckets listed in bucketOrder, so this is the event that fails if
		// bucketHostServices ever goes missing there while the push side
		// keeps shipping it.
		{Timestamp: base.Add(8 * time.Second), EventType: events.EventDNSBlocked, DstIP: "9.9.9.9", DstHostname: "esm.example", Protocol: "UDP", Process: "https", StepAttrOutcome: events.StepAttrUntagged},
	}

	// destination(group label) per event IP, for each presenter. Render
	// labels resolved steps "#N - name"; normalize to the GitHub name so
	// the two are comparable.
	dest := func(groups []StepEvents, render bool) map[string]string {
		out := map[string]string{}
		for _, g := range groups {
			label := g.Step.Name
			if render {
				if _, after, found := strings.Cut(label, " - "); found {
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
	assert.Equal(t, bucketContainerUnattr, renderDest["8.8.8.8"])
	assert.Equal(t, bucketHostServices, renderDest["9.9.9.9"])
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

// A composite action runs several `run:` blocks — several worker forks,
// several boundaries — inside ONE reported step, so the mapping cannot be
// injective. Boundaries landing inside the previous match's window must map
// to that same step: consuming the next step instead would shift every
// later mapping by one, misnaming events in the summary and shipping them
// under the wrong step in the SaaS push. (A transient runtime fork
// mid-step is absorbed the same way rather than shifting anything.)
func TestSummary_ResolveOrdinalSteps_CompositeMultipleBoundariesPerStep(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "composite", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
		{Name: "deploy", Number: 2, StartedAt: base.Add(10 * time.Second)},
	}
	boundaries := []events.AuditEvent{
		{EventType: events.EventStepBoundary, StepOrdinal: 1, Timestamp: base.Add(100 * time.Millisecond)},
		// Later run: blocks of the composite, mid-window and OUTSIDE the
		// rounding-slack band of deploy's start. (A composite block that
		// forks inside that band is indistinguishable from deploy's own
		// rounding-early fork on timestamps alone and goes to deploy by
		// design — see the tie-breakers and #103.)
		{EventType: events.EventStepBoundary, StepOrdinal: 2, Timestamp: base.Add(3 * time.Second)},
		{EventType: events.EventStepBoundary, StepOrdinal: 3, Timestamp: base.Add(7 * time.Second)},
		// The genuinely next step.
		{EventType: events.EventStepBoundary, StepOrdinal: 4, Timestamp: base.Add(10*time.Second + 100*time.Millisecond)},
	}
	idx := resolveOrdinalSteps(boundaries, steps)
	assert.Equal(t, 0, idx[1])
	assert.Equal(t, 0, idx[2], "second boundary in the window maps to the same step")
	assert.Equal(t, 0, idx[3], "third boundary too")
	assert.Equal(t, 1, idx[4], "later mappings must not shift")
}

// Sequential steps ABUT: prev's recorded completed_at equals the next
// step's started_at — natively (GitHub reports whole seconds) and after
// backfill. A boundary a fraction before the next step's start is that
// step's own rounding-early fork; prev's inclusive window must NOT capture
// it, or every such boundary (the common Actions shape) shifts one step
// left. Inside the slack band, next wins by design.
func TestSummary_ResolveOrdinalSteps_RoundingRescueBeatsAbuttingWindow(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "build", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
		{Name: "deploy", Number: 2, StartedAt: base.Add(10 * time.Second), CompletedAt: base.Add(20 * time.Second)},
	}
	boundaries := []events.AuditEvent{
		{EventType: events.EventStepBoundary, StepOrdinal: 1, Timestamp: base.Add(time.Second)},
		// 200ms before deploy's recorded start — inside build's inclusive
		// window because the windows abut.
		{EventType: events.EventStepBoundary, StepOrdinal: 2, Timestamp: base.Add(10*time.Second - 200*time.Millisecond)},
	}
	idx := resolveOrdinalSteps(boundaries, steps)
	assert.Equal(t, 0, idx[1])
	assert.Equal(t, 1, idx[2], "rounding-early boundary belongs to deploy despite build's abutting window")
}

// Locks the Run-order contract end to end: ordinals resolve against the
// GitHub-REPORTED step times BEFORE backfillStepCompletion synthesizes
// completed_at values — a backfilled end (next step's start) would place
// every rounding-early boundary inside the previous step's window and
// shift its traffic one step left.
func TestSummary_Run_ResolvesAgainstReportedTimesNotBackfilled(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.Create(path)
	require.NoError(t, err)
	enc := json.NewEncoder(f)
	evts := []events.AuditEvent{
		{Timestamp: base.Add(time.Second), EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/build.sh"},
		// Deploy's fork, 200ms before its recorded start.
		{Timestamp: base.Add(10*time.Second - 200*time.Millisecond), EventType: events.EventStepBoundary, PID: 11, StepOrdinal: 2, Process: "bash -e /tmp/deploy.sh"},
		{Timestamp: base.Add(12 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "9.9.9.9", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 2, Blocked: true},
	}
	for _, ev := range evts {
		require.NoError(t, enc.Encode(ev))
	}
	require.NoError(t, f.Close())

	// completed_at deliberately null on both steps — the shape GitHub
	// reports mid-job, and exactly what the backfill synthesizes over.
	stepsJSON := `[{"name":"build","number":1,"started_at":"2025-01-01T10:00:00Z"},` +
		`{"name":"deploy","number":2,"started_at":"2025-01-01T10:00:10Z"}]`
	var buf bytes.Buffer
	cmdSum := &SummaryCmd{AuditLog: path, Steps: stepsJSON, output: &buf}
	require.NoError(t, cmdSum.Run())
	out := buf.String()

	assert.Contains(t, out, `#### Step: "#2 - deploy"`, "the early boundary resolves to deploy, not build")
	assert.Contains(t, out, "| #2 | deploy |", "attribution table agrees")
	assert.NotContains(t, out, `"#2 - build"`)
}

// Skipped steps (`if:`-guarded — GitHub reports zero timestamps) never ran
// and never fork; the rounding rescue must scan past them to the step that
// actually ran, not die on the first zero-StartedAt entry (which would
// absorb the next real step's boundary into the PREVIOUS step).
func TestSummary_ResolveOrdinalSteps_SlackRescueScansPastSkippedSteps(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "build", Number: 1, StartedAt: base, CompletedAt: base.Add(18 * time.Second)},
		{Name: "skipped", Number: 2}, // zero StartedAt/CompletedAt
		{Name: "deploy", Number: 3, StartedAt: base.Add(20 * time.Second)},
	}
	boundaries := []events.AuditEvent{
		{EventType: events.EventStepBoundary, StepOrdinal: 1, Timestamp: base.Add(time.Second)},
		// Deploy's own fork, 100ms before its recorded start — and within
		// end-side slack of build, which must NOT win.
		{EventType: events.EventStepBoundary, StepOrdinal: 2, Timestamp: base.Add(20*time.Second - 100*time.Millisecond)},
	}
	idx := resolveOrdinalSteps(boundaries, steps)
	assert.Equal(t, 0, idx[1])
	assert.Equal(t, 2, idx[2], "rescue skips the zero-StartedAt step and lands on deploy")
}

// A worker fork in the gap AFTER a step completed (and well before the next
// starts) belongs to no reported step; absorbing it into either neighbor
// would misattribute its subtree's traffic, so it stays unresolved and
// renders as its own "#N" group.
func TestSummary_ResolveOrdinalSteps_InterStepGapBoundaryStaysUnresolved(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "build", Number: 1, StartedAt: base, CompletedAt: base.Add(2 * time.Second)},
		{Name: "deploy", Number: 2, StartedAt: base.Add(10 * time.Second)},
	}
	boundaries := []events.AuditEvent{
		{EventType: events.EventStepBoundary, StepOrdinal: 1, Timestamp: base.Add(time.Second)},
		// 3s after build completed, 5s before deploy starts: outside both
		// windows and both slack margins.
		{EventType: events.EventStepBoundary, StepOrdinal: 2, Timestamp: base.Add(5 * time.Second)},
		{EventType: events.EventStepBoundary, StepOrdinal: 3, Timestamp: base.Add(10*time.Second + 100*time.Millisecond)},
	}
	idx := resolveOrdinalSteps(boundaries, steps)
	assert.Equal(t, 0, idx[1])
	_, resolved := idx[2]
	assert.False(t, resolved, "gap boundary maps to neither neighbor")
	assert.Equal(t, 1, idx[3], "later mappings must not shift")
}

// With the mapping deliberately non-injective, a composite's several
// ordinals must form ONE render group keyed by step index, so render and
// push dedup at the same scope and their unique counts cannot drift (the
// divergence found in review: markdown said 2, the SaaS summary said 1).
func TestSummary_CausalGroups_CompositeOrdinalsMergeAndDedupTogether(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	steps := []GitHubStep{
		{Name: "composite", Number: 1, StartedAt: base, CompletedAt: base.Add(10 * time.Second)},
	}
	ordinalSteps := map[uint32]int{1: 0, 2: 0}
	// Both of the composite's run: blocks hit the SAME blocked destination.
	evts := []events.AuditEvent{
		{Timestamp: base.Add(time.Second), EventType: events.EventConnectionBlocked, DstIP: "9.9.9.9", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 1},
		{Timestamp: base.Add(5 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "9.9.9.9", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 2},
	}

	render := causalGroups(evts, steps, ordinalSteps)
	require.Len(t, render, 1, "one group per resolved step, not per ordinal")
	assert.Equal(t, "#1,#2 - composite", render[0].Step.Name)
	assert.Len(t, render[0].Events, 1, "dedup collapses across the composite's ordinals")

	push := buildCausalPushGroups(evts, steps, ordinalSteps)
	require.Len(t, push, 1)
	assert.Len(t, push[0].Events, 1, "push dedups at the same scope: unique counts agree")
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

// --- Container attribution (issue #106) ---

// ContainerOrigin must be checked FIRST: container traffic without a step tag
// belongs in the container tier even when the process name or an auto-allow
// classification would otherwise claim it — falling through to a looser
// bucket would hide unattributable container traffic among daemon/infra rows.
func TestSummary_UntaggedBucketLabel(t *testing.T) {
	tests := []struct {
		name string
		ev   events.AuditEvent
		want string
	}{
		{
			// Precedence: ContainerOrigin beats EVERY later arm at once.
			name: "container origin outranks dockerd process, untagged outcome, and auto-allow",
			ev: events.AuditEvent{
				ContainerOrigin: true, Process: "dockerd",
				StepAttrOutcome: events.StepAttrUntagged, AutoAllowedType: "cloud_metadata",
			},
			want: bucketContainerUnattr,
		},
		{
			name: "dockerd without container origin stays daemon traffic",
			ev:   events.AuditEvent{Process: "dockerd"},
			want: bucketDocker,
		},
		{
			name: "auto-allowed platform endpoint",
			ev:   events.AuditEvent{Process: "python3", AutoAllowedType: "cloud_metadata"},
			want: bucketAutoInfra,
		},
		{
			// Issue #114: the sockdiag lookup found the socket and its owner
			// is outside the workflow — an identified host service, not an
			// unexplained event.
			name: "untagged-outcome DNS event is a host system service",
			ev: events.AuditEvent{
				EventType:       events.EventDNSBlocked,
				Process:         "https",
				StepAttrOutcome: events.StepAttrUntagged,
			},
			want: bucketHostServices,
		},
		{
			// Docker stays the more specific tier: dockerd's own sockets are
			// also untagged, and must not migrate into host-services.
			name: "dockerd with untagged outcome stays daemon traffic",
			ev: events.AuditEvent{
				EventType:       events.EventDNSBlocked,
				Process:         "dockerd",
				StepAttrOutcome: events.StepAttrUntagged,
			},
			want: bucketDocker,
		},
		{
			// Not a shape today's producers emit (AutoAllowedType rides
			// allowed connection events, the outcome rides dns_blocked), but
			// the arm order is intentional and pinned: an identified outside
			// OWNER outranks a destination classification.
			name: "untagged outcome outranks auto-allow",
			ev: events.AuditEvent{
				Process:         "https",
				StepAttrOutcome: events.StepAttrUntagged,
				AutoAllowedType: "cloud_metadata",
			},
			want: bucketHostServices,
		},
		{
			// Lookup limitations are not identified outsiders: everything
			// short of untagged stays honestly unexplained.
			name: "not_found outcome stays unexplained",
			ev: events.AuditEvent{
				EventType:       events.EventDNSBlocked,
				Process:         "curl",
				StepAttrOutcome: events.StepAttrNotFound,
			},
			want: bucketUnknown,
		},
		{
			name: "dump_error outcome stays unexplained",
			ev: events.AuditEvent{
				EventType:       events.EventDNSBlocked,
				Process:         "curl",
				StepAttrOutcome: events.StepAttrDumpError,
			},
			want: bucketUnknown,
		},
		{
			name: "plain untagged traffic is genuinely unexplained",
			ev:   events.AuditEvent{Process: "curl"},
			want: bucketUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, untaggedBucketLabel(tt.ev))
		})
	}
}

// End to end: an ordinal-0 container-origin block renders under the container
// bucket heading — not "Unattributed" and (despite the dockerd process name)
// not the Docker-daemon bucket.
func TestSummary_Run_ContainerOriginUntaggedLandsInContainerBucket(t *testing.T) {
	base := time.Now()
	out := runSummary(t, []events.AuditEvent{
		{Timestamp: base, EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/a.sh"},
		{Timestamp: base.Add(time.Second), EventType: events.EventConnectionBlocked, DstIP: "203.0.113.9", DstPort: 443, Protocol: "TCP", Process: "dockerd", Blocked: true, ContainerOrigin: true},
	})
	assert.Contains(t, out, `#### Step: "`+bucketContainerUnattr,
		"container-origin traffic gets its own tier")
	assert.Contains(t, out, "203.0.113.9")
	assert.NotContains(t, out, `#### Step: "`+bucketUnknown,
		"must not fall through to the generic unattributed bucket")
	assert.NotContains(t, out, `#### Step: "`+bucketDocker,
		"container origin outranks the dockerd process name end to end")
}

// End to end: an ordinal-0 DNS block whose sockdiag lookup identified an
// owner outside the workflow renders under the host-services heading — not
// the generic unattributed bucket (issue #114).
func TestSummary_Run_UntaggedOutcomeLandsInHostServicesBucket(t *testing.T) {
	base := time.Now()
	out := runSummary(t, []events.AuditEvent{
		{Timestamp: base, EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/a.sh"},
		{Timestamp: base.Add(time.Second), EventType: events.EventDNSBlocked, DstHostname: "esm.ubuntu.com", Process: "https", PID: 2398, StepAttrOutcome: events.StepAttrUntagged, Blocked: true},
	})
	assert.Contains(t, out, `#### Step: "`+bucketHostServices,
		"identified outside owners get their own tier")
	assert.Contains(t, out, "esm.ubuntu.com")
	assert.NotContains(t, out, `#### Step: "`+bucketUnknown,
		"must not fall through to the generic unattributed bucket")
}

// A container-origin event WITH a resolved ordinal is a fully attributed
// event: it lands in its step's group like any tagged traffic, and the
// container bucket never appears.
func TestSummary_Run_ContainerOriginWithOrdinalLandsInStepGroup(t *testing.T) {
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.Create(path)
	require.NoError(t, err)
	enc := json.NewEncoder(f)
	evts := []events.AuditEvent{
		{Timestamp: base.Add(1 * time.Second), EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/build.sh"},
		{Timestamp: base.Add(2 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "203.0.113.7", DstPort: 443, Protocol: "TCP", Process: "python3", StepOrdinal: 1, ContainerOrigin: true, ContainerID: "abc123456789", Blocked: true},
	}
	for _, ev := range evts {
		require.NoError(t, enc.Encode(ev))
	}
	require.NoError(t, f.Close())

	steps := `[{"name":"build","number":1,"started_at":"2025-01-01T10:00:00Z","completed_at":"2025-01-01T10:00:10Z"}]`
	var buf bytes.Buffer
	cmdSum := &SummaryCmd{AuditLog: path, Steps: steps, output: &buf}
	require.NoError(t, cmdSum.Run())
	out := buf.String()

	assert.Contains(t, out, `#### Step: "#1 - build"`, "step-tagged container traffic groups under its step")
	assert.Contains(t, out, "203.0.113.7")
	assert.NotContains(t, out, `#### Step: "`+bucketContainerUnattr,
		"a resolved ordinal keeps the event out of the container bucket")
}

// container_attribution events are telemetry markers, not connections: the
// summary must run fine with them in the log and render nothing from them —
// no destination-less row, no effect on the counts table.
func TestSummary_Run_ContainerAttributionEventsRenderNothing(t *testing.T) {
	base := time.Now()
	out := runSummary(t, []events.AuditEvent{
		{Timestamp: base, EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/a.sh"},
		{Timestamp: base.Add(time.Second), EventType: events.EventContainerAttribution, StepOrdinal: 1, ContainerID: "deadbeef4242", AttributionKind: "start", TagLatencyMS: 12.5},
		{Timestamp: base.Add(2 * time.Second), EventType: events.EventConnectionBlocked, DstIP: "198.51.100.4", DstPort: 443, Protocol: "TCP", Process: "curl", StepOrdinal: 1, Blocked: true},
	})
	assert.Contains(t, out, "198.51.100.4", "the real connection still renders")
	assert.NotContains(t, out, "deadbeef4242",
		"the attribution marker's container id must not surface as a table row")
	assert.NotContains(t, out, "container_attribution", "no raw event-type leakage")
	assert.Contains(t, out, "| Connections blocked | 1 | 1 |",
		"counts cover only real connection events")
}

// A log holding only boundaries and attribution markers has zero network
// activity; like the boundary-only case, it must take the concise "no events"
// path instead of rendering a summary of zeros.
func TestSummary_Run_AttributionOnlyLogPrintsNoEventsMessage(t *testing.T) {
	base := time.Now()
	out := runSummary(t, []events.AuditEvent{
		{Timestamp: base, EventType: events.EventStepBoundary, PID: 10, StepOrdinal: 1, Process: "bash -e /tmp/a.sh"},
		{Timestamp: base.Add(time.Second), EventType: events.EventContainerAttribution, StepOrdinal: 1, ContainerID: "deadbeef4242", AttributionKind: "start"},
	})
	assert.Contains(t, out, "No network events were logged during this workflow run.")
	assert.NotContains(t, out, "Events by Step")
}
