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

// Causal step attribution for the summary: mapping step ordinals to GitHub
// steps, grouping events by the step that created their socket (for both the
// rendered summary and the SaaS push), and rendering the attribution table.
// Audit log I/O, the legacy temporal correlation, and the SaaS push live in
// summary.go; the rest of the markdown rendering lives in summary_render.go.
package cmd

import (
	"fmt"
	"sort"

	"github.com/code-cargo/cargowall/pkg/events"
)

// resolveOrdinalSteps maps each causal step ordinal to a step INDEX (not a
// name — GitHub step names repeat, e.g. several unnamed "Run" steps, so a
// name can't identify a group). Callers derive the display name from the
// index; grouping keys on the index so same-named steps stay distinct.
//
// A step_boundary event is emitted when the step process forks — the very
// start of the step's window — so "the last step started at or before the
// boundary timestamp" names the ordinal, without trusting window *ends*
// (which is exactly where timestamp bucketing of connection events goes
// wrong: long-lived sockets and post-job uploads land in whatever step is
// current when packets flow).
//
// The assignment is monotonic: boundaries and steps are both ordered, and
// two boundaries can never belong to the same step, so each boundary only
// considers steps after the previous match. This disambiguates steps that
// start within the same second — the GitHub API reports second-granularity
// timings, and back-to-back cheap steps otherwise tie.
func resolveOrdinalSteps(stepBoundaries []events.AuditEvent, steps []GitHubStep) map[uint32]int {
	boundaries := make([]events.AuditEvent, len(stepBoundaries))
	copy(boundaries, stepBoundaries)
	sort.Slice(boundaries, func(i, j int) bool {
		return boundaries[i].StepOrdinal < boundaries[j].StepOrdinal
	})

	idx := make(map[uint32]int)
	prev := -1
	for _, b := range boundaries {
		best := -1
		for i := prev + 1; i < len(steps); i++ {
			if steps[i].StartedAt.IsZero() || steps[i].StartedAt.After(b.Timestamp) {
				continue
			}
			// Strictly-later only: within a same-second tie group the
			// earliest unassigned step wins, and later boundaries walk
			// through the rest of the group via the monotonic cursor.
			if best == -1 || steps[i].StartedAt.After(steps[best].StartedAt) {
				best = i
			}
		}
		// Rounding can put a boundary a fraction before its own step's
		// recorded start; the next unassigned step is then the right one.
		if best == -1 && prev+1 < len(steps) {
			best = prev + 1
		}
		if best >= 0 {
			idx[b.StepOrdinal] = best
			prev = best
		}
	}
	return idx
}

// ordinalStepName is the display name for an ordinal, or "" when unresolved
// or the resolved step is unnamed.
func ordinalStepName(steps []GitHubStep, ordinalSteps map[uint32]int, ord uint32) string {
	if i, ok := ordinalSteps[ord]; ok && i < len(steps) {
		return steps[i].Name
	}
	return ""
}

// Bucket labels for traffic that doesn't resolve to a real GitHub step,
// shared by the rendered summary and the SaaS push so both group identically.
const (
	bucketRunner    = "CI infrastructure (Runner.Worker)"
	bucketPreDaemon = "Started before cargowall attached"
	bucketDocker    = "Docker-mediated (daemon-created sockets; per-step attribution requires container support)"
	bucketAutoInfra = "Auto-allowed platform endpoints (untagged)"
	bucketUnknown   = "Unattributed (no socket tag: pre-attach socket or unrecognized origin)"
)

// bucketOrder is the fixed display order for non-step buckets in the rendered
// summary (the push path preserves the GitHub timeline scaffold instead).
var bucketOrder = []string{bucketRunner, bucketPreDaemon, bucketDocker, bucketAutoInfra, bucketUnknown}

// causalClass is how a causally-tagged event maps to a group.
type causalClass int

const (
	causalStep     causalClass = iota // resolved to a real GitHub step
	causalOrdinal                     // tagged, but the ordinal didn't resolve to a step
	causalBucketed                    // runner / pre-daemon / untagged-by-cause
)

// classifyCausal is the single assignment rule behind BOTH the rendered
// summary and the SaaS push, so the two groupings can never drift. For
// causalBucketed it returns the canonical bucket label; the step/ordinal
// classes carry identity in the event's own ordinal and each presenter
// routes them (render groups by ordinal, push fills the step scaffold).
func classifyCausal(ev events.AuditEvent, ordinalSteps map[uint32]int) (causalClass, string) {
	switch ev.StepOrdinal {
	case events.StepOrdinalNone:
		return causalBucketed, untaggedBucketLabel(ev)
	case events.StepOrdinalRunner:
		return causalBucketed, bucketRunner
	case events.StepOrdinalPreDaemon:
		return causalBucketed, bucketPreDaemon
	default:
		if _, ok := ordinalSteps[ev.StepOrdinal]; ok {
			return causalStep, ""
		}
		return causalOrdinal, ""
	}
}

// untaggedBucketLabel classifies an ordinal-0 event by known cause:
// Docker-daemon sockets are a known attribution gap (container support
// lands in a later phase), auto-allowed platform endpoints are
// infrastructure noise regardless of tagging, and only the remainder is
// genuinely unexplained.
func untaggedBucketLabel(ev events.AuditEvent) string {
	switch {
	case dockerProcesses[ev.Process]:
		return bucketDocker
	case ev.AutoAllowedType != "":
		return bucketAutoInfra
	default:
		return bucketUnknown
	}
}

// dockerProcesses are daemon processes whose sockets carry container and
// image traffic on behalf of steps — attributable only once container
// support (docker event correlation) exists.
var dockerProcesses = map[string]bool{
	"dockerd":         true,
	"containerd":      true,
	"docker-proxy":    true,
	"containerd-shim": true,
}

// causalGroups builds the rendered "Events by Step" grouping from flat
// events: resolved and unresolved step ordinals first (ascending, labeled
// "#N — name" when the name resolved, "#N" otherwise), then the fixed-order
// buckets. Collapsed (empty groups dropped) and re-deduplicated. Takes flat
// events directly — the temporal correlation is legacy-only, never an
// intermediate for this path.
func causalGroups(regular []events.AuditEvent, steps []GitHubStep, ordinalSteps map[uint32]int) []StepEvents {
	byOrdinal := make(map[uint32][]events.AuditEvent)
	var ordinals []uint32
	byBucket := make(map[string][]events.AuditEvent)
	for _, ev := range regular {
		if class, bucket := classifyCausal(ev, ordinalSteps); class == causalBucketed {
			byBucket[bucket] = append(byBucket[bucket], ev)
			continue
		}
		if _, seen := byOrdinal[ev.StepOrdinal]; !seen {
			ordinals = append(ordinals, ev.StepOrdinal)
		}
		byOrdinal[ev.StepOrdinal] = append(byOrdinal[ev.StepOrdinal], ev)
	}
	sort.Slice(ordinals, func(i, j int) bool { return ordinals[i] < ordinals[j] })

	var groups []StepEvents
	for _, ord := range ordinals {
		label := fmt.Sprintf("#%d", ord)
		if name := ordinalStepName(steps, ordinalSteps, ord); name != "" {
			label = fmt.Sprintf("#%d — %s", ord, name)
		}
		groups = append(groups, StepEvents{Step: GitHubStep{Name: label}, Events: byOrdinal[ord]})
	}
	for _, b := range bucketOrder {
		if evs := byBucket[b]; len(evs) > 0 {
			groups = append(groups, StepEvents{Step: GitHubStep{Name: b}, Events: evs})
		}
	}
	deduplicateStepEvents(groups)
	return groups
}

// buildCausalPushGroups assembles the SaaS payload's step groups when
// attribution is available: the full GitHub step scaffold (timeline
// preserved, pre-attach steps included, empty steps kept), with each event
// assigned to the step its ordinal resolved to — never to the step whose
// time window it happened to land in. Events whose ordinal didn't resolve
// ship in the same labeled buckets the rendered summary uses. The wire
// schema is unchanged; only the assignment rule differs from the legacy
// temporal correlation.
func buildCausalPushGroups(regular []events.AuditEvent, steps []GitHubStep, ordinalSteps map[uint32]int) []StepEvents {
	groups := make([]StepEvents, len(steps))
	for i, s := range steps {
		groups[i] = StepEvents{Step: s}
	}

	extraIdx := map[string]int{}
	extra := func(label string) *StepEvents {
		if i, ok := extraIdx[label]; ok {
			return &groups[i]
		}
		groups = append(groups, StepEvents{Step: GitHubStep{Name: label}})
		extraIdx[label] = len(groups) - 1
		return &groups[len(groups)-1]
	}

	for _, ev := range regular {
		var g *StepEvents
		switch class, bucket := classifyCausal(ev, ordinalSteps); class {
		case causalStep:
			// Key on the resolved step INDEX, never the name: two steps can
			// share a name, and a name lookup would collapse them into one.
			g = &groups[ordinalSteps[ev.StepOrdinal]]
		case causalOrdinal:
			g = extra(fmt.Sprintf("#%d", ev.StepOrdinal))
		default: // causalBucketed
			g = extra(bucket)
		}
		g.Events = append(g.Events, ev)
	}

	deduplicateStepEvents(groups)
	return groups
}

// stepOrdinalLabel renders a causal step tag for the entries tables: a real
// ordinal as "#N" (resolvable against the Step Attribution section), the
// reserved sentinels as scope names, and 0 (untagged — pre-attribution
// socket or attribution off) as "-".
func stepOrdinalLabel(ordinal uint32) string {
	switch ordinal {
	case events.StepOrdinalNone:
		return "-"
	case events.StepOrdinalRunner:
		return "runner"
	case events.StepOrdinalPreDaemon:
		return "pre"
	default:
		return fmt.Sprintf("#%d", ordinal)
	}
}

// generateStepAttributionSection renders the causal step table: one row per
// step_boundary event, mapping each ordinal to the GitHub step it resolved
// to and the process the runner actually launched for it.
func (c *SummaryCmd) generateStepAttributionSection(stepBoundaries []events.AuditEvent, steps []GitHubStep, ordinalSteps map[uint32]int) {
	if len(stepBoundaries) == 0 {
		return
	}
	// Sort a copy: the caller's slice is shared with summaryData (and the
	// ordinal resolution), so rendering must not reorder it.
	boundaries := make([]events.AuditEvent, len(stepBoundaries))
	copy(boundaries, stepBoundaries)
	sort.Slice(boundaries, func(i, j int) bool {
		return boundaries[i].StepOrdinal < boundaries[j].StepOrdinal
	})
	fmt.Fprintln(c.output, "### Step Attribution")
	fmt.Fprintln(c.output)
	fmt.Fprintln(c.output, "Causal mapping of the `Step` column: the step process whose subtree created each connection's socket.")
	fmt.Fprintln(c.output)
	fmt.Fprintln(c.output, "| Step | GitHub step | Process |")
	fmt.Fprintln(c.output, "|------|-------------|---------|")
	for _, b := range boundaries {
		process := b.Process
		if process == "" {
			process = "-"
		}
		name := ordinalStepName(steps, ordinalSteps, b.StepOrdinal)
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(c.output, "| #%d | %s | `%s` |\n", b.StepOrdinal, mdCell(name), mdCode(process))
	}
	fmt.Fprintln(c.output)
}
