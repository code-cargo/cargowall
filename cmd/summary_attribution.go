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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/code-cargo/cargowall/pkg/events"
)

// resolveRoundingSlack is how far before a step's recorded start a boundary
// may fire and still be treated as that step's own rounding error rather
// than a mid-step transient fork. GitHub step timings are truncated to the
// second, so the genuine gap is under 1s; 2s leaves margin for clock skew.
const resolveRoundingSlack = 2 * time.Second

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
// The assignment is monotonic — boundaries and steps are both ordered, so
// each boundary first considers steps after the previous match, which
// disambiguates steps that start within the same second (the GitHub API
// reports second-granularity timings, and back-to-back cheap steps
// otherwise tie). It is NOT injective: a composite action runs several
// `run:` blocks — several worker forks, several boundaries — under one
// reported step, so a boundary landing inside the previous match's window
// maps to that same step rather than consuming the next one — except
// within resolveRoundingSlack of the next step's start, where the next
// step wins (see the tie-breakers in the body).
//
// Pass GitHub-REPORTED step times only: backfilled completed_at values
// (the next step's start) make every window abut its successor, which
// would hand the window tie-breaker synthetic evidence — Run resolves
// BEFORE backfillStepCompletion for exactly this reason.
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
		// The next step that actually ran, needed by the tie-breakers
		// below. Skipped steps (`if:`-guarded — zero StartedAt) never ran
		// and never fork, so scan past them.
		nextIdx := -1
		for j := prev + 1; j < len(steps); j++ {
			if !steps[j].StartedAt.IsZero() {
				nextIdx = j
				break
			}
		}
		nearNext := nextIdx >= 0 && steps[nextIdx].StartedAt.After(b.Timestamp) &&
			steps[nextIdx].StartedAt.Sub(b.Timestamp) <= resolveRoundingSlack

		// Unmatched boundary: ordered tie-breakers.
		//
		// 1. Rounding rescue: within slack of the next step's recorded
		//    start, the boundary is that step's own fork (GitHub truncates
		//    step times to the second). This wins even inside prev's
		//    recorded window: sequential steps ABUT — prev's end equals
		//    next's start, natively and after backfill — so the window
		//    rule would otherwise capture every rounding-early boundary
		//    and systematically shift attribution one step left. Inside
		//    this shared band timestamps cannot distinguish a composite's
		//    final block from the next step's early fork; next-wins is
		//    the deliberate choice until cmdline correlation (#103) can
		//    tell them apart.
		if best == -1 && nearNext {
			best = nextIdx
		}
		// 2. Inside prev's RECORDED window: another direct worker fork of
		//    the same reported step — composite actions run one fork per
		//    `run:` block (this also absorbs transient runtime forks,
		//    empirically real — see steps.Options.OrdinalBase — into
		//    whatever step was running rather than letting them shift the
		//    mapping).
		if best == -1 && prev >= 0 && !steps[prev].StartedAt.After(b.Timestamp) &&
			!steps[prev].CompletedAt.IsZero() && !b.Timestamp.After(steps[prev].CompletedAt) {
			best = prev
		}
		// 3. Just past prev's recorded end (or prev's end unknown):
		//    end-side rounding of the same step. Farther than slack is a
		//    fork in the inter-step gap that belongs to no step; it stays
		//    unresolved and renders as its bare "#N" group.
		if best == -1 && prev >= 0 && !steps[prev].StartedAt.After(b.Timestamp) {
			end := steps[prev].CompletedAt
			if end.IsZero() || b.Timestamp.Sub(end) <= resolveRoundingSlack {
				best = prev
			}
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
	bucketRunner          = "CI infrastructure (Runner.Worker)"
	bucketPreDaemon       = "Started before cargowall attached"
	bucketDocker          = "Docker daemon (host-side sockets: image pulls, port proxy)"
	bucketContainerUnattr = "Container traffic (unattributed: socket predates tagging or unknown container)"
	bucketAutoInfra       = "Auto-allowed platform endpoints (untagged)"
	bucketUnknown         = "Unattributed (no socket tag: pre-attach socket or unrecognized origin)"
)

// bucketOrder is the fixed display order for non-step buckets in the rendered
// summary (the push path preserves the GitHub timeline scaffold instead).
var bucketOrder = []string{bucketRunner, bucketPreDaemon, bucketDocker, bucketContainerUnattr, bucketAutoInfra, bucketUnknown}

// causalClass is how a causally-tagged event maps to a group.
type causalClass int

const (
	causalStep     causalClass = iota // resolved to a real GitHub step
	causalOrdinal                     // tagged, but the ordinal didn't resolve to a step
	causalBucketed                    // runner / pre-daemon / untagged-by-cause
)

// causalAssignment is where one event lands. Per class exactly one payload
// field is meaningful: step for causalStep, the event's own ordinal for
// causalOrdinal, bucket for causalBucketed.
type causalAssignment struct {
	class  causalClass
	step   int    // index into steps; valid iff class == causalStep
	bucket string // canonical bucket label; valid iff class == causalBucketed
}

// assignCausal is the single assignment rule behind BOTH the rendered
// summary and the SaaS push, so the two groupings can never drift: it
// decides everything (including the resolved step index), and the
// presenters only route and format the decision.
func assignCausal(ev events.AuditEvent, ordinalSteps map[uint32]int) causalAssignment {
	switch ev.StepOrdinal {
	case events.StepOrdinalNone:
		return causalAssignment{class: causalBucketed, bucket: untaggedBucketLabel(ev)}
	case events.StepOrdinalRunner:
		return causalAssignment{class: causalBucketed, bucket: bucketRunner}
	case events.StepOrdinalPreDaemon:
		return causalAssignment{class: causalBucketed, bucket: bucketPreDaemon}
	default:
		if i, ok := ordinalSteps[ev.StepOrdinal]; ok {
			return causalAssignment{class: causalStep, step: i}
		}
		return causalAssignment{class: causalOrdinal}
	}
}

// untaggedBucketLabel classifies an ordinal-0 event by known cause.
// Container origin is checked FIRST and unconditionally: traffic classified
// as container-originated but without a step tag must land in the container
// tier and may never fall through to a looser bucket — that ordering is the
// summary-side form of the "unattributable container traffic gets its own
// tier" requirement (issue #106). Then Docker-daemon host sockets, then
// auto-allowed platform endpoints, and only the remainder is genuinely
// unexplained.
func untaggedBucketLabel(ev events.AuditEvent) string {
	switch {
	case ev.ContainerOrigin:
		return bucketContainerUnattr
	case dockerProcesses[ev.Process]:
		return bucketDocker
	case ev.AutoAllowedType != "":
		return bucketAutoInfra
	default:
		return bucketUnknown
	}
}

// dockerProcesses are daemon processes whose own host-side sockets carry
// image and proxy traffic (docker pulls, docker-proxy port forwarding).
// Genuinely daemon-attributed — distinct from container workload traffic,
// which container attribution (issue #106) ties to steps or the container
// tier via ContainerOrigin above.
var dockerProcesses = map[string]bool{
	"dockerd":         true,
	"containerd":      true,
	"docker-proxy":    true,
	"containerd-shim": true,
}

// causalGroups builds the rendered "Events by Step" grouping from flat
// events: resolved ordinals grouped by their STEP INDEX — a composite's
// several ordinals form ONE group (labeled "#2,#3 - name"), so dedup runs
// at the same scope as the push and the two report identical unique counts
// — then unresolved ordinals as bare "#N" groups, all ordered by smallest
// ordinal, then the fixed-order buckets. Collapsed (empty groups dropped)
// and re-deduplicated. Takes flat events directly — the temporal
// correlation is legacy-only, never an intermediate for this path.
func causalGroups(regular []events.AuditEvent, steps []GitHubStep, ordinalSteps map[uint32]int) []StepEvents {
	byStep := make(map[int][]events.AuditEvent)
	stepOrds := make(map[int][]uint32)
	byOrdinal := make(map[uint32][]events.AuditEvent)
	byBucket := make(map[string][]events.AuditEvent)
	for _, ev := range regular {
		switch a := assignCausal(ev, ordinalSteps); a.class {
		case causalStep:
			byStep[a.step] = append(byStep[a.step], ev)
			if !slices.Contains(stepOrds[a.step], ev.StepOrdinal) {
				stepOrds[a.step] = append(stepOrds[a.step], ev.StepOrdinal)
			}
		case causalOrdinal:
			byOrdinal[ev.StepOrdinal] = append(byOrdinal[ev.StepOrdinal], ev)
		default: // causalBucketed
			byBucket[a.bucket] = append(byBucket[a.bucket], ev)
		}
	}

	// Chronological order for step and bare-ordinal groups alike: ordinals
	// are fork-ordered, so a group's smallest ordinal is its position.
	type keyedGroup struct {
		key uint32
		se  StepEvents
	}
	var ordered []keyedGroup
	for i, evs := range byStep {
		ords := stepOrds[i]
		slices.Sort(ords)
		labels := make([]string, len(ords))
		for k, o := range ords {
			labels[k] = fmt.Sprintf("#%d", o)
		}
		name := strings.Join(labels, ",")
		if steps[i].Name != "" {
			name += " - " + steps[i].Name
		}
		// Carry the resolved step's timestamps so the heading renders its
		// time range, exactly like the temporal grouping's headings.
		ordered = append(ordered, keyedGroup{key: ords[0], se: StepEvents{
			Step:   GitHubStep{Name: name, StartedAt: steps[i].StartedAt, CompletedAt: steps[i].CompletedAt},
			Events: evs,
		}})
	}
	for ord, evs := range byOrdinal {
		ordered = append(ordered, keyedGroup{key: ord, se: StepEvents{
			Step: GitHubStep{Name: fmt.Sprintf("#%d", ord)}, Events: evs,
		}})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].key < ordered[j].key })

	var groups []StepEvents
	for _, g := range ordered {
		groups = append(groups, g.se)
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

	// Indices, not pointers: extra() appends to groups, and a reallocation
	// would leave a previously taken *StepEvents pointing at the old array.
	extraIdx := map[string]int{}
	extra := func(label string) int {
		if i, ok := extraIdx[label]; ok {
			return i
		}
		groups = append(groups, StepEvents{Step: GitHubStep{Name: label}})
		extraIdx[label] = len(groups) - 1
		return len(groups) - 1
	}

	for _, ev := range regular {
		var gi int
		switch a := assignCausal(ev, ordinalSteps); a.class {
		case causalStep:
			// The assignment carries the step INDEX, never a name: two
			// steps can share a name, and a name lookup would collapse
			// them into one.
			gi = a.step
		case causalOrdinal:
			gi = extra(fmt.Sprintf("#%d", ev.StepOrdinal))
		default: // causalBucketed
			gi = extra(a.bucket)
		}
		groups[gi].Events = append(groups[gi].Events, ev)
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
