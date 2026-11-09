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

package steps

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/events"
)

// boundary is one step's start: its fork, stamped with the wall-clock
// time the kernel saw it happen, so external event streams that carry
// their own timestamps (Docker's timeNano) can be resolved against the
// step that was active when the event happened, not whichever step is
// active when a possibly backlogged stream gets processed. pid is the step
// root, numbered in our pid namespace; reported is whether its
// step_boundary event is written. notStep is set once the root is known to
// be no step: a runner helper (events.StepClassRunner), or a copy of
// Runner.Worker that exited without exec'ing. end is when the root exited
// after exec'ing, zero while it runs (or its exit event was lost).
type boundary struct {
	ordinal  uint32
	at       time.Time
	end      time.Time
	pid      uint32
	reported bool
	notStep  bool
}

// clock is a reading of the wall clock and of CLOCK_MONOTONIC, the clock
// bpf_ktime_get_ns reads, taken together, to date kernel events by.
type clock struct {
	wall time.Time
	mono uint64 // ns
}

func readClock() clock {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return clock{wall: time.Now(), mono: uint64(ts.Nano())}
}

// at dates a kernel event at ktime by the wall clock, never after the
// reading: an event can't happen after it is read, so a ktime of 0 or past
// the reading dates it at the reading.
func (c clock) at(ktime uint64) time.Time {
	if ktime == 0 || ktime >= c.mono {
		return c.wall
	}
	return c.wall.Add(-time.Duration(c.mono - ktime))
}

// boundaryHistory bounds the ring; ordinals are monotonic so old entries
// only matter for as long as an external event could plausibly be delayed.
const boundaryHistory = 256

// reportAfter is how long a step waits for the exec or exit event that
// reports it. One that has not come by then was lost (a full ring buffer,
// a full map_step_exec_pending), and the step is reported from /proc.
const reportAfter = 2 * time.Second

// recordBoundary appends one observed boundary, trimming the ring to
// boundaryHistory (append reallocation keeps the retained backing bounded).
func (t *Tracker) recordBoundary(b boundary) {
	t.boundaryMu.Lock()
	defer t.boundaryMu.Unlock()
	t.boundaries = append(t.boundaries, b)
	if len(t.boundaries) > boundaryHistory {
		t.boundaries = t.boundaries[1:]
	}
}

// OrdinalAt returns the ordinal of the latest step boundary at or before
// tm, or 0 when tm predates every observed boundary (callers treat 0 as
// untagged, which degrades to the stricter attribution tier by design).
//
// A root known to be no step, forked while a step's root runs, is passed
// over: a runner helper Runner.Worker forks during a step doesn't end that
// step. One forked between steps, after the last step's root exited, is
// not: what it starts gets no step's rules, not the ended step's. A root
// not identified yet, or never (events.StepClassUnknown), counts as a
// step. Its ordinal is bound no step's rules until it is identified as
// that step, so resolving to it is never wider than resolving to the step
// before it. A lost exit event leaves a root running as far as this
// knows, so a no-step root after it is passed over.
//
// Boundaries are in the order their events were read, which their kernel
// times need not follow (a fork recorded from its exec, its fork event
// lost), so the latest is looked for among all of them.
func (t *Tracker) OrdinalAt(tm time.Time) uint32 {
	t.boundaryMu.Lock()
	defer t.boundaryMu.Unlock()
	var latest *boundary
	for i := range t.boundaries {
		b := &t.boundaries[i]
		if b.at.After(tm) || (latest != nil && b.at.Before(latest.at)) {
			continue
		}
		if b.notStep && t.stepRunning(b.at) {
			continue
		}
		latest = b
	}
	if latest == nil {
		return 0
	}
	return latest.ordinal
}

// stepRunning reports whether the root of a boundary that may be a step
// had started at tm and not yet exited, with boundaryMu held.
func (t *Tracker) stepRunning(tm time.Time) bool {
	for _, b := range t.boundaries {
		if !b.notStep && !b.at.After(tm) && (b.end.IsZero() || b.end.After(tm)) {
			return true
		}
	}
	return false
}

// ended records when ordinal's root exited, for OrdinalAt.
func (t *Tracker) ended(ordinal uint32, at time.Time) {
	t.boundaryMu.Lock()
	defer t.boundaryMu.Unlock()
	for i := len(t.boundaries) - 1; i >= 0; i-- {
		if t.boundaries[i].ordinal == ordinal {
			t.boundaries[i].end = at
			return
		}
	}
}

// claimBoundary marks ordinal's boundary reported and returns it, recording
// one at the given time when its fork event never came (OrdinalAt then
// knows the step from then on). notStep is what the event says of the root.
// ok is false when it was already reported.
func (t *Tracker) claimBoundary(ordinal, pid uint32, at time.Time, notStep bool) (b boundary, ok bool) {
	t.boundaryMu.Lock()
	for i := len(t.boundaries) - 1; i >= 0; i-- {
		if t.boundaries[i].ordinal == ordinal {
			b, ok = t.boundaries[i], !t.boundaries[i].reported
			t.boundaries[i].reported = true
			t.boundaries[i].notStep = notStep
			t.boundaryMu.Unlock()
			return b, ok
		}
	}
	t.boundaryMu.Unlock()
	b = boundary{ordinal: ordinal, at: at, pid: pid, reported: true, notStep: notStep}
	t.recordBoundary(b)
	return b, true
}

// unreported claims the boundaries not yet reported that forked before
// cutoff.
func (t *Tracker) unreported(cutoff time.Time) []boundary {
	t.boundaryMu.Lock()
	defer t.boundaryMu.Unlock()
	var out []boundary
	for i := range t.boundaries {
		if b := &t.boundaries[i]; !b.reported && b.at.Before(cutoff) {
			b.reported = true
			out = append(out, *b)
		}
	}
	return out
}

// run consumes the step events and re-reports each step as an audit event
// with its command line attached, giving the summary pipeline a
// human-readable marker per step even before the action supplies plan
// names. It wakes every reportAfter while a step waits, to report one
// whose event was lost, and reports what is left when the reader closes.
func (t *Tracker) run() {
	defer close(t.done)
	for {
		t.reader.SetDeadline(time.Now().Add(reportAfter))
		record, err := t.reader.Read()
		switch {
		case errors.Is(err, ringbuf.ErrClosed):
			t.reportLost(time.Now().Add(time.Hour))
			return
		case errors.Is(err, os.ErrDeadlineExceeded):
			t.reportLost(time.Now().Add(-reportAfter))
		case err != nil:
			t.logger.Error("Failed to read step event", "error", err)
		default:
			t.handleStepEvent(record.RawSample, readClock())
		}
	}
}

// reportLost reports the steps forked before cutoff whose exec or exit
// event never came, with what /proc shows for the root by now: a lost
// event's step must not vanish from the audit stream. It is reported
// unidentified, and not identified at all: /proc shows the root's
// environment as the step may since have rewritten it. Should the exec
// event come after all, it identifies the step then.
func (t *Tracker) reportLost(cutoff time.Time) {
	for _, b := range t.unreported(cutoff) {
		t.reportStep(b, sanitizeCmdline(readCmdline(int(b.pid))), Identity{Class: events.StepClassUnknown})
	}
}

// handleStepEvent handles one step event, read at now. A fork starts the
// step: the boundary is recorded at once, so OrdinalAt callers racing it
// resolve against it promptly, and the fork's time is the boundary's. The
// root's first exec says what the step runs and which step it is, and only
// then is the step reported, and its exit after is the step's end. A root
// that exits without exec'ing ran a copy of Runner.Worker, whose command
// line it reports, and is no step.
func (t *Tracker) handleStepEvent(raw []byte, now clock) {
	if len(raw) < 4 {
		return
	}
	switch bpf.StepBpfStepEventKind(binary.NativeEndian.Uint32(raw)) {
	case bpf.StepBpfStepEventKindSTEP_EV_FORK:
		if len(raw) < int(unsafe.Sizeof(bpf.StepBpfStepChildEvent{})) {
			return
		}
		ev := (*bpf.StepBpfStepChildEvent)(unsafe.Pointer(&raw[0]))
		t.recordBoundary(boundary{ordinal: ev.Ordinal, at: now.at(ev.Ktime), pid: ev.Tgid})
	case bpf.StepBpfStepEventKindSTEP_EV_EXIT:
		if len(raw) < int(unsafe.Sizeof(bpf.StepBpfStepChildEvent{})) {
			return
		}
		ev := (*bpf.StepBpfStepChildEvent)(unsafe.Pointer(&raw[0]))
		if b, ok := t.claimBoundary(ev.Ordinal, ev.Tgid, now.at(ev.Ktime), true); ok {
			t.reportStep(b, sanitizeCmdline(t.workerCmdline), Identity{})
		}
	case bpf.StepBpfStepEventKindSTEP_EV_END:
		if len(raw) < int(unsafe.Sizeof(bpf.StepBpfStepChildEvent{})) {
			return
		}
		ev := (*bpf.StepBpfStepChildEvent)(unsafe.Pointer(&raw[0]))
		t.ended(ev.Ordinal, now.at(ev.Ktime))
	case bpf.StepBpfStepEventKindSTEP_EV_EXEC:
		if len(raw) < int(unsafe.Sizeof(bpf.StepBpfStepExecEvent{})) {
			return
		}
		// The record carries the step's environment and arguments, its
		// secrets among them. Nothing taken from it below shares its
		// memory, so it is wiped once read rather than left in the heap.
		defer clear(raw)
		ev := (*bpf.StepBpfStepExecEvent)(unsafe.Pointer(&raw[0]))
		id := identify(cBytes(ev.Env[:]), int(ev.EnvLen))
		b, ok := t.claimBoundary(ev.Ordinal, ev.Tgid, now.wall, id.Class == events.StepClassRunner)
		t.identified(ev.Ordinal, id)
		if !ok {
			// Reported as lost already, unidentified: the kernel's copy
			// came late, and still names the step.
			t.logger.Info("Workflow step identified after it was reported",
				"step_ordinal", ev.Ordinal,
				"step_id", id.StepID,
				"step_class", id.Class)
			return
		}
		n := min(int(ev.ArgvLen), len(ev.Argv))
		cmdline := formatCmdline(cBytes(ev.Argv[:n]), int(ev.ArgvLen) > len(ev.Argv))
		if cmdline == "" {
			// The kernel could not read the arguments: the program's
			// name, from the same exec. /proc could by now show
			// another exec, or another process on a reused pid.
			cmdline = strings.TrimRight(string(cBytes(ev.Comm[:])), "\x00")
		}
		t.reportStep(b, sanitizeCmdline(cmdline), id)
	}
}

// identified hands a step's identity to Options.OnIdentified, ahead of the
// step's report: a policy bound on it applies the sooner.
func (t *Tracker) identified(ordinal uint32, id Identity) {
	if t.onIdentified != nil {
		t.onIdentified(ordinal, id)
	}
}

// cBytes views a bpf2go char array as bytes.
func cBytes(a []int8) []byte {
	if len(a) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&a[0])), len(a))
}

// reportStep logs a step and writes its step_boundary event, stamped with
// the step's fork time. The pid is numbered in our pid namespace (see
// map_task_nspid).
func (t *Tracker) reportStep(b boundary, cmdline string, id Identity) {
	t.logger.Info("Workflow step process started",
		"step_ordinal", b.ordinal,
		"step_id", id.StepID,
		"step_class", id.Class,
		"pid", b.pid,
		"cmdline", cmdline)
	if t.auditLogger == nil {
		return
	}
	if err := t.auditLogger.LogEvent(events.AuditEvent{
		Timestamp:   b.at,
		EventType:   events.EventStepBoundary,
		Process:     cmdline,
		PID:         b.pid,
		StepOrdinal: b.ordinal,
		StepID:      id.StepID,
		StepClass:   id.Class,
	}); err != nil {
		t.logger.Error("Failed to write audit log", "error", err)
	}
}

// sanitizeCmdline reduces an emitted command line to its first two argv
// tokens plus any runner-generated script or action paths from later
// positions. Boundary events describe Runner.Worker's direct children: the
// step's own script path — the correlation token plan matching needs —
// lives under the runner's _temp (run: steps, composite blocks) or
// _actions (JS actions) directories, and sits at argv[2+] whenever shell
// flags are in play (`bash --noprofile --norc -e -o pipefail x.sh` is the
// standard run-step shape). Every other later token is where flags and
// values (and therefore secrets passed on a command line, e.g. docker
// args) could appear, and is dropped. Everything written to logs, the
// audit JSONL, or the summary goes through this.
func sanitizeCmdline(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) <= 2 {
		return cmdline
	}
	kept := append([]string(nil), fields[:2]...)
	dropped := false
	for _, f := range fields[2:] {
		if isRunnerPath(f) {
			kept = append(kept, f)
		} else {
			dropped = true
		}
	}
	out := strings.Join(kept, " ")
	if dropped {
		out += " ..."
	}
	return out
}

// isRunnerPath reports whether an argv token is a bare absolute path into
// the runner's _temp/_actions trees — the shape of the script and action
// paths the runner itself passes. Anchored, not a substring test: a
// user-controlled value merely EMBEDDING those substrings (a URL with a
// query string, a --flag=value, a volume spec) must not ride through the
// redaction, so anything that isn't a plain absolute path ('=' from
// flag-or-env values, ':' from URLs and mount specs) is rejected.
func isRunnerPath(tok string) bool {
	if !strings.HasPrefix(tok, "/") || strings.ContainsAny(tok, "=:") {
		return false
	}
	return strings.Contains(tok, "/_temp/") || strings.Contains(tok, "/_actions/")
}
