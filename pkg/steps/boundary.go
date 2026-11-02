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

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/events"
)

// boundary is one step's start: its fork as run() observed it, stamped
// with wall-clock receive time so external event streams that carry their
// own timestamps (Docker's timeNano) can be resolved against the step that
// was active when the event happened, not whichever step is active when a
// possibly backlogged stream gets processed. pid is the step root,
// numbered in our pid namespace; reported is whether its step_boundary
// event is written.
type boundary struct {
	ordinal  uint32
	at       time.Time
	pid      uint32
	reported bool
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

// OrdinalAt returns the ordinal of the latest step boundary observed at or
// before tm, or 0 when tm predates every observed boundary (callers treat 0
// as untagged, which degrades to the stricter attribution tier by design).
func (t *Tracker) OrdinalAt(tm time.Time) uint32 {
	t.boundaryMu.Lock()
	defer t.boundaryMu.Unlock()
	for i := len(t.boundaries) - 1; i >= 0; i-- {
		if !t.boundaries[i].at.After(tm) {
			return t.boundaries[i].ordinal
		}
	}
	return 0
}

// claimBoundary marks ordinal's boundary reported and returns it, recording
// one at now when its fork event never came (OrdinalAt then knows the step
// from its exec on). ok is false when it was already reported.
func (t *Tracker) claimBoundary(ordinal, pid uint32, now time.Time) (b boundary, ok bool) {
	t.boundaryMu.Lock()
	for i := len(t.boundaries) - 1; i >= 0; i-- {
		if t.boundaries[i].ordinal == ordinal {
			b, ok = t.boundaries[i], !t.boundaries[i].reported
			t.boundaries[i].reported = true
			t.boundaryMu.Unlock()
			return b, ok
		}
	}
	t.boundaryMu.Unlock()
	b = boundary{ordinal: ordinal, at: now, pid: pid, reported: true}
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
			t.handleStepEvent(record.RawSample, time.Now())
		}
	}
}

// reportLost reports the steps forked before cutoff whose exec or exit
// event never came, with what /proc shows for the root by now: a lost
// event's step must not vanish from the audit stream.
func (t *Tracker) reportLost(cutoff time.Time) {
	for _, b := range t.unreported(cutoff) {
		t.reportStep(b, sanitizeCmdline(readCmdline(int(b.pid))))
	}
}

// handleStepEvent handles one step event. A fork starts the step: the
// boundary is recorded at once, so OrdinalAt callers racing it resolve
// against it promptly, and its time is the boundary's. The root's first
// exec says what the step runs, and only then is the step reported. A root
// that exits without exec'ing ran a copy of Runner.Worker, whose command
// line it reports.
func (t *Tracker) handleStepEvent(raw []byte, now time.Time) {
	if len(raw) < 4 {
		return
	}
	switch bpf.StepBpfStepEventKind(binary.NativeEndian.Uint32(raw)) {
	case bpf.StepBpfStepEventKindSTEP_EV_FORK:
		if len(raw) < int(unsafe.Sizeof(bpf.StepBpfStepChildEvent{})) {
			return
		}
		ev := (*bpf.StepBpfStepChildEvent)(unsafe.Pointer(&raw[0]))
		t.recordBoundary(boundary{ordinal: ev.Ordinal, at: now, pid: ev.Tgid})
	case bpf.StepBpfStepEventKindSTEP_EV_EXEC, bpf.StepBpfStepEventKindSTEP_EV_EXIT:
		if len(raw) < int(unsafe.Sizeof(bpf.StepBpfStepExecEvent{})) {
			return
		}
		ev := (*bpf.StepBpfStepExecEvent)(unsafe.Pointer(&raw[0]))
		b, ok := t.claimBoundary(ev.Ordinal, ev.Tgid, now)
		if !ok {
			return // reported as lost already
		}
		cmdline := t.workerCmdline
		if bpf.StepBpfStepEventKind(ev.Kind) == bpf.StepBpfStepEventKindSTEP_EV_EXEC {
			n := min(int(ev.ArgvLen), len(ev.Argv))
			cmdline = formatCmdline(cBytes(ev.Argv[:n]), int(ev.ArgvLen) > len(ev.Argv))
			if cmdline == "" {
				// The kernel could not read the arguments: the program's
				// name, from the same exec. /proc could by now show
				// another exec, or another process on a reused pid.
				cmdline = strings.TrimRight(string(cBytes(ev.Comm[:])), "\x00")
			}
		}
		t.reportStep(b, sanitizeCmdline(cmdline))
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
func (t *Tracker) reportStep(b boundary, cmdline string) {
	t.logger.Info("Workflow step process started",
		"step_ordinal", b.ordinal,
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
