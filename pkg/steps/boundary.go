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

// Package steps provides causal per-workflow-step attribution of network
// traffic. Runner.Worker forks one direct child process per workflow step;
// the step_fork tracepoint (bpf/stepbpf.c) tags each such child with a
// monotonically increasing ordinal, every other fork inherits the forking
// thread's tag, and the cgroup hooks copy the tag onto each socket cookie —
// so every TC event carries the step that (transitively) created its socket.
// Attribution only: no verdict consults these maps.
//
// Pid numbering: the kernel side keys everything by global (init-namespace)
// ids; everything this package reads from /proc — the worker pid, the
// daemon's own pid, container leaders reported by dockerd — is numbered in
// the daemon's pid namespace, a different space whenever cargowall runs
// inside a container (ARC runners are Kubernetes pods). The step_task_iter
// BPF iterator bridges the two: it walks the daemon's namespace subtree,
// seeds the kernel's global→namespace table (map_task_nspid, which is what
// makes boundary events and socket pids resolvable) and streams the
// process tree in global ids, so seeding and container tagging never scan
// /proc. On a plain VM the translation is the identity.
package steps

import (
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/events"
)

// Step event kinds on map_step_events; every event starts with its kind
// (STEP_EV_* in bpf/stepbpf.c).
const (
	stepEvFork = 1
	stepEvExec = 2
	stepEvExit = 3
)

// forkedAtMax bounds the fork times kept for steps whose exec or exit
// event has not arrived: ordinals only grow, so an entry this far behind
// the newest one lost its event.
const forkedAtMax = 1024

// run consumes the step events and re-reports each step as an audit event
// with its command line attached, giving the summary pipeline a
// human-readable marker per step even before the action supplies plan
// names.
func (t *Tracker) run() {
	defer close(t.done)
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			t.logger.Error("Failed to read step event", "error", err)
			continue
		}
		t.handleStepEvent(record.RawSample, time.Now())
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
	switch binary.NativeEndian.Uint32(raw) {
	case stepEvFork:
		if len(raw) < int(unsafe.Sizeof(bpf.StepBpfStepChildEvent{})) {
			return
		}
		ev := (*bpf.StepBpfStepChildEvent)(unsafe.Pointer(&raw[0]))
		t.recordBoundary(ev.Ordinal, now)
		if t.forkedAt == nil {
			t.forkedAt = make(map[uint32]time.Time)
		}
		t.forkedAt[ev.Ordinal] = now
		if len(t.forkedAt) > forkedAtMax {
			for ord := range t.forkedAt {
				if ord+forkedAtMax < ev.Ordinal {
					delete(t.forkedAt, ord)
				}
			}
		}
	case stepEvExec, stepEvExit:
		if len(raw) < int(unsafe.Sizeof(bpf.StepBpfStepExecEvent{})) {
			return
		}
		ev := (*bpf.StepBpfStepExecEvent)(unsafe.Pointer(&raw[0]))
		cmdline := t.workerCmdline
		if ev.Kind == stepEvExec {
			n := min(int(ev.ArgvLen), len(ev.Argv))
			argv := unsafe.Slice((*byte)(unsafe.Pointer(&ev.Argv[0])), n)
			cmdline = formatCmdline(argv, int(ev.ArgvLen) > len(ev.Argv))
			if cmdline == "" {
				// The kernel could not read the arguments. The exec is
				// done, so /proc no longer races it.
				cmdline = readCmdline(int(ev.Tgid))
			}
		}
		at, ok := t.forkedAt[ev.Ordinal]
		if !ok {
			at = now
		}
		delete(t.forkedAt, ev.Ordinal)
		t.reportStep(ev.Ordinal, ev.Tgid, sanitizeCmdline(cmdline), at)
	}
}

// reportStep logs a step and writes its step_boundary event, stamped with
// the step's fork time. pid is numbered in our pid namespace (see
// map_task_nspid).
func (t *Tracker) reportStep(ordinal, pid uint32, cmdline string, forkedAt time.Time) {
	t.logger.Info("Workflow step process started",
		"step_ordinal", ordinal,
		"pid", pid,
		"cmdline", cmdline)
	if t.auditLogger == nil {
		return
	}
	if err := t.auditLogger.LogEvent(events.AuditEvent{
		Timestamp:   forkedAt,
		EventType:   events.EventStepBoundary,
		Process:     cmdline,
		PID:         pid,
		StepOrdinal: ordinal,
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
// audit JSONL, or the summary goes through this; the full string stays
// internal to the fork→exec retry comparison.
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
