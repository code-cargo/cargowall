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
	"bytes"
	"encoding/binary"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/events"
)

const (
	evFork = uint32(bpf.StepBpfStepEventKindSTEP_EV_FORK)
	evExec = uint32(bpf.StepBpfStepEventKindSTEP_EV_EXEC)
	evExit = uint32(bpf.StepBpfStepEventKindSTEP_EV_EXIT)
)

// forkEvent encodes a step event as cw_step_fork streams it.
func forkEvent(tgid, ordinal uint32) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.NativeEndian, bpf.StepBpfStepChildEvent{Kind: evFork, Tgid: tgid, Ordinal: ordinal})
	return buf.Bytes()
}

// execEvent encodes a step event as cw_step_exec or cw_step_exit streams it:
// argv is the bytes the kernel copied, argvLen the argument area's length,
// comm the program's name.
func execEvent(kind, tgid, ordinal uint32, argv string, argvLen uint32, comm string) []byte {
	ev := bpf.StepBpfStepExecEvent{Kind: kind, Tgid: tgid, Ordinal: ordinal, ArgvLen: argvLen}
	for i := range min(len(argv), len(ev.Argv)) {
		ev.Argv[i] = int8(argv[i])
	}
	for i := range min(len(comm), len(ev.Comm)-1) {
		ev.Comm[i] = int8(comm[i])
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.NativeEndian, ev)
	return buf.Bytes()
}

type boundarySink struct{ events []events.AuditEvent }

func (s *boundarySink) Consume(ev events.AuditEvent) { s.events = append(s.events, ev) }

func newBoundaryTracker(t *testing.T) (*Tracker, *boundarySink) {
	t.Helper()
	al, err := events.NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &boundarySink{}
	al.AddSink(sink)
	return &Tracker{
		workerCmdline: "/home/runner/bin/Runner.Worker spawnclient 118 121",
		auditLogger:   al,
		logger:        slog.New(slog.DiscardHandler),
	}, sink
}

// A step is reported once its root execs, with what the exec runs and the
// fork's time: the boundary is the step's start, and OrdinalAt resolves
// against it from the fork on.
func TestHandleStepEvent_ReportsAtExecWithForkTime(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	forked := time.Unix(1000, 0)
	tr.handleStepEvent(forkEvent(42, 7), forked)
	assert.Equal(t, uint32(7), tr.OrdinalAt(forked.Add(time.Millisecond)))
	assert.Empty(t, sink.events, "a fork alone has not said what the step runs")

	argv := "/usr/bin/bash\x00-e\x00/home/runner/work/_temp/abc.sh\x00"
	tr.handleStepEvent(execEvent(evExec, 42, 7, argv, uint32(len(argv)), "bash"), forked.Add(30*time.Millisecond))
	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, events.EventStepBoundary, ev.EventType)
	assert.Equal(t, "/usr/bin/bash -e /home/runner/work/_temp/abc.sh", ev.Process)
	assert.Equal(t, uint32(42), ev.PID)
	assert.Equal(t, uint32(7), ev.StepOrdinal)
	assert.True(t, ev.Timestamp.Equal(forked), "the boundary keeps its fork time, got %v", ev.Timestamp)
	assert.Empty(t, tr.unreported(forked.Add(time.Hour)))
}

// A root that exits without exec'ing ran a copy of Runner.Worker.
func TestHandleStepEvent_ExitWithoutExecReportsWorker(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	tr.handleStepEvent(forkEvent(43, 8), time.Unix(1000, 0))
	tr.handleStepEvent(execEvent(evExit, 43, 8, "", 0, ""), time.Unix(1001, 0))
	require.Len(t, sink.events, 1)
	assert.Equal(t, sanitizeCmdline(tr.workerCmdline), sink.events[0].Process)
	assert.True(t, sink.events[0].Timestamp.Equal(time.Unix(1000, 0)))
}

// An argument area longer than the kernel copies is marked cut; one the
// kernel could not read falls back to the program's name from the same
// exec, never to /proc, which may by now show another process.
func TestHandleStepEvent_CutAndUnreadableArguments(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	long := strings.Repeat("a", cmdlineMax)
	tr.handleStepEvent(execEvent(evExec, 44, 9, long, cmdlineMax+50, "a"), time.Unix(1000, 0))
	tr.handleStepEvent(execEvent(evExec, uint32(os.Getpid()), 10, "", 0, "node"), time.Unix(1000, 0))
	require.Len(t, sink.events, 2)
	assert.Equal(t, long+"...", sink.events[0].Process)
	assert.Equal(t, "node", sink.events[1].Process)
}

// An exec whose fork event never came still starts the step for OrdinalAt,
// from the exec's time.
func TestHandleStepEvent_ExecWithoutForkRecordsBoundary(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	at := time.Unix(1000, 0)
	tr.handleStepEvent(execEvent(evExec, 45, 11, "true\x00", 5, "true"), at)
	require.Len(t, sink.events, 1)
	assert.True(t, sink.events[0].Timestamp.Equal(at))
	assert.Equal(t, uint32(11), tr.OrdinalAt(at))
}

// A step whose exec or exit event was lost is reported, once, from what
// /proc shows; its event, should it come after all, reports nothing more.
func TestReportLost_ReportsAStepWhoseEventNeverCame(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	forked := time.Unix(1000, 0)
	tr.handleStepEvent(forkEvent(uint32(os.Getpid()), 12), forked)
	tr.reportLost(forked) // not yet overdue
	assert.Empty(t, sink.events)

	tr.reportLost(forked.Add(reportAfter + time.Millisecond))
	require.Len(t, sink.events, 1)
	assert.Contains(t, sink.events[0].Process, ".test")
	assert.True(t, sink.events[0].Timestamp.Equal(forked))

	tr.handleStepEvent(execEvent(evExec, uint32(os.Getpid()), 12, "late\x00", 5, "late"), forked.Add(time.Minute))
	tr.reportLost(forked.Add(time.Hour))
	assert.Len(t, sink.events, 1)
}

func TestHandleStepEvent_IgnoresShortAndUnknownRecords(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	tr.handleStepEvent(nil, time.Now())
	tr.handleStepEvent([]byte{1, 0}, time.Now())
	tr.handleStepEvent(forkEvent(1, 1)[:8], time.Now())
	tr.handleStepEvent(execEvent(evExec, 1, 1, "x", 1, "x")[:20], time.Now())
	tr.handleStepEvent(execEvent(9, 1, 1, "x", 1, "x"), time.Now())
	assert.Empty(t, sink.events)
	assert.Empty(t, tr.boundaries)
}

func TestFormatCmdline(t *testing.T) {
	assert.Equal(t, "a b", formatCmdline([]byte("a\x00b\x00"), false))
	assert.Equal(t, "a b...", formatCmdline([]byte("a\x00b"), true))
	assert.Empty(t, formatCmdline(nil, true), "nothing to mark")
	over := strings.Repeat("x", cmdlineMax+10)
	assert.Equal(t, over[:cmdlineMax]+"...", formatCmdline([]byte(over), false))
	// A cut the kernel made inside a multi-byte character drops its start.
	assert.Equal(t, "/tmp/é...", formatCmdline([]byte("/tmp/é\xe2\x82"), true))
	assert.Equal(t, "/tmp/é€...", formatCmdline([]byte("/tmp/é€"), true))
}
