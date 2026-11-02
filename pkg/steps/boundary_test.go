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

// forkEvent encodes a step event as step_fork streams it.
func forkEvent(tgid, ordinal uint32) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.NativeEndian, bpf.StepBpfStepChildEvent{Kind: stepEvFork, Tgid: tgid, Ordinal: ordinal})
	return buf.Bytes()
}

// execEvent encodes a step event as step_exec or step_exit streams it:
// argv is the bytes the kernel copied, argvLen the argument area's length.
func execEvent(kind, tgid, ordinal uint32, argv string, argvLen uint32) []byte {
	ev := bpf.StepBpfStepExecEvent{Kind: kind, Tgid: tgid, Ordinal: ordinal, ArgvLen: argvLen}
	for i := range min(len(argv), len(ev.Argv)) {
		ev.Argv[i] = int8(argv[i])
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
	tr.handleStepEvent(execEvent(stepEvExec, 42, 7, argv, uint32(len(argv))), forked.Add(30*time.Millisecond))
	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, events.EventStepBoundary, ev.EventType)
	assert.Equal(t, "/usr/bin/bash -e /home/runner/work/_temp/abc.sh", ev.Process)
	assert.Equal(t, uint32(42), ev.PID)
	assert.Equal(t, uint32(7), ev.StepOrdinal)
	assert.True(t, ev.Timestamp.Equal(forked), "the boundary keeps its fork time, got %v", ev.Timestamp)
	assert.Empty(t, tr.forkedAt)
}

// A root that exits without exec'ing ran a copy of Runner.Worker.
func TestHandleStepEvent_ExitWithoutExecReportsWorker(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	tr.handleStepEvent(forkEvent(43, 8), time.Unix(1000, 0))
	tr.handleStepEvent(execEvent(stepEvExit, 43, 8, "", 0), time.Unix(1001, 0))
	require.Len(t, sink.events, 1)
	assert.Equal(t, sanitizeCmdline(tr.workerCmdline), sink.events[0].Process)
	assert.True(t, sink.events[0].Timestamp.Equal(time.Unix(1000, 0)))
}

// An argument area longer than the kernel copies is marked cut; one the
// kernel could not read falls back to /proc, which the finished exec no
// longer races.
func TestHandleStepEvent_CutAndUnreadableArguments(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	long := strings.Repeat("a", cmdlineMax)
	tr.handleStepEvent(execEvent(stepEvExec, 44, 9, long, cmdlineMax+50), time.Unix(1000, 0))
	tr.handleStepEvent(execEvent(stepEvExec, uint32(os.Getpid()), 10, "", 0), time.Unix(1000, 0))
	require.Len(t, sink.events, 2)
	assert.Equal(t, long+"...", sink.events[0].Process)
	assert.Contains(t, sink.events[1].Process, ".test")
	assert.True(t, sink.events[0].Timestamp.Equal(time.Unix(1000, 0)), "with no fork seen, the event's own time")
}

func TestHandleStepEvent_IgnoresShortAndUnknownRecords(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	tr.handleStepEvent(nil, time.Now())
	tr.handleStepEvent([]byte{1, 0}, time.Now())
	tr.handleStepEvent(forkEvent(1, 1)[:8], time.Now())
	tr.handleStepEvent(execEvent(stepEvExec, 1, 1, "x", 1)[:20], time.Now())
	tr.handleStepEvent(execEvent(9, 1, 1, "x", 1), time.Now())
	assert.Empty(t, sink.events)
	assert.Empty(t, tr.forkedAt)
}

// Fork times whose exec or exit event never came are dropped once they
// fall forkedAtMax ordinals behind.
func TestHandleStepEvent_BoundsForkTimes(t *testing.T) {
	tr, _ := newBoundaryTracker(t)
	for ord := uint32(1); ord <= forkedAtMax+10; ord++ {
		tr.handleStepEvent(forkEvent(ord, ord), time.Unix(int64(ord), 0))
	}
	assert.LessOrEqual(t, len(tr.forkedAt), forkedAtMax+1)
	assert.NotContains(t, tr.forkedAt, uint32(1))
	assert.Contains(t, tr.forkedAt, uint32(forkedAtMax+10))
}

func TestFormatCmdline(t *testing.T) {
	assert.Equal(t, "a b", formatCmdline([]byte("a\x00b\x00"), false))
	assert.Equal(t, "a b...", formatCmdline([]byte("a\x00b"), true))
	assert.Empty(t, formatCmdline(nil, true), "nothing to mark")
	over := strings.Repeat("x", cmdlineMax+10)
	assert.Equal(t, over[:cmdlineMax]+"...", formatCmdline([]byte(over), false))
}
