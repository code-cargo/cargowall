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
	evEnd  = uint32(bpf.StepBpfStepEventKindSTEP_EV_END)
)

// forkEvent encodes a step event as cw_step_fork streams it.
func forkEvent(tgid, ordinal uint32) []byte {
	return childEvent(evFork, tgid, ordinal)
}

// exitEvent encodes a step root's exit before any exec, as cw_step_exit
// streams it.
func exitEvent(tgid, ordinal uint32) []byte {
	return childEvent(evExit, tgid, ordinal)
}

// endEvent encodes a step root's exit after its exec, as cw_step_exit
// streams it.
func endEvent(tgid, ordinal uint32) []byte {
	return childEvent(evEnd, tgid, ordinal)
}

// forkEventAt is forkEvent with the kernel time of the fork.
func forkEventAt(tgid, ordinal uint32, ktime uint64) []byte {
	return childEventAt(evFork, tgid, ordinal, ktime)
}

func childEvent(kind, tgid, ordinal uint32) []byte {
	return childEventAt(kind, tgid, ordinal, 0)
}

func childEventAt(kind, tgid, ordinal uint32, ktime uint64) []byte {
	var buf bytes.Buffer
	ev := bpf.StepBpfStepChildEvent{Kind: kind, Tgid: tgid, Ordinal: ordinal, Ktime: ktime}
	_ = binary.Write(&buf, binary.NativeEndian, ev)
	return buf.Bytes()
}

// wallClock is a reading with no monotonic part: every event read at it,
// none carrying a kernel time, is dated at tm.
func wallClock(tm time.Time) clock {
	return clock{wall: tm}
}

// execEvent encodes a step event as cw_step_exec streams it: argv is the
// bytes the kernel copied, argvLen the argument area's length, comm the
// program's name. Its environment is unreadable.
func execEvent(kind, tgid, ordinal uint32, argv string, argvLen uint32, comm string) []byte {
	return execEventEnv(kind, tgid, ordinal, argv, argvLen, comm, "", 0)
}

// execEventEnv is execEvent with env, the environment bytes the kernel
// copied, and envLen the area's length.
func execEventEnv(kind, tgid, ordinal uint32, argv string, argvLen uint32, comm, env string, envLen uint32) []byte {
	ev := bpf.StepBpfStepExecEvent{Kind: kind, Tgid: tgid, Ordinal: ordinal, ArgvLen: argvLen, EnvLen: envLen}
	for i := range min(len(argv), len(ev.Argv)) {
		ev.Argv[i] = int8(argv[i])
	}
	for i := range min(len(comm), len(ev.Comm)-1) {
		ev.Comm[i] = int8(comm[i])
	}
	for i := range min(len(env), len(ev.Env)) {
		ev.Env[i] = int8(env[i])
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
	tr.handleStepEvent(forkEvent(42, 7), wallClock(forked))
	assert.Equal(t, uint32(7), tr.OrdinalAt(forked.Add(time.Millisecond)))
	assert.Empty(t, sink.events, "a fork alone has not said what the step runs")

	argv := "/usr/bin/bash\x00-e\x00/home/runner/work/_temp/abc.sh\x00"
	tr.handleStepEvent(execEvent(evExec, 42, 7, argv, uint32(len(argv)), "bash"), wallClock(forked.Add(30*time.Millisecond)))
	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, events.EventStepBoundary, ev.EventType)
	assert.Equal(t, "/usr/bin/bash -e /home/runner/work/_temp/abc.sh", ev.Process)
	assert.Equal(t, uint32(42), ev.PID)
	assert.Equal(t, uint32(7), ev.StepOrdinal)
	assert.True(t, ev.Timestamp.Equal(forked), "the boundary keeps its fork time, got %v", ev.Timestamp)
	assert.Empty(t, tr.unreported(forked.Add(time.Hour)))
}

// identities records what Options.OnIdentified is told, and how many
// boundary events were written by then.
type identities struct {
	sink *boundarySink
	got  []identified
}

type identified struct {
	ordinal  uint32
	id       Identity
	reported int
}

func (r *identities) record(ordinal uint32, id Identity) {
	r.got = append(r.got, identified{ordinal, id, len(r.sink.events)})
}

// A step root's exec names the step, from the environment the kernel read
// at that exec: the boundary event carries it, OnIdentified is told before
// the step's report is written, and the environment is wiped once read.
func TestHandleStepEvent_IdentifiesTheStep(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	ids := &identities{sink: sink}
	tr.onIdentified = ids.record

	env := "HOME=/home/runner\x00GITHUB_ACTION=build\x00SECRET=hunter2\x00"
	argv := "curl\x00--oauth2-bearer\x00s3cret\x00"
	raw := execEventEnv(evExec, 42, 7, argv, uint32(len(argv)), "curl", env, uint32(len(env)))
	tr.handleStepEvent(raw, wallClock(time.Unix(1000, 0)))

	require.Len(t, sink.events, 1)
	assert.Equal(t, "build", sink.events[0].StepID)
	assert.Equal(t, events.StepClassStep, sink.events[0].StepClass)
	assert.Equal(t, "curl --oauth2-bearer ...", sink.events[0].Process)
	assert.Equal(t, []identified{{7, Identity{StepID: "build", Class: events.StepClassStep}, 0}}, ids.got)
	assert.NotContains(t, string(raw), "hunter2")
	assert.NotContains(t, string(raw), "s3cret")
}

// The record holds the whole of the kernel's copy, and past the
// environment's length that is whatever an older record left in the ring:
// another step's name, say. Only the environment's own bytes count.
func TestHandleStepEvent_StaleBytesPastTheEnvironment(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	env := "HOME=/home/runner\x00"
	stale := env + "GITHUB_ACTION=older-step\x00"
	tr.handleStepEvent(execEventEnv(evExec, 42, 7, "node\x00", 5, "node", stale, uint32(len(env))), wallClock(time.Unix(1000, 0)))
	require.Len(t, sink.events, 1)
	assert.Equal(t, events.StepClassRunner, sink.events[0].StepClass)
	assert.Empty(t, sink.events[0].StepID)
}

// What each other outcome reports, and tells OnIdentified.
func TestHandleStepEvent_UnidentifiedSteps(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	ids := &identities{sink: sink}
	tr.onIdentified = ids.record

	helper := "HOME=/home/runner\x00PATH=/usr/bin\x00"
	tr.handleStepEvent(execEventEnv(evExec, 42, 7, "node\x00", 5, "node", helper, uint32(len(helper))), wallClock(time.Unix(1000, 0)))
	cut := "HOME=/home/runner\x00"
	tr.handleStepEvent(execEventEnv(evExec, 43, 8, "bash\x00", 5, "bash", cut, 64*1024), wallClock(time.Unix(1000, 0)))
	tr.handleStepEvent(execEvent(evExec, 44, 9, "bash\x00", 5, "bash"), wallClock(time.Unix(1000, 0)))

	require.Len(t, sink.events, 3)
	assert.Equal(t, events.StepClassRunner, sink.events[0].StepClass, "a runner helper")
	assert.Equal(t, events.StepClassUnknown, sink.events[1].StepClass, "cut before the name")
	assert.Equal(t, events.StepClassUnknown, sink.events[2].StepClass, "unreadable")
	for _, ev := range sink.events {
		assert.Empty(t, ev.StepID)
	}
	assert.Equal(t, []identified{
		{7, Identity{Class: events.StepClassRunner}, 0},
		{8, Identity{Class: events.StepClassUnknown}, 1},
		{9, Identity{Class: events.StepClassUnknown}, 2},
	}, ids.got)
}

// A root that exits without exec'ing ran a copy of Runner.Worker, and is
// no step: it is reported, but never identified.
func TestHandleStepEvent_ExitWithoutExecReportsWorker(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	ids := &identities{sink: sink}
	tr.onIdentified = ids.record
	tr.handleStepEvent(forkEvent(43, 8), wallClock(time.Unix(1000, 0)))
	tr.handleStepEvent(exitEvent(43, 8), wallClock(time.Unix(1001, 0)))
	require.Len(t, sink.events, 1)
	assert.Equal(t, sanitizeCmdline(tr.workerCmdline), sink.events[0].Process)
	assert.True(t, sink.events[0].Timestamp.Equal(time.Unix(1000, 0)))
	assert.Empty(t, sink.events[0].StepClass)
	assert.Empty(t, ids.got)
}

// An argument area longer than the kernel copies is marked cut; one the
// kernel could not read falls back to the program's name from the same
// exec, never to /proc, which may by now show another process.
func TestHandleStepEvent_CutAndUnreadableArguments(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	long := strings.Repeat("a", cmdlineMax)
	tr.handleStepEvent(execEvent(evExec, 44, 9, long, cmdlineMax+50, "a"), wallClock(time.Unix(1000, 0)))
	tr.handleStepEvent(execEvent(evExec, uint32(os.Getpid()), 10, "", 0, "node"), wallClock(time.Unix(1000, 0)))
	require.Len(t, sink.events, 2)
	assert.Equal(t, long+"...", sink.events[0].Process)
	assert.Equal(t, "node", sink.events[1].Process)
}

// An exec whose fork event never came still starts the step for OrdinalAt,
// from the exec's time.
func TestHandleStepEvent_ExecWithoutForkRecordsBoundary(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	at := time.Unix(1000, 0)
	tr.handleStepEvent(execEvent(evExec, 45, 11, "true\x00", 5, "true"), wallClock(at))
	require.Len(t, sink.events, 1)
	assert.True(t, sink.events[0].Timestamp.Equal(at))
	assert.Equal(t, uint32(11), tr.OrdinalAt(at))
}

// A step whose exec or exit event was lost is reported, once, from what
// /proc shows; its event, should it come after all, reports nothing more.
func TestReportLost_ReportsAStepWhoseEventNeverCame(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	forked := time.Unix(1000, 0)
	tr.handleStepEvent(forkEvent(uint32(os.Getpid()), 12), wallClock(forked))
	tr.reportLost(forked) // not yet overdue
	assert.Empty(t, sink.events)

	tr.reportLost(forked.Add(reportAfter + time.Millisecond))
	require.Len(t, sink.events, 1)
	assert.Contains(t, sink.events[0].Process, ".test")
	assert.True(t, sink.events[0].Timestamp.Equal(forked))
	assert.Equal(t, events.StepClassUnknown, sink.events[0].StepClass, "/proc can't identify a step")

	tr.handleStepEvent(execEvent(evExec, uint32(os.Getpid()), 12, "late\x00", 5, "late"), wallClock(forked.Add(time.Minute)))
	tr.reportLost(forked.Add(time.Hour))
	assert.Len(t, sink.events, 1)
}

// A step reported as lost is not identified then: /proc can't say which step
// it is. Its exec event, should it come after all, identifies it, once,
// without reporting the step again.
func TestReportLost_LateExecStillIdentifies(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	ids := &identities{sink: sink}
	tr.onIdentified = ids.record
	forked := time.Unix(1000, 0)
	tr.handleStepEvent(forkEvent(uint32(os.Getpid()), 12), wallClock(forked))
	tr.reportLost(forked.Add(reportAfter + time.Millisecond))
	require.Len(t, sink.events, 1)
	assert.Empty(t, ids.got)

	env := "GITHUB_ACTION=build\x00"
	tr.handleStepEvent(execEventEnv(evExec, uint32(os.Getpid()), 12, "late\x00", 5, "late", env, uint32(len(env))), wallClock(forked.Add(time.Minute)))
	assert.Equal(t, []identified{{12, Identity{StepID: "build", Class: events.StepClassStep}, 1}}, ids.got)
	assert.Len(t, sink.events, 1, "reported once")
}

func TestHandleStepEvent_IgnoresShortAndUnknownRecords(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	tr.handleStepEvent(nil, wallClock(time.Now()))
	tr.handleStepEvent([]byte{1, 0}, wallClock(time.Now()))
	tr.handleStepEvent(forkEvent(1, 1)[:8], wallClock(time.Now()))
	tr.handleStepEvent(endEvent(1, 1)[:8], wallClock(time.Now()))
	tr.handleStepEvent(endEvent(1, 1), wallClock(time.Now())) // a step not seen
	tr.handleStepEvent(execEvent(evExec, 1, 1, "x", 1, "x")[:20], wallClock(time.Now()))
	tr.handleStepEvent(execEvent(9, 1, 1, "x", 1, "x"), wallClock(time.Now()))
	assert.Empty(t, sink.events)
	assert.Empty(t, tr.boundaries)
}

// A kernel time dates an event before the reading by as much as the
// monotonic clock has run since, and never after the reading.
func TestClockAt(t *testing.T) {
	c := clock{wall: time.Unix(1000, 0), mono: 5 * uint64(time.Second)}
	assert.True(t, c.at(3*uint64(time.Second)).Equal(time.Unix(998, 0)))
	assert.True(t, c.at(5*uint64(time.Second)).Equal(c.wall), "read as it happened")
	assert.True(t, c.at(6*uint64(time.Second)).Equal(c.wall), "not after the reading")
	assert.True(t, c.at(0).Equal(c.wall), "no kernel time")
}

// A reader that falls behind dates each fork when it happened, not when it
// was read: a container started between two steps resolves to the step
// that was running then.
func TestHandleStepEvent_ForkDatedByKernelTime(t *testing.T) {
	tr, sink := newBoundaryTracker(t)
	sec := uint64(time.Second)
	late := clock{wall: time.Unix(1000, 0), mono: 10 * sec}
	tr.handleStepEvent(forkEventAt(41, 6, 4*sec), late)
	tr.handleStepEvent(forkEventAt(42, 7, 7*sec), late)
	assert.Zero(t, tr.OrdinalAt(time.Unix(993, 0)))
	assert.Equal(t, uint32(6), tr.OrdinalAt(time.Unix(995, 0)))
	assert.Equal(t, uint32(7), tr.OrdinalAt(time.Unix(998, 0)))

	env := "GITHUB_ACTION=build\x00"
	tr.handleStepEvent(execEventEnv(evExec, 42, 7, "bash\x00", 5, "bash", env, uint32(len(env))), late)
	require.Len(t, sink.events, 1)
	assert.True(t, sink.events[0].Timestamp.Equal(time.Unix(997, 0)), "reported at its fork, got %v", sink.events[0].Timestamp)

	// A root that exits without exec'ing, its fork event lost, is dated at
	// its exit.
	tr.handleStepEvent(childEventAt(evExit, 43, 8, 8*sec), late)
	require.Len(t, sink.events, 2)
	assert.True(t, sink.events[1].Timestamp.Equal(time.Unix(998, 0)))
}

// Stepping through a job's roots in order: a runner helper or a copy of
// Runner.Worker doesn't end the step it forks in, once it is known to be
// one. A root not identified yet, or whose identity the kernel couldn't
// read, still does. Forked once every step's root has exited, a runner
// helper is passed over no more.
func TestOrdinalAt_PassesOverRootsThatAreNoStep(t *testing.T) {
	tr, _ := newBoundaryTracker(t)
	step := "GITHUB_ACTION=build\x00"
	helper := "HOME=/home/runner\x00PATH=/usr/bin\x00"
	at := func(s int64) clock { return wallClock(time.Unix(s, 0)) }

	tr.handleStepEvent(forkEvent(41, 6), at(1000))
	tr.handleStepEvent(execEventEnv(evExec, 41, 6, "bash\x00", 5, "bash", step, uint32(len(step))), at(1000))

	tr.handleStepEvent(forkEvent(42, 7), at(1010))
	assert.Equal(t, uint32(7), tr.OrdinalAt(time.Unix(1015, 0)), "not identified yet")
	tr.handleStepEvent(execEventEnv(evExec, 42, 7, "node\x00", 5, "node", helper, uint32(len(helper))), at(1011))
	assert.Equal(t, uint32(6), tr.OrdinalAt(time.Unix(1015, 0)), "a runner helper")

	tr.handleStepEvent(forkEvent(43, 8), at(1020))
	tr.handleStepEvent(exitEvent(43, 8), at(1021))
	assert.Equal(t, uint32(6), tr.OrdinalAt(time.Unix(1025, 0)), "a copy of Runner.Worker")

	tr.handleStepEvent(forkEvent(44, 9), at(1030))
	tr.handleStepEvent(execEventEnv(evExec, 44, 9, "bash\x00", 5, "bash", "", 0), at(1030))
	assert.Equal(t, uint32(9), tr.OrdinalAt(time.Unix(1035, 0)), "unknown")

	// A root reported lost is unknown until its exec comes after all.
	tr.handleStepEvent(forkEvent(45, 10), at(1040))
	tr.reportLost(time.Unix(1050, 0))
	assert.Equal(t, uint32(10), tr.OrdinalAt(time.Unix(1045, 0)))
	tr.handleStepEvent(execEventEnv(evExec, 45, 10, "node\x00", 5, "node", helper, uint32(len(helper))), at(1051))
	assert.Equal(t, uint32(9), tr.OrdinalAt(time.Unix(1045, 0)))

	tr.handleStepEvent(endEvent(41, 6), at(1060))
	tr.handleStepEvent(forkEvent(46, 11), at(1065))
	tr.handleStepEvent(execEventEnv(evExec, 46, 11, "node\x00", 5, "node", helper, uint32(len(helper))), at(1065))
	assert.Equal(t, uint32(9), tr.OrdinalAt(time.Unix(1066, 0)), "the unknown root still runs")
	tr.handleStepEvent(endEvent(44, 9), at(1070))
	tr.handleStepEvent(forkEvent(47, 12), at(1075))
	tr.handleStepEvent(execEventEnv(evExec, 47, 12, "node\x00", 5, "node", helper, uint32(len(helper))), at(1075))
	assert.Equal(t, uint32(12), tr.OrdinalAt(time.Unix(1076, 0)), "no step runs")
	assert.Equal(t, uint32(9), tr.OrdinalAt(time.Unix(1067, 0)), "and the window before is as it was")
}

// How the runner's docker CLI processes resolve, all of them direct
// children of Runner.Worker. "Initialize containers" creates and starts
// the job and service containers with no step environment, before any
// step: they resolve to the runner's own docker call, bound no rules, and
// get the job's rules. A local action's image is built just before its
// step, with no step environment either, once the step before has ended:
// what the build starts gets the job's rules too, not the ended step's.
// The action's docker run carries its step's environment (GITHUB_ACTION
// among it), so the action's container resolves to that step, and a
// runner check made while it runs doesn't end it.
func TestOrdinalAt_ContainerActionsAndJobContainers(t *testing.T) {
	tr, _ := newBoundaryTracker(t)
	noStep := "PATH=/usr/bin\x00"
	docker := func(ordinal uint32, s int64, env string) {
		at := wallClock(time.Unix(s, 0))
		tr.handleStepEvent(forkEvent(100+ordinal, ordinal), at)
		tr.handleStepEvent(execEventEnv(evExec, 100+ordinal, ordinal, "docker\x00", 7, "docker", env, uint32(len(env))), at)
	}

	docker(1, 1000, noStep) // docker create, a service container
	docker(2, 1001, noStep) // docker start
	assert.Equal(t, uint32(2), tr.OrdinalAt(time.Unix(1001, 500)))

	run := "GITHUB_ACTION=__run\x00"
	tr.handleStepEvent(forkEvent(103, 3), wallClock(time.Unix(1010, 0)))
	tr.handleStepEvent(execEventEnv(evExec, 103, 3, "bash\x00", 5, "bash", run, uint32(len(run))), wallClock(time.Unix(1010, 0)))
	assert.Equal(t, uint32(3), tr.OrdinalAt(time.Unix(1012, 0)))
	tr.handleStepEvent(endEvent(103, 3), wallClock(time.Unix(1015, 0)))

	docker(4, 1020, noStep) // docker build, a local action's image
	assert.Equal(t, uint32(4), tr.OrdinalAt(time.Unix(1021, 0)))
	docker(5, 1030, "GITHUB_ACTION=lint\x00") // docker run
	assert.Equal(t, uint32(5), tr.OrdinalAt(time.Unix(1031, 0)))
	docker(6, 1035, noStep) // a runner check, docker exec
	assert.Equal(t, uint32(5), tr.OrdinalAt(time.Unix(1036, 0)))
}

// A step end the kernel had no room to report is warned of, once, naming
// the step it leaves running; a check within reportAfter of the last
// reads nothing.
func TestCheckEndsLost(t *testing.T) {
	var log bytes.Buffer
	tr := &Tracker{logger: slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelWarn}))}
	lost := uint64(0)
	tr.endsLost = func() (uint64, error) { return lost, nil }
	step := "GITHUB_ACTION=build\x00"
	tr.handleStepEvent(forkEvent(41, 6), wallClock(time.Unix(1000, 0)))
	tr.handleStepEvent(execEventEnv(evExec, 41, 6, "bash\x00", 5, "bash", step, uint32(len(step))), wallClock(time.Unix(1000, 0)))

	now := time.Unix(2000, 0)
	tr.checkEndsLost(now)
	assert.Empty(t, log.String())
	lost = 1
	tr.checkEndsLost(now.Add(time.Second))
	assert.Empty(t, log.String(), "not due yet")
	tr.checkEndsLost(now.Add(reportAfter))
	assert.Contains(t, log.String(), `level=WARN msg="Step end events lost`)
	assert.Contains(t, log.String(), "lost=1 step_ordinal=6")
	log.Reset()
	tr.checkEndsLost(now.Add(3 * reportAfter))
	assert.Empty(t, log.String(), "warned of once")
}

// The latest boundary is the latest by time, whatever order the events
// were read in.
func TestOrdinalAt_LatestByTimeNotReadOrder(t *testing.T) {
	tr := &Tracker{}
	tr.recordBoundary(boundary{ordinal: 8, at: time.Unix(1010, 0)})
	tr.recordBoundary(boundary{ordinal: 7, at: time.Unix(1005, 0)})
	assert.Equal(t, uint32(7), tr.OrdinalAt(time.Unix(1007, 0)))
	assert.Equal(t, uint32(8), tr.OrdinalAt(time.Unix(1012, 0)))
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
