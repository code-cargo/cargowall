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

package containers

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/events"
)

// waitLog waits for a line in the tracker's log. Handlers count before they
// log, so once the line is there its counters are final.
func (f *fixture) waitLog(t *testing.T, substr string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(f.logs.String(), substr) }, waitFor, tick,
		"log line %q", substr)
}

// addMismatchedContainer wires a container whose init pid sits in another
// container's cgroup: its start fails the identity check, so this /proc is
// never proven to see the daemon's pids.
func (f *fixture) addMismatchedContainer(t *testing.T, id string, pid int, ip string) {
	t.Helper()
	writeProcEntry(t, f.procRoot, pid, cgroupV2Line(strings.Repeat("0", 64))+"\n", "app")
	mkScopeDir(t, f.cgroupRoot, id)
	f.daemon.setContainer(makeInspect(id, pid, ip, false))
}

func TestExecStartRetagsEffectiveOrdinal(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("e", 64)
	f.addContainer(t, id, 4242, "172.17.0.4", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	execID := strings.Repeat("f", 64)
	writeProcEntry(t, f.procRoot, 4343, cgroupV2Line(id)+"\n", "sh")
	f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4343, ContainerID: id})
	// The exec belongs to the step active at exec time, never the
	// container's birth step.
	f.tagger.setOrdinal(9)
	f.daemon.push(execStartEvent(id, execID, time.Now().UnixNano()))

	ev := f.waitAttribution(t, "exec", id)
	assert.Equal(t, uint32(9), ev.StepOrdinal)
	assert.Equal(t, uint32(4343), ev.PID)
	assert.Contains(t, f.tagger.tagCalls(), tagCall{pid: 4343, ordinal: 9})

	// DNS attribution follows the newest exec: effectiveOrdinal moved on.
	ord, _, ok := f.tracker.LookupClient(&net.UDPAddr{IP: net.ParseIP("172.17.0.4"), Port: 1})
	require.True(t, ok)
	assert.Equal(t, uint32(9), ord)
}

// Pins the fix for the CI failure on PR #109: dockerd emits exec_start
// BEFORE it records the exec pid from containerd, so the first inspect(s)
// read Pid 0 for a live exec. The tracker must retry through that window
// instead of dropping attribution.
func TestExecStartRetriesUntilDockerdPublishesPid(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("9", 64)
	f.addContainer(t, id, 4242, "172.17.0.30", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	execID := strings.Repeat("d", 64)
	writeProcEntry(t, f.procRoot, 4646, cgroupV2Line(id)+"\n", "sh")
	f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4646, ContainerID: id})
	f.daemon.setExecPidDelay(execID, 2)
	f.tagger.setOrdinal(9)
	f.daemon.push(execStartEvent(id, execID, time.Now().UnixNano()))

	ev := f.waitAttribution(t, "exec", id)
	assert.Equal(t, uint32(9), ev.StepOrdinal)
	assert.Equal(t, uint32(4646), ev.PID)
	// Two Pid-0 inspects at 50ms apart put the measured latency at or above
	// the retry interval — the honest cost of the publish race.
	assert.GreaterOrEqual(t, ev.TagLatencyMS, 50.0)
	assert.Contains(t, f.tagger.tagCalls(), tagCall{pid: 4646, ordinal: 9})
}

func TestExecStartWithoutExecIDFallsBackToDiff(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("1", 64)
	f.addContainer(t, id, 4242, "172.17.0.5", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	// Daemons that omit Actor.Attributes["execID"] force the fallback:
	// diff the container's live ExecIDs against what was already handled.
	execID := strings.Repeat("2", 64)
	writeProcEntry(t, f.procRoot, 4444, cgroupV2Line(id)+"\n", "sh")
	f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4444, ContainerID: id})
	f.daemon.updateContainer(id, func(c *containerInspect) { c.ExecIDs = []string{execID} })
	f.tagger.setOrdinal(11)
	f.daemon.push(execStartEvent(id, "", time.Now().UnixNano()))

	ev := f.waitAttribution(t, "exec", id)
	assert.Equal(t, uint32(4444), ev.PID)
	assert.Contains(t, f.tagger.tagCalls(), tagCall{pid: 4444, ordinal: 11})
}

// `docker run --rm alpine true`: the container's init is reaped before its
// pid is checked, while dockerd, not yet told of the exit, still reports it
// running for a while. Asked again, it reports it stopped. That is nothing to tag, not
// a failed identity check, and must not reach the job as a warning.
func TestStartExitedBeforeCheckIsNotAWarning(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("6", 64)
	mkScopeDir(t, f.cgroupRoot, id)
	f.daemon.setContainer(makeInspect(id, 4242, "172.17.0.31", false))
	f.daemon.setRunningFor(id, 3) // the start's inspect, then two asks before dockerd hears of the exit
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))

	f.waitLog(t, "Container exited before it could be tagged")
	assert.EqualValues(t, 1, f.tracker.exitedBeforeTag.Load())
	assert.Zero(t, f.tracker.identityRejected.Load())
	assert.Empty(t, f.tagger.tagCalls())
	assert.NotContains(t, f.logs.String(), "level=WARN")
}

// A container whose pid this /proc cannot see while the daemon keeps
// reporting it running is the daemon in another pid namespace, where every
// check fails, and a daemon that cannot say is no proof of an exit: both
// keep the warning, the second with the daemon's error.
func TestStartIdentityFailuresStillWarn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script func(d *fakeDaemon, id string)
		want   string
	}{
		{name: "running, pid not visible", script: func(*fakeDaemon, string) {}},
		{
			name:   "daemon can no longer report it",
			script: func(d *fakeDaemon, id string) { d.setKnownFor(id, 1) },
			want:   "daemon_error=",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			id := strings.Repeat("6", 64)
			mkScopeDir(t, f.cgroupRoot, id)
			f.daemon.setContainer(makeInspect(id, 4242, "172.17.0.31", false))
			tc.script(f.daemon, id)
			f.tagger.setOrdinal(7)
			f.start(t)
			f.daemon.push(startEvent(id, time.Now().UnixNano()))

			f.waitLog(t, `level=WARN msg="Container identity check failed; not tagging"`)
			assert.EqualValues(t, 1, f.tracker.identityRejected.Load())
			assert.Zero(t, f.tracker.exitedBeforeTag.Load())
			assert.Contains(t, f.logs.String(), tc.want)
		})
	}
}

// A one-off exec (setup-buildx's post step) can finish before its pid is
// checked. Once a container's identity check has passed, this /proc is
// known to see the daemon's pids, so the missing pid has exited whatever
// the daemon still says. Before that, the daemon is asked until it reports
// the exec stopped. Both ways of finding the exec are covered: by the
// event's execID, and by diffing the container's ExecIDs when it lacks one,
// which must hand back the id the daemon is asked about.
func TestExecExitedBeforeCheckIsNotAWarning(t *testing.T) {
	for _, tc := range []struct {
		name       string
		proven     bool // the container's own check passed
		withExecID bool
	}{
		{name: "pids proven visible", proven: true, withExecID: true},
		{name: "pids unproven, execID attribute", withExecID: true},
		{name: "pids unproven, ExecIDs diff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			id := strings.Repeat("6", 64)
			if tc.proven {
				f.addContainer(t, id, 4242, "172.17.0.31", false)
			} else {
				f.addMismatchedContainer(t, id, 4242, "172.17.0.31")
			}
			f.tagger.setOrdinal(7)
			f.start(t)
			f.daemon.push(startEvent(id, time.Now().UnixNano()))
			f.waitAttribution(t, "start", id)

			execID := strings.Repeat("7", 64)
			f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4747, ContainerID: id})
			if !tc.proven {
				f.daemon.setRunningFor(execID, 3) // running at resolve and for two asks, then stopped
			}
			f.daemon.updateContainer(id, func(c *containerInspect) { c.ExecIDs = []string{execID} })
			f.tagger.setOrdinal(9)
			attr := ""
			if tc.withExecID {
				attr = execID
			}
			f.daemon.push(execStartEvent(id, attr, time.Now().UnixNano()))

			f.waitLog(t, "Exec exited before it could be tagged")
			assert.EqualValues(t, 1, f.tracker.exitedBeforeTag.Load())
			assert.NotContains(t, f.tagger.tagCalls(), tagCall{pid: 4747, ordinal: 9})
			assert.NotContains(t, f.logs.String(), "Exec identity check failed")
		})
	}
}

// An exec the daemon already reports finished is never checked: its pid
// may since be another process's, even one in the same container, which
// the identity check would pass and tag with this exec's step.
func TestExecAlreadyExitedIsNeverChecked(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("6", 64)
	f.addContainer(t, id, 4242, "172.17.0.31", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	execID := strings.Repeat("7", 64)
	writeProcEntry(t, f.procRoot, 4343, cgroupV2Line(id)+"\n", "recycled")
	f.daemon.setExec(execID, execInspect{ID: execID, Running: false, Pid: 4343, ContainerID: id})
	f.tagger.setOrdinal(9)
	f.daemon.push(execStartEvent(id, execID, time.Now().UnixNano()))

	f.waitLog(t, "Exec exited before it could be tagged")
	assert.EqualValues(t, 1, f.tracker.exitedBeforeTag.Load())
	assert.NotContains(t, f.tagger.tagCalls(), tagCall{pid: 4343, ordinal: 9})
	assert.NotContains(t, f.logs.String(), "level=WARN")
}

// Failures that are not that race keep the warning:
//   - a running exec whose pid this /proc cannot see, before any check has
//     proven it can: the daemon's pids are in another namespace;
//   - a pid that exists in another cgroup: the recycled pid the identity
//     check is for;
//   - a daemon that can no longer report the exec, which is no proof of an
//     exit, and whose error the warning carries.
func TestExecIdentityFailuresStillWarn(t *testing.T) {
	otherID := strings.Repeat("b", 64)
	for _, tc := range []struct {
		name     string
		proven   bool
		recycled bool // the pid has a /proc entry, in otherID's cgroup
		knownFor int  // > 0: the daemon 404s the exec after this many inspects
		want     string
	}{
		{name: "running, pid not visible, pids unproven"},
		{name: "pid recycled into another cgroup", proven: true, recycled: true},
		{name: "daemon can no longer report it", knownFor: 1, want: "daemon_error="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			id := strings.Repeat("8", 64)
			if tc.proven {
				f.addContainer(t, id, 4242, "172.17.0.32", false)
			} else {
				f.addMismatchedContainer(t, id, 4242, "172.17.0.32")
			}
			f.tagger.setOrdinal(7)
			f.start(t)
			f.daemon.push(startEvent(id, time.Now().UnixNano()))
			f.waitAttribution(t, "start", id)

			execID := strings.Repeat("a", 64)
			if tc.recycled {
				writeProcEntry(t, f.procRoot, 4848, cgroupV2Line(otherID)+"\n", "app")
			}
			f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4848, ContainerID: id})
			if tc.knownFor > 0 {
				f.daemon.setKnownFor(execID, tc.knownFor)
			}
			f.tagger.setOrdinal(9)
			f.daemon.push(execStartEvent(id, execID, time.Now().UnixNano()))

			f.waitLog(t, `level=WARN msg="Exec identity check failed; not tagging"`)
			assert.Zero(t, f.tracker.exitedBeforeTag.Load())
			assert.NotContains(t, f.tagger.tagCalls(), tagCall{pid: 4848, ordinal: 9})
			assert.Contains(t, f.logs.String(), tc.want)
		})
	}
}

// Shutting down while the daemon is still being asked is not a finding:
// the question was cut short, and the job's log must not end on a warning
// for it.
func TestExecCheckCutShortByCloseIsQuiet(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("8", 64)
	f.addMismatchedContainer(t, id, 4242, "172.17.0.32")
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	execID := strings.Repeat("a", 64)
	f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4848, ContainerID: id})
	f.tagger.setOrdinal(9)
	f.daemon.push(execStartEvent(id, execID, time.Now().UnixNano()))
	require.Eventually(t, func() bool { return f.daemon.inspectCount(execID) >= 2 }, waitFor, tick,
		"the handler is asking the daemon")

	f.tracker.Close() // waits for the handler
	assert.NotContains(t, f.logs.String(), "Exec identity check failed")
	assert.EqualValues(t, 1, f.tracker.identityRejected.Load(), "only the container's own mismatch")
}

// An exec whose own check passes proves this /proc sees the daemon's pids
// as well as a container's start does: a later exec's missing pid has then
// exited, whatever the daemon still reports.
func TestExecCheckProvesPidsVisible(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("8", 64)
	f.addMismatchedContainer(t, id, 4242, "172.17.0.32")
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	first := strings.Repeat("a", 64)
	writeProcEntry(t, f.procRoot, 4848, cgroupV2Line(id)+"\n", "sh")
	f.daemon.setExec(first, execInspect{ID: first, Running: true, Pid: 4848, ContainerID: id})
	f.tagger.setOrdinal(9)
	f.daemon.push(execStartEvent(id, first, time.Now().UnixNano()))
	f.waitAttribution(t, "exec", id)

	second := strings.Repeat("c", 64)
	f.daemon.setExec(second, execInspect{ID: second, Running: true, Pid: 4949, ContainerID: id})
	f.daemon.push(execStartEvent(id, second, time.Now().UnixNano()))

	f.waitLog(t, "Exec exited before it could be tagged")
	assert.NotContains(t, f.logs.String(), "Exec identity check failed")
}

// A container that passes its identity check but is gone from the task walk
// by the time the step maps are written was not tagged. It counts as having
// exited before tagging, and its marker reports ordinal 0, never the step
// it would have had.
func TestStartGoneBeforeTagReportsNoTag(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("a", 64)
	f.addContainer(t, id, 4242, "172.17.0.40", false)
	f.tagger.setGone(4242)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))

	ev := f.waitAttribution(t, "start", id)
	assert.Zero(t, ev.StepOrdinal)
	assert.Zero(t, f.tracker.tagged.Load())
	assert.EqualValues(t, 1, f.tracker.exitedBeforeTag.Load())
	assert.NotContains(t, f.logs.String(), "level=WARN")
}

// Adoption that tags nothing leaves nothing for the replayed start to
// upgrade.
func TestReconcileGoneBeforeTagIsNotUpgraded(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("b", 64)
	f.addContainer(t, id, 5151, "172.17.0.41", false)
	f.daemon.setList(containerSummary{ID: id})
	f.tagger.setGone(5151)
	f.tagger.setOrdinal(7)
	f.start(t)

	ev := f.waitAttribution(t, "reconcile", id)
	assert.Zero(t, ev.StepOrdinal)
	assert.Zero(t, f.tracker.reconciled.Load())
	assert.EqualValues(t, 1, f.tracker.exitedBeforeTag.Load())

	// Replay the start, then a marker container to order the assertions.
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	markerID := strings.Repeat("c", 64)
	f.addContainer(t, markerID, 5656, "172.17.0.42", false)
	f.daemon.push(startEvent(markerID, time.Now().UnixNano()))
	f.waitAttribution(t, "start", markerID)
	assert.NotContains(t, f.logs.String(), "upgraded")
	assert.EqualValues(t, 1, f.tracker.exitedBeforeTag.Load())
}

// An upgrade whose task is gone tags nothing and says so, while the
// container's address still takes the real start's step.
func TestUpgradeReconciledStartGoneBeforeTag(t *testing.T) {
	tagger := &fakeTagger{}
	tagger.setOrdinal(6)
	tagger.setGone(4242)
	tr := &Tracker{
		tagger:     tagger,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		containers: map[string]*containerInfo{},
	}
	info := &containerInfo{
		id: strings.Repeat("a", 64), initPID: 4242,
		birthOrdinal: events.StepOrdinalPreDaemon, effectiveOrdinal: events.StepOrdinalPreDaemon, preDaemon: true,
	}
	tr.containers[info.id] = info

	tr.upgradeReconciledStart(info, info.id, time.Now().UnixNano())

	assert.Zero(t, tr.tagged.Load())
	assert.EqualValues(t, 1, tr.exitedBeforeTag.Load())
	assert.Equal(t, uint32(6), info.effectiveOrdinal)
}

// An exec whose task is gone by the time it would be tagged is not
// attributed, and the container's address keeps its own step.
func TestExecGoneBeforeTagReportsNoTag(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("d", 64)
	f.addContainer(t, id, 4242, "172.17.0.43", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	execID := strings.Repeat("e", 64)
	writeProcEntry(t, f.procRoot, 4747, cgroupV2Line(id)+"\n", "sh")
	f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4747, ContainerID: id})
	f.tagger.setGone(4747)
	f.tagger.setOrdinal(9)
	f.daemon.push(execStartEvent(id, execID, time.Now().UnixNano()))

	f.waitLog(t, "Exec exited before it could be tagged")
	assert.Zero(t, f.tracker.execTagged.Load())
	assert.EqualValues(t, 1, f.tracker.exitedBeforeTag.Load())
	assert.NotContains(t, f.logs.String(), "Container exec attributed")
	ord, _, ok := f.tracker.LookupClient(&net.UDPAddr{IP: net.ParseIP("172.17.0.43"), Port: 1})
	require.True(t, ok)
	assert.Equal(t, uint32(7), ord)
}
