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

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/origin"
	"github.com/code-cargo/cargowall/pkg/podenv"
	"github.com/code-cargo/cargowall/pkg/steps"
)

// syncBuffer is a log the decision's goroutine writes while a test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// privileged is a privileged container's shape outside Kubernetes, in a
// pid namespace of its own, whose hook scope reads the daemon's runtime.
func privileged(d podenv.Dockerd) podenv.Shape {
	const own = "/system.slice/docker-a.scope"
	return podenv.Shape{
		CgroupNS: podenv.CgroupNSHost, PidNS: podenv.PidNSPrivate, CgroupPath: own,
		CgroupMount: podenv.CgroupMountOurs, SocketCgroups: podenv.SocketCgroupsKept, InitCgroup: own,
		OwnTree: podenv.CgroupTreeOurs, Dockerd: d,
	}
}

var (
	// stillToCome is a daemon that has not answered; confirmed one whose
	// runtime is in our pid namespace; outside one whose runtime is not.
	stillToCome = podenv.Dockerd{Kind: podenv.DockerdLocal, Reason: "its answer: context deadline exceeded"}
	confirmed   = podenv.Dockerd{Kind: podenv.DockerdLocal, Answers: true, Runtime: 7}
	outside     = podenv.Dockerd{
		Kind: podenv.DockerdLocal, Answers: true,
		Reason: "its runtime: the containerd it reaches at /run/containerd/containerd.sock is outside our pid namespace",
	}
)

// scopeRun is a hook loaded with a daemon still to come up, whose recheck
// finds each of rechecks in turn (the last one again after), under the
// posture requested and the policy's mode.
type scopeRun struct {
	a        *containerAttribution
	cmd      *StartCmd
	log      *syncBuffer
	rechecks atomic.Int32
}

func newScopeRun(t *testing.T, egress string, enforcing bool, rechecks ...podenv.Dockerd) *scopeRun {
	t.Helper()
	redirectStateFiles(t)
	run := &scopeRun{
		cmd: &StartCmd{ContainerEgress: egress, FailureFile: filepath.Join(t.TempDir(), "failed")},
		log: &syncBuffer{},
	}
	logger := slog.New(slog.NewTextHandler(run.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := newPostures(run.cmd, "6.6.141", enforcing, logger)
	p.write()
	saved, retry, retryMax := recheckShape, recheckRetry, recheckRetryMax
	t.Cleanup(func() { recheckShape, recheckRetry, recheckRetryMax = saved, retry, retryMax })
	recheckRetry, recheckRetryMax = time.Millisecond, 4*time.Millisecond
	recheckShape = func(s podenv.Shape) podenv.Shape {
		n := int(run.rechecks.Add(1)) - 1
		s.Dockerd = rechecks[min(n, len(rechecks)-1)]
		return s
	}
	run.a = &containerAttribution{postures: p, logger: logger}
	run.a.scope.shape = privileged(stillToCome)
	run.a.scope.pending = true
	return run
}

// settled waits until no recheck is running, and reports whether the
// daemon's rules are still to decide.
func (r *scopeRun) settled(t *testing.T) bool {
	t.Helper()
	var pending bool
	require.Eventually(t, func() bool {
		r.a.scope.mu.Lock()
		defer r.a.scope.mu.Unlock()
		pending = r.a.scope.pending
		return !r.a.scope.deciding
	}, 2*time.Second, 5*time.Millisecond)
	return pending
}

// A daemon whose runtime is in our pid namespace confirms the hook: one
// Info, the posture standing as applied, nothing refused.
func TestScopeDecision_Confirmed(t *testing.T) {
	run := newScopeRun(t, ContainerEgressEnforce, true, confirmed)
	run.a.ready()
	run.a.daemonAnswered()
	assert.False(t, run.settled(t))
	assert.Contains(t, run.log.String(), "Container egress hook confirmed once Docker answered")
	assert.False(t, readPostures()[0].degraded())
	assert.Empty(t, run.cmd.refusedLate)
	run.a.Close()
	assert.NotContains(t, run.log.String(), "never answered")
	assert.NoError(t, refusalExit(nil, run.cmd))
}

// A daemon whose containers fall outside the hook's scope loses the
// posture once it answers, the hook staying up. Under an enforcing policy
// a fail-closed rung's loss is an Error, and a refusal too late to refuse
// startup: the failure sentinel names it with a reason that is not a
// startup's, and the run's exit status is the refusal's. Under an auditing
// policy, or for the observe rung, it is a Warn and refuses nothing.
func TestScopeDecision_Lost(t *testing.T) {
	const why = "once Docker answered: the cgroup hook judges only our pid namespace"
	for _, c := range []struct {
		name      string
		egress    string
		enforcing bool
		refused   bool
	}{
		{name: "enforce", egress: ContainerEgressEnforce, enforcing: true, refused: true},
		{name: "enforce rung under an auditing policy", egress: ContainerEgressEnforce},
		{name: "observe", egress: ContainerEgressObserve, enforcing: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := newScopeRun(t, c.egress, c.enforcing, outside)
			run.a.ready()
			run.a.daemonAnswered()
			assert.False(t, run.settled(t))
			line := readPostures()[0]
			assert.Equal(t, "off", line.Applied)
			assert.Contains(t, line.Reason, why)
			assert.Contains(t, line.Reason, "outside our pid namespace")
			assert.Equal(t, c.refused, strings.Contains(run.log.String(), "level=ERROR"), run.log.String())
			sentinel, err := os.ReadFile(run.cmd.FailureFile)
			if !c.refused {
				assert.Empty(t, run.cmd.refusedLate)
				assert.ErrorIs(t, err, os.ErrNotExist, "nothing refused, no failure sentinel")
				assert.NoError(t, refusalExit(nil, run.cmd))
				return
			}
			assert.Equal(t, postureContainerEgress, run.cmd.refusedLate)
			require.NoError(t, err)
			pid, refused, reason := sentinelLines(t, sentinel)
			assert.Equal(t, fmt.Sprintf("pid=%d", os.Getpid()), pid)
			assert.Equal(t, "refused=container-egress", refused)
			assert.True(t, strings.HasPrefix(reason,
				"cargowall: --container-egress=enforce requested but could not be applied, decided after startup: "+why), reason)
			assert.NotContains(t, reason, "startup failed")
			var coder interface{ ExitCode() int }
			require.ErrorAs(t, refusalExit(nil, run.cmd), &coder)
			assert.Equal(t, exitRefused, coder.ExitCode())
		})
	}
}

// sentinelLines splits a failure sentinel naming a refused posture.
func sentinelLines(t *testing.T, data []byte) (pid, refused, reason string) {
	t.Helper()
	lines := strings.SplitN(strings.TrimSuffix(string(data), "\n"), "\n", 3)
	require.Len(t, lines, 3, string(data))
	return lines[0], lines[1], lines[2]
}

// Nothing is decided until both the daemon has answered its tracker and
// startup is done, whichever comes first. A recheck that finds the daemon
// still not answering the probe probes it again on its own, with no other
// connect, until it decides: the tracker's event stream stays up, so its
// next connect may never come.
func TestScopeDecision_Order(t *testing.T) {
	run := newScopeRun(t, ContainerEgressEnforce, true, stillToCome, stillToCome, confirmed)
	run.a.daemonAnswered()
	assert.True(t, run.settled(t))
	assert.Zero(t, run.rechecks.Load(), "not before startup is done")
	run.a.ready()
	assert.False(t, run.settled(t), "decided on its own, with no other connect")
	assert.EqualValues(t, 3, run.rechecks.Load())
	assert.Equal(t, 2, strings.Count(run.log.String(), "probing again"), run.log.String())
	assert.Contains(t, run.log.String(), "Container egress hook confirmed")
	run.a.daemonAnswered()
	run.settled(t)
	assert.EqualValues(t, 3, run.rechecks.Load(), "nothing left to decide")

	run = newScopeRun(t, ContainerEgressEnforce, true, confirmed)
	run.a.ready()
	assert.True(t, run.settled(t))
	assert.Zero(t, run.rechecks.Load(), "not before the daemon answers")
	run.a.daemonAnswered()
	assert.False(t, run.settled(t))
}

// A connect that comes while a recheck runs is not lost when that recheck
// finds the daemon still to come up: the decision goes on to the next
// recheck, which decides.
func TestScopeDecision_ConnectDuringRecheck(t *testing.T) {
	run := newScopeRun(t, ContainerEgressEnforce, true, stillToCome, outside)
	inFlight, release := make(chan struct{}), make(chan struct{})
	stub := recheckShape
	var first sync.Once
	recheckShape = func(s podenv.Shape) podenv.Shape {
		first.Do(func() {
			close(inFlight)
			<-release
		})
		return stub(s)
	}
	run.a.ready()
	run.a.daemonAnswered()
	<-inFlight
	run.a.daemonAnswered()
	close(release)
	assert.False(t, run.settled(t))
	assert.EqualValues(t, 2, run.rechecks.Load())
	assert.Equal(t, "off", readPostures()[0].Applied)
	assert.Equal(t, postureContainerEgress, run.cmd.refusedLate)
}

// A daemon that never answers its tracker made no container: teardown says
// the hook judged the job's traffic throughout, and the posture stands as
// applied.
// Nothing is decided after teardown, and a hook with nothing pending says
// nothing at it.
func TestScopeDecision_NeverAnswered(t *testing.T) {
	run := newScopeRun(t, ContainerEgressEnforce, true, outside)
	run.a.ready()
	run.a.Close()
	assert.Equal(t, 1, strings.Count(run.log.String(), "Docker never answered while cargowall ran"), run.log.String())
	assert.Contains(t, run.log.String(), "the posture stands as applied")
	run.a.daemonAnswered()
	run.settled(t)
	assert.Zero(t, run.rechecks.Load(), "nothing is decided after teardown")
	assert.False(t, readPostures()[0].degraded())
	assert.Empty(t, run.cmd.refusedLate)

	run = newScopeRun(t, ContainerEgressEnforce, true, outside)
	run.a.scope.pending = false
	run.a.ready()
	run.a.daemonAnswered()
	run.a.Close()
	assert.Zero(t, run.rechecks.Load())
	assert.Empty(t, run.log.String())

	// A daemon that answered its tracker but never the probe may have had
	// containers outside the hook's scope: the posture is lost at teardown,
	// and the probing stops.
	run = newScopeRun(t, ContainerEgressEnforce, true, stillToCome)
	run.a.ready()
	run.a.daemonAnswered()
	require.Eventually(t, func() bool { return run.rechecks.Load() >= 3 }, 2*time.Second, time.Millisecond)
	run.a.Close()
	assert.Equal(t, "off", readPostures()[0].Applied)
	assert.Contains(t, readPostures()[0].Reason, "Docker answered its tracker, but not the probe")
	assert.Equal(t, postureContainerEgress, run.cmd.refusedLate)
	assert.NotContains(t, run.log.String(), "never answered while")
	after := run.rechecks.Load()
	time.Sleep(20 * time.Millisecond)
	assert.LessOrEqual(t, run.rechecks.Load(), after+1, "no probing after teardown")

	assert.NotPanics(t, func() {
		(*containerAttribution)(nil).daemonAnswered()
		(*containerAttribution)(nil).ready()
	})
}

// The hook loads at once with a daemon still to come up, leaving its rules
// to decide; one that fails to load is lost at startup, with nothing left
// to decide. (origin.Start refuses nil TC objects before touching the
// kernel.)
func TestScopeDecision_FromStartup(t *testing.T) {
	p, buf := ledgerWithLog(t, ContainerEgressObserve, TLSSNIOff)
	a, err := newContainerAttribution(true, origin.ModeShadow, &steps.Tracker{}, nil, privileged(stillToCome), nil, p, p.logger)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "nil TC BPF objects", "the hook was asked to load, not refused for the daemon")
	assert.False(t, a.scope.pending, "a hook that did not load leaves nothing to decide")
	a.Close()
	assert.NotContains(t, buf.String(), "never answered")
}
