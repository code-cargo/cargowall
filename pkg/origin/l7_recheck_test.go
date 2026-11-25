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

package origin

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// recheckOracle is an oracle driven synchronously whose re-checks are
// queued to one stage with no worker, so a test can clobber the kernel
// entry and run each read itself.
func recheckOracle(t *testing.T, queue int) (*L7, *bpf.OriginBpfObjects, *syncBuffer) {
	t.Helper()
	objs := loadL7Objects(t)
	logs := &syncBuffer{}
	l := newL7(objs, L7Options{Matcher: allowSet{"auth.docker.io": true, "example.com": true}},
		slog.New(slog.NewTextHandler(logs, nil)))
	l.rechecks = &l7Rechecker{
		l: l, quit: make(chan struct{}),
		stages: []*recheckStage{{max: queue, wake: make(chan struct{}, 1)}},
	}
	return l, objs, logs
}

// syncBuffer is a log buffer the workers write while the test reads it.
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

func tlsHello(cookie uint64, seq uint32, flags uint8) *bpf.L7Event {
	ev := makeL7Event(443, seq, snitest.BuildClientHello("auth.docker.io"), false)
	ev.Cookie = cookie
	ev.Timestamp = 5000
	ev.Flags |= flags
	return ev
}

// entryState is the kernel entry's state, or 0xff when there is none. It
// never fails the test, so it is safe inside Eventually.
func entryState(objs *bpf.OriginBpfObjects, ev *bpf.L7Event) uint8 {
	var v bpf.OriginBpfL7FlowVal
	if objs.MapL7Flow.Lookup(ev.FlowKey(), &v) != nil {
		return 0xff
	}
	return v.State
}

// clobber writes what the kernel's commit of a punt writes: PENDING, with
// the punt's sequence number.
func clobber(t *testing.T, objs *bpf.OriginBpfObjects, ev *bpf.L7Event, seq uint32) {
	t.Helper()
	require.NoError(t, objs.MapL7Flow.Put(ev.FlowKey(), bpf.OriginBpfL7FlowVal{
		State: l7StatePending, Punts: 1, LastPuntSeq: seq, LastPuntLen: ev.PayloadLen, Ts: 4000,
	}))
}

// decide runs one first-flight punt through the oracle and returns the
// re-check it queued.
func decide(t *testing.T, l *L7, ev *bpf.L7Event) l7Recheck {
	t.Helper()
	st := l.rechecks.stages[0]
	before := len(st.q)
	l.onSample(ev)
	require.Len(t, st.q, before+1, "a TCP verdict queues a re-check")
	r := st.q[len(st.q)-1]
	st.q = st.q[:len(st.q)-1]
	return r
}

// The commit of the very punt the verdict answered wrote PENDING over it:
// the re-check writes the verdict again, and counts it.
func TestL7RecheckRepairsClobberedVerdict(t *testing.T) {
	l, objs, _ := recheckOracle(t, 4)
	ev := tlsHello(1, 1000, l7PuntNewConn)
	r := decide(t, l, ev)
	require.Equal(t, l7StateAllowed, entryState(objs, ev))

	assert.Equal(t, recheckHeld, l.rechecks.recheck(r), "not clobbered: read again later")
	assert.Zero(t, l.rechecks.repaired.Load())

	clobber(t, objs, ev, ev.Seq)
	assert.Equal(t, recheckRepaired, l.rechecks.recheck(r))
	assert.Equal(t, l7StateAllowed, entryState(objs, ev))
	assert.Equal(t, uint64(1), l.rechecks.repaired.Load())

	// A denial is repaired the same way.
	l.matcher = allowSet{}
	denied := tlsHello(2, 2000, l7PuntNewConn)
	r = decide(t, l, denied)
	clobber(t, objs, denied, denied.Seq)
	assert.Equal(t, recheckRepaired, l.rechecks.recheck(r))
	assert.Equal(t, l7StateDenied, entryState(objs, denied))
}

// A PENDING entry with another sequence number, or a NEED_HELLO entry,
// belongs to a later connection of the socket, and an evicted entry strands
// nothing: none gets the old verdict, and none is read again.
func TestL7RecheckLeavesOtherEntriesAlone(t *testing.T) {
	l, objs, _ := recheckOracle(t, 4)
	ev := tlsHello(1, 1000, l7PuntNewConn)
	r := decide(t, l, ev)

	clobber(t, objs, ev, ev.Seq+7)
	assert.Equal(t, recheckSuperseded, l.rechecks.recheck(r))
	assert.Equal(t, l7StatePending, entryState(objs, ev), "another punt's PENDING is left alone")

	require.NoError(t, objs.MapL7Flow.Put(ev.FlowKey(), bpf.OriginBpfL7FlowVal{State: l7StateNeedHello, Ts: 9000}))
	assert.Equal(t, recheckSuperseded, l.rechecks.recheck(r))
	assert.Equal(t, l7StateNeedHello, entryState(objs, ev), "a NEED_HELLO is left alone")

	require.NoError(t, objs.MapL7Flow.Put(ev.FlowKey(), bpf.OriginBpfL7FlowVal{State: l7StateDenied}))
	assert.Equal(t, recheckSuperseded, l.rechecks.recheck(r), "another verdict is a later cycle's")

	require.NoError(t, objs.MapL7Flow.Delete(ev.FlowKey()))
	assert.Equal(t, recheckSuperseded, l.rechecks.recheck(r), "an evicted entry strands nothing")
	assert.Zero(t, l.rechecks.repaired.Load())
}

// A punt that reset the oracle's record since the verdict (a later
// connection's NEW_CONN, a NO_STATE after eviction) means the verdict no
// longer answers for the flow, even where the entry looks like its clobber.
func TestL7RecheckSkipsAResetFlow(t *testing.T) {
	l, objs, _ := recheckOracle(t, 4)

	// Reset and decided again, with the same verdict: another cycle.
	ev := tlsHello(1, 1000, l7PuntNewConn)
	r := decide(t, l, ev)
	_ = decide(t, l, tlsHello(1, 3000, l7PuntNewConn))
	clobber(t, objs, ev, ev.Seq)
	assert.Equal(t, recheckSuperseded, l.rechecks.recheck(r), "a later cycle owns the flow")

	// Reset and still assembling.
	ev = tlsHello(2, 1000, l7PuntNewConn)
	r = decide(t, l, ev)
	partial := makeL7Event(443, 5000, snitest.BuildClientHello("auth.docker.io")[:20], false)
	partial.Cookie = 2
	partial.Flags |= l7PuntNoState
	l.onSample(partial)
	clobber(t, objs, ev, ev.Seq)
	assert.Equal(t, recheckSuperseded, l.rechecks.recheck(r), "an undecided cycle owns the flow")
	assert.Zero(t, l.rechecks.repaired.Load())
}

// A clobbered entry whose record the oracle no longer holds (evicted from
// a full table) is counted and warned once, never repaired: nothing
// vouches for the verdict.
func TestL7RecheckCountsAnUnownedClobber(t *testing.T) {
	l, objs, logs := recheckOracle(t, 4)
	for cookie := uint64(1); cookie <= 2; cookie++ {
		ev := tlsHello(cookie, 1000, l7PuntNewConn)
		r := decide(t, l, ev)
		delete(l.flows, ev.FlowKey())
		clobber(t, objs, ev, ev.Seq)
		assert.Equal(t, recheckUnowned, l.rechecks.recheck(r))
		assert.Equal(t, l7StatePending, entryState(objs, ev))
	}
	assert.Equal(t, uint64(2), l.rechecks.unowned.Load())
	assert.Zero(t, l.rechecks.repaired.Load())
	_ = logs // the worker warns, once; TestL7RecheckLoopWarnsOnce covers it
}

// The read, the record check and the write happen under l.mu, so no cycle
// can be decided between the check and the write: a later connection's
// verdict either changed the record first or lands after the repair.
func TestL7RecheckWritesUnderTheOracleLock(t *testing.T) {
	l, objs, _ := recheckOracle(t, 4)
	ev := tlsHello(1, 1000, l7PuntNewConn)
	r := decide(t, l, ev)
	clobber(t, objs, ev, ev.Seq)

	held := false
	l.rechecks.beforeWrite = func() {
		if l.mu.TryLock() {
			l.mu.Unlock()
			return
		}
		held = true
	}
	require.Equal(t, recheckRepaired, l.rechecks.recheck(r))
	assert.True(t, held, "the repair's write must happen with l.mu held")
}

// A full queue drops the re-check, counts it and warns once; onSample
// never blocks on it. QUIC queues none: its retransmits re-punt.
func TestL7RecheckQueueFullDoesNotBlock(t *testing.T) {
	l, _, logs := recheckOracle(t, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for cookie := uint64(1); cookie <= 3; cookie++ {
			l.onSample(tlsHello(cookie, 1000, l7PuntNewConn))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("onSample blocked on a full re-check queue")
	}
	assert.Len(t, l.rechecks.stages[0].q, 1)
	assert.Equal(t, uint64(2), l.rechecks.droppedUnchecked.Load())
	assert.Equal(t, 1, strings.Count(logs.String(), "L7 verdict re-check dropped"))

	l.rechecks.stages[0].q = nil
	l.onSample(makeL7Event(443, 0, snitest.RFC9001ClientInitial(), true))
	assert.Empty(t, l.rechecks.stages[0].q, "a QUIC verdict queues no re-check")
}

// gatedRechecker is a running rechecker whose stages wait for the test to
// release them, one re-check at a time, instead of on the clock. A stage
// announces on entered[stage] when a re-check reaches its wait, which also
// says the stage before it has finished its read.
func gatedRechecker(t *testing.T, l *L7, stages int) (gates, entered []chan struct{}) {
	t.Helper()
	gates = make([]chan struct{}, stages)
	entered = make([]chan struct{}, stages)
	for i := range gates {
		gates[i] = make(chan struct{})
		entered[i] = make(chan struct{}, 16)
	}
	rc := &l7Rechecker{l: l, quit: make(chan struct{})}
	rc.wait = func(stage int, _ time.Duration) bool {
		entered[stage] <- struct{}{}
		select {
		case <-gates[stage]:
			return true
		case <-rc.quit:
			return false
		}
	}
	caps := make([]int, stages)
	for i := range caps {
		caps[i] = 16
	}
	rc.start(make([]time.Duration, stages), caps)
	l.rechecks = rc
	t.Cleanup(rc.stop)
	return gates, entered
}

// Each stage reads the entry when released: a clobber before the first
// read is repaired by it, one after a read that found the verdict in place
// by a later stage, the last included; and a repaired or superseded
// re-check is not read again.
func TestL7RecheckLoopStages(t *testing.T) {
	l, objs, _ := recheckOracle(t, 16)
	gates, entered := gatedRechecker(t, l, 3)
	reach := func(stage int) {
		t.Helper()
		select {
		case <-entered[stage]:
		case <-time.After(5 * time.Second):
			t.Fatalf("no re-check reached stage %d", stage+1)
		}
	}
	repaired := func(n uint64) func() bool {
		return func() bool { return l.rechecks.repaired.Load() == n }
	}

	early := tlsHello(1, 1000, l7PuntNewConn)
	l.onSample(early)
	reach(0)
	clobber(t, objs, early, early.Seq)
	gates[0] <- struct{}{}
	require.Eventually(t, repaired(1), 5*time.Second, time.Millisecond, "the first read repairs an early clobber")
	assert.Equal(t, l7StateAllowed, entryState(objs, early))

	late := tlsHello(2, 1000, l7PuntNewConn)
	l.onSample(late)
	reach(0)
	gates[0] <- struct{}{} // the verdict is in place: on to stage 2
	reach(1)
	gates[1] <- struct{}{} // still in place: on to stage 3
	reach(2)
	clobber(t, objs, late, late.Seq)
	gates[2] <- struct{}{}
	require.Eventually(t, repaired(2), 5*time.Second, time.Millisecond, "the last read repairs a late clobber")
	assert.Equal(t, l7StateAllowed, entryState(objs, late))

	// The repaired early re-check went no further: only the late one ever
	// reached stages 2 and 3.
	assert.Empty(t, entered[1])
	assert.Empty(t, entered[2])
}

// Stopping does not wait out the delays.
func TestL7RecheckStopDoesNotSleep(t *testing.T) {
	l, _, _ := recheckOracle(t, 16)
	rc := newL7Rechecker(l, []time.Duration{time.Hour})
	rc.queue(l7Recheck{written: time.Now()})
	start := time.Now()
	rc.stop()
	assert.Less(t, time.Since(start), time.Second)
}

// A failed read other than a missing entry, or a failed repair write, is
// counted and read again, never taken for an eviction.
func TestL7RecheckCountsFailures(t *testing.T) {
	l, objs, _ := recheckOracle(t, 4)
	ev := tlsHello(1, 1000, l7PuntNewConn)
	r := decide(t, l, ev)
	clobber(t, objs, ev, ev.Seq)

	// The write fails: the map is closed under it.
	flow, err := objs.MapL7Flow.Clone()
	require.NoError(t, err)
	l.flow = flow
	l.rechecks.beforeWrite = func() { _ = flow.Close() }
	assert.Equal(t, recheckFailed, l.rechecks.recheck(r))
	assert.Equal(t, uint64(1), l.rechecks.failed.Load())

	// The read fails, with something other than a missing key.
	l.rechecks.beforeWrite = nil
	assert.Equal(t, recheckFailed, l.rechecks.recheck(r))
	assert.Equal(t, uint64(2), l.rechecks.failed.Load())
	assert.Zero(t, l.rechecks.repaired.Load())

	// Back on the live map, the entry is still the clobber, and is repaired.
	l.flow = objs.MapL7Flow
	assert.Equal(t, recheckRepaired, l.rechecks.recheck(r))
	assert.Equal(t, l7StateAllowed, entryState(objs, ev))
}

// In observe mode the kernel passes a PENDING flow's packets and its next
// segment re-punts, so a clobber strands nothing: no re-check is queued.
func TestL7RecheckNotQueuedUnderObserve(t *testing.T) {
	l, _, _ := recheckOracle(t, 4)
	l.onSample(tlsHello(1, 1000, l7PuntNewConn|l7PuntObserve))
	assert.Empty(t, l.rechecks.stages[0].q)
}

// Each stage is sized by how long entries stay in it, so the last, which
// holds them longest, is not the first to fill.
func TestRecheckStageCaps(t *testing.T) {
	assert.Equal(t, []int{1024, 2376, 13926}, recheckStageCaps(l7RecheckDelays))
}

// A re-check the next stage has no room for is dropped, counted as checked,
// and warned once; and the worker warns once for unowned clobbers and
// failures, never under l.mu.
func TestL7RecheckLoopWarnsOnce(t *testing.T) {
	l, objs, logs := recheckOracle(t, 16)
	gates := make([]chan struct{}, 2)
	entered := make([]chan struct{}, 2)
	for i := range gates {
		gates[i] = make(chan struct{})
		entered[i] = make(chan struct{}, 16)
	}
	rc := &l7Rechecker{l: l, quit: make(chan struct{})}
	rc.wait = func(stage int, _ time.Duration) bool {
		entered[stage] <- struct{}{}
		select {
		case <-gates[stage]:
			return true
		case <-rc.quit:
			return false
		}
	}
	rc.start(make([]time.Duration, 2), []int{16, 1})
	l.rechecks = rc
	t.Cleanup(rc.stop)
	reach := func(stage int) {
		t.Helper()
		select {
		case <-entered[stage]:
		case <-time.After(5 * time.Second):
			t.Fatalf("no re-check reached stage %d", stage+1)
		}
	}

	// Three verdicts in place: the first fills stage 2 (it waits at its
	// gate), the second takes the one slot, the third has none.
	for cookie := uint64(1); cookie <= 3; cookie++ {
		l.onSample(tlsHello(cookie, 1000, l7PuntNewConn))
		reach(0)
		gates[0] <- struct{}{}
		if cookie == 1 {
			reach(1) // stage 2 has taken it and holds it at its gate
		}
	}
	require.Eventually(t, func() bool { return rc.droppedChecked.Load() == 1 }, 5*time.Second, time.Millisecond)
	assert.Zero(t, rc.droppedUnchecked.Load())

	// Two unowned clobbers: one Warn.
	for cookie := uint64(10); cookie <= 11; cookie++ {
		ev := tlsHello(cookie, 1000, l7PuntNewConn)
		l.onSample(ev)
		l.mu.Lock()
		delete(l.flows, ev.FlowKey())
		l.mu.Unlock()
		clobber(t, objs, ev, ev.Seq)
		reach(0)
		gates[0] <- struct{}{}
	}
	require.Eventually(t, func() bool { return rc.unowned.Load() == 2 }, 5*time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		return strings.Count(logs.String(), "no oracle record left to repair it from") == 1
	}, 5*time.Second, time.Millisecond)
	assert.Equal(t, 1, strings.Count(logs.String(), "L7 verdict re-check dropped"))
}
