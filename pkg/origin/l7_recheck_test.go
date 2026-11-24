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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// recheckOracle is an oracle driven synchronously whose re-checks are
// collected rather than run, so a test can clobber the kernel entry and run
// each check itself.
func recheckOracle(t *testing.T, queue int) (*L7, *bpf.OriginBpfObjects) {
	t.Helper()
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{"auth.docker.io": true, "example.com": true}}, nil)
	l.recheckCh = make(chan l7Recheck, queue)
	return l, objs
}

func tlsHello(cookie uint64, seq uint32, flags uint8) *bpf.L7Event {
	ev := makeL7Event(443, seq, snitest.BuildClientHello("auth.docker.io"), false)
	ev.Cookie = cookie
	ev.Timestamp = 5000
	ev.Flags |= flags
	return ev
}

func entry(t *testing.T, objs *bpf.OriginBpfObjects, ev *bpf.L7Event) bpf.OriginBpfL7FlowVal {
	t.Helper()
	var v bpf.OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &v))
	return v
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
	l.onSample(ev)
	select {
	case r := <-l.recheckCh:
		return r
	default:
		t.Fatal("a TCP verdict queued no re-check")
		return l7Recheck{}
	}
}

// The commit of the very punt the verdict answered wrote PENDING over it:
// the re-check writes the verdict again, and counts it.
func TestL7RecheckRepairsClobberedVerdict(t *testing.T) {
	l, objs := recheckOracle(t, 4)
	ev := tlsHello(1, 1000, l7PuntNewConn)
	r := decide(t, l, ev)
	require.Equal(t, l7StateAllowed, entry(t, objs, ev).State)

	// Not clobbered: nothing to do.
	require.False(t, l.recheck(r))
	require.Zero(t, l.verdictsRepaired.Load())

	clobber(t, objs, ev, ev.Seq)
	require.True(t, l.recheck(r))
	require.Equal(t, l7StateAllowed, entry(t, objs, ev).State)
	require.Equal(t, uint64(1), l.verdictsRepaired.Load())

	// A denial is repaired the same way.
	l.matcher = allowSet{}
	denied := tlsHello(2, 2000, l7PuntNewConn)
	r = decide(t, l, denied)
	clobber(t, objs, denied, denied.Seq)
	require.True(t, l.recheck(r))
	require.Equal(t, l7StateDenied, entry(t, objs, denied).State)
}

// A PENDING entry with another sequence number, or a NEED_HELLO entry,
// belongs to a later connection of the socket: the old verdict must not
// land on it.
func TestL7RecheckLeavesOtherEntriesAlone(t *testing.T) {
	l, objs := recheckOracle(t, 4)
	ev := tlsHello(1, 1000, l7PuntNewConn)
	r := decide(t, l, ev)

	clobber(t, objs, ev, ev.Seq+7)
	require.False(t, l.recheck(r))
	require.Equal(t, l7StatePending, entry(t, objs, ev).State, "another punt's PENDING is left alone")

	require.NoError(t, objs.MapL7Flow.Put(ev.FlowKey(), bpf.OriginBpfL7FlowVal{State: l7StateNeedHello, Ts: 9000}))
	require.False(t, l.recheck(r))
	require.Equal(t, l7StateNeedHello, entry(t, objs, ev).State, "a NEED_HELLO is left alone")

	require.NoError(t, objs.MapL7Flow.Delete(ev.FlowKey()))
	require.False(t, l.recheck(r), "an evicted entry is left alone")
	require.Zero(t, l.verdictsRepaired.Load())
}

// A punt that reset the oracle's record since the verdict (a later
// connection's NEW_CONN, a NO_STATE after eviction) means the verdict no
// longer answers for the flow, even where the entry looks like its clobber.
func TestL7RecheckSkipsAResetFlow(t *testing.T) {
	l, objs := recheckOracle(t, 4)

	// Reset and decided again, with the same verdict: another cycle.
	ev := tlsHello(1, 1000, l7PuntNewConn)
	r := decide(t, l, ev)
	_ = decide(t, l, tlsHello(1, 3000, l7PuntNewConn))
	clobber(t, objs, ev, ev.Seq)
	require.False(t, l.recheck(r), "a later cycle owns the flow")

	// Reset and still assembling.
	ev = tlsHello(2, 1000, l7PuntNewConn)
	r = decide(t, l, ev)
	partial := makeL7Event(443, 5000, snitest.BuildClientHello("auth.docker.io")[:20], false)
	partial.Cookie = 2
	partial.Flags |= l7PuntNoState
	l.onSample(partial)
	clobber(t, objs, ev, ev.Seq)
	require.False(t, l.recheck(r), "an undecided cycle owns the flow")
	require.Zero(t, l.verdictsRepaired.Load())
}

// A full queue drops the re-check and counts it; onSample never blocks on
// it. QUIC queues none: its retransmits re-punt.
func TestL7RecheckQueueFullDoesNotBlock(t *testing.T) {
	l, _ := recheckOracle(t, 1)
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
	require.Len(t, l.recheckCh, 1)
	require.Equal(t, uint64(2), l.recheckDropped.Load())

	<-l.recheckCh
	l.onSample(makeL7Event(443, 0, snitest.RFC9001ClientInitial(), true))
	require.Empty(t, l.recheckCh, "a QUIC verdict queues no re-check")
}

// The two stages run on their delays: a clobber before the first read is
// repaired by it, and one between the reads by the second.
func TestL7RecheckLoopStages(t *testing.T) {
	l, objs := recheckOracle(t, 4)
	in := l.recheckCh
	second := make(chan l7Recheck, 4)
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	go l.recheckLoop(in, l7RecheckFirst, second, firstDone)
	go l.recheckLoop(second, l7RecheckSecond, nil, secondDone)
	t.Cleanup(func() {
		close(in)
		<-firstDone
		<-secondDone
	})

	early := tlsHello(1, 1000, l7PuntNewConn)
	l.onSample(early) // queues its re-check
	clobber(t, objs, early, early.Seq)
	require.Eventually(t, func() bool { return entry(t, objs, early).State == l7StateAllowed },
		l7RecheckFirst+100*time.Millisecond, time.Millisecond, "the first read repairs an early clobber")
	require.Equal(t, uint64(1), l.verdictsRepaired.Load())

	late := tlsHello(2, 1000, l7PuntNewConn)
	l.onSample(late)
	time.Sleep(l7RecheckFirst + 20*time.Millisecond) // past the first read
	clobber(t, objs, late, late.Seq)
	require.Eventually(t, func() bool { return entry(t, objs, late).State == l7StateAllowed },
		l7RecheckSecond+100*time.Millisecond, time.Millisecond, "the second read repairs a late clobber")
	require.Equal(t, uint64(2), l.verdictsRepaired.Load())
}
