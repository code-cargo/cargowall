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

// The verdict re-check: the oracle checks that a TCP verdict it wrote is
// still in the kernel entry a moment later, and writes it again when the
// kernel's own commit of the punt it answered overwrote it.
//
// The kernel submits a punt, then l7_commit_pending looks the flow entry up
// and writes PENDING unless it finds a terminal verdict. A verdict landing
// between that lookup and the update is overwritten with PENDING. For TCP
// nothing repairs that on its own: the client's retransmit has the same
// sequence number and length, so the kernel deduplicates it against the
// punt already sent, no stale punt reaches the oracle to re-assert, and the
// connection stalls with every retransmit dropped. (QUIC never deduplicates,
// so each retransmitted Initial re-punts and is repaired by reassertVerdict.)
//
// The clobbering update follows the verdict write within the rest of one
// run of the kernel program, microseconds, and a client's first
// retransmit is no sooner than the 200 ms minimum RTO. So the entry is read
// back about 5 ms after the write, again at about 150 ms, both before the
// first retransmit, and once more at about a second, for a commit delayed
// by a preempted or starved vCPU; a repair then still lands before the
// client's later retransmits. A commit delayed past the last read is not
// repaired: design-l7.md states that residual.

package origin

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
)

// l7RecheckDelays are the reads' delays from the verdict write, one stage
// each.
var l7RecheckDelays = []time.Duration{5 * time.Millisecond, 150 * time.Millisecond, time.Second}

// recheckBeforeWrite, when set, runs just before a repair's write, with
// l.mu held. Tests only.
var recheckBeforeWrite func(*L7)

// l7RecheckQueue bounds each stage's queue. A full queue drops the re-check,
// counted and warned once, rather than block the ring-buffer reader. A
// queue's memory is only what it holds.
const l7RecheckQueue = 4096

// l7Recheck is one verdict to check: the flow, what was written, and what
// identifies the punt it answered and the oracle's cycle that decided it.
type l7Recheck struct {
	key     bpf.OriginBpfL7FlowKey
	verdict uint8
	// seq is the deciding sample's sequence number. The commit that
	// clobbers a verdict is the commit of that very punt, so it leaves
	// last_punt_seq at this value.
	seq uint32
	// gen is the oracle's cycle (l7flow.gen) that decided.
	gen uint64
	// written is when the verdict was written; every delay runs from it.
	written time.Time
}

// recheckResult is what one read of a re-check found.
type recheckResult uint8

const (
	// recheckHeld: the entry still holds the verdict, or the repair's write
	// failed. Read again at the next stage.
	recheckHeld recheckResult = iota
	// recheckRepaired: the entry was the deciding punt's own commit, and the
	// verdict was written again.
	recheckRepaired
	// recheckSuperseded: the entry or the oracle's record belongs to a later
	// connection or cycle, or the entry is gone. Never read again.
	recheckSuperseded
	// recheckUnowned: the entry is the deciding punt's commit, but the
	// oracle holds no record of the flow (evicted from a full table), so
	// nothing vouches for the verdict. Counted and warned, never repaired.
	recheckUnowned
)

// l7Rechecker runs the stages. Each holds re-checks in due order, since
// every one in it has the same delay, and passes on to the next those
// whose entry still held the verdict.
type l7Rechecker struct {
	l      *L7
	stages []*recheckStage
	quit   chan struct{}
	wg     sync.WaitGroup
	// wait sleeps stage's worker for d, reporting false when quit closes
	// first. A field so a test can release the stages itself.
	wait func(stage int, d time.Duration) bool

	repaired         atomic.Uint64
	unowned          atomic.Uint64
	droppedUnchecked atomic.Uint64 // dropped before the first read
	droppedChecked   atomic.Uint64 // dropped after a read found the verdict in place
	warnedDrop       atomic.Bool
	warnedUnowned    atomic.Bool
}

type recheckStage struct {
	delay time.Duration
	mu    sync.Mutex
	q     []l7Recheck
	max   int
	wake  chan struct{}
}

// newL7Rechecker starts one worker per delay.
func newL7Rechecker(l *L7, delays []time.Duration, maxQueued int) *l7Rechecker {
	rc := &l7Rechecker{l: l, quit: make(chan struct{})}
	rc.wait = rc.sleep
	return rc.start(delays, maxQueued)
}

// start adds a stage per delay and starts their workers.
func (rc *l7Rechecker) start(delays []time.Duration, maxQueued int) *l7Rechecker {
	for _, d := range delays {
		rc.stages = append(rc.stages, &recheckStage{delay: d, max: maxQueued, wake: make(chan struct{}, 1)})
	}
	for i := range rc.stages {
		rc.wg.Add(1)
		go rc.run(i)
	}
	return rc
}

// push appends r, reporting false when the stage is full.
func (s *recheckStage) push(r l7Recheck) bool {
	s.mu.Lock()
	if len(s.q) >= s.max {
		s.mu.Unlock()
		return false
	}
	s.q = append(s.q, r)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return true
}

// pop takes the head, waiting for one; false once quit closes.
func (s *recheckStage) pop(quit <-chan struct{}) (l7Recheck, bool) {
	for {
		s.mu.Lock()
		if len(s.q) > 0 {
			r := s.q[0]
			s.q = s.q[1:]
			if len(s.q) == 0 {
				s.q = nil // let the backing array go
			}
			s.mu.Unlock()
			return r, true
		}
		s.mu.Unlock()
		select {
		case <-s.wake:
		case <-quit:
			return l7Recheck{}, false
		}
	}
}

// queue schedules the re-check of a TCP verdict just written. It never
// blocks: with the first stage full it drops the re-check, counts it, and
// warns the first time. Nil-safe: an oracle driven synchronously has no
// rechecker and queues nothing.
func (rc *l7Rechecker) queue(r l7Recheck) {
	if rc == nil {
		return
	}
	if !rc.stages[0].push(r) {
		rc.droppedUnchecked.Add(1)
		rc.warnDrop()
	}
}

func (rc *l7Rechecker) warnDrop() {
	if rc.warnedDrop.CompareAndSwap(false, true) && rc.l.logger != nil {
		rc.l.logger.Warn("L7 verdict re-check dropped: its queue is full, so a TCP verdict the kernel's punt " +
			"commit overwrote may go unrepaired and that connection stall under enforce; the teardown line counts them")
	}
}

// run is stage i's worker: each re-check waits out its delay from the
// write, is read, and moves to the next stage while its entry still holds
// the verdict. A stop ends the wait at once and discards the rest: once
// the oracle is closing, a repair no longer matters.
func (rc *l7Rechecker) run(i int) {
	defer rc.wg.Done()
	st := rc.stages[i]
	for {
		r, ok := st.pop(rc.quit)
		if !ok {
			return
		}
		if !rc.wait(i, time.Until(r.written.Add(st.delay))) {
			return
		}
		if rc.l.recheck(r, rc) != recheckHeld || i+1 == len(rc.stages) {
			continue
		}
		if !rc.stages[i+1].push(r) {
			rc.droppedChecked.Add(1)
			rc.warnDrop()
		}
	}
}

// sleep is the default wait.
func (rc *l7Rechecker) sleep(_ int, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-rc.quit:
		return false
	}
}

// stop ends the workers without waiting out their delays. Nil-safe.
func (rc *l7Rechecker) stop() {
	if rc == nil {
		return
	}
	close(rc.quit)
	rc.wg.Wait()
}

// statsAttrs are the counters for the oracle's teardown line. Nil-safe.
func (rc *l7Rechecker) statsAttrs() []any {
	if rc == nil {
		return nil
	}
	return []any{
		"verdicts_repaired", rc.repaired.Load(),
		"verdict_rechecks_unowned", rc.unowned.Load(),
		"verdict_rechecks_dropped_unchecked", rc.droppedUnchecked.Load(),
		"verdict_rechecks_dropped_checked", rc.droppedChecked.Load(),
	}
}

// recheck reads r's entry and re-asserts its verdict when, and only when,
// the entry is the commit of the very punt the verdict answered and the
// oracle still stands by that verdict.
//
// It holds l.mu across the read of the entry, the record check and the
// write. The oracle changes a flow's record only under l.mu, so a later
// cycle has either changed the record before this looks, and is left
// alone, or decides after this write, and overwrites it with its own
// verdict. What l.mu cannot hold off is the kernel: a later connection's
// SYN or punt landing between the read and the write, a window of one map
// update, which writeFlowState leaves open the same way.
//
// Anything else is left alone. A NEED_HELLO entry, or a PENDING one with
// another sequence number, belongs to a later connection of the socket, and
// writing the old verdict over it would admit a first flight nobody
// adjudicated. A record reset since (a NEW_CONN, NO_STATE or REPIN punt
// started a new cycle) means the verdict no longer answers for the flow.
func (l *L7) recheck(r l7Recheck, rc *l7Rechecker) recheckResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	var cur bpf.OriginBpfL7FlowVal
	if err := l.flow.Lookup(&r.key, &cur); err != nil {
		return recheckSuperseded // evicted: no entry left to strand the flow
	}
	if cur.State == r.verdict {
		return recheckHeld
	}
	if cur.State != l7StatePending || cur.LastPuntSeq != r.seq {
		return recheckSuperseded
	}
	st := l.flows[r.key]
	if st == nil {
		rc.unowned.Add(1)
		if rc.warnedUnowned.CompareAndSwap(false, true) && l.logger != nil {
			l.logger.Warn("L7 verdict overwritten by the kernel's punt commit, with no oracle record left to " +
				"repair it from (the flow table was full); that connection stalls under enforce")
		}
		return recheckUnowned
	}
	if !st.decided || st.gen != r.gen || st.verdict != r.verdict {
		return recheckSuperseded
	}
	if recheckBeforeWrite != nil {
		recheckBeforeWrite(l)
	}
	if err := l.flow.Update(r.key, bpf.OriginBpfL7FlowVal{State: r.verdict}, ebpf.UpdateAny); err != nil {
		if l.logger != nil {
			l.logger.Warn("L7 verdict repair failed; read again at the next stage", "err", err)
		}
		return recheckHeld
	}
	rc.repaired.Add(1)
	return recheckRepaired
}
