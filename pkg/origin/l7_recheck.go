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
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
)

// l7RecheckDelays are the reads' delays from the verdict write, one stage
// each.
var l7RecheckDelays = []time.Duration{5 * time.Millisecond, 150 * time.Millisecond, time.Second}

// l7RecheckRate is the sustained rate of TCP verdicts the stages are sized
// for. An entry stays in a stage for that stage's delay less the one
// before (5 ms, 145 ms, 850 ms), so each holds at most this rate times that
// span, and l7RecheckMinQueue at the least. Past it a re-check is dropped,
// counted and warned once, rather than block the ring-buffer reader. A
// queue's memory is only what it holds.
const (
	l7RecheckRate     = 16384
	l7RecheckMinQueue = 1024
)

// recheckStageCaps sizes each stage by how long entries stay in it.
func recheckStageCaps(delays []time.Duration) []int {
	caps := make([]int, len(delays))
	var prev time.Duration
	for i, d := range delays {
		caps[i] = max(l7RecheckMinQueue, int(float64(l7RecheckRate)*(d-prev).Seconds()+0.5))
		prev = d
	}
	return caps
}

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
	// recheckHeld: the entry still holds the verdict. Read again at the
	// next stage.
	recheckHeld recheckResult = iota
	// recheckRepaired: the entry was the deciding punt's own commit, and the
	// verdict was written again.
	recheckRepaired
	// recheckSuperseded: the entry or the oracle's record belongs to a later
	// connection or cycle, or the entry is gone. Never read again.
	recheckSuperseded
	// recheckFailed: the read or the repair's write failed. Counted, warned
	// once, and read again at the next stage, if there is one.
	recheckFailed
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
	// beforeWrite, when set, runs just before a repair's write, with l.mu
	// held. Tests only.
	beforeWrite func()

	repaired         atomic.Uint64
	unowned          atomic.Uint64
	failed           atomic.Uint64 // reads and repair writes that failed
	droppedUnchecked atomic.Uint64 // dropped before the first read
	droppedChecked   atomic.Uint64 // dropped after a read found the verdict in place
	warnedDrop       atomic.Bool
	warnedUnowned    atomic.Bool
	warnedFailed     atomic.Bool
}

type recheckStage struct {
	delay time.Duration
	mu    sync.Mutex
	q     []l7Recheck
	max   int
	wake  chan struct{}
}

// newL7Rechecker starts one worker per delay, each stage sized by how long
// its entries stay (recheckStageCaps).
func newL7Rechecker(l *L7, delays []time.Duration) *l7Rechecker {
	rc := &l7Rechecker{l: l, quit: make(chan struct{})}
	rc.wait = rc.sleep
	return rc.start(delays, recheckStageCaps(delays))
}

// start adds a stage per delay, holding at most caps[i], and starts their
// workers.
func (rc *l7Rechecker) start(delays []time.Duration, caps []int) *l7Rechecker {
	for i, d := range delays {
		rc.stages = append(rc.stages, &recheckStage{delay: d, max: caps[i], wake: make(chan struct{}, 1)})
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
	rc.warnOnce(&rc.warnedDrop, "L7 verdict re-check dropped: its queue is full, so a TCP verdict the kernel's "+
		"punt commit overwrote may go unrepaired and that connection stall under enforce; the teardown line counts them")
}

// warnOnce logs msg the first time flag is set. Never called with l.mu held.
func (rc *l7Rechecker) warnOnce(flag *atomic.Bool, msg string) {
	if flag.CompareAndSwap(false, true) && rc.l.logger != nil {
		rc.l.logger.Warn(msg)
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
		switch rc.recheck(r) {
		case recheckUnowned:
			rc.warnOnce(&rc.warnedUnowned, "L7 verdict overwritten by the kernel's punt commit, with no oracle "+
				"record left to repair it from (the flow table was full); that connection stalls under enforce")
			continue
		case recheckFailed:
			rc.warnOnce(&rc.warnedFailed, "L7 verdict re-check failed to read or repair its flow entry; a TCP "+
				"verdict the kernel's punt commit overwrote may go unrepaired; the teardown line counts them")
		case recheckHeld:
		default: // repaired or superseded: done
			continue
		}
		if i+1 == len(rc.stages) {
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
		"verdict_rechecks_failed", rc.failed.Load(),
		"verdict_rechecks_dropped_unchecked", rc.droppedUnchecked.Load(),
		"verdict_rechecks_dropped_checked", rc.droppedChecked.Load(),
	}
}

// recheck reads r's entry and re-asserts its verdict when, and only when,
// the entry is the commit of the very punt the verdict answered and the
// oracle still stands by that verdict.
//
// The first read is unlocked: all but about one in a thousand find the
// verdict in place, and the punt reader needs l.mu for every punt. Only an
// entry showing the deciding punt's PENDING takes l.mu, and is read again
// under it, with the record check and the write. The oracle changes a
// flow's record only under l.mu, so a later cycle has either changed the
// record before this looks, and is left alone, or decides after this
// write, and overwrites it with its own verdict. What l.mu cannot hold off
// is the kernel: a later connection's SYN or punt landing between the read
// and the write, a window of one map update, which writeFlowState leaves
// open the same way.
//
// Anything else is left alone. A NEED_HELLO entry, or a PENDING one with
// another sequence number, belongs to a later connection of the socket, and
// writing the old verdict over it would admit a first flight nobody
// adjudicated. A record whose cycle number differs (a NEW_CONN, NO_STATE or
// REPIN punt started a new cycle; a reset zeroes it, and each decision
// draws a fresh one) means the verdict no longer answers for the flow.
func (rc *l7Rechecker) recheck(r l7Recheck) recheckResult {
	l := rc.l
	if res, clobbered := rc.read(r); !clobbered {
		return res
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if res, clobbered := rc.read(r); !clobbered {
		return res
	}
	st := l.flows[r.key]
	if st == nil {
		rc.unowned.Add(1)
		return recheckUnowned
	}
	if st.gen != r.gen {
		return recheckSuperseded
	}
	if rc.beforeWrite != nil {
		rc.beforeWrite()
	}
	if err := l.flow.Update(r.key, bpf.OriginBpfL7FlowVal{State: r.verdict}, ebpf.UpdateAny); err != nil {
		rc.failed.Add(1)
		return recheckFailed
	}
	rc.repaired.Add(1)
	return recheckRepaired
}

// read looks r's entry up and reports whether it is the deciding punt's
// own commit (PENDING with its sequence number); otherwise what that makes
// the re-check. Only a missing entry means evicted: any other lookup error
// is a failure, read again at the next stage.
func (rc *l7Rechecker) read(r l7Recheck) (recheckResult, bool) {
	var cur bpf.OriginBpfL7FlowVal
	if err := rc.l.flow.Lookup(&r.key, &cur); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return recheckSuperseded, false // evicted: no entry left to strand the flow
		}
		rc.failed.Add(1)
		return recheckFailed, false
	}
	if cur.State == r.verdict {
		return recheckHeld, false
	}
	if cur.State != l7StatePending || cur.LastPuntSeq != r.seq {
		return recheckSuperseded, false
	}
	return 0, true
}
