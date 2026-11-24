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
// retransmit is no sooner than the 200 ms minimum RTO. So two reads, about 5
// ms and about 150 ms after the write, both land before the client needs the
// verdict, and the second catches a commit delayed by an interrupt.

package origin

import (
	"time"

	"github.com/code-cargo/cargowall/bpf"
)

const (
	// l7RecheckFirst and l7RecheckSecond are the delays, from the verdict
	// write, of the two reads.
	l7RecheckFirst  = 5 * time.Millisecond
	l7RecheckSecond = 150 * time.Millisecond
	// l7RecheckQueue bounds each stage's queue. A full queue drops the
	// re-check, counted, rather than block the ring-buffer reader.
	l7RecheckQueue = 4096
)

// l7Recheck is one verdict to check: the flow, what was written, and what
// identifies the punt it answered and the oracle's cycle that decided it.
type l7Recheck struct {
	key     bpf.OriginBpfL7FlowKey
	verdict uint8
	// seq is the deciding sample's sequence number. The commit that
	// clobbers a verdict is the commit of that very punt, so it leaves
	// last_punt_seq at this value.
	seq uint32
	// punted is the deciding sample's kernel timestamp, for writeFlowState's
	// guard against a later connection's NEED_HELLO.
	punted uint64
	// gen is the oracle's cycle (l7flow.gen) that decided.
	gen uint64
	// written is when the verdict was written; both delays run from it.
	written time.Time
}

// queueRecheck schedules the re-check of a TCP verdict just written. It
// never blocks: with no worker (the oracle driven synchronously) it does
// nothing, and with the queue full it drops the re-check and counts it.
func (l *L7) queueRecheck(r l7Recheck) {
	if l.recheckCh == nil {
		return
	}
	select {
	case l.recheckCh <- r:
	default:
		l.recheckDropped.Add(1)
	}
}

// recheckLoop runs one stage: each re-check waits until its delay from the
// write has passed, is checked, and moves to next (the second stage) unless
// it was repaired. Both delays are constant, so each queue is in due order
// and the head is always the next one due.
func (l *L7) recheckLoop(in <-chan l7Recheck, delay time.Duration, next chan<- l7Recheck, done chan<- struct{}) {
	defer close(done)
	if next != nil {
		defer close(next)
	}
	for r := range in {
		if wait := time.Until(r.written.Add(delay)); wait > 0 {
			time.Sleep(wait)
		}
		if l.recheck(r) || next == nil {
			continue
		}
		select {
		case next <- r:
		default:
			l.recheckDropped.Add(1)
		}
	}
}

// recheck re-asserts r's verdict when, and only when, the kernel entry is
// the commit of the very punt the verdict answered and the oracle still
// stands by that verdict. Reports whether it repaired the entry.
//
// Anything else is left alone. A NEED_HELLO entry, or a PENDING one with
// another sequence number, belongs to a later connection of the socket, and
// writing the old verdict over it would admit a first flight nobody
// adjudicated. An oracle record reset since (a NEW_CONN, NO_STATE or REPIN
// punt started a new cycle) means the verdict no longer answers for the flow.
func (l *L7) recheck(r l7Recheck) bool {
	var cur bpf.OriginBpfL7FlowVal
	if err := l.flow.Lookup(&r.key, &cur); err != nil {
		return false
	}
	if cur.State != l7StatePending || cur.LastPuntSeq != r.seq {
		return false
	}
	l.mu.Lock()
	st := l.flows[r.key]
	current := st != nil && st.decided && st.gen == r.gen && st.verdict == r.verdict
	l.mu.Unlock()
	if !current {
		return false
	}
	if err := l.writeFlowState(r.key, r.verdict, nil, r.punted); err != nil {
		if l.logger != nil {
			l.logger.Warn("L7 verdict repair failed — flow will be dropped until re-adjudicated", "err", err)
		}
		return false
	}
	l.verdictsRepaired.Add(1)
	return true
}
