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
	"sync"
	"time"

	"github.com/code-cargo/cargowall/pkg/podenv"
)

// scopeDecision is the hook's scope over a daemon still to come up at
// startup, left for it to decide once it answers. Where the scope reads the
// daemon's runtime (podenv.Shape.HookScopeOrPending), one that has not
// answered has shown nothing of where its containers' tasks will be, and has
// made none yet: the hook loads at once with the scope every other rule
// gives, which never reaches a task outside our pid namespace, and the
// daemon's rules are decided when it answers its tracker (daemonAnswered),
// probing it again until it answers the probe too. They confirm the hook,
// or find that the daemon's containers fall outside its scope: they go
// unjudged by it, which loses the posture (postureLedger.loseLate), while
// the hook, and the L7 layer riding it, stay up for everything the scope
// does reach. The decision waits for startup to be done (ready): a refusal
// it names in the failure sentinel must come after the ready one, or a
// reader waiting on either would take it for a refused startup. At
// teardown, one still undecided is settled by what is known (closeScope).
type scopeDecision struct {
	// shape is what startup found, whose daemon is probed again (Recheck)
	// when it answers. Set before the hook is shared, read-only after.
	shape podenv.Shape

	mu sync.Mutex
	// pending is whether the daemon's rules are still to decide; answered
	// whether it has answered its tracker; started whether startup is
	// done; deciding whether a recheck is running or waiting to run again
	// (retry); closing whether teardown has begun, after which no recheck
	// starts; closed whether it is done, after which nothing is decided.
	pending, answered, started, deciding, closing, closed bool
	// probing is closed when the recheck running ends, nil while none
	// runs. backoff is how long the last wait before another recheck was,
	// 0 until a recheck has found the daemon still to come up, and retry
	// its timer, stopped at teardown.
	probing chan struct{}
	backoff time.Duration
	retry   *time.Timer
}

// recheckShape is the shape with its daemon probed again
// (podenv.Shape.Recheck), or a test's stand-in.
var recheckShape = func(s podenv.Shape) podenv.Shape { return s.Recheck(dockerSocket) }

// How long a recheck that found a daemon which has answered its tracker
// still to come up waits to probe it again: from recheckRetry, doubling to
// recheckRetryMax. The tracker's event stream stays up once connected, so
// its next connect cannot be what decides.
var recheckRetry, recheckRetryMax = 250 * time.Millisecond, 5 * time.Second

// recheckAtTeardown is how long teardown waits for a recheck still running
// to decide: one of a daemon that answers takes milliseconds, while one
// that does not would hold teardown for its every timeout.
var recheckAtTeardown = 3 * time.Second

// daemonAnswered is the tracker's report that the daemon answered. Nil-safe.
func (a *containerAttribution) daemonAnswered() {
	if a == nil {
		return
	}
	a.scope.mu.Lock()
	defer a.scope.mu.Unlock()
	a.scope.answered = true
	a.decideLocked()
}

// ready reports that startup is done, its ready sentinel written. Nil-safe.
func (a *containerAttribution) ready() {
	if a == nil {
		return
	}
	a.scope.mu.Lock()
	defer a.scope.mu.Unlock()
	a.scope.started = true
	a.decideLocked()
}

// decideLocked starts the recheck once the daemon has answered and startup
// is done, unless one is running or waiting to, there is nothing left to
// decide, or teardown has begun.
func (a *containerAttribution) decideLocked() {
	d := &a.scope
	if !d.pending || !d.answered || !d.started || d.deciding || d.closing || d.closed {
		return
	}
	d.deciding = true
	a.recheckLocked()
}

// recheckLocked runs a recheck off the caller's goroutine, the tracker's
// or a timer's: it asks the daemon over the socket.
func (a *containerAttribution) recheckLocked() {
	a.scope.probing = make(chan struct{})
	go a.decide()
}

// retryRecheck is the timer's: the next recheck, unless teardown has begun.
func (a *containerAttribution) retryRecheck() {
	d := &a.scope
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing || d.closed {
		d.deciding = false
		return
	}
	a.recheckLocked()
}

// decide probes the daemon again and decides its rules: confirmed, or
// lost. A daemon that answered its tracker but not the probe is probed
// again on its own (recheckRetry), until its rules are decided or teardown
// ends the decision, whatever the tracker connects meanwhile. A decision is
// recorded under mu, which teardown takes before it reads what was decided.
func (a *containerAttribution) decide() {
	shape := recheckShape(a.scope.shape)
	_, pending, err := shape.HookScopeOrPending()
	d := &a.scope
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		close(d.probing)
		d.probing = nil
	}()
	switch {
	case d.closed: // teardown stopped waiting for it
	case pending:
		d.backoff = min(max(2*d.backoff, recheckRetry), recheckRetryMax)
		if d.closing {
			break // teardown is waiting, and decides
		}
		a.logger.Debug("Docker answered its tracker but not the probe that decides the container egress hook's scope "+
			"over its containers; probing again", "in", d.backoff, "reason", shape.Dockerd.Reason)
		d.retry = time.AfterFunc(d.backoff, a.retryRecheck)
		return // still deciding
	case err != nil:
		d.pending = false
		a.postures.loseLate(postureContainerEgress, "once Docker answered: "+a.postures.errReason(err))
	default:
		d.pending = false
		a.logger.Info("Container egress hook confirmed once Docker answered: its containers are within the hook's scope",
			"dockerd", shape.Dockerd.Kind.String(), "dockerd_runtime", shape.Dockerd.Runtime)
	}
	d.deciding = false
}

// closeScope ends the decision at teardown. A recheck still running is
// waited for, within recheckAtTeardown and outside mu, and decides as it
// would have; nothing is decided after. One still undecided is settled by
// what is known. Before startup was done nothing was put to use, and there
// is nothing to say. A daemon that never answered its tracker made no
// container, and the posture stands as applied. One that did, then never
// answered the probe, or whose probe had not finished, may have had
// containers outside the hook's scope, so the posture is lost.
func (a *containerAttribution) closeScope() {
	d := &a.scope
	d.mu.Lock()
	d.closing = true
	if d.retry != nil {
		d.retry.Stop()
	}
	probing := d.probing
	d.mu.Unlock()
	finished := true
	if probing != nil {
		select {
		case <-probing:
		case <-time.After(recheckAtTeardown):
			finished = false
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	switch {
	case !d.pending || !d.started:
	case !d.answered:
		a.logger.Info("Docker never answered its tracker while cargowall ran: the container egress hook judged this " +
			"job's traffic throughout, and no container of the daemon's can have run, so the posture stands as applied")
	case !finished:
		a.postures.loseLate(postureContainerEgress, "Docker answered its tracker, but the probe that decides the "+
			"hook's scope over its containers had not finished by teardown")
	default:
		a.postures.loseLate(postureContainerEgress, "Docker answered its tracker, but not the probe that decides "+
			"the hook's scope over its containers, before teardown")
	}
}
