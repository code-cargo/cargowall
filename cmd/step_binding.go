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
	"errors"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/steps"
)

// stepBinder binds each step the tracker identifies to the policy its own
// rules sit under, once: map_step_policy, which both hooks share and the
// bridge stamp reads, takes the step's ordinal to that policy. From then
// on the step's sockets are judged by the job's rules and then its own;
// until then, and for good if the step is never identified, by the job's
// alone. A step is identified at its first exec, after its program starts,
// so a connection it makes before is judged as the job's: once the step is
// bound, its blocks from before that its policy lets through are
// re-reported as late-allowed.
type stepBinder struct {
	configMgr *config.Manager
	policies  stepPolicyMap
	// reconcile re-reports a bound step's blocks from before its binding
	// (dns.Server.ReconcileBoundStep); nil without the DNS proxy.
	reconcile func(ordinal, policy uint32, stepID string)
	logger    *slog.Logger

	mu    sync.RWMutex
	bound map[uint32]uint32 // step ordinal to policy
	full  bool              // the map refused a binding for room, warned of once

	queue chan boundStep
	stop  chan struct{}
	done  chan struct{}
}

// stepPolicyMap is map_step_policy, as the binder writes it.
type stepPolicyMap interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

// boundStep is a binding the binder's worker re-reports blocks for.
type boundStep struct {
	ordinal, policy uint32
	stepID          string
}

// stepBindQueue bounds the bindings waiting for their re-report: a step
// bound while it is full is bound all the same, and its blocks from before
// stay as they were reported.
const stepBindQueue = 256

// armStepBinder starts binding steps, once the policy's step rules have
// settled, and only if some survived: whatever binds steps keys off the
// config manager, never a collection's gate, which a drop after the load
// leaves on. It takes the tracker's identifications over, those from before
// it included (steps.Tracker.SetOnIdentified), and hands the DNS proxy its
// lookup for the per-step late-allows. It returns nil, whose Close does
// nothing, when nothing is bound.
func armStepBinder(configMgr *config.Manager, tracker *steps.Tracker, policies stepPolicyMap, dnsServer *dns.Server,
	logger *slog.Logger,
) *stepBinder {
	if tracker == nil {
		return nil
	}
	if !configMgr.HasStepRules() {
		tracker.SetOnIdentified(nil)
		return nil
	}
	b := newStepBinder(configMgr, policies, logger)
	if dnsServer != nil {
		b.reconcile = dnsServer.ReconcileBoundStep
		dnsServer.SetStepBindings(b.policyOf)
	}
	go b.work()
	tracker.SetOnIdentified(b.identified)
	return b
}

func newStepBinder(configMgr *config.Manager, policies stepPolicyMap, logger *slog.Logger) *stepBinder {
	return &stepBinder{
		configMgr: configMgr,
		policies:  policies,
		logger:    logger,
		bound:     make(map[uint32]uint32),
		queue:     make(chan boundStep, stepBindQueue),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// identified binds a step the tracker identified to its policy, if its id
// has rules, once. It runs on the tracker's step-event reader, so it must
// not block: the re-report is the worker's.
func (b *stepBinder) identified(ordinal uint32, id steps.Identity) {
	if id.Class != events.StepClassStep {
		return
	}
	policy, ok := b.configMgr.StepPolicy(id.StepID)
	if !ok {
		return
	}
	b.mu.Lock()
	if _, held := b.bound[ordinal]; held {
		b.mu.Unlock()
		return
	}
	err := b.policies.Update(ordinal, policy, ebpf.UpdateAny)
	switch {
	case err == nil:
		b.bound[ordinal] = policy
	case errors.Is(err, unix.E2BIG) && b.full:
	case errors.Is(err, unix.E2BIG):
		b.full = true
		b.logger.Warn("Step not bound to its policy: the step policy map is full; this step and later ones get the job's rules",
			"step", id.StepID, "step_ordinal", ordinal, "policy", policy)
	default:
		b.logger.Warn("Step not bound to its policy; it gets the job's rules",
			"step", id.StepID, "step_ordinal", ordinal, "policy", policy, "error", err)
	}
	b.mu.Unlock()
	if err != nil {
		return
	}
	b.logger.Info("Step bound to its policy", "step", id.StepID, "step_ordinal", ordinal, "policy", policy)
	if b.reconcile == nil {
		return
	}
	select {
	case b.queue <- boundStep{ordinal: ordinal, policy: policy, stepID: id.StepID}:
	case <-b.stop:
	default:
		b.logger.Debug("Bound step's earlier blocks not re-reported: the queue is full", "step", id.StepID)
	}
}

// policyOf is the policy step ordinal is bound to: the DNS proxy's lookup
// (dns.Server.SetStepBindings). It takes only the binder's own lock, never
// held while blocks are consumed.
func (b *stepBinder) policyOf(ordinal uint32) (uint32, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	policy, ok := b.bound[ordinal]
	return policy, ok
}

// work re-reports each bound step's earlier blocks, until Close.
func (b *stepBinder) work() {
	defer close(b.done)
	for {
		select {
		case s := <-b.queue:
			b.reconcile(s.ordinal, s.policy, s.stepID)
		case <-b.stop:
			return
		}
	}
}

// Close stops the re-reports, and waits for one under way, so the audit
// logger, closed after, is still there for it. Nil-safe.
func (b *stepBinder) Close() {
	if b == nil {
		return
	}
	close(b.stop)
	<-b.done
}
