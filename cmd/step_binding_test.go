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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/firewall"
	"github.com/code-cargo/cargowall/pkg/steps"
)

// policyMap is map_step_policy, as the binder writes it: what it holds, or
// err for every write.
type policyMap struct {
	mu   sync.Mutex
	held map[uint32]uint32
	err  error
}

func (m *policyMap) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if m.held == nil {
		m.held = map[uint32]uint32{}
	}
	m.held[key.(uint32)] = value.(uint32)
	return nil
}

func (m *policyMap) snapshot() map[uint32]uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[uint32]uint32{}
	for k, v := range m.held {
		out[k] = v
	}
	return out
}

// stepsPolicy has two steps with rules, fetch at policy 1 and deploy at 2.
const stepsPolicy = `{"defaultAction": "deny", "rules": [], "steps": [
	{"id": "fetch", "rules": [{"type": "hostname", "value": "step.example.com"}]},
	{"id": "lint", "rules": []},
	{"id": "deploy", "rules": [{"type": "hostname", "value": "deploy.example.com"}]}
]}`

func step(id string) steps.Identity {
	return steps.Identity{StepID: id, Class: events.StepClassStep}
}

// A step is bound to the policy its id's rules sit under, once, when it is
// identified, and the DNS proxy's lookup reads it. A runner helper, an
// unknown step, a step without rules and one under another id's spelling
// are bound to nothing: they get the job's rules.
func TestStepBinder_BindsIdentifiedSteps(t *testing.T) {
	cm := config.NewConfigManager()
	loadPolicyFile(t, cm, stepsPolicy)
	m := &policyMap{}
	b := newStepBinder(cm, m, slog.New(slog.DiscardHandler))
	b.identified(7, step("fetch"))
	b.identified(8, step("deploy"))
	b.identified(9, steps.Identity{StepID: "fetch", Class: events.StepClassRunner})
	b.identified(10, steps.Identity{Class: events.StepClassUnknown})
	b.identified(11, step("lint"))
	b.identified(12, step("__run"))
	b.identified(13, step("Fetch"))
	assert.Equal(t, map[uint32]uint32{7: 1, 8: 2}, m.snapshot())

	m.held = nil
	b.identified(7, step("deploy"))
	assert.Empty(t, m.snapshot(), "bound once")
	p, ok := b.policyOf(7)
	assert.True(t, ok)
	assert.Equal(t, uint32(1), p)
	_, ok = b.policyOf(9)
	assert.False(t, ok)
}

// A binding the map refuses leaves the step with the job's rules: a full
// map is warned of once, any other refusal each time, and neither is
// looked up as bound.
func TestStepBinder_RefusedBindings(t *testing.T) {
	cm := config.NewConfigManager()
	loadPolicyFile(t, cm, stepsPolicy)
	var logs bytes.Buffer
	m := &policyMap{err: fmt.Errorf("update: %w", unix.E2BIG)}
	b := newStepBinder(cm, m, slog.New(slog.NewTextHandler(&logs, nil)))
	b.identified(7, step("fetch"))
	b.identified(8, step("deploy"))
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("the step policy map is full")))
	m.err = errors.New("no memory")
	b.identified(9, step("fetch"))
	assert.Contains(t, logs.String(), "no memory")
	for _, o := range []uint32{7, 8, 9} {
		_, ok := b.policyOf(o)
		assert.False(t, ok, "ordinal %d", o)
	}
	assert.NotContains(t, logs.String(), "Step bound")
}

// Each binding's earlier blocks are re-reported off the tracker's reader,
// by the worker, and Close waits for one under way.
func TestStepBinder_ReconcilesOffTheReader(t *testing.T) {
	cm := config.NewConfigManager()
	loadPolicyFile(t, cm, stepsPolicy)
	b := newStepBinder(cm, &policyMap{}, slog.New(slog.DiscardHandler))
	got := make(chan boundStep, 4)
	release := make(chan struct{})
	b.reconcile = func(ordinal, policy uint32, stepID string) {
		got <- boundStep{ordinal, policy, stepID}
		<-release
	}
	go b.work()
	b.identified(7, step("fetch"))
	b.identified(8, step("deploy")) // queued behind the first, which blocks
	select {
	case s := <-got:
		assert.Equal(t, boundStep{7, 1, "fetch"}, s)
	case <-time.After(5 * time.Second):
		t.Fatal("no re-report")
	}
	closed := make(chan struct{})
	go func() { b.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned with a re-report under way")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	b.identified(9, step("fetch")) // after Close: bound, never re-reported
	_, ok := b.policyOf(9)
	assert.True(t, ok)
}

// Nothing is armed without a tracker, or without step rules once they
// settled, and then the tracker keeps no identities for one.
func TestArmStepBinder_OnlyWithStepRules(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cm := config.NewConfigManager()
	loadPolicyFile(t, cm, stepsPolicy)
	assert.Nil(t, armStepBinder(cm, nil, &policyMap{}, nil, logger))
	cm.DropStepRules("L7 is not running")
	assert.Nil(t, armStepBinder(cm, &steps.Tracker{}, &policyMap{}, nil, logger))
	var none *stepBinder
	none.Close()

	cm = config.NewConfigManager()
	loadPolicyFile(t, cm, stepsPolicy)
	b := armStepBinder(cm, &steps.Tracker{}, &policyMap{}, nil, logger)
	require.NotNil(t, b)
	b.Close()
}

// The binder hands the DNS proxy its lookup: a step it binds is one the
// event pipeline's step tier opens an address for.
func TestArmStepBinder_HandsTheProxyItsLookup(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cm := config.NewConfigManager()
	loadPolicyFile(t, cm, stepsPolicy)
	srv := dns.NewServer(cm, nil, "192.0.2.1:53", "127.0.0.1:0", logger)
	fw := firewall.NewMockFirewall(t)
	fw.EXPECT().AddPolicyIP(uint32(1), mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	fw.EXPECT().Allows(uint32(1), mock.Anything, uint16(443), uint8(unix.IPPROTO_TCP)).Return(true)
	srv.SetFirewall(fw)
	ip := net.ParseIP("10.1.0.130")
	cm.RecordForwardResolution("step.example.com", ip.String())

	b := armStepBinder(cm, &steps.Tracker{}, &policyMap{}, srv, logger)
	require.NotNil(t, b)
	defer b.Close()
	ok, _ := srv.LateAllowStep(7, "step.example.com", ip, 443, unix.IPPROTO_TCP)
	assert.False(t, ok, "not bound yet")
	b.identified(7, step("fetch"))
	ok, _ = srv.LateAllowStep(7, "step.example.com", ip, 443, unix.IPPROTO_TCP)
	assert.True(t, ok, "bound, by the binder's lookup")
}

// Re-reports past the queue's room are dropped, warned of once, and the
// steps are bound all the same.
func TestStepBinder_FullQueueWarnsOnce(t *testing.T) {
	cm := config.NewConfigManager()
	loadPolicyFile(t, cm, stepsPolicy)
	var logs bytes.Buffer
	b := newStepBinder(cm, &policyMap{}, slog.New(slog.NewTextHandler(&logs, nil)))
	b.reconcile = func(uint32, uint32, string) {}
	for o := range uint32(stepBindQueue + 5) {
		b.identified(100+o, step("fetch"))
	}
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("are not re-reported as late-allowed")))
	_, ok := b.policyOf(100 + stepBindQueue + 4)
	assert.True(t, ok, "bound all the same")
}
