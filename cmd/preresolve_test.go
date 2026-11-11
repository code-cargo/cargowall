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
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
)

// stalledResolver never answers: every lookup waits for its context to end,
// the way a lookup does when the upstream drops every query.
type stalledResolver struct{ calls atomic.Int64 }

func (r *stalledResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	r.calls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r *stalledResolver) LookupHost(ctx context.Context, _ string) ([]string, error) {
	r.calls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

// answeringResolver answers every lookup at once.
type answeringResolver struct {
	mu    sync.Mutex
	hosts []string
}

func (r *answeringResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return []string{"peer-" + addr + ".example."}, nil
}

func (r *answeringResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, host)
	r.mu.Unlock()
	return []string{"192.0.2.10"}, nil
}

type recordingCacheSink struct {
	mu      sync.Mutex
	answers map[string][]string
	applied int
}

func (s *recordingCacheSink) RecordSystemCacheAnswer(hostname string, ips []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.answers == nil {
		s.answers = make(map[string][]string)
	}
	s.answers[hostname] = ips
}

func (s *recordingCacheSink) ApplyRulesToTrackedHostnames() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied++
}

// policyTracking returns a manager tracking n hostnames, more than one round
// of workers.
func policyTracking(t *testing.T, n int) *config.Manager {
	t.Helper()
	rules := make([]config.Rule, n)
	for i := range rules {
		rules[i] = config.Rule{Type: config.RuleTypeHostname, Value: fmt.Sprintf("host%d.example.com", i), Action: config.ActionAllow}
	}
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionDeny))
	require.Len(t, cm.GetTrackedHostnames(), n)
	return cm
}

func existingPeers(n int) existingConns {
	conns := make(existingConns, n)
	for i := range n {
		conns[fmt.Sprintf("198.51.100.%d", i+1)] = []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	}
	return conns
}

// An upstream that answers nothing must not hold startup past the deadline,
// however many names and peers there are to look up: every round shares it.
func TestPreResolve_StalledResolverReturnsWithinDeadline(t *testing.T) {
	cm := policyTracking(t, 3*preResolveWorkers)
	sink := &recordingCacheSink{}
	stub, proxy := &stalledResolver{}, &stalledResolver{}

	started := time.Now()
	preResolve(context.Background(), existingPeers(3*preResolveWorkers), cm, sink, stub, proxy, slog.Default())
	elapsed := time.Since(started)

	assert.Less(t, elapsed, preResolveDeadline+time.Second, "pre-resolution outlasted its deadline")
	assert.Equal(t, 1, sink.applied, "the cache entries are applied whatever the deadline left")
	assert.Positive(t, stub.calls.Load())
}

// A shutdown signal during startup drains pre-resolution at once.
func TestPreResolve_CancelledContextReturnsAtOnce(t *testing.T) {
	cm := policyTracking(t, 3*preResolveWorkers)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	preResolve(ctx, existingPeers(8), cm, &recordingCacheSink{}, &stalledResolver{}, &stalledResolver{}, slog.Default())
	assert.Less(t, time.Since(started), time.Second)
}

// With an upstream that answers, pre-resolution still does all it did when
// it ran one lookup at a time: every peer named, every cached answer
// recorded and applied, every tracked name resolved through the proxy.
func TestPreResolve_HealthyResolverPopulatesEverything(t *testing.T) {
	const names = 3 * preResolveWorkers
	cm := policyTracking(t, names)
	conns := existingPeers(names)
	sink := &recordingCacheSink{}
	stub, proxy := &answeringResolver{}, &answeringResolver{}

	preResolve(context.Background(), conns, cm, sink, stub, proxy, slog.Default())

	for ip := range conns {
		assert.Equal(t, "peer-"+ip+".example", cm.LookupHostnameByIP(ip))
	}
	assert.Len(t, sink.answers, names)
	assert.Equal(t, 1, sink.applied)
	assert.ElementsMatch(t, stub.hosts, proxy.hosts, "phase 2 resolves the same names phase 1 read")
	assert.Len(t, proxy.hosts, names)
}

func TestLookupEach_BoundsConcurrencyAndCountsCutOff(t *testing.T) {
	items := make([]string, 5*preResolveWorkers)
	for i := range items {
		items[i] = fmt.Sprint(i)
	}

	var inFlight, peak atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	ok, cutOff := lookupEach(ctx, items, time.Hour, func(ctx context.Context, _ string) bool {
		n := inFlight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-ctx.Done()
		inFlight.Add(-1)
		return false
	})

	assert.LessOrEqual(t, peak.Load(), int64(preResolveWorkers))
	assert.Zero(t, ok)
	assert.Equal(t, len(items), cutOff, "every lookup was still running, or never started, when the deadline passed")
}

func TestLookupEach_PerLookupBoundIsNotACutOff(t *testing.T) {
	items := []string{"a", "b", "c"}
	ok, cutOff := lookupEach(context.Background(), items, 10*time.Millisecond, func(ctx context.Context, item string) bool {
		if item == "a" {
			return true
		}
		<-ctx.Done()
		return false
	})
	assert.Equal(t, 1, ok)
	assert.Zero(t, cutOff, "a lookup that timed out on its own bound is a failed lookup, not a cut-off one")
}
