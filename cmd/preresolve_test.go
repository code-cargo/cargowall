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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/dns"
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

// jsonLogger logs every record to buf as a JSON line.
func jsonLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// logRecords is what a jsonLogger wrote at level.
func logRecords(t *testing.T, buf *bytes.Buffer, level slog.Level) []map[string]any {
	t.Helper()
	var records []map[string]any
	for line := range bytes.Lines(buf.Bytes()) {
		var r map[string]any
		require.NoError(t, json.Unmarshal(line, &r))
		if r[slog.LevelKey] == level.String() {
			records = append(records, r)
		}
	}
	return records
}

// An upstream that answers nothing must not hold startup past the deadline,
// however many names and peers there are to look up: every round shares it.
// What the deadline cut off is logged as a Warn.
func TestPreResolve_StalledResolverReturnsWithinDeadline(t *testing.T) {
	cm := policyTracking(t, 3*preResolveWorkers)
	sink := &recordingCacheSink{}
	stub, proxy := &stalledResolver{}, &stalledResolver{}
	var logs bytes.Buffer

	started := time.Now()
	preResolve(context.Background(), existingPeers(3*preResolveWorkers), cm, sink, stub, proxy, jsonLogger(&logs))
	elapsed := time.Since(started)

	assert.Less(t, elapsed, preResolveDeadline+time.Second, "pre-resolution outlasted its deadline")
	assert.Equal(t, 1, sink.applied, "the cache entries are applied whatever the deadline left")
	assert.Positive(t, stub.calls.Load())

	warns := logRecords(t, &logs, slog.LevelWarn)
	require.Len(t, warns, 1, "the cut-off is logged as one Warn")
	count := func(key string) float64 {
		n, ok := warns[0][key].(float64)
		require.True(t, ok, "the Warn carries %s", key)
		return n
	}
	assert.Positive(t, count("cut_off"))
	assert.Equal(t, count("cut_off"), count("peers_cut_off")+count("cache_cut_off")+count("proxy_cut_off"),
		"the Warn's total is its rounds' cut-offs")
	assert.Contains(t, warns[0][slog.MessageKey], "observed-port allows", "the Warn says what the cut-off costs")
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
	var logs bytes.Buffer

	preResolve(context.Background(), conns, cm, sink, stub, proxy, jsonLogger(&logs))

	assert.Empty(t, logRecords(t, &logs, slog.LevelWarn), "nothing was cut off, so nothing is a Warn")
	var done []any
	for _, r := range logRecords(t, &logs, slog.LevelInfo) {
		if r[slog.MessageKey] == "Pre-resolved tracked hostnames via DNS proxy" {
			done = append(done, r["resolved"], r["cut_off"])
		}
	}
	assert.Equal(t, []any{float64(names), float64(0)}, done, "the success line reports every name resolved")
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

// cachedForwardSlowPTR answers forward lookups at once, as resolved's cache
// does, and reverse lookups late, as a PTR resolved has to ask upstream for.
type cachedForwardSlowPTR struct {
	forward  map[string][]string
	ptrDelay time.Duration
}

func (r *cachedForwardSlowPTR) LookupHost(_ context.Context, host string) ([]string, error) {
	if ips, ok := r.forward[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r *cachedForwardSlowPTR) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	select {
	case <-time.After(r.ptrDelay):
		return []string{"edge-" + addr + ".cdn.example.net."}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// refusingProxy fails every lookup at once, as the proxy does for a name the
// job denies.
type refusingProxy struct{}

func (refusingProxy) LookupHost(_ context.Context, host string) ([]string, error) {
	return nil, &net.DNSError{Err: "server misbehaving", Name: host}
}

// gateRecorder records what gateExistingConnections writes.
type gateRecorder struct {
	mu   sync.Mutex
	adds map[string]gateWrite
}

type gateWrite struct {
	action config.Action
	ports  []config.Port
}

func (g *gateRecorder) AddIP(ip net.IP, action config.Action, ports []config.Port) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.adds == nil {
		g.adds = make(map[string]gateWrite)
	}
	g.adds[ip.String()+" "+string(action)] = gateWrite{action: action, ports: ports}
	return true, nil
}

// An existing connection's address that resolved has cached for a tracked
// name keeps that name, though its PTR, naming a CDN edge, lands after: the
// gate must still block the peer the job denies, and give the allowed one its
// rule's ports. Run through the real DNS server and config manager, with the
// proxy refusing, as it does a denied name.
func TestPreResolve_CachedForwardNameWinsOverLatePTR(t *testing.T) {
	https := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "denied.example.com", Action: config.ActionDeny},
		{Type: config.RuleTypeHostname, Value: "allowed.example.com", Action: config.ActionAllow, Ports: https},
	}, config.ActionDeny))
	srv := dns.NewServer(cm, nil, "127.0.0.1:1", "127.0.0.1:0", slog.New(slog.DiscardHandler))
	conns := existingConns{
		"203.0.113.5": {{Port: 8443, Protocol: config.ProtocolTCP}},
		"203.0.113.6": {{Port: 8443, Protocol: config.ProtocolTCP}},
	}
	stub := &cachedForwardSlowPTR{
		forward: map[string][]string{
			"denied.example.com":  {"203.0.113.5"},
			"allowed.example.com": {"203.0.113.6"},
		},
		ptrDelay: 30 * time.Millisecond,
	}

	preResolve(context.Background(), conns, cm, srv, stub, refusingProxy{}, quietLogger())
	gate := &gateRecorder{}
	gateExistingConnections(conns, cm, gate, nil, nil, quietLogger())

	assert.Equal(t, "denied.example.com", cm.LookupHostnameByIP("203.0.113.5"))
	assert.Equal(t, "allowed.example.com", cm.LookupHostnameByIP("203.0.113.6"))
	assert.NotContains(t, gate.adds, "203.0.113.5 allow", "the peer the job denies is blocked")
	require.Contains(t, gate.adds, "203.0.113.6 allow")
	assert.Equal(t, https, gate.adds["203.0.113.6 allow"].ports, "the allowed peer gets its rule's ports, not its observed one")
}
