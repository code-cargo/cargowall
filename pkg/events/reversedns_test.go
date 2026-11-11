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

package events

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

// fakeClock is a settable time source for the tracker.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// scriptedResolver answers LookupAddr from a script, one entry per call; the
// last entry repeats. It records when each call happened. The retry worker
// calls it from its own goroutine.
type scriptedResolver struct {
	clock   *fakeClock
	results []scriptedAnswer
	mu      sync.Mutex
	calls   []time.Time
}

type scriptedAnswer struct {
	names []string
	err   error
}

func (r *scriptedResolver) LookupAddr(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, r.clock.now())
	a := r.results[min(len(r.calls), len(r.results))-1]
	return a.names, a.err
}

func (r *scriptedResolver) callTimes() []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

var (
	errPTRTimeout  = &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsTemporary: true}
	errPTRNotFound = &net.DNSError{Err: "no such host", IsNotFound: true}
)

// useScriptedReverseDNS swaps the package's tracker, resolver and retry
// worker for ones the test drives, restoring them when the test ends.
func useScriptedReverseDNS(t *testing.T, answers ...scriptedAnswer) (*fakeClock, *scriptedResolver) {
	t.Helper()
	clock := newFakeClock()
	res := &scriptedResolver{clock: clock, results: answers}
	prevTracker, prevResolver, prevRetries := reverseDNS, reverseDNSResolver, reverseDNSRetries
	reverseDNS = newReverseDNSTracker(reverseDNSCacheMax, clock.now)
	reverseDNSResolver = res
	reverseDNSRetries = newReverseDNSRetrier(reverseDNS, res, reverseDNSRetryQueue)
	retries := reverseDNSRetries
	t.Cleanup(func() {
		retries.wait()
		close(retries.queue)
		reverseDNS, reverseDNSResolver, reverseDNSRetries = prevTracker, prevResolver, prevRetries
	})
	return clock, res
}

// builderPolicy allows remote build machines only by their reverse names,
// the shape a client that dials its builder by IP needs.
func builderPolicy(t *testing.T) *config.Manager {
	t.Helper()
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "*.compute-1.amazonaws.com",
		Action: config.ActionAllow,
		Ports:  []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
	}}, config.ActionDeny))
	return cm
}

const builderIP = "198.51.100.7"

func builderDrop() VerdictRecord {
	return VerdictRecord{
		SrcIP: "10.1.0.5", DstIP: builderIP, SrcPort: 40001, DstPort: 443,
		Proto: unix.IPPROTO_TCP, Dropped: true,
	}
}

// reportBuilderDrop reports one dropped builder dial, through the cgroup
// hook's path, and returns its audit event.
func reportBuilderDrop(t *testing.T, cm *config.Manager, fw *mockFirewallUpdater) AuditEvent {
	t.Helper()
	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	ReportVerdict(builderDrop(), cm, nil, auditLogger, fw, nil, newTestLogger())
	require.Len(t, sink.events, 1)
	return sink.events[0]
}

// processBuilderSYN reports one TC event for a dial to the builder, denied
// or allowed, and returns its audit event.
func processBuilderSYN(t *testing.T, cm *config.Manager, fw *mockFirewallUpdater, allowed bool) AuditEvent {
	t.Helper()
	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	ev := BpfBlockedEvent{
		IpVersion: 4, IpProto: unix.IPPROTO_TCP,
		SrcIp: ipv4ToUint32("10.1.0.5"), DstIp: ipv4ToUint32(builderIP), SrcPort: 40001, DstPort: 443,
	}
	if allowed {
		ev.Allowed = 1
	}
	processEvent(makeBpfEvent(ev), cm, nil, auditLogger, fw, nil, newTestLogger(), nil)
	require.Len(t, sink.events, 1)
	return sink.events[0]
}

// A reverse lookup that times out must not be the last word. Once the
// backoff passes, a drop of the same destination has it looked up again, on
// the retry worker. The drop itself is judged without a name; the name the
// retry finds is in the cache for the next drop, which the rule late-allows.
func TestReportVerdict_PTRTimeoutThenSuccessLateAllows(t *testing.T) {
	clock, res := useScriptedReverseDNS(t,
		scriptedAnswer{err: errPTRTimeout},
		scriptedAnswer{names: []string{"ec2-198-51-100-7.compute-1.amazonaws.com."}},
	)
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}

	ev := reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionBlocked, ev.EventType)
	assert.Empty(t, ev.DstHostname, "the timed-out lookup found no name")

	ev = reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionBlocked, ev.EventType, "inside the backoff: no second lookup yet")
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), 1)

	clock.advance(reverseDNSBaseBackoff)
	ev = reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionBlocked, ev.EventType, "the retry runs off the reporting path")
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), 2)
	assert.Empty(t, fw.addedIPs)

	ev = reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionLateAllowed, ev.EventType)
	assert.Equal(t, "*.compute-1.amazonaws.com", ev.MatchedRule)
	assert.Equal(t, "ec2-198-51-100-7.compute-1.amazonaws.com", ev.DstHostname)
	require.Len(t, fw.addedIPs, 1)
	assert.True(t, fw.addedIPs[0].ip.Equal(net.ParseIP(builderIP)))
	assert.Len(t, res.callTimes(), 2, "the late-allow came from the cache")
}

// The same on the TC path, whose events are prepared on the ring-buffer
// reader.
func TestProcessEvent_PTRTimeoutThenSuccessLateAllows(t *testing.T) {
	clock, res := useScriptedReverseDNS(t,
		scriptedAnswer{err: errPTRTimeout},
		scriptedAnswer{names: []string{"ec2-198-51-100-7.compute-1.amazonaws.com."}},
	)
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}

	assert.Equal(t, EventConnectionBlocked, processBuilderSYN(t, cm, fw, false).EventType)
	clock.advance(reverseDNSBaseBackoff)
	assert.Equal(t, EventConnectionBlocked, processBuilderSYN(t, cm, fw, false).EventType)
	reverseDNSRetries.wait()

	ev := processBuilderSYN(t, cm, fw, false)
	assert.Equal(t, EventConnectionLateAllowed, ev.EventType)
	assert.Equal(t, "*.compute-1.amazonaws.com", ev.MatchedRule)
	require.Len(t, fw.addedIPs, 1)
	assert.Len(t, res.callTimes(), 2)
}

// A name only labels an allowed connection; it late-allows nothing. An
// allowed destination whose lookup fails therefore keeps its single lookup,
// however long its allowed traffic goes on.
func TestProcessEvent_AllowedIPWithFailingPTRIsLookedUpOnce(t *testing.T) {
	clock, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRTimeout})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}

	for range 20 {
		assert.Equal(t, EventConnectionAllowed, processBuilderSYN(t, cm, fw, true).EventType)
		clock.advance(time.Minute)
	}
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), 1)
	assert.Empty(t, fw.addedIPs)
}

// An authoritative "no such name" is an answer: the IP is not looked up
// again, however long the run goes on.
func TestReportVerdict_PTRNotFoundIsNotRetried(t *testing.T) {
	clock, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRNotFound})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}

	reportBuilderDrop(t, cm, fw)
	clock.advance(time.Hour)
	ev := reportBuilderDrop(t, cm, fw)
	reverseDNSRetries.wait()

	assert.Equal(t, EventConnectionBlocked, ev.EventType)
	assert.Len(t, res.callTimes(), 1)
	assert.Empty(t, fw.addedIPs)
}

// A destination that keeps failing costs at most reverseDNSMaxAttempts
// lookups, each spaced by the doubled backoff, however often it is denied.
func TestReportVerdict_PTRFailuresSpacedAndCapped(t *testing.T) {
	clock, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRTimeout})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}

	// A client redialing every half second for ten minutes.
	for range 1200 {
		reportBuilderDrop(t, cm, fw)
		reverseDNSRetries.wait()
		clock.advance(500 * time.Millisecond)
	}

	calls := res.callTimes()
	require.Len(t, calls, reverseDNSMaxAttempts)
	for i := 1; i < len(calls); i++ {
		gap := calls[i].Sub(calls[i-1])
		assert.GreaterOrEqual(t, gap, reverseDNSBaseBackoff<<(i-1), "lookup %d came too soon", i+1)
	}
	assert.Empty(t, fw.addedIPs)
}

// A retry the full queue can't take gives its claim back: the IP is due
// again at the next denial, not stuck in flight.
func TestReverseDNSRetrier_FullQueueReleasesClaim(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)
	block := make(chan struct{})
	res := blockingResolver(block)
	r := newReverseDNSRetrier(tr, res, 1)
	t.Cleanup(func() { close(block); r.wait(); close(r.queue) })
	cm := config.NewConfigManager()

	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		claimed, _ := tr.begin(ip, true)
		require.True(t, claimed)
		tr.finish(ip, false)
	}
	clock.advance(reverseDNSBaseBackoff)
	for i, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		claimed, first := tr.begin(ip, true)
		require.True(t, claimed)
		require.False(t, first)
		require.True(t, r.enqueue(ip, cm, newTestLogger()))
		// The first is taken by the worker, which blocks in its lookup; the
		// second waits in the queue, filling it.
		require.Eventually(t, func() bool { return len(r.queue) == i }, time.Second, time.Millisecond)
	}

	claimed, _ := tr.begin("192.0.2.3", true)
	require.True(t, claimed)
	if !r.enqueue("192.0.2.3", cm, newTestLogger()) {
		tr.release("192.0.2.3")
	}
	claimed, first := tr.begin("192.0.2.3", true)
	assert.True(t, claimed, "the released IP is due again")
	assert.False(t, first)
}

// blockingResolver's lookups wait until it is closed.
type blockingResolver chan struct{}

func (b blockingResolver) LookupAddr(context.Context, string) ([]string, error) {
	<-b
	return nil, errPTRTimeout
}

func TestReverseDNSTracker_SettledIsFinal(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)

	claimed, first := tr.begin("192.0.2.1", true)
	require.True(t, claimed)
	require.True(t, first)
	assert.Equal(t, reverseDNSAttempt{}, tr.finish("192.0.2.1", true))
	clock.advance(24 * time.Hour)
	claimed, _ = tr.begin("192.0.2.1", true)
	assert.False(t, claimed)
	claimed, _ = tr.begin("192.0.2.2", false)
	assert.True(t, claimed, "another IP is tracked on its own, and its first lookup is any event's")
}

func TestReverseDNSTracker_FailureBacksOffAndCaps(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)
	const ip = "192.0.2.1"

	for n := 1; n < reverseDNSMaxAttempts; n++ {
		claimed, first := tr.begin(ip, true)
		require.True(t, claimed, "lookup %d", n)
		assert.Equal(t, n == 1, first)
		attempt := tr.finish(ip, false)
		want := reverseDNSBaseBackoff << (n - 1)
		assert.Equal(t, reverseDNSAttempt{failures: n, retryIn: want}, attempt)

		clock.advance(want - time.Nanosecond)
		claimed, _ = tr.begin(ip, true)
		assert.False(t, claimed, "still inside backoff %d", n)
		clock.advance(time.Nanosecond)
	}

	claimed, _ := tr.begin(ip, true)
	require.True(t, claimed, "the last allowed lookup")
	assert.Equal(t, reverseDNSAttempt{failures: reverseDNSMaxAttempts, exhausted: true}, tr.finish(ip, false))
	clock.advance(24 * time.Hour)
	claimed, _ = tr.begin(ip, true)
	assert.False(t, claimed, "out of attempts for the run")
}

func TestReverseDNSTracker_OnlyADenialRetries(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)
	claimed, _ := tr.begin("192.0.2.1", false)
	require.True(t, claimed, "the first lookup is any event's")
	tr.finish("192.0.2.1", false)
	clock.advance(time.Hour)

	claimed, _ = tr.begin("192.0.2.1", false)
	assert.False(t, claimed, "an allowed event takes no retry")
	claimed, first := tr.begin("192.0.2.1", true)
	assert.True(t, claimed, "a denial does")
	assert.False(t, first)
}

func TestReverseDNSTracker_OneLookupAtATime(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)

	claimed, _ := tr.begin("192.0.2.1", true)
	require.True(t, claimed)
	claimed, _ = tr.begin("192.0.2.1", true)
	assert.False(t, claimed, "a second caller must not start a concurrent lookup")
	tr.finish("192.0.2.1", false)
	clock.advance(reverseDNSBaseBackoff)
	claimed, _ = tr.begin("192.0.2.1", true)
	assert.True(t, claimed)
}

// The TC reader and the cgroup hook's verdict worker prepare events on
// their own goroutines: however many race for one IP, one claims it.
func TestReverseDNSTracker_ConcurrentCallersClaimOnce(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)
	const callers = 32

	race := func() int {
		var claims atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range callers {
			wg.Go(func() {
				<-start
				if claimed, _ := tr.begin("192.0.2.1", true); claimed {
					claims.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()
		return int(claims.Load())
	}

	assert.Equal(t, 1, race(), "the first lookup")
	tr.finish("192.0.2.1", false)
	clock.advance(reverseDNSBaseBackoff)
	assert.Equal(t, 1, race(), "a retry")
	tr.finish("192.0.2.1", true)
	assert.Equal(t, 0, race(), "a settled IP")
}

func TestReverseDNSTracker_Bounded(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(3, clock.now)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		claimed, _ := tr.begin(ip, true)
		require.True(t, claimed)
		tr.finish(ip, true)
		clock.advance(time.Second)
	}

	claimed, _ := tr.begin("192.0.2.4", true)
	require.True(t, claimed)
	assert.Equal(t, 3, tr.size())
	claimed, first := tr.begin("192.0.2.1", true)
	assert.True(t, claimed, "the least recently touched IP was evicted")
	assert.True(t, first, "and starts over")
	assert.Equal(t, 3, tr.size())

	// An IP evicted while its lookup ran still has the outcome recorded,
	// without the tracker growing past its bound.
	tr.finish("192.0.2.2", false)
	assert.LessOrEqual(t, tr.size(), 3)
}

// The settled/transient split must hold for the resolver cargowall uses:
// Go's own (the binary is built without cgo), against a real DNS server.
func TestReverseLookupSettled_GoResolver(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			// A recursive resolver's answer. Without RA, Go reads an empty
			// NOERROR as a lame referral rather than an empty answer.
			m.RecursionAvailable = true
			switch r.Question[0].Name {
			case "1.2.0.192.in-addr.arpa.":
				m.Answer = append(m.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
					Ptr: "builder.example.",
				})
			case "2.2.0.192.in-addr.arpa.":
				m.Rcode = dns.RcodeNameError
			case "3.2.0.192.in-addr.arpa.":
				// NOERROR with no answer.
			case "4.2.0.192.in-addr.arpa.":
				m.Rcode = dns.RcodeServerFailure
			case "5.2.0.192.in-addr.arpa.":
				return // no reply at all
			default:
				m.Rcode = dns.RcodeRefused
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown(); _ = pc.Close() })

	addr := pc.LocalAddr().String()
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
	lookup := func(ip string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := res.LookupAddr(ctx, ip)
		return err
	}

	assert.True(t, reverseLookupSettled(lookup("192.0.2.1")), "a name")
	assert.True(t, reverseLookupSettled(lookup("192.0.2.2")), "NXDOMAIN")
	assert.True(t, reverseLookupSettled(lookup("192.0.2.3")), "an empty answer")

	for ip, what := range map[string]string{
		"192.0.2.4": "SERVFAIL",
		"192.0.2.5": "a timeout",
		"192.0.2.6": "REFUSED",
	} {
		err := lookup(ip)
		require.Error(t, err, what)
		assert.False(t, reverseLookupSettled(err), "%s must be retried", what)
	}
	assert.False(t, reverseLookupSettled(errors.New("connection refused")), "a non-DNS error")
}
