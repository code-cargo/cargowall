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
	"sync"
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
// last entry repeats. It records when each call happened.
type scriptedResolver struct {
	clock   *fakeClock
	results []scriptedAnswer
	calls   []time.Time
}

type scriptedAnswer struct {
	names []string
	err   error
}

func (r *scriptedResolver) LookupAddr(context.Context, string) ([]string, error) {
	r.calls = append(r.calls, r.clock.now())
	a := r.results[min(len(r.calls), len(r.results))-1]
	return a.names, a.err
}

var (
	errPTRTimeout  = &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsTemporary: true}
	errPTRNotFound = &net.DNSError{Err: "no such host", IsNotFound: true}
)

// useScriptedReverseDNS swaps the package's tracker and resolver for ones
// the test drives, restoring both when the test ends.
func useScriptedReverseDNS(t *testing.T, answers ...scriptedAnswer) (*fakeClock, *scriptedResolver) {
	t.Helper()
	clock := newFakeClock()
	res := &scriptedResolver{clock: clock, results: answers}
	prevTracker, prevResolver := reverseDNS, reverseDNSResolver
	reverseDNS = newReverseDNSTracker(reverseDNSCacheMax, clock.now)
	reverseDNSResolver = res
	t.Cleanup(func() { reverseDNS, reverseDNSResolver = prevTracker, prevResolver })
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

func builderDrop() VerdictRecord {
	return VerdictRecord{
		SrcIP: "10.1.0.5", DstIP: "198.51.100.7", SrcPort: 40001, DstPort: 443,
		Proto: unix.IPPROTO_TCP, Dropped: true,
	}
}

// reportBuilderDrop reports one dropped builder dial and returns its audit
// event.
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

// A reverse lookup that times out must not be the last word: once the
// backoff passes, the next drop of the same destination looks it up again,
// and when the name now resolves the rule late-allows it.
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
	assert.Empty(t, fw.addedIPs)

	ev = reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionBlocked, ev.EventType, "inside the backoff: no second lookup yet")
	assert.Len(t, res.calls, 1)

	clock.advance(reverseDNSBaseBackoff)
	ev = reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionLateAllowed, ev.EventType)
	assert.Equal(t, "*.compute-1.amazonaws.com", ev.MatchedRule)
	assert.Equal(t, "ec2-198-51-100-7.compute-1.amazonaws.com", ev.DstHostname)
	require.Len(t, fw.addedIPs, 1)
	assert.True(t, fw.addedIPs[0].ip.Equal(net.ParseIP("198.51.100.7")))
	assert.Len(t, res.calls, 2)
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

	assert.Equal(t, EventConnectionBlocked, ev.EventType)
	assert.Len(t, res.calls, 1)
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
		clock.advance(500 * time.Millisecond)
	}

	require.Len(t, res.calls, reverseDNSMaxAttempts)
	for i := 1; i < len(res.calls); i++ {
		gap := res.calls[i].Sub(res.calls[i-1])
		assert.GreaterOrEqual(t, gap, reverseDNSBaseBackoff<<(i-1), "lookup %d came too soon", i+1)
	}
	assert.Empty(t, fw.addedIPs)
}

func TestReverseDNSTracker_SettledIsFinal(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)

	require.True(t, tr.begin("192.0.2.1"))
	assert.Equal(t, reverseDNSAttempt{}, tr.finish("192.0.2.1", true))
	clock.advance(24 * time.Hour)
	assert.False(t, tr.begin("192.0.2.1"))
	assert.True(t, tr.begin("192.0.2.2"), "another IP is tracked on its own")
}

func TestReverseDNSTracker_FailureBacksOffAndCaps(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)
	const ip = "192.0.2.1"

	for n := 1; n < reverseDNSMaxAttempts; n++ {
		require.True(t, tr.begin(ip), "lookup %d", n)
		attempt := tr.finish(ip, false)
		want := reverseDNSBaseBackoff << (n - 1)
		assert.Equal(t, reverseDNSAttempt{failures: n, retryIn: want}, attempt)

		clock.advance(want - time.Nanosecond)
		assert.False(t, tr.begin(ip), "still inside backoff %d", n)
		clock.advance(time.Nanosecond)
	}

	require.True(t, tr.begin(ip), "the last allowed lookup")
	assert.Equal(t, reverseDNSAttempt{failures: reverseDNSMaxAttempts, exhausted: true}, tr.finish(ip, false))
	clock.advance(24 * time.Hour)
	assert.False(t, tr.begin(ip), "out of attempts for the run")
}

func TestReverseDNSTracker_OneLookupAtATime(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(10, clock.now)

	require.True(t, tr.begin("192.0.2.1"))
	assert.False(t, tr.begin("192.0.2.1"), "a second caller must not start a concurrent lookup")
	tr.finish("192.0.2.1", false)
	clock.advance(reverseDNSBaseBackoff)
	assert.True(t, tr.begin("192.0.2.1"))
}

func TestReverseDNSTracker_Bounded(t *testing.T) {
	clock := newFakeClock()
	tr := newReverseDNSTracker(3, clock.now)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		require.True(t, tr.begin(ip))
		tr.finish(ip, true)
		clock.advance(time.Second)
	}

	require.True(t, tr.begin("192.0.2.4"))
	assert.Equal(t, 3, tr.size())
	assert.True(t, tr.begin("192.0.2.1"), "the least recently touched IP was evicted")
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
