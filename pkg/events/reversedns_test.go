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
	"net/netip"
	"slices"
	"strings"
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
// calls it from its own goroutine. LookupHost, the forward lookup confirming
// a reverse name, answers from forwardScript the same way when it is set,
// and otherwise as public DNS does (see publicForward).
type scriptedResolver struct {
	clock         *fakeClock
	results       []scriptedAnswer
	forwardScript []scriptedAnswer
	mu            sync.Mutex
	calls         []time.Time
	forwardCalls  int
}

// scriptedAnswer is one scripted lookup result: names for a reverse lookup,
// addresses for a forward one.
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

func (r *scriptedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forwardCalls++
	if len(r.forwardScript) == 0 {
		return publicForward(host)
	}
	a := r.forwardScript[min(r.forwardCalls, len(r.forwardScript))-1]
	return toAddrs(a.names), a.err
}

func (r *scriptedResolver) forwardCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.forwardCalls
}

func toAddrs(ss []string) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	return addrs
}

// publicForward answers a forward lookup as public DNS does for the names
// these tests use: an EC2 public name (ec2-A-B-C-D.<region>.amazonaws.com)
// resolves to the address it spells, and any other name does not exist. A
// PTR record can claim any name, but only the claimed domain's owner decides
// where that name resolves.
func publicForward(host string) ([]netip.Addr, error) {
	label, rest, _ := strings.Cut(strings.TrimSuffix(host, "."), ".")
	if strings.HasPrefix(label, "ec2-") && strings.HasSuffix(rest, ".amazonaws.com") {
		if ip, err := netip.ParseAddr(strings.ReplaceAll(strings.TrimPrefix(label, "ec2-"), "-", ".")); err == nil {
			return []netip.Addr{ip}, nil
		}
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
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

// githubPolicy allows github.com on tcp/443, as the GitHub Actions preset's
// service-host rule does: the kind of rule a forged PTR record aims at.
func githubPolicy(t *testing.T) *config.Manager {
	t.Helper()
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "github.com",
		Action: config.ActionAllow,
		Ports:  []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
	}}, config.ActionDeny))
	return cm
}

// attackerIP is an address whose owner set its PTR record to a name under an
// allowed host.
const attackerIP = "203.0.113.66"

// forgedPTR is the reverse lookup's answer for attackerIP.
var forgedPTR = scriptedAnswer{names: []string{"exfil.github.com."}}

// forgedNameForwards are the forward answers the forged name can get: the
// owner of github.com decides them, and neither leads back to attackerIP.
var forgedNameForwards = map[string]scriptedAnswer{
	"the claimed name does not exist":     {err: &net.DNSError{Err: "no such host", IsNotFound: true}},
	"the claimed name resolves elsewhere": {names: []string{"140.82.112.3"}},
}

// A PTR record is the address owner's claim, and can name any host. One
// naming a subdomain of an allowed host must neither late-allow nor label a
// denied connection to an address that host's own DNS never gave, or anyone
// who controls a reverse zone could open the firewall to their own server.
func TestReportVerdict_ForgedPTRDoesNotLateAllow(t *testing.T) {
	for name, forward := range forgedNameForwards {
		t.Run(name, func(t *testing.T) {
			clock, res := useScriptedReverseDNS(t, forgedPTR)
			res.forwardScript = []scriptedAnswer{forward}
			cm := githubPolicy(t)
			fw := &mockFirewallUpdater{}

			for range 3 { // the client's SYN retransmits, each past any backoff
				ev := reportDrop(t, cm, fw, dropTo(attackerIP, 443))
				assert.Equal(t, EventConnectionBlocked, ev.EventType)
				assert.Empty(t, ev.DstHostname, "the forged name labels nothing")
				assert.Empty(t, ev.MatchedRule)
				reverseDNSRetries.wait()
				clock.advance(reverseDNSBaseBackoff << reverseDNSMaxAttempts)
			}
			reverseDNSRetries.wait()
			assert.Empty(t, fw.addedIPs, "nothing opened under the forged name")
			assert.Empty(t, cm.LookupHostnameByIP(attackerIP), "the forged name is not cached")
			assert.Len(t, res.callTimes(), 1, "a refuted name is a settled answer: no retry")
		})
	}
}

// The same on the TC path, whose events are prepared on the ring-buffer
// reader.
func TestProcessEvent_ForgedPTRDoesNotLateAllow(t *testing.T) {
	for name, forward := range forgedNameForwards {
		t.Run(name, func(t *testing.T) {
			_, res := useScriptedReverseDNS(t, forgedPTR)
			res.forwardScript = []scriptedAnswer{forward}
			cm := githubPolicy(t)
			fw := &mockFirewallUpdater{}
			auditLogger, err := NewAuditLogger("", false)
			require.NoError(t, err)
			sink := &recordingSink{}
			auditLogger.AddSink(sink)

			for range 3 { // the client's SYN retransmits
				processEvent(makeBpfEvent(BpfBlockedEvent{
					IpVersion: 4, IpProto: unix.IPPROTO_TCP,
					SrcIp: ipv4ToUint32("10.1.0.5"), DstIp: ipv4ToUint32(attackerIP), SrcPort: 40001, DstPort: 443,
				}), cm, nil, auditLogger, fw, nil, newTestLogger(), nil)
			}
			reverseDNSRetries.wait()

			require.Len(t, sink.events, 3)
			for _, ev := range sink.events {
				assert.Equal(t, EventConnectionBlocked, ev.EventType)
				assert.Empty(t, ev.DstHostname, "the forged name labels nothing")
			}
			assert.Empty(t, fw.addedIPs, "nothing opened under the forged name")
		})
	}
}

// A PTR answer can carry several names. A forged one first must not stop a
// genuine one after it from naming the IP, and the genuine one is matched and
// reported lowercased, whatever case it came back in.
func TestReportVerdict_GenuinePTRNameAfterAForgedOneLateAllows(t *testing.T) {
	useScriptedReverseDNS(t, scriptedAnswer{names: []string{
		"exfil.github.com.", "Ec2-198-51-100-7.Compute-1.Amazonaws.Com.",
	}})
	https := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "github.com", Action: config.ActionAllow, Ports: https},
		{Type: config.RuleTypeHostname, Value: "*.compute-1.amazonaws.com", Action: config.ActionAllow, Ports: https},
	}, config.ActionDeny))
	fw := &mockFirewallUpdater{}

	ev := reportBuilderDrop(t, cm, fw)

	assert.Equal(t, EventConnectionLateAllowed, ev.EventType)
	assert.Equal(t, "*.compute-1.amazonaws.com", ev.MatchedRule)
	assert.Equal(t, "ec2-198-51-100-7.compute-1.amazonaws.com", ev.DstHostname)
	require.Len(t, fw.addedIPs, 1)
	assert.True(t, fw.addedIPs[0].ip.Equal(net.ParseIP(builderIP)))
}

// A reverse name no rule allows can't change a verdict, so it is neither
// confirmed nor used as a label: no forward query goes to a zone the
// destination's owner chose, and none reaches the proxy's filter, which would
// refuse it and record it as the job's query.
func TestReportVerdict_PTRNameNoRuleAllowsIsNotLookedUp(t *testing.T) {
	clock, res := useScriptedReverseDNS(t, scriptedAnswer{names: []string{"server9.hosting.example."}})
	cm := githubPolicy(t)
	fw := &mockFirewallUpdater{}

	for range 2 {
		ev := reportDrop(t, cm, fw, dropTo(attackerIP, 443))
		assert.Equal(t, EventConnectionBlocked, ev.EventType)
		assert.Empty(t, ev.DstHostname, "a name no rule allows labels nothing")
		reverseDNSRetries.wait()
		clock.advance(reverseDNSBaseBackoff << reverseDNSMaxAttempts)
	}

	assert.Zero(t, res.forwardCount(), "no forward query for a name no rule allows")
	assert.Len(t, res.callTimes(), 1, "the PTR answer settled the IP")
	assert.Empty(t, fw.addedIPs)
}

// A forward lookup that fails says nothing about the reverse name, any more
// than a failed PTR lookup does: the IP is looked up again after the backoff,
// and the name, once confirmed, late-allows. A transient failure must not
// block a destination its reverse name allows for the rest of the run.
func TestReportVerdict_ConfirmationTimeoutRetriesThenLateAllows(t *testing.T) {
	clock, res := useScriptedReverseDNS(t,
		scriptedAnswer{names: []string{"ec2-198-51-100-7.compute-1.amazonaws.com."}})
	res.forwardScript = []scriptedAnswer{{err: errPTRTimeout}, {names: []string{builderIP}}}
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}

	ev := reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionBlocked, ev.EventType)
	assert.Empty(t, ev.DstHostname, "the name is not confirmed yet")
	assert.Empty(t, fw.addedIPs)

	clock.advance(reverseDNSBaseBackoff)
	ev = reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionBlocked, ev.EventType, "the retry runs off the reporting path")
	reverseDNSRetries.wait()

	ev = reportBuilderDrop(t, cm, fw)
	assert.Equal(t, EventConnectionLateAllowed, ev.EventType)
	assert.Equal(t, "*.compute-1.amazonaws.com", ev.MatchedRule)
	assert.Equal(t, "ec2-198-51-100-7.compute-1.amazonaws.com", ev.DstHostname)
	require.Len(t, fw.addedIPs, 1)
	assert.True(t, fw.addedIPs[0].ip.Equal(net.ParseIP(builderIP)))
	assert.Len(t, res.callTimes(), 2)
}

// gatedResolver answers retries with each IP's PTR name, but only once its
// gate is open; until then a lookup waits, the way one waits on a slow
// upstream. onLookup, when set, runs as a lookup starts.
type gatedResolver struct {
	gate     chan struct{}
	opened   sync.Once
	onLookup func(ip string)
	mu       sync.Mutex
	calls    map[string]int
}

// open lets every lookup, waiting or to come, through.
func (g *gatedResolver) open() { g.opened.Do(func() { close(g.gate) }) }

func newGatedResolver() *gatedResolver {
	return &gatedResolver{gate: make(chan struct{}), calls: make(map[string]int)}
}

func (g *gatedResolver) LookupAddr(_ context.Context, ip string) ([]string, error) {
	g.mu.Lock()
	g.calls[ip]++
	g.mu.Unlock()
	if g.onLookup != nil {
		g.onLookup(ip)
	}
	<-g.gate
	return []string{"ec2-" + strings.ReplaceAll(ip, ".", "-") + ".compute-1.amazonaws.com."}, nil
}

func (g *gatedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return publicForward(host)
}

func (g *gatedResolver) callsFor(ip string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[ip]
}

// useGatedRetries gives the test a retry worker of its own, with a queue of
// queueLen, answering through gated. Call after useScriptedReverseDNS.
func useGatedRetries(t *testing.T, gated *gatedResolver, queueLen int) *reverseDNSRetrier {
	t.Helper()
	r := newReverseDNSRetrier(reverseDNS, gated, queueLen)
	prev := reverseDNSRetries
	reverseDNSRetries = r
	t.Cleanup(func() {
		gated.open()
		r.wait()
		close(r.queue)
		reverseDNSRetries = prev
	})
	return r
}

func dropTo(ip string, port uint16) VerdictRecord {
	rec := builderDrop()
	rec.DstIP, rec.DstPort = ip, port
	return rec
}

func reportDrop(t *testing.T, cm *config.Manager, fw *mockFirewallUpdater, rec VerdictRecord) AuditEvent {
	t.Helper()
	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	ReportVerdict(rec, cm, nil, auditLogger, fw, nil, newTestLogger())
	require.Len(t, sink.events, 1)
	return sink.events[0]
}

// A retry the full queue can't take gives its claim back, so the IP is due
// again at its next denial rather than stuck in flight for the run.
func TestReportVerdict_FullRetryQueueReleasesTheClaim(t *testing.T) {
	clock, _ := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRTimeout})
	gated := newGatedResolver()
	r := useGatedRetries(t, gated, 1)
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	ips := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}

	for _, ip := range ips {
		reportDrop(t, cm, fw, dropTo(ip, 443)) // the first lookup times out
	}
	clock.advance(reverseDNSBaseBackoff)
	reportDrop(t, cm, fw, dropTo(ips[0], 443))
	require.Eventually(t, func() bool { return gated.callsFor(ips[0]) == 1 }, time.Second, time.Millisecond,
		"the worker took the first retry and waits in its lookup")
	reportDrop(t, cm, fw, dropTo(ips[1], 443)) // fills the queue
	reportDrop(t, cm, fw, dropTo(ips[2], 443)) // finds it full

	gated.open()
	r.wait()
	reportDrop(t, cm, fw, dropTo(ips[2], 443)) // due again, so queued this time
	r.wait()

	ev := reportDrop(t, cm, fw, dropTo(ips[2], 443))
	assert.Equal(t, EventConnectionLateAllowed, ev.EventType, "the dropped retry ran at the IP's next denial")
	assert.Equal(t, 1, gated.callsFor(ips[2]))
}

// policyWithForwardAndPTRRules allows builder.example by its forward name on
// tcp/443, and *.compute-1.amazonaws.com by reverse name on tcp/8443: a
// destination's name decides which rule a denial is judged under.
func policyWithForwardAndPTRRules(t *testing.T) *config.Manager {
	t.Helper()
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "builder.example", Action: config.ActionAllow,
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
		},
		{
			Type: config.RuleTypeHostname, Value: "*.compute-1.amazonaws.com", Action: config.ActionAllow,
			Ports: []config.Port{{Port: 8443, Protocol: config.ProtocolTCP}},
		},
	}, config.ActionDeny))
	return cm
}

// A forward answer that lands while a retry waits in the queue keeps its
// name: the worker finds the IP named and settles it without a lookup.
func TestReverseDNSRetrier_ForwardNameWhileQueuedIsKept(t *testing.T) {
	clock, _ := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRTimeout})
	gated := newGatedResolver()
	r := useGatedRetries(t, gated, 4)
	cm := policyWithForwardAndPTRRules(t)
	fw := &mockFirewallUpdater{}
	const busy, ip = "198.51.100.1", builderIP

	reportDrop(t, cm, fw, dropTo(busy, 8443))
	reportDrop(t, cm, fw, dropTo(ip, 8443))
	clock.advance(reverseDNSBaseBackoff)
	reportDrop(t, cm, fw, dropTo(busy, 8443))
	require.Eventually(t, func() bool { return gated.callsFor(busy) == 1 }, time.Second, time.Millisecond)
	reportDrop(t, cm, fw, dropTo(ip, 8443)) // queued behind the busy one

	cm.UpdateDNSMapping("builder.example", ip) // the proxy answers for it meanwhile
	gated.open()
	r.wait()

	assert.Zero(t, gated.callsFor(ip), "the IP was named by then: no lookup")
	assert.Equal(t, "builder.example", cm.LookupHostnameByIP(ip))
	ev := reportDrop(t, cm, fw, dropTo(ip, 8443))
	assert.Equal(t, EventConnectionBlocked, ev.EventType, "judged under the forward name's rule, which allows only 443")
	assert.Equal(t, "builder.example", ev.DstHostname)
}

// A forward answer that lands while a retry's lookup runs keeps its name: the
// PTR name the lookup brings back is not recorded over it.
func TestReverseDNSRetrier_ForwardNameDuringTheLookupIsKept(t *testing.T) {
	clock, _ := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRTimeout})
	gated := newGatedResolver()
	r := useGatedRetries(t, gated, 4)
	cm := policyWithForwardAndPTRRules(t)
	fw := &mockFirewallUpdater{}
	gated.onLookup = func(ip string) { cm.UpdateDNSMapping("builder.example", ip) }

	reportDrop(t, cm, fw, dropTo(builderIP, 8443))
	clock.advance(reverseDNSBaseBackoff)
	reportDrop(t, cm, fw, dropTo(builderIP, 8443))
	gated.open()
	r.wait()

	assert.Equal(t, 1, gated.callsFor(builderIP))
	assert.Equal(t, "builder.example", cm.LookupHostnameByIP(builderIP))
	assert.Equal(t, EventConnectionBlocked, reportDrop(t, cm, fw, dropTo(builderIP, 8443)).EventType)
	assert.NotContains(t, portsOpened(fw), uint16(8443), "nothing opened under the reverse name's rule")
}

// forwardDuringLookup is a first lookup's resolver: the proxy records a
// forward answer for the IP while the PTR query is out.
type forwardDuringLookup struct{ cm *config.Manager }

func (f forwardDuringLookup) LookupAddr(_ context.Context, ip string) ([]string, error) {
	f.cm.UpdateDNSMapping("builder.example", ip)
	return []string{"ec2-198-51-100-7.compute-1.amazonaws.com."}, nil
}

func (forwardDuringLookup) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return publicForward(host)
}

// The same on the first lookup, which runs while the event is prepared: the
// event and the run keep the forward name.
func TestReportVerdict_ForwardNameDuringFirstLookupIsKept(t *testing.T) {
	useScriptedReverseDNS(t)
	cm := policyWithForwardAndPTRRules(t)
	reverseDNSResolver = forwardDuringLookup{cm: cm}
	fw := &mockFirewallUpdater{}

	ev := reportDrop(t, cm, fw, dropTo(builderIP, 8443))

	assert.Equal(t, EventConnectionBlocked, ev.EventType, "not late-allowed under the reverse name's 8443 rule")
	assert.Equal(t, "builder.example", ev.DstHostname)
	assert.Equal(t, "builder.example", cm.LookupHostnameByIP(builderIP))
	assert.NotContains(t, portsOpened(fw), uint16(8443), "nothing opened under the reverse name's rule")
}

// portsOpened lists the ports the firewall was asked to allow.
func portsOpened(fw *mockFirewallUpdater) []uint16 {
	var ports []uint16
	for _, call := range fw.addedIPs {
		if call.action == config.ActionAllow {
			for _, p := range call.ports {
				ports = append(ports, p.Port)
			}
		}
	}
	return ports
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
