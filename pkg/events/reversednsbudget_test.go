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
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

const (
	networkCapLog = "reached the cap for a network"
	runCapLog     = "reached the run's cap"
)

func infoLogger(buf *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(buf, nil)) }

// At most reverseDNSPerNetwork distinct addresses per IPv4 /24 and per IPv6
// /48 are let through, and an address let through is let through again
// without counting, its IPv4-mapped form included.
func TestReverseDNSBudget_PerNetworkCap(t *testing.T) {
	var logs bytes.Buffer
	logger := infoLogger(&logs)
	b := newReverseDNSBudget(reverseDNSPerNetwork, reverseDNSRunMaxV4, reverseDNSRunMaxV6)

	assert.True(t, b.take("192.0.2.1", logger))
	assert.True(t, b.take("192.0.2.2", logger))
	assert.False(t, b.take("192.0.2.3", logger), "a third address in the /24")
	assert.False(t, b.take("::ffff:192.0.2.4", logger), "a third, IPv4-mapped")
	assert.True(t, b.take("192.0.2.1", logger), "again: no new count")
	assert.True(t, b.take("::ffff:192.0.2.2", logger), "again, IPv4-mapped: no new count")
	assert.True(t, b.take("192.0.3.1", logger), "another /24")

	assert.True(t, b.take("2001:db8:abcd:1::1", logger))
	assert.True(t, b.take("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff", logger))
	assert.False(t, b.take("2001:db8:abcd:2::1", logger), "a third address in the /48, another /64")
	assert.True(t, b.take("2001:db8:abcd:1::1", logger), "again: no new count")
	assert.True(t, b.take("2001:db8:abce::1", logger), "another /48")

	assert.False(t, b.take("not an address", logger))

	assert.Equal(t, 2, strings.Count(logs.String(), networkCapLog), "once per network: %s", logs.String())
	assert.Contains(t, logs.String(), "network=192.0.2.0/24")
	assert.Contains(t, logs.String(), "network=2001:db8:abcd::/48")
	assert.Contains(t, logs.String(), "level=INFO")
	assert.NotContains(t, logs.String(), runCapLog)
}

// A local address is always let through and never counted: neither its
// network's cap nor its family's run cap is spent on it.
func TestReverseDNSBudget_LocalAddressesAreNotCounted(t *testing.T) {
	var logs bytes.Buffer
	logger := infoLogger(&logs)
	b := newReverseDNSBudget(reverseDNSPerNetwork, reverseDNSRunMaxV4, reverseDNSRunMaxV6)
	for i := range reverseDNSRunMaxV4 + 10 {
		require.True(t, b.take(fmt.Sprintf("10.96.%d.%d", i/200, i%200), logger), i)
	}
	for _, ip := range []string{"100.64.0.1", "100.64.0.2", "100.64.0.3", "fd00::1", "fd00::2", "fd00::3", "::ffff:10.96.0.9"} {
		assert.True(t, b.take(ip, logger), ip)
	}
	for i := range reverseDNSRunMaxV4 {
		require.True(t, b.take(v4Network(i), logger), "the IPv4 run cap is untouched: %d", i)
	}
	assert.Empty(t, logs.String(), "no cap was reached on the local addresses")
}

// v4Network and v6Network return the i-th of distinct IPv4 /24s and IPv6
// /48s, an address in each.
func v4Network(i int) string { return fmt.Sprintf("203.%d.%d.1", i/256, i%256) }

func v6Network(i int) string { return fmt.Sprintf("2001:db8:%x::1", i) }

// At most reverseDNSRunMaxV4 distinct IPv4 addresses, and reverseDNSRunMaxV6
// IPv6 ones, are let through in a run, whatever networks they are in. The
// families are counted apart, and addresses already let through still are.
func TestReverseDNSBudget_RunCap(t *testing.T) {
	var logs bytes.Buffer
	logger := infoLogger(&logs)
	b := newReverseDNSBudget(reverseDNSPerNetwork, reverseDNSRunMaxV4, reverseDNSRunMaxV6)
	for i := range reverseDNSRunMaxV4 {
		require.True(t, b.take(v4Network(i), logger), i)
	}
	assert.False(t, b.take("192.0.2.1", logger), "past the IPv4 cap")
	assert.False(t, b.take("::ffff:192.0.2.1", logger), "past the IPv4 cap, IPv4-mapped")
	assert.True(t, b.take(v4Network(0), logger), "already let through")
	assert.Equal(t, 1, strings.Count(logs.String(), runCapLog), logs.String())
	assert.Contains(t, logs.String(), "family=IPv4 cap=256")

	for i := range reverseDNSRunMaxV6 {
		require.True(t, b.take(v6Network(i), logger), "the IPv6 cap is its own: %d", i)
	}
	assert.False(t, b.take("2001:db9::1", logger), "past the IPv6 cap")
	assert.True(t, b.take(v6Network(0), logger), "already let through")
	assert.Equal(t, 2, strings.Count(logs.String(), runCapLog), "once per family: %s", logs.String())
	assert.Contains(t, logs.String(), "family=IPv6 cap=64")
	assert.NotContains(t, logs.String(), networkCapLog)

	b.reset()
	assert.True(t, b.take("192.0.2.1", logger), "reset forgets what was spent")
	assert.True(t, b.take("2001:db9::1", logger), "reset forgets what was spent")
}

// reportDropTo reports one dropped dial to ip:443 through the cgroup hook's
// path and returns its audit event.
func reportDropTo(t *testing.T, cm *config.Manager, fw *mockFirewallUpdater, ip string, logger *slog.Logger) AuditEvent {
	t.Helper()
	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	src := "10.1.0.5"
	if strings.Contains(ip, ":") {
		src = "fd00::5"
	}
	ReportVerdict(VerdictRecord{
		SrcIP: src, DstIP: ip, SrcPort: 40001, DstPort: 443, Proto: unix.IPPROTO_TCP, Dropped: true,
	}, cm, nil, auditLogger, fw, nil, logger)
	require.Len(t, sink.events, 1)
	return sink.events[0]
}

// The denials a job's connections meet cost at most two reverse lookups per
// IPv4 /24 and per IPv6 /48, however many addresses there they are denied
// at, or how often. Past the cap an address goes unnamed with no lookup, and
// the cap is logged once per network.
func TestReportVerdict_ReverseLookupsCappedPerNetwork(t *testing.T) {
	_, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRNotFound})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	var logs bytes.Buffer
	logger := infoLogger(&logs)

	for range 3 {
		for _, ip := range []string{
			"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
			"2001:db8:abcd::1", "2001:db8:abcd:1::1", "2001:db8:abcd:2::1", "2001:db8:abcd:3::1",
		} {
			ev := reportDropTo(t, cm, fw, ip, logger)
			assert.Equal(t, EventConnectionBlocked, ev.EventType)
			assert.Empty(t, ev.DstHostname)
		}
	}
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), 4, "two per network")
	assert.Equal(t, 2, strings.Count(logs.String(), networkCapLog), logs.String())
	assert.Empty(t, fw.addedIPs)
}

// An address past a cap is final for the run: however often it is denied,
// and however long after, it is never looked up, so no retry runs it past
// the cap.
func TestReportVerdict_CappedAddressIsNeverLookedUp(t *testing.T) {
	clock, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRNotFound})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	logger := newTestLogger()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		reportDropTo(t, cm, fw, ip, logger)
	}
	for range 5 {
		clock.advance(reverseDNSBaseBackoff << reverseDNSMaxAttempts)
		reportDropTo(t, cm, fw, "192.0.2.3", logger)
		reverseDNSRetries.wait()
	}
	assert.Len(t, res.callTimes(), 2, "the capped address was never looked up")
}

// A retry of an address already looked up costs no further share of the
// cap: a timed-out lookup's retry runs, and the network still has room for
// a second address.
func TestReportVerdict_ReverseLookupRetriesCountOnce(t *testing.T) {
	clock, res := useScriptedReverseDNS(t,
		scriptedAnswer{err: errPTRTimeout},
		scriptedAnswer{err: errPTRNotFound},
	)
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	logger := newTestLogger()

	reportDropTo(t, cm, fw, "192.0.2.1", logger)
	clock.advance(reverseDNSBaseBackoff)
	reportDropTo(t, cm, fw, "192.0.2.1", logger)
	reverseDNSRetries.wait()
	require.Len(t, res.callTimes(), 2, "the lookup, then its retry")

	reportDropTo(t, cm, fw, "192.0.2.2", logger)
	reportDropTo(t, cm, fw, "192.0.2.3", logger)
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), 3, "the second address is looked up, the third isn't")
}

// Past a family's run cap, a denied address of that family in a network
// with room goes unnamed too, and the cap is logged once per family.
func TestReportVerdict_ReverseLookupsCappedPerRun(t *testing.T) {
	_, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRNotFound})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	var logs bytes.Buffer
	logger := infoLogger(&logs)

	for i := range reverseDNSRunMaxV4 + 3 {
		reportDropTo(t, cm, fw, v4Network(i), logger)
	}
	for i := range reverseDNSRunMaxV6 + 3 {
		reportDropTo(t, cm, fw, v6Network(i), logger)
	}
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), reverseDNSRunMaxV4+reverseDNSRunMaxV6)
	assert.Equal(t, 2, strings.Count(logs.String(), runCapLog), logs.String())
}

// A remote builder dialled by IP, whose reverse name a rule allows and
// resolves back to it, is still late-allowed: it is named within its own
// network's cap while its family's run cap isn't reached, whatever other
// networks' caps have been.
func TestReportVerdict_BuilderLateAllowedWithinTheCaps(t *testing.T) {
	_, res := useScriptedReverseDNS(t,
		scriptedAnswer{err: errPTRNotFound},
		scriptedAnswer{err: errPTRNotFound},
		scriptedAnswer{err: errPTRNotFound},
		scriptedAnswer{names: []string{"ec2-198-51-100-7.compute-1.amazonaws.com."}},
	)
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	logger := newTestLogger()

	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		reportDropTo(t, cm, fw, ip, logger)
	}
	reportDropTo(t, cm, fw, "198.51.100.8", logger)
	ev := reportDropTo(t, cm, fw, builderIP, logger)
	assert.Equal(t, EventConnectionLateAllowed, ev.EventType, "the builder is its network's second address")
	assert.Equal(t, "*.compute-1.amazonaws.com", ev.MatchedRule)
	assert.Equal(t, "ec2-198-51-100-7.compute-1.amazonaws.com", ev.DstHostname)
	require.Len(t, fw.addedIPs, 1)
	assert.True(t, fw.addedIPs[0].ip.Equal(net.ParseIP(builderIP)))
	assert.Len(t, res.callTimes(), 4, "192.0.2.3 was past its network's cap")
}

// Past the IPv4 run cap a builder dialled by IP goes unnamed, so a builder
// only its reverse name could allow stays blocked: the cost of the cap.
func TestReportVerdict_BuilderUnnamedPastTheIPv4RunCap(t *testing.T) {
	_, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRNotFound})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	logger := newTestLogger()
	for i := range reverseDNSRunMaxV4 {
		reportDropTo(t, cm, fw, v4Network(i), logger)
	}
	ev := reportDropTo(t, cm, fw, builderIP, logger)
	assert.Equal(t, EventConnectionBlocked, ev.EventType)
	assert.Empty(t, ev.DstHostname)
	assert.Empty(t, fw.addedIPs)
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), reverseDNSRunMaxV4, "the builder was never looked up")
}

// IPv6 denials, however many, spend only the IPv6 cap: an IPv4 builder
// after them is still named and late-allowed.
func TestReportVerdict_IPv6DenialsLeaveAnIPv4BuilderNamed(t *testing.T) {
	answers := make([]scriptedAnswer, reverseDNSRunMaxV6, reverseDNSRunMaxV6+1)
	for i := range answers {
		answers[i] = scriptedAnswer{err: errPTRNotFound}
	}
	answers = append(answers, scriptedAnswer{names: []string{"ec2-198-51-100-7.compute-1.amazonaws.com."}})
	_, res := useScriptedReverseDNS(t, answers...)
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	logger := newTestLogger()
	for i := range reverseDNSRunMaxV6 + 3 {
		reportDropTo(t, cm, fw, v6Network(i), logger)
	}
	ev := reportDropTo(t, cm, fw, builderIP, logger)
	assert.Equal(t, EventConnectionLateAllowed, ev.EventType)
	assert.Equal(t, "ec2-198-51-100-7.compute-1.amazonaws.com", ev.DstHostname)
	require.Len(t, fw.addedIPs, 1)
	assert.Len(t, res.callTimes(), reverseDNSRunMaxV6+1)
}

// Denied local addresses, cluster service addresses dialled by IP for
// instance, are each looked up however many share a /24, so the one a rule
// allows by its reverse name is still named.
func TestReportVerdict_LocalAddressesAreLookedUpUncapped(t *testing.T) {
	_, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRNotFound})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	logger := newTestLogger()
	for _, ip := range []string{"10.96.0.10", "10.96.0.11", "10.96.0.12", "10.96.0.1"} {
		reportDropTo(t, cm, fw, ip, logger)
	}
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), 4)
}

// A lookup for an allowed connection is only a label, and costs nothing of
// the denials' caps.
func TestProcessEvent_AllowedLookupsDoNotSpendTheCap(t *testing.T) {
	_, res := useScriptedReverseDNS(t, scriptedAnswer{err: errPTRNotFound})
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}
	assert.Equal(t, EventConnectionAllowed, processBuilderSYN(t, cm, fw, true).EventType)
	reverseDNSRetries.wait()
	require.Len(t, res.callTimes(), 1)

	reportDropTo(t, cm, fw, "198.51.100.8", newTestLogger())
	reportDropTo(t, cm, fw, "198.51.100.9", newTestLogger())
	reverseDNSRetries.wait()
	assert.Len(t, res.callTimes(), 3, "both denials in the builder's /24 are still looked up")
}
