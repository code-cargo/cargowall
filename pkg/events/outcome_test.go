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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

func verdictRec(dropped bool) VerdictRecord {
	return VerdictRecord{
		SrcIP:       "172.17.0.2",
		DstIP:       "93.184.216.34",
		SrcPort:     40001,
		DstPort:     443,
		Proto:       unix.IPPROTO_TCP,
		PID:         4242,
		StepOrdinal: 7,
		Dropped:     dropped,
	}
}

// A drop reported by the cgroup hook is a policy outcome indistinguishable
// in kind from a TC drop, and must carry the same enrichment — hostname
// among it. The thin-record regression this guards against reported bare
// IPs with no hostname, no CNAME, and no late-allow.
func TestReportVerdict_BlockedCarriesHostname(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)

	ReportVerdict(verdictRec(true), cm, nil, auditLogger, nil, newTestLogger())

	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, EventConnectionBlocked, ev.EventType)
	assert.Equal(t, "example.com", ev.DstHostname, "hostname resolution must run for cgroup verdicts")
	assert.Equal(t, "172.17.0.2", ev.SrcIP, "src IP must survive to the audit record")
	assert.Equal(t, uint32(7), ev.StepOrdinal)
	assert.Equal(t, uint32(4242), ev.PID)
	assert.True(t, ev.Blocked)
}

// A degraded report is the saturated-pipeline path: it must stay bounded —
// no hostname resolution, no firewall writes, no notification — while the
// audit record still lands with kind selection identical to the full path
// and container decoration intact. This pins the contract Record.Degraded
// documents in pkg/origin.
func TestReportVerdict_DegradedIsBoundedButAudited(t *testing.T) {
	cm := config.NewConfigManager()
	// An allow rule + DNS mapping that WOULD late-allow on the full path:
	// the degraded path must not consult either.
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "example.com",
		Action: config.ActionAllow,
	}}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	fw := &mockFirewallUpdater{}

	rec := verdictRec(true)
	rec.Degraded = true
	rec.Decorate = func(a *AuditEvent) {
		a.ContainerOrigin = true
		a.ContainerID = "abc123def456"
	}
	ReportVerdict(rec, cm, nil, auditLogger, fw, newTestLogger())

	require.Empty(t, fw.addedIPs, "degraded reports must not write to the firewall")
	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, EventConnectionBlocked, ev.EventType, "kind selection matches the full path (no late-allow)")
	assert.Empty(t, ev.DstHostname, "no resolution: the record carries the bare IP")
	assert.Equal(t, "93.184.216.34", ev.DstIP)
	assert.True(t, ev.ContainerOrigin, "decoration still runs — it is bounded")
	assert.Equal(t, "abc123def456", ev.ContainerID)
	assert.True(t, ev.Blocked)
}

// Late-allow is the behavioral half: a denial whose destination actually
// resolves to an allowed host must open the firewall and report as
// late-allowed, exactly as on the TC path. Without this, enforce mode never
// self-heals a raw-IP connection that policy permits.
func TestReportVerdict_LateAllowOpensFirewall(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "example.com",
		Action: config.ActionAllow,
	}}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	fw := &mockFirewallUpdater{}

	ReportVerdict(verdictRec(true), cm, nil, auditLogger, fw, newTestLogger())

	require.NotEmpty(t, fw.addedIPs, "late-allow must open the firewall for the resolved host")
	require.Len(t, sink.events, 1)
	assert.Equal(t, EventConnectionLateAllowed, sink.events[0].EventType)
	assert.Equal(t, "example.com", sink.events[0].MatchedRule)
}

// Shadow mode is hypothetical: nothing was blocked, so it must not open the
// firewall and must not claim a block.
func TestReportVerdict_ShadowIsTelemetryOnly(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "example.com",
		Action: config.ActionAllow,
	}}, config.ActionDeny))
	cm.UpdateDNSMapping("example.com", "93.184.216.34")

	auditLogger, err := NewAuditLogger("", true)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	fw := &mockFirewallUpdater{}

	ReportVerdict(verdictRec(false), cm, nil, auditLogger, fw, newTestLogger())

	assert.Empty(t, fw.addedIPs, "a would-block must never mutate the firewall")
	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, EventCgroupWouldBlock, ev.EventType)
	assert.True(t, ev.WouldDeny)
	assert.False(t, ev.Blocked, "shadow mode blocked nothing")
}

// Container identity is decoration supplied by the caller, not something
// the pipeline knows about — and a host verdict (no decorator) must report
// just as completely.
func TestReportVerdict_DecoratorIsOptional(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	for _, tt := range []struct {
		name       string
		decorate   func(*AuditEvent)
		wantID     string
		wantOrigin bool
	}{
		{"host verdict, no decorator", nil, "", false},
		{"container verdict", func(a *AuditEvent) {
			a.ContainerOrigin = true
			a.ContainerID = "abc123def456"
		}, "abc123def456", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auditLogger, err := NewAuditLogger("", false)
			require.NoError(t, err)
			sink := &recordingSink{}
			auditLogger.AddSink(sink)

			rec := verdictRec(true)
			rec.Decorate = tt.decorate
			ReportVerdict(rec, cm, nil, auditLogger, nil, newTestLogger())

			require.Len(t, sink.events, 1)
			assert.Equal(t, tt.wantID, sink.events[0].ContainerID)
			assert.Equal(t, tt.wantOrigin, sink.events[0].ContainerOrigin)
			assert.Equal(t, EventConnectionBlocked, sink.events[0].EventType,
				"the outcome is the same regardless of decoration")
		})
	}
}

// A denial of an established flow must be distinguishable from a refused
// connection attempt on BOTH hooks — operators use that to tell "the
// allowlist killed a live connection" from "a new connection was refused".
// The cgroup hook re-adjudicates every packet, so it sees exactly this case.
func TestReportVerdict_MidStreamMatchesTC(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	for _, tt := range []struct {
		name      string
		midStream bool
	}{
		{"connection attempt", false},
		{"established flow killed", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auditLogger, err := NewAuditLogger("", false)
			require.NoError(t, err)
			sink := &recordingSink{}
			auditLogger.AddSink(sink)

			rec := verdictRec(true)
			rec.MidStream = tt.midStream
			ReportVerdict(rec, cm, nil, auditLogger, nil, newTestLogger())

			require.Len(t, sink.events, 1)
			// Same event type either way — MidStream is a flag, not a
			// different outcome, so RecentBlocks/summary/OTLP treat it like
			// any other block (matching the TC path).
			assert.Equal(t, EventConnectionBlocked, sink.events[0].EventType)
			assert.Equal(t, tt.midStream, sink.events[0].MidStream)
		})
	}
}

// A denied non-TCP/UDP protocol must report in the same shape TC gives it,
// or flipping --cgroup-enforce would silently change an event's type for
// every consumer that branches on it.
func TestReportVerdict_ProtocolBlockMatchesTC(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	auditLogger, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &recordingSink{}
	auditLogger.AddSink(sink)

	rec := verdictRec(true)
	rec.Proto = 47 // GRE
	rec.DstPort = 0
	rec.SrcPort = 0
	ReportVerdict(rec, cm, nil, auditLogger, nil, newTestLogger())

	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, EventProtocolBlocked, ev.EventType,
		"non-TCP/UDP denials keep TC's event type under enforcement")
	assert.Equal(t, "GRE", ev.Protocol)
	assert.Zero(t, ev.DstPort, "a protocol block carries no port")
}

// recordingSink captures audit events for assertions.
type recordingSink struct{ events []AuditEvent }

func (r *recordingSink) Consume(ev AuditEvent) { r.events = append(r.events, ev) }
