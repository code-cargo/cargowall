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

package dns

import (
	"log/slog"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// refusedQueryServer builds a filtering, deny-by-default server wired to a
// file-less audit logger, a recording sink, and the refusal buffer — the
// production shape of the #119 path, minus the file.
func refusedQueryServer(t *testing.T) (*Server, *recordingSink, *config.Manager) {
	t.Helper()

	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules(nil, config.ActionDeny))

	server := NewServer(cfg, firewall.NewMockFirewall(t), "8.8.8.8:53", "127.0.0.1:53", slog.Default())
	server.EnableQueryFiltering(true)

	auditLogger, err := events.NewAuditLogger("", false)
	require.NoError(t, err)
	t.Cleanup(func() { auditLogger.Close() })

	sink := &recordingSink{}
	auditLogger.AddSink(sink)
	buf := events.NewRecentDNSBlocks(0)
	auditLogger.AddSink(buf)
	server.SetAuditLogger(auditLogger)
	server.SetRecentDNSBlocks(buf)

	return server, sink, cfg
}

// refuse runs one query the current ruleset does not allow and asserts it was
// refused, returning the dns_blocked event it produced.
func refuse(t *testing.T, server *Server, sink *recordingSink, domain string) events.AuditEvent {
	t.Helper()

	before := len(sink.evs)
	w := &addrResponseWriter{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51445},
	}
	query := new(dns.Msg)
	query.SetQuestion(domain+".", dns.TypeA)
	server.handleDNSQuery(w, query)

	require.NotNil(t, w.msg, "handler must write a response")
	require.Equal(t, dns.RcodeRefused, w.msg.Rcode, "query must be refused, not forwarded")
	require.Len(t, sink.evs, before+1, "exactly one dns_blocked audit event")
	ev := sink.evs[before]
	require.Equal(t, events.EventDNSBlocked, ev.EventType)
	return ev
}

// The #119 sequence: a query is refused while the rule covering it is still
// loading, the rule lands, and the refusal is re-reported as late-allowed
// dated at the original refusal — so the summary supersedes it instead of
// shipping a denial the policy never intended.
func TestReconcileRefusedQueries_LateAllowsOnceRuleLoads(t *testing.T) {
	const domain = "productionresultssa16.blob.core.windows.net"

	server, sink, cfg := refusedQueryServer(t)
	blocked := refuse(t, server, sink, domain)

	// The Azure infrastructure auto-allow lands (as it does behind the
	// policy fetch), covering the name by parent domain.
	cfg.EnsureHostnameAllowed("blob.core.windows.net",
		[]config.Port{config.PortHTTPS}, config.AutoAddedTypeAzureInfrastructure)
	server.ApplyRulesToTrackedHostnames()

	require.Len(t, sink.evs, 2, "the refusal must be re-reported exactly once")
	late := sink.evs[1]
	require.Equal(t, events.EventDNSQueryLateAllowed, late.EventType)
	require.Equal(t, domain, late.DstHostname)
	require.Equal(t, "blob.core.windows.net", late.MatchedRule, "the rule that finally covered it")
	require.Equal(t, blocked.Timestamp, late.Timestamp,
		"dated at the original refusal so it supersedes that record")
	require.False(t, late.Blocked, "nothing was blocked when this was written")
	require.False(t, late.WouldDeny, "an enforce-mode run must not stamp would-deny on a late-allow")

	// The entry is consumed: a second pass must not re-report it.
	server.ApplyRulesToTrackedHostnames()
	require.Len(t, sink.evs, 2, "a taken refusal must not be re-reported")
}

// A name still refused after the rules load stays buffered — a later load
// may yet cover it, and until then the refusal is the standing verdict.
func TestReconcileRefusedQueries_StillRefusedStaysBuffered(t *testing.T) {
	server, sink, cfg := refusedQueryServer(t)
	refuse(t, server, sink, "evil.example.com")

	// A policy that does not cover the refused name.
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "github.com", Action: config.ActionAllow},
	}, config.ActionDeny))
	server.ApplyRulesToTrackedHostnames()
	require.Len(t, sink.evs, 1, "a name still refused must not be late-allowed")

	// It was kept, not dropped: once a rule covers it, it reconciles.
	cfg.EnsureHostnameAllowed("evil.example.com",
		[]config.Port{config.PortHTTPS}, config.AutoAddedTypeGitHubService)
	server.ApplyRulesToTrackedHostnames()
	require.Len(t, sink.evs, 2, "the buffered refusal must reconcile on a later pass")
	require.Equal(t, events.EventDNSQueryLateAllowed, sink.evs[1].EventType)
}

// The attribution on the refusal is the attribution on the re-report: a
// dropped field would silently demote the event in the causal grouping and
// the container tier of the summary.
func TestReconcileRefusedQueries_CarriesAttribution(t *testing.T) {
	server, sink, cfg := refusedQueryServer(t)
	server.SetStepLookup(func(net.Addr) events.StepAttribution {
		return events.StepAttribution{
			Ordinal: 4, Outcome: events.StepAttrOK, PID: 1893, Process: "Runner.Worker",
		}
	})

	blocked := refuse(t, server, sink, "telemetry.example.com")
	require.Equal(t, uint32(4), blocked.StepOrdinal, "precondition: the refusal is attributed")

	cfg.EnsureHostnameAllowed("telemetry.example.com",
		[]config.Port{config.PortHTTPS}, config.AutoAddedTypeGitHubService)
	server.ApplyRulesToTrackedHostnames()

	require.Len(t, sink.evs, 2)
	late := sink.evs[1]
	require.Equal(t, blocked.StepOrdinal, late.StepOrdinal)
	require.Equal(t, blocked.StepAttrOutcome, late.StepAttrOutcome)
	require.Equal(t, blocked.PID, late.PID)
	require.Equal(t, blocked.Process, late.Process)
}

// Reconciliation is reporting, not enforcement: it must run even when the
// firewall gate in ApplyRulesToTrackedHostnames short-circuits the replay.
func TestReconcileRefusedQueries_RunsWithoutFirewall(t *testing.T) {
	server, sink, cfg := refusedQueryServer(t)
	refuse(t, server, sink, "infra.example.com")

	server.SetFirewall(nil)
	cfg.EnsureHostnameAllowed("infra.example.com",
		[]config.Port{config.PortHTTPS}, config.AutoAddedTypeGitHubService)
	server.ApplyRulesToTrackedHostnames()

	require.Len(t, sink.evs, 2, "the nil-firewall gate must not skip reporting")
	require.Equal(t, events.EventDNSQueryLateAllowed, sink.evs[1].EventType)
}
