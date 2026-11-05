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
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// TestHandleDNSQuery_ClusterDomainDenials: in enforce mode a denied name in
// the cluster domain is answered NXDOMAIN, so a pod resolver walking its
// search list moves on to the bare name, while other denied names still get
// REFUSED. A search expansion of an allowed name is not reported; a denied
// cluster name that is not one is. Nothing denied is forwarded (the server's
// upstream is unreachable, so a forward would fail the WriteMsg expectation).
func TestHandleDNSQuery_ClusterDomainDenials(t *testing.T) {
	cases := []struct {
		name      string
		query     string
		rcode     int
		reported  bool
		reportAs  string
		rationale string
	}{
		{
			name: "expansion of allowed name", query: "Example.com.arc-runners.svc.cluster.local.",
			rcode: dns.RcodeNameError, reported: false,
			rationale: "an allowed name plus the pod's namespace suffix is the search walk, not a block",
		},
		{
			name: "expansion of allowed subdomain", query: "api.example.com.ci.svc.cluster.local.",
			rcode: dns.RcodeNameError, reported: false,
			rationale: "a plain rule allows subdomains, so their expansions are quiet too",
		},
		{
			name: "denied cluster service", query: "registry.infra.svc.cluster.local.",
			rcode: dns.RcodeNameError, reported: true, reportAs: "registry.infra.svc.cluster.local",
			rationale: "a cluster name the policy denies is still reported, but answered NXDOMAIN",
		},
		{
			name: "expansion of denied name", query: "evil.com.arc-runners.svc.cluster.local.",
			rcode: dns.RcodeNameError, reported: true, reportAs: "evil.com.arc-runners.svc.cluster.local",
			rationale: "the expansion of a denied name is a block like any other",
		},
		{
			name: "namespace label alone", query: "arc-runners.svc.cluster.local.",
			rcode: dns.RcodeNameError, reported: true, reportAs: "arc-runners.svc.cluster.local",
			rationale: "no name in front of the namespace label",
		},
		{
			name: "outside the cluster domain", query: "evil.com.",
			rcode: dns.RcodeRefused, reported: true, reportAs: "evil.com",
			rationale: "names outside the cluster domain keep REFUSED",
		},
		{
			name: "lookalike suffix", query: "evil.com.svc.cluster.localhost.",
			rcode: dns.RcodeRefused, reported: true, reportAs: "evil.com.svc.cluster.localhost",
			rationale: "only the real cluster domain gets NXDOMAIN",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := config.NewConfigManager()
			require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
				{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow},
			}, config.ActionDeny))

			server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
			server.upstream = "127.0.0.1:1"
			server.filterQueries = true
			auditPath := t.TempDir() + "/audit.json"
			auditLogger, err := events.NewAuditLogger(auditPath, false)
			require.NoError(t, err)
			defer auditLogger.Close()
			server.auditLogger = auditLogger

			query := new(dns.Msg)
			query.SetQuestion(c.query, dns.TypeA)
			w := &MockResponseWriter{}
			w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

			server.handleDNSQuery(w, query)

			w.AssertExpectations(t)
			require.NotNil(t, w.msg)
			assert.Equal(t, dns.RcodeToString[c.rcode], dns.RcodeToString[w.msg.Rcode], c.rationale)

			data, err := os.ReadFile(auditPath)
			require.NoError(t, err)
			if !c.reported {
				assert.Empty(t, data, c.rationale)
				return
			}
			evs := readDNSAuditEvents(t, auditPath)
			require.Len(t, evs, 1, c.rationale)
			assert.Equal(t, events.EventDNSBlocked, evs[0].EventType)
			assert.Equal(t, c.reportAs, evs[0].DstHostname)
		})
	}
}

// TestHandleDNSQuery_AuditModeExpansionNotReported: in audit mode a search
// expansion of an allowed name is forwarded as before, unreported.
func TestHandleDNSQuery_AuditModeExpansionNotReported(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow},
	}, config.ActionDeny))
	cfg.SetAuditMode(true)

	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	server.upstream = "127.0.0.1:1" // nothing answers: the forward fails, which still proves it was tried
	server.filterQueries = true
	auditPath := t.TempDir() + "/audit.json"
	auditLogger, err := events.NewAuditLogger(auditPath, true)
	require.NoError(t, err)
	defer auditLogger.Close()
	server.auditLogger = auditLogger

	query := new(dns.Msg)
	query.SetQuestion("example.com.arc-runners.svc.cluster.local.", dns.TypeA)
	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeToString[dns.RcodeServerFailure], dns.RcodeToString[w.msg.Rcode],
		"audit mode forwards the expansion; the unreachable upstream makes that a SERVFAIL")
	data, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	assert.Empty(t, data, "the expansion must not be reported as a would-be block")
}
