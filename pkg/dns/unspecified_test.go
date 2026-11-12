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
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// An allowed name answering the unspecified address opens nothing: no
// firewall write, no L7 scope, and a block to that address stays a block.
func TestHandleDNSQuery_UnspecifiedAnswerOpensNothing(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "zero.example.com", Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, Action: config.ActionAllow},
	}, config.ActionDeny))

	// No expectations: any firewall call fails the test.
	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	rec := &recordingRegistrar{}
	server.SetL7Registrar(rec)

	auditPath := filepath.Join(t.TempDir(), "audit.json")
	auditLogger, err := events.NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()
	server.SetAuditLogger(auditLogger)

	recentBlocks := events.NewRecentBlocks(0)
	recentBlocks.Consume(events.AuditEvent{
		Timestamp: time.Now().Add(-5 * time.Second),
		EventType: events.EventConnectionBlocked,
		DstIP:     "0.0.0.0",
		DstPort:   443,
		Protocol:  "TCP",
	})
	server.SetRecentBlocks(recentBlocks)

	const qname = "zero.example.com."
	seedCachedResponse(server, qname, makeCachedResponse(qname, "0.0.0.0"))
	query := new(dns.Msg)
	query.SetQuestion(qname, dns.TypeA)
	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	server.handleDNSQuery(w, query)
	w.AssertExpectations(t)

	assert.Empty(t, rec.scopes)
	assert.Empty(t, readAuditEvents(t, auditPath), "a block to the unspecified address was re-reported")
	assert.Len(t, recentBlocks.TakeMatching("0.0.0.0", nil, nil, false), 1)
}

// The one writer of map_l7_scope never scopes the unspecified address, even
// with forward-resolution evidence for it.
func TestRegisterL7_NeverScopesUnspecified(t *testing.T) {
	cfg := config.NewConfigManager()
	rec := &recordingRegistrar{}
	for _, addr := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0"} {
		ip := net.ParseIP(addr)
		cfg.RecordForwardResolution("zero.example.com", ip.String())
		RegisterL7Identity(rec, cfg, "zero.example.com", ip, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, nil)
	}
	assert.Empty(t, rec.scopes)

	// The same evidence for a real address scopes it.
	cfg.RecordForwardResolution("zero.example.com", "104.16.0.3")
	RegisterL7Identity(rec, cfg, "zero.example.com", net.ParseIP("104.16.0.3"), nil, nil)
	assert.Contains(t, rec.scopes, "104.16.0.3")
}
