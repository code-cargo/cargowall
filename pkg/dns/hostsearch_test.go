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
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// No test may inherit the machine's own search list: point the resolver
// config at a path that does not exist, so Start seeds nothing unless a test
// opts in through withResolvConf.
func TestMain(m *testing.M) {
	resolvConfPath = filepath.Join(os.TempDir(), "cargowall-dns-test-absent-resolv.conf")
	os.Exit(m.Run())
}

func TestHostSearchDomains_Parse(t *testing.T) {
	withResolvConf(t, "# generated\nnameserver 127.0.0.53\noptions edns0 trust-ad\n"+
		"domain old.example\n"+ // superseded: last directive wins
		"search LAN corp.example. # trailing comment\n")
	assert.Equal(t, []string{"lan", "corp.example"}, hostSearchDomains(resolvConfPath))

	withResolvConf(t, "")
	assert.Nil(t, hostSearchDomains(resolvConfPath), "unreadable file: no search list")
}

func TestSeedHostSearchDomains(t *testing.T) {
	withResolvConf(t, "search corp.lan com\n")
	cfg := config.NewConfigManager()
	s := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	s.logger = slog.Default()
	s.seedHostSearchDomains()
	assert.Equal(t, []string{".corp.lan"}, cfg.HostSearchDomains(), "published through the manager's normalization: public suffix dropped")

	withResolvConf(t, "")
	s.seedHostSearchDomains()
	assert.Empty(t, cfg.HostSearchDomains())
}

// The expanded form of an allowed single-label name passes the gate; the
// expanded form of an unknown one does not — stripping is not a bypass.
func TestIsQueryAllowed_HostSearchExpandedForm(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "myservice", Action: config.ActionAllow},
	}, config.ActionDeny))
	cfg.SetHostSearchDomains([]string{"corp.lan"}, slog.Default())
	s := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	s.filterQueries = true

	assert.True(t, s.isQueryAllowed("myservice.corp.lan", dns.TypeA))
	assert.True(t, s.isQueryAllowed("myservice", dns.TypeA))
	assert.False(t, s.isQueryAllowed("other.corp.lan", dns.TypeA))
}

// End to end, the shape every stub resolver produces: the FIRST query on the
// wire for "myservice" on a host with "search corp.lan" is
// "myservice.corp.lan" — and for a real host that is the record. It must be
// forwarded, answered, and its address opened under rule "myservice".
func TestHandleDNSQuery_HostSearchExpandedFormResolvesAndEnforces(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	upstream := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if r.Question[0].Name == "myservice.corp.lan." && r.Question[0].Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.10"),
				})
			} else {
				m.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = upstream.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = upstream.Shutdown(); _ = pc.Close() })

	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "myservice", Action: config.ActionAllow},
	}, config.ActionDeny))
	cfg.SetHostSearchDomains([]string{"corp.lan"}, slog.Default())
	mockFw := firewall.NewMockFirewall(t)
	mockFw.On("AddIP",
		mock.MatchedBy(func(ip net.IP) bool { return ip.Equal(net.ParseIP("192.0.2.10")) }),
		config.ActionAllow, []config.Port(nil)).
		Return(true, nil).Once()
	s := newTestServer(t, cfg, mockFw)
	s.upstream = pc.LocalAddr().String()
	s.filterQueries = true

	q := new(dns.Msg)
	q.SetQuestion("myservice.corp.lan.", dns.TypeA)
	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	s.handleDNSQuery(w, q)
	w.AssertExpectations(t)
	mockFw.AssertExpectations(t)

	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
	require.Len(t, w.msg.Answer, 1)
	assert.Equal(t, "192.0.2.10", w.msg.Answer[0].(*dns.A).A.String())
}
