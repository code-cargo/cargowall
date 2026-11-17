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
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
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

// reverseName is ip's canonical PTR name, lowercase and without the root dot,
// as the query gate sees it.
func reverseName(t *testing.T, ip string) string {
	t.Helper()
	name, err := dns.ReverseAddr(ip)
	require.NoError(t, err)
	return strings.TrimSuffix(name, ".")
}

// ip6ArpaName is ip's ip6.arpa name, all 32 nibbles, even for an
// IPv4-mapped address, which dns.ReverseAddr names under in-addr.arpa.
func ip6ArpaName(ip string) string {
	b := netip.MustParseAddr(ip).As16()
	labels := make([]string, 0, 32)
	for i := len(b) - 1; i >= 0; i-- {
		labels = append(labels, fmt.Sprintf("%x", b[i]&0xf), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(labels, ".") + ".ip6.arpa"
}

// The policy the reverse-lookup tests share: allow CIDRs for the job (one
// port-scoped) and for a step, and a deny CIDR, which makes nothing known.
const reverseQueryPolicy = `{
	"defaultAction": "deny",
	"rules": [
		{"type": "cidr", "value": "203.0.113.0/24", "action": "allow"},
		{"type": "cidr", "value": "2001:db8:1::/48", "ports": [{"port": 443, "protocol": "tcp"}], "action": "allow"},
		{"type": "cidr", "value": "198.51.100.0/24", "action": "deny"}
	],
	"steps": [
		{"id": "build", "rules": [
			{"type": "cidr", "value": "192.0.2.128/25"},
			{"type": "cidr", "value": "2001:db8:2::/48"}
		]}
	]
}`

func reverseQueryConfig(t *testing.T) *config.Manager {
	t.Helper()
	cfg := config.NewConfigManager()
	loadStepPolicy(t, cfg, reverseQueryPolicy)
	cfg.UpdateDNSMapping("named.example.com", "192.0.2.10")
	cfg.UpdateDNSMapping("named6.example.com", "2001:db8:3::10")
	return cfg
}

func TestReverseQueryAddr(t *testing.T) {
	for _, ip := range []string{"192.0.2.10", "0.0.0.0", "255.255.255.255", "2001:db8::1", "fe80::1", "::1"} {
		addr, ok := reverseQueryAddr(reverseName(t, ip))
		require.True(t, ok, ip)
		assert.Equal(t, netip.MustParseAddr(ip), addr, ip)
	}
	addr, ok := reverseQueryAddr(strings.ToUpper(reverseName(t, "2001:db8::abcd")) + ".")
	require.True(t, ok, "case and a root dot don't matter")
	assert.Equal(t, netip.MustParseAddr("2001:db8::abcd"), addr)
	addr, ok = reverseQueryAddr(ip6ArpaName("::ffff:192.0.2.10"))
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("192.0.2.10"), addr, "an IPv4-mapped address is its IPv4 address")
	assert.Equal(t, reverseName(t, "2001:db8::1"), ip6ArpaName("2001:db8::1"), "the helper names as dns.ReverseAddr does")

	for _, bad := range []string{"1.in-addr.arpa", "001.2.3.4.in-addr.arpa", "d.e.a.d.ip6.arpa", "example.com", ""} {
		_, ok := reverseQueryAddr(bad)
		assert.False(t, ok, bad)
	}
}

// Under query filtering, a reverse lookup is answered on its shape alone
// only for an address the run knows: one with a name, one inside an allow
// rule's CIDR (the job's or a step's), or a private, loopback, link-local or
// unique-local one. Any other is judged like any other name, so under a
// deny default it is refused.
func TestIsQueryAllowed_ReverseLookupsOfKnownAddressesOnly(t *testing.T) {
	server := newTestServer(t, reverseQueryConfig(t), firewall.NewMockFirewall(t))
	server.filterQueries = true

	for _, tc := range []struct {
		ip   string
		want bool
		why  string
	}{
		// An IPv4-mapped address is named under ip6.arpa (ip6ArpaName).
		{"192.0.2.10", true, "named by a DNS answer"},
		{"2001:db8:3::10", true, "named by a DNS answer"},
		{"::ffff:192.0.2.10", true, "the IPv4-mapped form of a named address"},
		{"203.0.113.9", true, "in a job allow CIDR"},
		{"2001:db8:1::9", true, "in a port-scoped job allow CIDR"},
		{"192.0.2.200", true, "in a step allow CIDR"},
		{"2001:db8:2:ffff::9", true, "in a step allow CIDR"},
		{"10.1.2.3", true, "private"},
		{"::ffff:10.1.2.3", true, "the IPv4-mapped form of a private address"},
		{"172.16.0.1", true, "private"},
		{"192.168.1.1", true, "private"},
		{"127.0.0.53", true, "loopback"},
		{"::1", true, "loopback"},
		{"169.254.169.254", true, "link-local"},
		{"fe80::1", true, "link-local"},
		{"fd00:1::1", true, "unique-local"},
		{"100.64.0.1", true, "shared address space"},
		{"100.127.255.254", true, "shared address space"},
		{"::ffff:100.100.1.1", true, "the IPv4-mapped form of a shared address"},
		{"100.128.0.1", false, "just past the shared address space"},
		{"100.63.255.255", false, "just before the shared address space"},
		{"192.0.2.11", false, "unknown, beside a named address"},
		{"2001:db8:abcd:1234:5678:9abc:def0:1234", false, "unknown"},
		{"::ffff:192.0.2.11", false, "the IPv4-mapped form of an unknown address"},
		{"198.51.100.7", false, "only a deny CIDR covers it"},
		{"8.8.8.8", false, "unknown"},
	} {
		name := reverseName(t, tc.ip)
		if strings.HasPrefix(tc.ip, "::ffff:") {
			name = ip6ArpaName(tc.ip)
		}
		assert.Equal(t, tc.want, server.isQueryAllowed(name, dns.TypePTR), "%s: %s", tc.ip, tc.why)
	}

	// A name learned later makes the address known.
	unknown := reverseName(t, "192.0.2.12")
	require.False(t, server.isQueryAllowed(unknown, dns.TypePTR))
	server.config.UpdateDNSMapping("later.example.com", "192.0.2.12")
	assert.True(t, server.isQueryAllowed(unknown, dns.TypePTR))

	// Only a PTR query of a known address: another type stays refused.
	assert.False(t, server.isQueryAllowed(reverseName(t, "192.0.2.10"), dns.TypeTXT))
}

// An address cargowall auto-allows as infrastructure (EnsureInfraAllowed,
// as autoAllowAzure calls it) or as its DNS upstream (EnsureDNSAllowed, v4
// and v6) is inside an allow CIDR, so its reverse lookup passes the gate.
// The allow is exact: an address never allowed, and the neighbour of an
// auto-allowed /32 or /128, stay refused, as does any other query type for
// an auto-allowed address's reverse name. An explicit deny over the address
// keeps it unknown, since the auto-allow is skipped there.
func TestIsQueryAllowed_ReverseLookupsOfAutoAllowedAddresses(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules(nil, config.ActionDeny))
	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	server.filterQueries = true
	wireserver := reverseName(t, "168.63.129.16")
	require.False(t, server.isQueryAllowed(wireserver, dns.TypePTR), "before any allow")

	// autoAllowAzure's calls, ports and all.
	cfg.EnsureInfraAllowed([]string{"168.63.129.16"},
		[]config.Port{config.PortDNS, config.PortHTTP, config.PortWireServer}, config.AutoAddedTypeAzureInfrastructure)
	cfg.EnsureInfraAllowed([]string{"168.63.129.16"}, []config.Port{config.PortICMP}, config.AutoAddedTypeAzureInfrastructure)
	cfg.EnsureDNSAllowed([]string{"8.8.4.4", "2001:4860:4860::8844"})

	for ip, want := range map[string]bool{
		"168.63.129.16":        true,
		"8.8.4.4":              true,
		"2001:4860:4860::8844": true,
		"9.9.9.9":              false, // never allowed
		"168.63.129.17":        false, // the /32's neighbour
		"8.8.4.5":              false, // the /32's neighbour
		"2001:4860:4860::8845": false, // the /128's neighbour
	} {
		assert.Equal(t, want, server.isQueryAllowed(reverseName(t, ip), dns.TypePTR), ip)
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
		assert.False(t, server.isQueryAllowed(wireserver, qtype), "%s of the wireserver's reverse name", dns.TypeToString[qtype])
	}

	denied := config.NewConfigManager()
	require.NoError(t, denied.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "168.63.129.16/32", Action: config.ActionDeny},
	}, config.ActionDeny))
	denied.EnsureInfraAllowed([]string{"168.63.129.16"}, nil, config.AutoAddedTypeAzureInfrastructure)
	server = newTestServer(t, denied, firewall.NewMockFirewall(t))
	server.filterQueries = true
	assert.False(t, server.isQueryAllowed(wireserver, dns.TypePTR), "an explicit deny keeps the address unknown")
}

// A hostname rule for a reverse-lookup name is dropped at load, so it
// opens nothing under the reverse zones: an unknown address's reverse
// lookup, and any other query type under its name, stay refused. The
// reverse lookup of an address an allow CIDR covers still passes.
func TestIsQueryAllowed_ReverseLookupHostRulesOpenNothing(t *testing.T) {
	cfg := config.NewConfigManager()
	loadStepPolicy(t, cfg, `{"defaultAction": "deny", "rules": [
		{"type": "hostname", "value": "7.2.0.192.in-addr.arpa", "action": "allow"},
		{"type": "hostname", "value": "**.ip6.arpa", "action": "allow"},
		{"type": "cidr", "value": "203.0.113.0/24", "action": "allow"}],
		"steps": [{"id": "build", "rules": [{"type": "hostname", "value": "*.in-addr.arpa"}]}]}`)
	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	server.filterQueries = true

	v4 := reverseName(t, "192.0.2.7")
	assert.False(t, server.isQueryAllowed(v4, dns.TypePTR))
	assert.False(t, server.isQueryAllowed(v4, dns.TypeTXT))
	assert.False(t, server.isQueryAllowed("data."+v4, dns.TypeTXT))
	assert.False(t, server.isQueryAllowed(reverseName(t, "2001:db8:abcd::1"), dns.TypePTR))
	assert.False(t, server.isQueryAllowed("a.b."+reverseName(t, "2001:db8:abcd::1"), dns.TypeA))
	assert.True(t, server.isQueryAllowed(reverseName(t, "203.0.113.9"), dns.TypePTR), "an allowed address")
}

// A reverse-lookup name is decided only by the address gate or the default
// action, whatever rule would match it: a rule above the reverse zones, a
// pattern whose top labels are wildcards, a job's or a step's. Under a deny
// default, an unknown address's reverse lookup is refused with a
// dns_blocked record, as is any other query type under the name; a known
// or CIDR-allowed address's reverse lookup passes. Each rule stays live for
// the names it was written for, so home.arpa still resolves under arpa.
func TestIsQueryAllowed_OnlyTheAddressGateOrTheDefaultDecidesReverseNames(t *testing.T) {
	v4, v6 := "192.0.2.7", "2001:db8:abcd::1"
	for _, tc := range []struct {
		rule    string
		matches string // a reverse name the rule matches, proving it loaded
		unknown []string
	}{
		{"arpa", "x.in-addr.arpa", []string{v4, v6}},
		{"**.arpa", "x.ip6.arpa", []string{v4, v6}},
		{"**.in-addr.*", "7.2.0.192.in-addr.arpa", []string{v4}},
		{"*.*.*.*.in-addr.*", "7.2.0.192.in-addr.arpa", []string{v4}},
		{"**.ip6.*", "x.ip6.arpa", []string{v6}},
	} {
		for _, step := range []bool{false, true} {
			name := tc.rule + " (job rule)"
			rule := `{"type": "hostname", "value": "` + tc.rule + `", "action": "allow"}`
			policy := `{"defaultAction": "deny", "rules": [` + rule + `, {"type": "cidr", "value": "203.0.113.0/24", "action": "allow"}]}`
			if step {
				name = tc.rule + " (step rule)"
				policy = `{"defaultAction": "deny", "rules": [{"type": "cidr", "value": "203.0.113.0/24", "action": "allow"}],
					"steps": [{"id": "build", "rules": [{"type": "hostname", "value": "` + tc.rule + `"}]}]}`
			}
			t.Run(name, func(t *testing.T) {
				cfg := config.NewConfigManager()
				loadStepPolicy(t, cfg, policy)
				if step {
					require.True(t, cfg.StepAllowsHostname(tc.matches), "the step rule is live")
				} else {
					require.True(t, cfg.MatchHostnameRule(tc.matches).HasAllow(), "the job rule is live")
				}
				cfg.UpdateDNSMapping("named.example.com", "192.0.2.10")
				cfg.UpdateDNSMapping("named6.example.com", "2001:db8:3::10")
				server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
				server.filterQueries = true
				auditFile := t.TempDir() + "/audit.json"
				auditLogger, err := events.NewAuditLogger(auditFile, false)
				require.NoError(t, err)
				t.Cleanup(func() { auditLogger.Close() })
				server.auditLogger = auditLogger

				for _, ip := range tc.unknown {
					rev := reverseName(t, ip)
					assert.False(t, server.isQueryAllowed(rev, dns.TypePTR), "PTR %s", ip)
					assert.False(t, server.isQueryAllowed(rev, dns.TypeTXT), "TXT %s", ip)
					assert.False(t, server.isQueryAllowed("data."+rev, dns.TypeTXT), "TXT under %s", ip)
					assert.False(t, server.isQueryAllowed("a.b."+rev, dns.TypeA), "A under %s", ip)

					q := new(dns.Msg)
					q.SetQuestion(rev+".", dns.TypePTR)
					w := &MockResponseWriter{}
					w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
					server.handleDNSQuery(w, q)
					require.NotNil(t, w.msg)
					assert.Equal(t, dns.RcodeRefused, w.msg.Rcode, "PTR %s through the proxy", ip)
				}
				evs := readDNSAuditEvents(t, auditFile)
				require.Len(t, evs, len(tc.unknown))
				for _, ev := range evs {
					assert.Equal(t, events.EventDNSBlocked, ev.EventType)
				}

				for _, ip := range []string{"192.0.2.10", "2001:db8:3::10", "203.0.113.9"} {
					assert.True(t, server.isQueryAllowed(reverseName(t, ip), dns.TypePTR), "a known address %s", ip)
				}
				if tc.rule == "arpa" || tc.rule == "**.arpa" {
					assert.True(t, server.isQueryAllowed("printer.home.arpa", dns.TypeA), "home.arpa still resolves")
				}
			})
		}
	}
}

// Under an allow default, a deny rule for a reverse zone still refuses an
// unknown address's reverse lookup, and a known address's passes.
func TestIsQueryAllowed_ReverseZoneDenyUnderAnAllowDefault(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "in-addr.arpa", Action: config.ActionDeny},
		{Type: config.RuleTypeHostname, Value: "arpa", Action: config.ActionAllow},
	}, config.ActionAllow))
	cfg.UpdateDNSMapping("named.example.com", "192.0.2.10")
	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	server.filterQueries = true
	assert.False(t, server.isQueryAllowed(reverseName(t, "192.0.2.7"), dns.TypePTR), "the deny refuses it")
	assert.True(t, server.isQueryAllowed(reverseName(t, "192.0.2.10"), dns.TypePTR), "a known address")
	assert.True(t, server.isQueryAllowed(reverseName(t, "2001:db8:abcd::1"), dns.TypePTR), "no deny: the default allows it")
}

// A search domain under a reverse zone is dropped at load, from a local
// file or the environment, and the rest of the policy loads: it could never
// allow a reverse-lookup name, which the address gate decides.
func TestSearchDomainsUnderReverseZonesAreDropped(t *testing.T) {
	cfg := config.NewConfigManager()
	path := t.TempDir() + "/policy.json"
	require.NoError(t, os.WriteFile(path, []byte(`{"defaultAction": "deny", "searchDomains":
		[".100.51.198.in-addr.arpa", ".in-addr.arpa", ".d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa", ".corp.internal"]}`), 0o600))
	require.NoError(t, cfg.LoadConfig(path))
	assert.Equal(t, []string{".corp.internal"}, cfg.GetSearchDomains())
	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	server.filterQueries = true
	assert.False(t, server.isQueryAllowed(reverseName(t, "198.51.100.7"), dns.TypePTR))
	assert.True(t, server.isQueryAllowed("db.corp.internal", dns.TypeA), "the rest loaded")

	t.Setenv("CARGOWALL_SEARCH_DOMAINS", ".100.51.198.in-addr.arpa,.corp.internal")
	cfg = config.NewConfigManager()
	require.NoError(t, cfg.LoadFromEnv())
	assert.Equal(t, []string{".corp.internal"}, cfg.GetSearchDomains())
}

// The answer to a PTR query never changes enforcement state, whatever
// records it carries: an address record or CNAME target in it, here behind
// a known address's reverse name and a rule above the reverse zones, is
// neither mapped, learned nor installed. The same records answering an
// address query are.
func TestHandleDNSQuery_PTRAnswerInstallsNothing(t *testing.T) {
	answerWith := func(qname string, qtype uint16) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(qname, qtype)
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "evil.example.net."},
			&dns.A{Hdr: dns.RR_Header{Name: "evil.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("6.6.6.6")},
		}
		return resp
	}
	newServer := func(t *testing.T, fw firewall.Firewall) *Server {
		cfg := config.NewConfigManager()
		require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
			{Type: config.RuleTypeCIDR, Value: "203.0.113.0/24", Action: config.ActionAllow},
			{Type: config.RuleTypeHostname, Value: "arpa", Action: config.ActionAllow},
			{Type: config.RuleTypeHostname, Value: "known.example.com", Action: config.ActionAllow},
		}, config.ActionDeny))
		server := newTestServer(t, cfg, fw)
		server.filterQueries = true
		return server
	}
	query := func(server *Server, qname string, qtype uint16) *dns.Msg {
		resp := answerWith(qname, qtype)
		q := new(dns.Msg)
		q.SetQuestion(qname, qtype)
		server.dnsCache.Put(server.generateCacheKey(q), &dnsCacheEntry{msg: resp}, 5*time.Minute)
		w := &MockResponseWriter{}
		w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
		server.handleDNSQuery(w, q)
		w.AssertExpectations(t)
		return w.msg
	}

	// The mock firewall fails the test on any call.
	server := newServer(t, firewall.NewMockFirewall(t))
	msg := query(server, reverseName(t, "203.0.113.9")+".", dns.TypePTR)
	require.NotNil(t, msg)
	assert.Equal(t, dns.RcodeSuccess, msg.Rcode, "the known address's lookup is answered")
	assert.Len(t, msg.Answer, 2, "and the answer reaches the job as it came")
	assert.Empty(t, server.config.LookupHostnameByIP("6.6.6.6"), "no address in it is mapped")
	_, learned := server.cnameAllowed.Get("evil.example.net")
	assert.False(t, learned, "no CNAME target in it is learned")
	assert.False(t, server.isQueryAllowed("evil.example.net", dns.TypeA))

	// The control: the same records answering an address query are applied.
	fw := firewall.NewMockFirewall(t)
	fw.On("AddIP", mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	server = newServer(t, fw)
	require.NotNil(t, query(server, "known.example.com.", dns.TypeA))
	assert.NotEmpty(t, server.config.LookupHostnameByIP("6.6.6.6"))
	_, learned = server.cnameAllowed.Get("evil.example.net")
	assert.True(t, learned)
}

// An unknown address's reverse lookup is judged by the rules like any
// other name, so a default allow allows it.
func TestIsQueryAllowed_ReverseLookupOfUnknownAddressFollowsTheDefault(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules(nil, config.ActionAllow))
	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	server.filterQueries = true
	assert.True(t, server.isQueryAllowed(reverseName(t, "192.0.2.11"), dns.TypePTR))
	assert.True(t, server.isQueryAllowed(reverseName(t, "2001:db8:abcd::1"), dns.TypePTR))
}

// A reverse lookup the gate refuses takes the refusal path every filtered
// query takes: REFUSED and a dns_blocked record under enforce, and in audit
// mode the record and the query forwarded. The record names the address
// the lookup asked about as its destination IP, with no hostname. A known
// address's lookup is answered, and writes no record.
func TestHandleDNSQuery_ReverseLookupRefusal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ip      string
		audit   bool
		refused bool
		blocked bool
	}{
		{"unknown IPv4, enforce", "192.0.2.11", false, true, true},
		{"unknown IPv6, enforce", "2001:db8:abcd::1", false, true, true},
		{"unknown IPv4, audit", "192.0.2.11", true, false, true},
		{"unknown IPv6, audit", "2001:db8:abcd::1", true, false, true},
		{"known IPv4, enforce", "192.0.2.10", false, false, false},
		{"known IPv6, enforce", "2001:db8:3::10", false, false, false},
		{"private IPv4, enforce", "10.1.2.3", false, false, false},
		{"unique-local IPv6, enforce", "fd00:1::1", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := reverseQueryConfig(t)
			cfg.SetAuditMode(tc.audit)
			server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
			server.filterQueries = true
			auditFile := t.TempDir() + "/audit.json"
			auditLogger, err := events.NewAuditLogger(auditFile, tc.audit)
			require.NoError(t, err)
			t.Cleanup(func() { auditLogger.Close() })
			server.auditLogger = auditLogger

			qname := reverseName(t, tc.ip) + "."
			// The answer comes from the cache, so a forwarded query needs no
			// upstream.
			q := new(dns.Msg)
			q.SetQuestion(qname, dns.TypePTR)
			resp := new(dns.Msg)
			resp.SetReply(q)
			resp.Answer = []dns.RR{&dns.PTR{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300},
				Ptr: "host.example.net.",
			}}
			server.dnsCache.Put(server.generateCacheKey(q), &dnsCacheEntry{msg: resp}, 5*time.Minute)

			w := &MockResponseWriter{}
			w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
			server.handleDNSQuery(w, q)
			w.AssertExpectations(t)
			require.NotNil(t, w.msg)
			if tc.refused {
				assert.Equal(t, dns.RcodeRefused, w.msg.Rcode)
				assert.Empty(t, w.msg.Answer)
			} else {
				assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
				require.Len(t, w.msg.Answer, 1)
			}

			data, err := os.ReadFile(auditFile)
			require.NoError(t, err)
			if !tc.blocked {
				assert.NotContains(t, string(data), string(events.EventDNSBlocked))
				return
			}
			evs := readDNSAuditEvents(t, auditFile)
			require.Len(t, evs, 1)
			assert.Equal(t, events.EventDNSBlocked, evs[0].EventType)
			assert.Equal(t, netip.MustParseAddr(tc.ip).String(), evs[0].DstIP)
			assert.Empty(t, evs[0].DstHostname)
			assert.Equal(t, tc.audit, evs[0].WouldDeny)
		})
	}
}

// A refused query for a reverse-lookup name that names no single address,
// or any other name, keeps the name as the record's hostname.
func TestBlockedQueryEvent(t *testing.T) {
	for domain, want := range map[string]events.AuditEvent{
		"7.2.0.192.in-addr.arpa":           {EventType: events.EventDNSBlocked, DstIP: "192.0.2.7"},
		reverseName(t, "2001:db8:abcd::1"): {EventType: events.EventDNSBlocked, DstIP: "2001:db8:abcd::1"},
		ip6ArpaName("::ffff:192.0.2.7"):    {EventType: events.EventDNSBlocked, DstIP: "192.0.2.7"},
		"exfil.payload.in-addr.arpa":       {EventType: events.EventDNSBlocked, DstHostname: "exfil.payload.in-addr.arpa"},
		"2.0.192.in-addr.arpa":             {EventType: events.EventDNSBlocked, DstHostname: "2.0.192.in-addr.arpa"},
		"evil.example.com":                 {EventType: events.EventDNSBlocked, DstHostname: "evil.example.com"},
		"7.2.0.192.in-addr.arpa.example":   {EventType: events.EventDNSBlocked, DstHostname: "7.2.0.192.in-addr.arpa.example"},
	} {
		assert.Equal(t, want, blockedQueryEvent(domain), domain)
	}
}
