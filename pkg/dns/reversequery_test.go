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

// reverseName is ip's canonical PTR name, lowercase and without the root dot.
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

func reverseQueryConfig(t *testing.T) *config.Manager {
	t.Helper()
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "203.0.113.0/24", Action: config.ActionAllow},
		{Type: config.RuleTypeCIDR, Value: "198.51.100.0/24", Action: config.ActionDeny},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("named.example.com", "192.0.2.10")
	cm.UpdateDNSMapping("named6.example.com", "2001:db8:3::10")
	return cm
}

func TestReverseQueryAddr(t *testing.T) {
	for _, ip := range []string{"192.0.2.10", "0.0.0.0", "255.255.255.255", "2001:db8::1", "fe80::1", "::1"} {
		addr, ok := reverseQueryAddr(reverseName(t, ip))
		require.True(t, ok, ip)
		assert.Equal(t, netip.MustParseAddr(ip), addr, ip)
	}
	addr, ok := reverseQueryAddr(ip6ArpaName("::ffff:192.0.2.10"))
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("192.0.2.10"), addr, "an IPv4-mapped address is its IPv4 address")
	for _, bad := range []string{"1.in-addr.arpa", "001.2.3.4.in-addr.arpa", "d.e.a.d.ip6.arpa", "example.com", ""} {
		_, ok := reverseQueryAddr(bad)
		assert.False(t, ok, bad)
	}
}

// Under query filtering a reverse lookup is answered on its shape alone only
// for an address the run knows: named, in an allow CIDR, or local. Anything
// else, under a deny default, is refused; and only a PTR query.
func TestIsQueryAllowed_ReverseLookupsOfKnownAddressesOnly(t *testing.T) {
	server := newTestServer(t, reverseQueryConfig(t), firewall.NewMockFirewall(t))
	server.filterQueries = true
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"192.0.2.10", true},
		{"2001:db8:3::10", true},
		{"203.0.113.9", true},
		{"10.1.2.3", true},
		{"127.0.0.53", true},
		{"169.254.169.254", true},
		{"fd00:1::1", true},
		{"100.64.0.1", true},
		{"192.0.2.11", false},
		{"198.51.100.7", false},
		{"8.8.8.8", false},
		{"2001:db8:abcd::1", false},
		{"100.128.0.1", false},
	} {
		assert.Equal(t, tc.want, server.isQueryAllowed(reverseName(t, tc.ip), dns.TypePTR), tc.ip)
	}
	assert.False(t, server.isQueryAllowed(reverseName(t, "192.0.2.10"), dns.TypeTXT), "only a PTR of a known address")

	unknown := reverseName(t, "192.0.2.12")
	require.False(t, server.isQueryAllowed(unknown, dns.TypePTR))
	server.config.UpdateDNSMapping("later.example.com", "192.0.2.12")
	assert.True(t, server.isQueryAllowed(unknown, dns.TypePTR), "known once named")
}

// Only the address gate or the default action decides a reverse-lookup name,
// whatever rule would match it: a rule above the zones, a wildcard pattern.
// Under a deny default, an unknown address's reverse lookup is refused, and
// a CIDR-allowed one passes; home.arpa still resolves under arpa.
func TestIsQueryAllowed_OnlyTheAddressGateOrTheDefaultDecidesReverseNames(t *testing.T) {
	for _, rule := range []string{"arpa", "**.arpa", "**.in-addr.*", "*.*.*.*.in-addr.*", "**.ip6.*"} {
		cm := config.NewConfigManager()
		require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
			{Type: config.RuleTypeHostname, Value: rule, Action: config.ActionAllow},
			{Type: config.RuleTypeCIDR, Value: "203.0.113.0/24", Action: config.ActionAllow},
		}, config.ActionDeny))
		server := newTestServer(t, cm, firewall.NewMockFirewall(t))
		server.filterQueries = true
		assert.False(t, server.isQueryAllowed(reverseName(t, "192.0.2.7"), dns.TypePTR), rule)
		assert.False(t, server.isQueryAllowed(reverseName(t, "2001:db8:abcd::1"), dns.TypePTR), rule)
		assert.False(t, server.isQueryAllowed("data."+reverseName(t, "192.0.2.7"), dns.TypeTXT), rule)
		assert.True(t, server.isQueryAllowed(reverseName(t, "203.0.113.9"), dns.TypePTR), rule)
		if rule == "arpa" || rule == "**.arpa" {
			assert.True(t, server.isQueryAllowed("printer.home.arpa", dns.TypeA), rule)
		}
	}
}

// Under an allow default, a deny rule for a reverse zone still refuses an
// unknown address's reverse lookup, and a known one passes.
func TestIsQueryAllowed_ReverseZoneDenyUnderAnAllowDefault(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "in-addr.arpa", Action: config.ActionDeny},
	}, config.ActionAllow))
	cm.UpdateDNSMapping("named.example.com", "192.0.2.10")
	server := newTestServer(t, cm, firewall.NewMockFirewall(t))
	server.filterQueries = true
	assert.False(t, server.isQueryAllowed(reverseName(t, "192.0.2.7"), dns.TypePTR))
	assert.True(t, server.isQueryAllowed(reverseName(t, "192.0.2.10"), dns.TypePTR))
	assert.True(t, server.isQueryAllowed(reverseName(t, "2001:db8:abcd::1"), dns.TypePTR))
}

func TestBlockedQueryEvent(t *testing.T) {
	for domain, want := range map[string]events.AuditEvent{
		"7.2.0.192.in-addr.arpa":           {EventType: events.EventDNSBlocked, DstIP: "192.0.2.7"},
		reverseName(t, "2001:db8:abcd::1"): {EventType: events.EventDNSBlocked, DstIP: "2001:db8:abcd::1"},
		ip6ArpaName("::ffff:192.0.2.7"):    {EventType: events.EventDNSBlocked, DstIP: "192.0.2.7"},
		"exfil.payload.in-addr.arpa":       {EventType: events.EventDNSBlocked, DstHostname: "exfil.payload.in-addr.arpa"},
		"evil.example.com":                 {EventType: events.EventDNSBlocked, DstHostname: "evil.example.com"},
	} {
		assert.Equal(t, want, blockedQueryEvent(domain), domain)
	}
}

// A refused reverse lookup is REFUSED and recorded by the address it asked
// about, with no hostname; a known address's lookup is answered.
func TestHandleDNSQuery_ReverseLookupRecordedByAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ip      string
		refused bool
	}{
		{"unknown v4", "192.0.2.11", true},
		{"unknown v6", "2001:db8:abcd::1", true},
		{"known v4", "192.0.2.10", false},
		{"private v4", "10.1.2.3", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := reverseQueryConfig(t)
			server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
			server.filterQueries = true
			auditFile := t.TempDir() + "/audit.json"
			al, err := events.NewAuditLogger(auditFile, false)
			require.NoError(t, err)
			t.Cleanup(func() { al.Close() })
			server.auditLogger = al

			qname := reverseName(t, tc.ip) + "."
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
			require.NotNil(t, w.msg)
			if tc.refused {
				assert.Equal(t, dns.RcodeRefused, w.msg.Rcode)
				evs := readDNSAuditEvents(t, auditFile)
				require.Len(t, evs, 1)
				assert.Equal(t, netip.MustParseAddr(tc.ip).String(), evs[0].DstIP)
				assert.Empty(t, evs[0].DstHostname)
				assert.WithinDuration(t, time.Now(), evs[0].Timestamp, time.Minute, "the record is stamped when it is logged")
			} else {
				assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
				assert.Empty(t, readFile(t, auditFile))
			}
		})
	}
}

// The answer to a PTR query never changes enforcement state: a CNAME target
// or address record in it, here behind a known address's reverse name and a
// rule above the zones, is neither mapped nor learned.
func TestHandleDNSQuery_PTRAnswerInstallsNothing(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "203.0.113.0/24", Action: config.ActionAllow},
		{Type: config.RuleTypeHostname, Value: "arpa", Action: config.ActionAllow},
	}, config.ActionDeny))
	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	server.filterQueries = true
	qname := reverseName(t, "203.0.113.9") + "."
	q := new(dns.Msg)
	q.SetQuestion(qname, dns.TypePTR)
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "evil.example.net."},
		&dns.A{Hdr: dns.RR_Header{Name: "evil.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("6.6.6.6")},
	}
	server.dnsCache.Put(server.generateCacheKey(q), &dnsCacheEntry{msg: resp}, 5*time.Minute)
	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	server.handleDNSQuery(w, q)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
	assert.Len(t, w.msg.Answer, 2, "the answer reaches the client as it came")
	assert.Empty(t, server.config.LookupHostnameByIP("6.6.6.6"), "no address in it is mapped")
	_, learned := server.cnameAllowed.Get("evil.example.net")
	assert.False(t, learned, "no CNAME target in it is learned")
}

// A search domain under a reverse zone is dropped at load, and the rest
// loads: it could never allow a reverse-lookup name.
func TestSearchDomainsUnderReverseZonesAreDropped(t *testing.T) {
	cfg := config.NewConfigManager()
	path := t.TempDir() + "/policy.json"
	require.NoError(t, os.WriteFile(path, []byte(`{"defaultAction": "deny", "searchDomains":
		[".100.51.198.in-addr.arpa", ".d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa", ".corp.internal"]}`), 0o600))
	require.NoError(t, cfg.LoadConfig(path))
	assert.Equal(t, []string{".corp.internal"}, cfg.GetSearchDomains())
	server := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	server.filterQueries = true
	assert.False(t, server.isQueryAllowed(reverseName(t, "198.51.100.7"), dns.TypePTR))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}
