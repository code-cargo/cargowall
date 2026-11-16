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
// mode the record and the query forwarded. A known address's lookup is
// answered, and writes no record.
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
			assert.Equal(t, strings.TrimSuffix(qname, "."), evs[0].DstHostname)
		})
	}
}
