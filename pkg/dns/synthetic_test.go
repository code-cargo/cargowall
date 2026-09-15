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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// Lima's /proc/net/route verbatim, plus a second default route at a LOWER
// metric out of eth1 listed AFTER it, so ordering by metric rather than
// table order is pinned. Gateways are little-endian: 0205A8C0 is 192.168.5.2.
const fixtureIPv4Routes = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0205A8C0	0003	0	0	200	00000000	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
eth0	0005A8C0	00000000	0001	0	0	200	00FFFFFF	0	0	0
eth1	00000000	010A0A0A	0003	0	0	100	00000000	0	0	0
`

// A gateway default route (flags UP|GATEWAY, metric 0x400 = 1024) beside the
// kernel's unreachable default on lo, which carries RTF_REJECT and no
// gateway bit — the row Lima actually has, and the one that must be skipped.
const fixtureIPv6Routes = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`

// withRouteFixtures points the /proc readers at fixture files. An empty v6
// leaves that table absent, as on a host with the IPv6 stack disabled.
func withRouteFixtures(t *testing.T, v4, v6 string) {
	t.Helper()
	dir := t.TempDir()
	prev4, prev6 := procNetRoute, procNetIPv6Route
	procNetRoute = filepath.Join(dir, "route")
	require.NoError(t, os.WriteFile(procNetRoute, []byte(v4), 0o644))
	procNetIPv6Route = filepath.Join(dir, "ipv6_route")
	if v6 != "" {
		require.NoError(t, os.WriteFile(procNetIPv6Route, []byte(v6), 0o644))
	}
	t.Cleanup(func() { procNetRoute, procNetIPv6Route = prev4, prev6 })
}

// withInterfaceAddrs fakes the interface-address lookup from CIDRs, the
// host-IP-plus-mask shape net.Interface.Addrs returns.
func withInterfaceAddrs(t *testing.T, addrs map[string][]string) {
	t.Helper()
	prev := interfaceAddrs
	interfaceAddrs = func(name string) ([]net.Addr, error) {
		cidrs, ok := addrs[name]
		if !ok {
			return nil, fmt.Errorf("no such interface %q", name)
		}
		var out []net.Addr
		for _, c := range cidrs {
			ip, ipn, err := net.ParseCIDR(c)
			require.NoError(t, err)
			out = append(out, &net.IPNet{IP: ip, Mask: ipn.Mask})
		}
		return out, nil
	}
	t.Cleanup(func() { interfaceAddrs = prev })
}

// withResolvConf points the client resolver config at a fixture; an empty
// string leaves it absent.
func withResolvConf(t *testing.T, content string) {
	t.Helper()
	prev := resolvConfPath
	resolvConfPath = filepath.Join(t.TempDir(), "resolv.conf")
	if content != "" {
		require.NoError(t, os.WriteFile(resolvConfPath, []byte(content), 0o644))
	}
	t.Cleanup(func() { resolvConfPath = prev })
}

// syntheticServer is a filtering, default-deny server with synthetic answers
// on — the configuration under which these names would otherwise be REFUSED,
// so every answer below also proves precedence over the gate. The mock
// firewall carries no expectations: any enforcement side effect would fail
// the test, pinning "resolution only". The resolver config starts with no
// search list; tests that need one set it.
func syntheticServer(t *testing.T) *Server {
	t.Helper()
	withResolvConf(t, "nameserver 127.0.0.53\n")
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules(nil, config.ActionDeny))
	s := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	s.filterQueries = true
	s.synthetic = true
	return s
}

func askSynthetic(t *testing.T, s *Server, w *MockResponseWriter, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	q.Id = 4242
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	s.handleDNSQuery(w, q)
	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, uint16(4242), w.msg.Id)
	return w.msg
}

func answerIPs(t *testing.T, m *dns.Msg) []string {
	t.Helper()
	var ips []string
	for _, rr := range m.Answer {
		assert.Equal(t, uint32(0), rr.Header().Ttl, "synthetic answers carry TTL 0")
		switch a := rr.(type) {
		case *dns.A:
			ips = append(ips, a.A.String())
		case *dns.AAAA:
			ips = append(ips, a.AAAA.String())
		default:
			t.Fatalf("unexpected RR type %T", rr)
		}
	}
	return ips
}

func TestHostSearchDomains(t *testing.T) {
	withResolvConf(t, "# generated\nnameserver 127.0.0.53\noptions edns0 trust-ad\n"+
		"domain old.example\n"+ // superseded: last directive wins
		"search LAN corp.example. # trailing comment\n")
	assert.Equal(t, []string{"lan", "corp.example"}, hostSearchDomains(resolvConfPath))

	withResolvConf(t, "")
	assert.Nil(t, hostSearchDomains(resolvConfPath), "unreadable file: no expansion recognised")
}

func TestSyntheticQuery(t *testing.T) {
	withResolvConf(t, "search lan vm.blacksmith.sh\n")
	for _, tc := range []struct {
		qname    string
		want     string
		expanded bool
		ok       bool
	}{
		{"_gateway.", "_gateway", false, true},
		{"_GATEWAY.", "_gateway", false, true},
		{"_outbound.", "_outbound", false, true},
		{"_localdnsstub.", "_localdnsstub", false, true},
		{"_localdnsproxy.", "_localdnsproxy", false, true},
		{"_gateway.lan.", "_gateway", true, true},
		{"_GATEWAY.LAN.", "_gateway", true, true},
		{"_outbound.vm.blacksmith.sh.", "_outbound", true, true},
		{"_gateway.example.com.", "", false, false},   // not a host search suffix
		{"_gateway.blacksmith.sh.", "", false, false}, // partial suffix is not the suffix
		{"gateway.lan.", "", false, false},
		{"example.com.", "", false, false},
	} {
		got, expanded, ok := syntheticQuery(tc.qname)
		assert.Equal(t, tc.ok, ok, tc.qname)
		assert.Equal(t, tc.expanded, expanded, tc.qname)
		assert.Equal(t, tc.want, got, tc.qname)
	}

	withResolvConf(t, "")
	_, _, ok := syntheticQuery("_gateway.lan.")
	assert.False(t, ok, "with no search list the expanded form is an ordinary query")
}

func TestParseIPv4Routes(t *testing.T) {
	routes, err := parseIPv4Routes(strings.NewReader(fixtureIPv4Routes))
	require.NoError(t, err)
	require.Len(t, routes, 2, "only up gateway default routes; docker0 and the link routes are skipped")
	assert.Equal(t, defaultRoute{iface: "eth0", gateway: net.IPv4(192, 168, 5, 2), metric: 200}, routes[0])
	assert.Equal(t, defaultRoute{iface: "eth1", gateway: net.IPv4(10, 10, 10, 1), metric: 100}, routes[1])
}

func TestParseIPv6Routes(t *testing.T) {
	routes, err := parseIPv6Routes(strings.NewReader(fixtureIPv6Routes))
	require.NoError(t, err)
	require.Len(t, routes, 1, "the unreachable default on lo has no gateway bit")
	assert.Equal(t, "eth0", routes[0].iface)
	assert.Equal(t, "fe80::1", routes[0].gateway.String())
	assert.Equal(t, uint32(1024), routes[0].metric)
}

func TestDefaultRoutes_OrderedByMetricAcrossFamilies(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, fixtureIPv6Routes)
	routes, err := defaultRoutes()
	require.NoError(t, err)
	var got []string
	for _, rt := range routes {
		got = append(got, rt.gateway.String())
	}
	assert.Equal(t, []string{"10.10.10.1", "192.168.5.2", "fe80::1"}, got)
}

func TestDefaultRoutes_IPv6TableAbsent(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, "")
	routes, err := defaultRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 2)
}

func TestDefaultRoutes_TableUnreadable(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, "")
	procNetRoute = filepath.Join(t.TempDir(), "absent")
	_, err := defaultRoutes()
	assert.Error(t, err)
}

func TestOutboundAddrs(t *testing.T) {
	withInterfaceAddrs(t, map[string][]string{
		// The gateway-subnet address wins over an earlier unrelated one.
		"eth0": {"10.99.0.7/24", "192.168.5.15/24", "fe80::2/64"},
		"eth1": {"10.10.10.20/24"},
	})
	routes := []defaultRoute{
		{iface: "eth1", gateway: net.IPv4(10, 10, 10, 1), metric: 100},
		{iface: "eth0", gateway: net.IPv4(192, 168, 5, 2), metric: 200},
		{iface: "eth0", gateway: net.ParseIP("fe80::1"), metric: 1024},
		{iface: "wg0", gateway: net.IPv4(10, 8, 0, 1), metric: 2000}, // unreadable interface contributes nothing
	}
	var got []string
	for _, ip := range outboundAddrs(routes) {
		got = append(got, ip.String())
	}
	assert.Equal(t, []string{"10.10.10.20", "192.168.5.15", "fe80::2"}, got)
}

func TestOutboundAddrs_FallsBackToGlobalUnicast(t *testing.T) {
	// No address shares the gateway's subnet (a /32 point-to-point uplink):
	// the interface's global unicast address is the answer, not link-local.
	withInterfaceAddrs(t, map[string][]string{"eth0": {"169.254.1.2/16", "203.0.113.9/32"}})
	got := outboundAddrs([]defaultRoute{{iface: "eth0", gateway: net.IPv4(203, 0, 113, 1)}})
	require.Len(t, got, 1)
	assert.Equal(t, "203.0.113.9", got[0].String())
}

func TestHandleDNSQuery_SyntheticGatewayBeatsFilterGate(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, fixtureIPv6Routes)
	s := syntheticServer(t)

	m := askSynthetic(t, s, &MockResponseWriter{}, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	assert.True(t, m.Authoritative)
	assert.Equal(t, []string{"10.10.10.1", "192.168.5.2"}, answerIPs(t, m), "gateways by metric, IPv4 only for an A query")

	// Resolution only: nothing is tracked for the name.
	s.hostnameIPsMutex.RLock()
	defer s.hostnameIPsMutex.RUnlock()
	assert.Empty(t, s.hostnameIPs)
}

func TestHandleDNSQuery_SyntheticGatewayAAAA(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, fixtureIPv6Routes)
	m := askSynthetic(t, syntheticServer(t), &MockResponseWriter{}, "_gateway.", dns.TypeAAAA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	assert.Equal(t, []string{"fe80::1"}, answerIPs(t, m))
}

func TestHandleDNSQuery_SyntheticNoDataForOtherTypes(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, fixtureIPv6Routes)
	m := askSynthetic(t, syntheticServer(t), &MockResponseWriter{}, "_gateway.", dns.TypeTXT)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode, "NODATA, as resolved answers it")
	assert.True(t, m.Authoritative)
	assert.Empty(t, m.Answer)
}

func TestHandleDNSQuery_SyntheticNoDefaultRoute(t *testing.T) {
	withRouteFixtures(t, "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
		"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n", "")
	m := askSynthetic(t, syntheticServer(t), &MockResponseWriter{}, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode, "no default route is an honest empty answer, not a failure")
	assert.Empty(t, m.Answer)
}

func TestHandleDNSQuery_SyntheticStubAndProxy(t *testing.T) {
	s := syntheticServer(t)
	m := askSynthetic(t, s, &MockResponseWriter{}, "_localdnsstub.", dns.TypeA)
	assert.Equal(t, []string{"127.0.0.53"}, answerIPs(t, m))

	m = askSynthetic(t, s, &MockResponseWriter{}, "_localdnsproxy.", dns.TypeA)
	assert.Equal(t, []string{"127.0.0.54"}, answerIPs(t, m))

	m = askSynthetic(t, s, &MockResponseWriter{}, "_localdnsstub.", dns.TypeAAAA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	assert.Empty(t, m.Answer, "the stub has no IPv6 listener")
}

func TestHandleDNSQuery_SyntheticOutbound(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, "")
	withInterfaceAddrs(t, map[string][]string{
		"eth0": {"192.168.5.15/24"},
		"eth1": {"10.10.10.20/24"},
	})
	m := askSynthetic(t, syntheticServer(t), &MockResponseWriter{}, "_outbound.", dns.TypeA)
	assert.Equal(t, []string{"10.10.10.20", "192.168.5.15"}, answerIPs(t, m))
}

func TestHandleDNSQuery_SyntheticRouteTableUnreadable(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, "")
	procNetRoute = filepath.Join(t.TempDir(), "absent")
	m := askSynthetic(t, syntheticServer(t), &MockResponseWriter{}, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeServerFailure, m.Rcode, "a table we cannot read is 'try again', not 'no such name'")
}

// The search-expanded form is the first query a resolver sends for the
// bare name: answered NXDOMAIN, not REFUSED — the rcode every client,
// c-ares included, treats as "try the next form".
func TestHandleDNSQuery_SyntheticExpandedIsNXDomain(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, "")
	s := syntheticServer(t)
	withResolvConf(t, "search lan vm.blacksmith.sh\n")

	for _, q := range []string{"_gateway.lan.", "_gateway.vm.blacksmith.sh.", "_outbound.lan."} {
		m := askSynthetic(t, s, &MockResponseWriter{}, q, dns.TypeA)
		assert.Equal(t, dns.RcodeNameError, m.Rcode, q)
		assert.True(t, m.Authoritative, q)
		assert.Empty(t, m.Answer, q)
	}
}

// Only the host's own expansions are answered: a suffix that is not on the
// search list, or no search list at all, leaves the query on the ordinary
// path — REFUSED here — rather than the proxy inventing a negative answer.
func TestHandleDNSQuery_SyntheticExpandedOtherwiseOrdinary(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, "")
	s := syntheticServer(t)

	m := askSynthetic(t, s, &MockResponseWriter{}, "_gateway.lan.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode, "no search list")

	withResolvConf(t, "search lan\n")
	m = askSynthetic(t, s, &MockResponseWriter{}, "_gateway.example.com.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode, "suffix not on the search list")
}

// Off (resolved not running), the name takes the ordinary path — and under
// filtering with default deny that is REFUSED, which is exactly the enforce
// symptom in #126. Pins that the feature, not something else, is what
// answers the name above.
func TestHandleDNSQuery_SyntheticDisabledIsRefused(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, "")
	s := syntheticServer(t)
	s.synthetic = false
	m := askSynthetic(t, s, &MockResponseWriter{}, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode)
}

// containerListenerWriter answers on the docker-bridge listener.
type containerListenerWriter struct{ MockResponseWriter }

func (c *containerListenerWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("172.17.0.1"), Port: 53}
}

// A container's native path never resolved these names, and the host's
// gateway is the wrong answer in a container netns: container listeners
// fall through to the ordinary path.
func TestHandleDNSQuery_SyntheticSkippedOnContainerListener(t *testing.T) {
	withRouteFixtures(t, fixtureIPv4Routes, "")
	s := syntheticServer(t)
	s.listenerModes = map[string]listenerAttribution{"172.17.0.1": attributeContainerIP}

	q := new(dns.Msg)
	q.SetQuestion("_gateway.", dns.TypeA)
	w := &containerListenerWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	s.handleDNSQuery(w, q)
	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeRefused, w.msg.Rcode)
}
