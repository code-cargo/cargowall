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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

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

// withFakeStub runs a stand-in for the resolved stub that answers the way
// resolved does — "_gateway" and "_outbound" A with AA and TTL 0, the
// localhost family as 127.0.0.1, AAAA as NODATA, anything else as NXDOMAIN —
// and returns a snapshot function for the questions it was asked. Returns
// only once the server is serving: Shutdown before ActivateAndServe is a
// "server not started" no-op that leaves the conn open.
func withFakeStub(t *testing.T) func() []dns.Question {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu   sync.Mutex
		seen []dns.Question
	)
	// runner-abc stands in for the machine's own hostname.
	answers := map[string]string{"_gateway.": "192.168.5.2", "_outbound.": "192.168.5.15", "runner-abc.": "10.0.0.5"}
	started := make(chan struct{})
	stub := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			q := r.Question[0]
			mu.Lock()
			seen = append(seen, q)
			mu.Unlock()
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			ip, known := answers[q.Name]
			if strings.HasSuffix(q.Name, "localhost.") || strings.HasSuffix(q.Name, "localhost.localdomain.") {
				ip, known = "127.0.0.1", true
			}
			switch {
			case !known:
				m.Rcode = dns.RcodeNameError
			case q.Qtype == dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   net.ParseIP(ip).To4(),
				})
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = stub.ActivateAndServe() }()
	<-started
	t.Cleanup(func() {
		_ = stub.Shutdown()
		_ = pc.Close()
	})
	prev := resolvedStubAddr
	resolvedStubAddr = pc.LocalAddr().String()
	t.Cleanup(func() { resolvedStubAddr = prev })
	return func() []dns.Question {
		mu.Lock()
		defer mu.Unlock()
		return append([]dns.Question(nil), seen...)
	}
}

// syntheticServer is a filtering, default-deny server — the configuration
// under which these names would otherwise be REFUSED, so every answer below
// also proves precedence over the gate — with a fake stub, no host search
// list, and the given rules. The mock firewall carries no expectations
// unless a test adds them: with no rule naming a synthetic name, any
// firewall call fails the test.
func syntheticServer(t *testing.T, rules ...config.Rule) (*Server, func() []dns.Question) {
	t.Helper()
	return syntheticServerWithDefault(t, config.ActionDeny, rules...)
}

func syntheticServerWithDefault(t *testing.T, defaultAction config.Action, rules ...config.Rule) (*Server, func() []dns.Question) {
	t.Helper()
	seen := withFakeStub(t)
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules(rules, defaultAction))
	s := newTestServer(t, cfg, firewall.NewMockFirewall(t))
	s.filterQueries = true
	return s, seen
}

func ask(t *testing.T, s *Server, w *MockResponseWriter, q *dns.Msg) *dns.Msg {
	t.Helper()
	q.Id = 4242
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	s.handleDNSQuery(w, q)
	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, uint16(4242), w.msg.Id)
	return w.msg
}

func askName(t *testing.T, s *Server, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	return ask(t, s, &MockResponseWriter{}, q)
}

func TestSyntheticQuery(t *testing.T) {
	isHostSuffix := func(rest string) bool { return rest == "lan" || rest == "vm.blacksmith.sh" }
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
		{"localhost.", "localhost", false, true},
		{"API.localhost.", "api.localhost", false, true},
		{"localhost.localdomain.", "localhost.localdomain", false, true},
		{"foo.localhost.localdomain.", "foo.localhost.localdomain", false, true},
		{"localhost.example.com.", "", false, false},
		{"notlocalhost.", "", false, false},
	} {
		got, expanded, ok := syntheticQuery(tc.qname, isHostSuffix)
		assert.Equal(t, tc.ok, ok, tc.qname)
		assert.Equal(t, tc.expanded, expanded, tc.qname)
		assert.Equal(t, tc.want, got, tc.qname)
	}

	_, _, ok := syntheticQuery("_gateway.lan.", func(string) bool { return false })
	assert.False(t, ok, "with no search list the expanded form is an ordinary query")
}

// The bare name is relayed to the stub and resolved's answer written back
// as-is, ahead of a gate that would otherwise REFUSE it. Nothing is cached;
// the answer IS tracked, so a later connection to the address is attributed
// to the name — and with no rule naming it, the firewall is not touched.
func TestServeSynthetic_RelaysBareNameToStub(t *testing.T) {
	s, seen := syntheticServer(t)

	m := askName(t, s, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	assert.True(t, m.Authoritative)
	require.Len(t, m.Answer, 1)
	a, ok := m.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "192.168.5.2", a.A.String())
	assert.Equal(t, uint32(0), a.Hdr.Ttl)

	require.Len(t, seen(), 1)
	assert.Equal(t, "_gateway.", seen()[0].Name)

	_, cached := s.dnsCache.Get(s.generateCacheKey(&dns.Msg{Question: []dns.Question{{Name: "_gateway.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}))
	assert.False(t, cached, "stub answers are not cached")
	assert.Equal(t, "_gateway", s.config.LookupHostnameByIP("192.168.5.2"), "the address is attributed to the name")
	s.hostnameIPsMutex.RLock()
	defer s.hostnameIPsMutex.RUnlock()
	assert.Contains(t, s.hostnameIPs, "_gateway")
}

// A rule can name a synthetic name (#129): allow opens the gateway's address
// on the rule's ports, deny closes it — the L4 enforcement any upstream
// answer gets, so "_gateway" is a portable rule where a provider CIDR was.
func TestServeSynthetic_RuleNamesTheGateway(t *testing.T) {
	gateway := mock.MatchedBy(func(ip net.IP) bool { return ip.Equal(net.ParseIP("192.168.5.2")) })
	ports := []config.Port{{Port: 1041, Protocol: config.ProtocolTCP}}
	s, _ := syntheticServer(t, config.Rule{Type: config.RuleTypeHostname, Value: "_gateway", Ports: ports, Action: config.ActionAllow})
	mockFw := s.firewall.(*firewall.MockFirewall)
	mockFw.On("AddIP", gateway, config.ActionAllow, ports).Return(true, nil).Once()
	m := askName(t, s, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	mockFw.AssertExpectations(t)

	// A deny only needs a BPF entry when the default would otherwise allow.
	s, _ = syntheticServerWithDefault(t, config.ActionAllow, config.Rule{Type: config.RuleTypeHostname, Value: "_gateway", Action: config.ActionDeny})
	mockFw = s.firewall.(*firewall.MockFirewall)
	mockFw.On("AddIP", gateway, config.ActionDeny, []config.Port(nil)).Return(true, nil).Once()
	m = askName(t, s, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode, "a deny rule still resolves the name; it closes the address")
	mockFw.AssertExpectations(t)
}

// "_gateway" is an address alias, never a name a peer presents. An all-ports
// allow — which would L7-scope a real name's address for TLS, HTTP and QUIC —
// must stay L4 here: no forward-resolution evidence is minted, so registerL7
// scopes nothing (SCOPE IFF BOUND), and HTTP to the host agent carrying
// "Host: <ip>" is not an L7 miss. Attribution is unaffected.
func TestServeSynthetic_AllowDoesNotL7Scope(t *testing.T) {
	s, _ := syntheticServer(t, config.Rule{Type: config.RuleTypeHostname, Value: "_gateway", Action: config.ActionAllow})
	rec := &recordingRegistrar{}
	s.SetL7Registrar(rec)
	s.firewall.(*firewall.MockFirewall).
		On("AddIP", mock.MatchedBy(func(ip net.IP) bool { return ip.Equal(net.ParseIP("192.168.5.2")) }), config.ActionAllow, []config.Port(nil)).
		Return(true, nil).Once()

	m := askName(t, s, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	assert.Empty(t, rec.scopes, "a synthetic name must not L7-scope its address")
	assert.False(t, s.config.NameResolvedToIP("_gateway", "192.168.5.2"), "no forward-resolution evidence for an alias")
	assert.Equal(t, "_gateway", s.config.LookupHostnameByIP("192.168.5.2"), "attribution still applies")
}

// Whatever resolved says is what the client gets: NODATA for a family it
// has no address for, NXDOMAIN for a name it does not synthesize. The proxy
// shapes nothing itself.
func TestServeSynthetic_RelaysStubVerdictVerbatim(t *testing.T) {
	s, _ := syntheticServer(t)

	m := askName(t, s, "_gateway.", dns.TypeAAAA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	assert.Empty(t, m.Answer)

	m = askName(t, s, "_localdnsproxy.", dns.TypeA)
	assert.Equal(t, dns.RcodeNameError, m.Rcode)
}

// A stub that does not answer — resolved stopped, or never installed — sends
// the name down the ordinary path, REFUSED here, rather than SERVFAIL: the
// runtime directory outlives a stopped resolved, so this is the only probe.
func TestServeSynthetic_StubUnreachableIsOrdinary(t *testing.T) {
	s, _ := syntheticServer(t)
	resolvedStubAddr = "127.0.0.1:1" // nothing listens; UDP gets ECONNREFUSED at once
	m := askName(t, s, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode)
}

// The localhost family resolved synthesizes beyond what /etc/hosts carries —
// relayed, but not tracked: any label under .localhost is accepted, and
// retaining each alias would grow hostnameIPs without bound.
func TestServeSynthetic_RelaysLocalhostFamilyUntracked(t *testing.T) {
	s, seen := syntheticServer(t)
	for _, q := range []string{"api.localhost.", "localhost.localdomain.", "foo.localhost.localdomain."} {
		m := askName(t, s, q, dns.TypeA)
		assert.Equal(t, dns.RcodeSuccess, m.Rcode, q)
		require.Len(t, m.Answer, 1, q)
		assert.Equal(t, "127.0.0.1", m.Answer[0].(*dns.A).A.String(), q)
	}
	assert.Len(t, seen(), 3)
	assert.Empty(t, s.config.LookupHostnameByIP("127.0.0.1"))
	s.hostnameIPsMutex.RLock()
	defer s.hostnameIPsMutex.RUnlock()
	assert.Empty(t, s.hostnameIPs)
}

// The search-expanded form is the first query a resolver sends for the
// bare name: NXDOMAIN, not REFUSED — the rcode every client, c-ares
// included, treats as "try the next form" — and never relayed to the stub.
func TestServeSynthetic_ExpandedIsNXDomain(t *testing.T) {
	s, seen := syntheticServer(t)
	s.config.SetHostSearchDomains([]string{"lan", "vm.blacksmith.sh"}, s.logger)

	for _, q := range []string{"_gateway.lan.", "_gateway.vm.blacksmith.sh.", "_outbound.lan."} {
		m := askName(t, s, q, dns.TypeA)
		assert.Equal(t, dns.RcodeNameError, m.Rcode, q)
		assert.True(t, m.Authoritative, q)
		assert.Empty(t, m.Answer, q)
	}
	assert.Empty(t, seen(), "expanded forms never reach the stub")
}

// Only the host's own expansions are answered: a suffix that is not on the
// search list, or no search list at all, leaves the query on the ordinary
// path — REFUSED here — rather than the proxy inventing a negative answer.
func TestServeSynthetic_ExpandedOtherwiseOrdinary(t *testing.T) {
	s, _ := syntheticServer(t)

	m := askName(t, s, "_gateway.lan.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode, "no search list")

	s.config.SetHostSearchDomains([]string{"lan"}, s.logger)
	m = askName(t, s, "_gateway.example.com.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode, "suffix not on the search list")
}

func TestServeSynthetic_NonINClassIsOrdinary(t *testing.T) {
	s, seen := syntheticServer(t)
	q := new(dns.Msg)
	q.SetQuestion("_gateway.", dns.TypeA)
	q.Question[0].Qclass = dns.ClassCHAOS
	m := ask(t, s, &MockResponseWriter{}, q)
	assert.Equal(t, dns.RcodeRefused, m.Rcode)
	assert.Empty(t, seen())
}

func withMachineHostname(t *testing.T, name string, err error) {
	t.Helper()
	prev := machineHostname
	machineHostname = func() (string, error) { return name, err }
	t.Cleanup(func() { machineHostname = prev })
}

func TestSeedMachineNames(t *testing.T) {
	for _, tc := range []struct {
		hostname string
		err      error
		want     []string
	}{
		{"Runner-ABC.corp.example.", nil, []string{"runner-abc.corp.example", "runner-abc", "runner-abc.local"}},
		{"runner-abc", nil, []string{"runner-abc", "runner-abc.local"}},
		{"", nil, nil},
		{"runner-abc", os.ErrNotExist, nil},
	} {
		withMachineHostname(t, tc.hostname, tc.err)
		s := newTestServer(t, config.NewConfigManager(), firewall.NewMockFirewall(t))
		s.seedMachineNames()
		assert.Equal(t, tc.want, s.machineNames, tc.hostname)
	}
}

// The machine's own hostname is a synthetic record too (its addresses, or
// 127.0.0.2 with none), and /etc/hosts does not always pin it: relayed and
// tracked like the underscore set, a fixed handful of names.
func TestServeSynthetic_MachineHostnameRelayedAndTracked(t *testing.T) {
	s, seen := syntheticServer(t)
	s.machineNames = []string{"runner-abc", "runner-abc.local"}

	m := askName(t, s, "runner-abc.", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	require.Len(t, m.Answer, 1)
	assert.Equal(t, "10.0.0.5", m.Answer[0].(*dns.A).A.String())
	assert.Len(t, seen(), 1)
	assert.Equal(t, "runner-abc", s.config.LookupHostnameByIP("10.0.0.5"))
	assert.False(t, s.config.NameResolvedToIP("runner-abc", "10.0.0.5"), "the machine's own name is an alias too: no L7 evidence")

	m = askName(t, s, "other-host.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode, "only the machine's own names are relayed")
}

// containerListenerWriter answers on the docker-bridge listener.
type containerListenerWriter struct{ MockResponseWriter }

func (c *containerListenerWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("172.17.0.1"), Port: 53}
}

// A container's native path never resolved these names, and the host's
// gateway is the wrong answer in a container netns: container listeners
// fall through to the ordinary path.
func TestServeSynthetic_ContainerListenerIsOrdinary(t *testing.T) {
	s, seen := syntheticServer(t)
	s.listenerModes = map[string]listenerAttribution{"172.17.0.1": attributeContainerIP}

	q := new(dns.Msg)
	q.SetQuestion("_gateway.", dns.TypeA)
	w := &containerListenerWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()
	s.handleDNSQuery(w, q)
	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeRefused, w.msg.Rcode)
	assert.Empty(t, seen())
}
