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
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

func withResolvedRunning(t *testing.T, running bool) {
	t.Helper()
	prev := resolvedRunning
	resolvedRunning = func() (bool, error) { return running, nil }
	t.Cleanup(func() { resolvedRunning = prev })
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

// withFakeStub runs a stand-in for the resolved stub that answers the way
// resolved does — "_gateway" and "_outbound" A with AA and TTL 0, AAAA as
// NODATA, anything it does not know as NXDOMAIN — and returns a snapshot
// function for the questions it was asked.
func withFakeStub(t *testing.T) func() []dns.Question {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu   sync.Mutex
		seen []dns.Question
	)
	answers := map[string]string{"_gateway.": "192.168.5.2", "_outbound.": "192.168.5.15"}
	stub := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			q := r.Question[0]
			mu.Lock()
			seen = append(seen, q)
			mu.Unlock()
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			switch ip, known := answers[q.Name]; {
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
	t.Cleanup(func() { _ = stub.Shutdown() })
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
// also proves precedence over the gate — with resolved "running", a fake
// stub, and a resolver config without a search list. The mock firewall
// carries no expectations: any enforcement side effect fails the test.
func syntheticServer(t *testing.T) (*Server, func() []dns.Question) {
	t.Helper()
	withResolvedRunning(t, true)
	withResolvConf(t, "nameserver 127.0.0.53\n")
	seen := withFakeStub(t)
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules(nil, config.ActionDeny))
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

// The bare name is relayed to the stub and resolved's answer written back
// as-is, ahead of a gate that would otherwise REFUSE it — and nothing is
// cached, tracked or enforced.
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
	s.hostnameIPsMutex.RLock()
	defer s.hostnameIPsMutex.RUnlock()
	assert.Empty(t, s.hostnameIPs, "stub answers are not tracked")
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

func TestServeSynthetic_StubUnreachableIsServfail(t *testing.T) {
	s, _ := syntheticServer(t)
	resolvedStubAddr = "127.0.0.1:1" // nothing listens; UDP gets ECONNREFUSED at once
	m := askName(t, s, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeServerFailure, m.Rcode)
}

// The search-expanded form is the first query a resolver sends for the
// bare name: NXDOMAIN, not REFUSED — the rcode every client, c-ares
// included, treats as "try the next form" — and never relayed to the stub.
func TestServeSynthetic_ExpandedIsNXDomain(t *testing.T) {
	s, seen := syntheticServer(t)
	withResolvConf(t, "search lan vm.blacksmith.sh\n")

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

	withResolvConf(t, "search lan\n")
	m = askName(t, s, "_gateway.example.com.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode, "suffix not on the search list")
}

// With resolved not running the name takes the ordinary path — and under
// filtering with default deny that is REFUSED, the enforce symptom in #126.
// Pins that the relay, not something else, answers the name above, and that
// the stub is not consulted on a host that has none.
func TestServeSynthetic_ResolvedNotRunningIsOrdinary(t *testing.T) {
	s, seen := syntheticServer(t)
	withResolvedRunning(t, false)
	m := askName(t, s, "_gateway.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, m.Rcode)
	assert.Empty(t, seen())
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
