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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
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

// MockResponseWriter implements dns.ResponseWriter for testing
type MockResponseWriter struct {
	mock.Mock
	msg *dns.Msg
}

func (m *MockResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (m *MockResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.1.1.1"), Port: 12345}
}

func (m *MockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.msg = msg
	args := m.Called(msg)
	return args.Error(0)
}

func (m *MockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m *MockResponseWriter) Close() error {
	return nil
}

func (m *MockResponseWriter) TsigStatus() error {
	return nil
}

func (m *MockResponseWriter) TsigTimersOnly(bool) {}

func (m *MockResponseWriter) Hijack() {}

func TestNewServer(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := &firewall.MockFirewall{}
	logger := slog.Default()

	server := NewServer(cfg, fw, "8.8.8.8:53", "127.0.0.1:53", logger)

	assert.NotNil(t, server)
	assert.Equal(t, cfg, server.config)
	assert.Equal(t, fw, server.firewall)
	assert.Equal(t, "8.8.8.8:53", server.upstream)
	assert.Equal(t, "127.0.0.1:53", server.listenAddr)
	assert.NotNil(t, server.client)
	assert.NotNil(t, server.hostnameIPs)
	assert.NotNil(t, server.dnsCache)
}

func TestGenerateCacheKey(t *testing.T) {
	server := &Server{}

	tests := []struct {
		name     string
		msg      *dns.Msg
		expected string
	}{
		{
			name: "A record query",
			msg: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: "example.com.|A|IN",
		},
		{
			name: "AAAA record query",
			msg: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example.com.",
						Qtype:  dns.TypeAAAA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: "example.com.|AAAA|IN",
		},
		{
			name: "TXT record query",
			msg: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example.com.",
						Qtype:  dns.TypeTXT,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: "example.com.|TXT|IN",
		},
		{
			name: "MX record query",
			msg: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example.com.",
						Qtype:  dns.TypeMX,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: "example.com.|MX|IN",
		},
		{
			name: "SRV record query",
			msg: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "_xmpp._tcp.example.com.",
						Qtype:  dns.TypeSRV,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: "_xmpp._tcp.example.com.|SRV|IN",
		},
		{
			name: "uppercase name is lowercased",
			msg: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "EXAMPLE.COM.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: "example.com.|A|IN",
		},
		{
			name:     "empty question",
			msg:      &dns.Msg{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := server.generateCacheKey(tt.msg)
			assert.Equal(t, tt.expected, key)
		})
	}
}

func TestStripSearchDomains(t *testing.T) {
	tests := []struct {
		name          string
		searchDomains []string
		hostname      string
		expected      string
	}{
		// Kubernetes suffixes are always active (hardcoded defaults).
		{"k8s default", nil, "myservice.default.svc.cluster.local", "myservice"},
		{"k8s svc", nil, "myservice.svc.cluster.local", "myservice"},
		{"k8s cluster", nil, "myservice.cluster.local", "myservice"},
		{"no match", nil, "myservice.example.com", "myservice.example.com"},
		{"no suffix", nil, "myservice", "myservice"},

		// User-configured suffixes are stripped alongside the K8s defaults.
		{"aws compute", []string{".compute.internal"}, "ip-10-0-0-5.us-west-2.compute.internal", "ip-10-0-0-5.us-west-2"},
		{"aws ec2", []string{".ec2.internal"}, "bastion.ec2.internal", "bastion"},
		{"azure", []string{".internal.cloudapp.net"}, "myvm.internal.cloudapp.net", "myvm"},

		// Case-insensitive: DNS names are case-insensitive but configured
		// suffixes are normalized to lowercase by normalizeSearchDomains.
		{"case-insensitive aws", []string{".compute.internal"}, "Bastion.Compute.Internal", "Bastion"},
		{"case-insensitive k8s", nil, "MyService.SVC.Cluster.Local", "MyService"},

		// Longest matching suffix wins, regardless of slice order.
		{
			name:          "longest configured suffix wins (specific first)",
			searchDomains: []string{".us-west-2.compute.internal", ".compute.internal"},
			hostname:      "ip-10-0-0-5.us-west-2.compute.internal",
			expected:      "ip-10-0-0-5",
		},
		{
			name:          "longest configured suffix wins (general first)",
			searchDomains: []string{".compute.internal", ".us-west-2.compute.internal"},
			hostname:      "ip-10-0-0-5.us-west-2.compute.internal",
			expected:      "ip-10-0-0-5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := config.NewConfigManager()
			// LoadConfigFromRules initializes cm.config so AddSearchDomains
			// can actually take effect (the helper no-ops on nil config, by
			// design — matches other auto-allow helpers).
			require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))
			if tt.searchDomains != nil {
				cm.AddSearchDomains(tt.searchDomains, slog.Default())
			}
			server := &Server{config: cm}
			result := server.stripSearchDomains(tt.hostname)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractIPsFromResponse(t *testing.T) {
	server := &Server{logger: slog.Default()}

	// Create a DNS response with A records
	msg := &dns.Msg{
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("192.168.1.1"),
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    600,
				},
				A: net.ParseIP("192.168.1.2"),
			},
		},
	}

	ips, ttl := server.extractIPsFromResponse(msg)

	assert.Len(t, ips, 2)
	assert.Contains(t, ips, net.ParseIP("192.168.1.1"))
	assert.Contains(t, ips, net.ParseIP("192.168.1.2"))
	assert.Equal(t, uint32(300), ttl, "minimum TTL across answers")
}

func TestAddIPToBPFMaps(t *testing.T) {
	mockFw := new(firewall.MockFirewall)
	server := &Server{
		firewall: mockFw,
		logger:   slog.Default(),
	}

	ip := net.ParseIP("192.168.1.1")
	ports := []config.Port{{Port: 80, Protocol: config.ProtocolAll}, {Port: 443, Protocol: config.ProtocolAll}}

	// Test successful addition
	mockFw.On("AddIP", ip, config.ActionAllow, ports).Return(true, nil)

	err := server.addIPToBPFMaps(ip, "example.com", config.ActionAllow, ports)
	assert.NoError(t, err)

	mockFw.AssertExpectations(t)
}

func TestRemoveIPFromBPFMaps(t *testing.T) {
	mockFw := new(firewall.MockFirewall)
	server := &Server{
		firewall: mockFw,
		logger:   slog.Default(),
	}

	ip := net.ParseIP("192.168.1.1")

	mockFw.On("RemoveIP", ip).Return(nil)

	err := server.removeIPFromBPFMaps(ip)
	assert.NoError(t, err)

	mockFw.AssertExpectations(t)
}

func TestDNSCacheLazyExpiration(t *testing.T) {
	cache := newLRUCache[string, *dnsCacheEntry](10000)
	server := &Server{
		dnsCache: cache,
		logger:   slog.Default(),
	}

	// Add an entry with a very short TTL
	cacheKey := "example.com.|A|IN"
	cache.Put(cacheKey, &dnsCacheEntry{
		msg: &dns.Msg{
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.168.1.1"),
				},
			},
		},
	}, 1*time.Millisecond) // Expires almost immediately

	// Wait for it to expire
	time.Sleep(5 * time.Millisecond)

	// Create a mock query
	query := &dns.Msg{
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}

	// Check cache - should be expired
	_, found := server.dnsCache.Get(server.generateCacheKey(query))

	assert.False(t, found)
}

func TestDNSTrackingBeforeRules(t *testing.T) {
	// Test that DNS entries are tracked even before rules are loaded
	configMgr := config.NewConfigManager()
	mockFirewall := firewall.NewMockFirewall(t)
	logger := slog.Default()

	// Create server WITHOUT rules initially
	server := NewServer(configMgr, mockFirewall, "8.8.8.8:53", "127.0.0.1:53", logger)

	// Simulate a DNS resolution before rules are loaded
	// This mimics what happens with NATS hostname
	server.hostnameIPsMutex.Lock()
	server.hostnameIPs["nats.nats.svc.cluster.local"] = map[string]bool{
		"10.15.1.105": true,
	}
	server.hostnameIPsMutex.Unlock()

	// Also update the config manager's mapping
	configMgr.UpdateDNSMapping("nats.nats.svc.cluster.local", "10.15.1.105")

	// Now load config with rules for NATS
	rules := []config.Rule{
		{
			Type:   config.RuleTypeHostname,
			Value:  "nats.nats.svc.cluster.local",
			Ports:  []config.Port{{Port: 4222, Protocol: config.ProtocolAll}},
			Action: config.ActionAllow,
		},
	}
	err := configMgr.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	// Expect AddIP to be called when we reprocess
	mockFirewall.On(
		"AddIP",
		net.ParseIP("10.15.1.105"),
		config.ActionAllow,
		[]config.Port{{Port: 4222, Protocol: config.ProtocolAll}},
	).Return(true, nil).Once()

	// Call ApplyRulesToTrackedHostnames - this should add the tracked IP
	server.ApplyRulesToTrackedHostnames()

	// Verify that the IP was added to the firewall
	mockFirewall.AssertExpectations(t)
}

func TestHostnameIPTracking(t *testing.T) {
	cfg := config.NewConfigManager()
	mockFw := firewall.NewMockFirewall(t)

	// Setup config with a tracked hostname
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow, Ports: []config.Port{{Port: 443, Protocol: config.ProtocolAll}}},
	}, config.ActionDeny)
	require.NoError(t, err)

	server := newTestServer(t, cfg, mockFw)

	// --- Phase 1: first resolution returns two IPs ---

	// Pre-populate cache with the first response (two A records)
	firstResp := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: 9999, Response: true, Rcode: dns.RcodeSuccess},
		Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.168.1.1"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.168.1.2"),
			},
		},
	}
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: firstResp.Copy()}, 5*time.Minute)

	// Expect AddIP for both IPs
	mockFw.On("AddIP", net.ParseIP("192.168.1.1"), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()
	mockFw.On("AddIP", net.ParseIP("192.168.1.2"), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 1234

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)
	w.AssertExpectations(t)

	// Verify IPs are tracked
	server.hostnameIPsMutex.RLock()
	trackedIPs := server.hostnameIPs["example.com"]
	server.hostnameIPsMutex.RUnlock()

	assert.True(t, trackedIPs["192.168.1.1"])
	assert.True(t, trackedIPs["192.168.1.2"])

	// --- Phase 2: round-robin response returns only 192.168.1.3 ---
	// Old IPs (192.168.1.1, 192.168.1.2) should be accumulated, not removed.

	// Replace the cached entry with the new response
	newResp := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: 9999, Response: true, Rcode: dns.RcodeSuccess},
		Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.168.1.3"),
			},
		},
	}
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: newResp.Copy()}, 5*time.Minute)

	// Expect AddIP for new IP only — no RemoveIP calls
	mockFw.On("AddIP", net.ParseIP("192.168.1.3"), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

	query2 := new(dns.Msg)
	query2.SetQuestion("example.com.", dns.TypeA)
	query2.Id = 1235

	w2 := &MockResponseWriter{}
	w2.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w2, query2)
	w2.AssertExpectations(t)

	// Verify all IPs are accumulated (old IPs preserved)
	server.hostnameIPsMutex.RLock()
	updatedIPs := server.hostnameIPs["example.com"]
	server.hostnameIPsMutex.RUnlock()

	assert.True(t, updatedIPs["192.168.1.3"], "new IP should be added")
	assert.True(t, updatedIPs["192.168.1.1"], "old IP should be preserved")
	assert.True(t, updatedIPs["192.168.1.2"], "old IP should be preserved")
}

func TestDNSResponseCaching(t *testing.T) {
	cache := newLRUCache[string, *dnsCacheEntry](10000)
	server := &Server{
		dnsCache: cache,
		logger:   slog.Default(),
	}

	// Create a DNS response to cache
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       1234,
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Question: []dns.Question{
			{Name: "cached.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "cached.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    600,
				},
				A: net.ParseIP("10.0.0.1"),
			},
		},
	}

	// Generate cache key
	query := &dns.Msg{
		Question: []dns.Question{
			{Name: "cached.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}
	cacheKey := server.generateCacheKey(query)

	// Store in cache
	cache.Put(cacheKey, &dnsCacheEntry{
		msg: response.Copy(),
	}, 600*time.Second)

	// Retrieve from cache
	cached, found := cache.Get(cacheKey)

	assert.True(t, found)
	assert.NotNil(t, cached)
	assert.Equal(t, 1, len(cached.msg.Answer))

	// Check that the cached response has the correct data
	if aRecord, ok := cached.msg.Answer[0].(*dns.A); ok {
		assert.Equal(t, "10.0.0.1", aRecord.A.String())
		assert.Equal(t, uint32(600), aRecord.Hdr.Ttl)
	} else {
		t.Fatal("Expected A record in cached response")
	}
}

// TestDNSServerHostnamePortsLookup verifies that the happy-path DNS code uses
// the combined config lookup so the action and ports come from the same rule.
func TestDNSServerHostnamePortsLookup(t *testing.T) {
	cfg := config.NewConfigManager()

	rules := []config.Rule{
		{
			Type:   config.RuleTypeHostname,
			Value:  "api.example.com",
			Action: config.ActionAllow,
			Ports:  []config.Port{{Port: 443, Protocol: config.ProtocolAll}, {Port: 8443, Protocol: config.ProtocolAll}},
		},
		{
			Type:   config.RuleTypeHostname,
			Value:  "example.com",
			Action: config.ActionAllow,
			Ports:  []config.Port{{Port: 80, Protocol: config.ProtocolAll}, {Port: 443, Protocol: config.ProtocolAll}},
		},
		{
			Type:   config.RuleTypeHostname,
			Value:  "*.*.internal.cloudapp.net",
			Action: config.ActionAllow,
			Ports:  []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
		},
	}
	err := cfg.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	tests := []struct {
		hostname string
		expected []config.Port
	}{
		{"api.example.com", []config.Port{{Port: 443, Protocol: config.ProtocolAll}, {Port: 8443, Protocol: config.ProtocolAll}}},
		{"example.com", []config.Port{{Port: 80, Protocol: config.ProtocolAll}, {Port: 443, Protocol: config.ProtocolAll}}},
		{"sub.example.com", []config.Port{{Port: 80, Protocol: config.ProtocolAll}, {Port: 443, Protocol: config.ProtocolAll}}}, // parent-domain match
		{"abc.def.internal.cloudapp.net", []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}},                             // pattern match
		{"only1.internal.cloudapp.net", nil}, // pattern needs 2 labels
		{"other.com", nil},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			v := cfg.MatchHostnameRule(tt.hostname)
			assert.Equal(t, tt.expected, v.AllowPorts)
		})
	}
}

func TestCacheSizeLimit(t *testing.T) {
	const maxCacheSize = 100 // Use smaller size for test performance
	cache := newLRUCache[string, *dnsCacheEntry](maxCacheSize)

	// Fill cache to max size
	for i := 0; i < maxCacheSize; i++ {
		cacheKey := fmt.Sprintf("host%d.example.com.|A|IN", i)
		cache.Put(cacheKey, &dnsCacheEntry{
			msg: &dns.Msg{},
		}, time.Hour)
	}

	assert.Equal(t, maxCacheSize, cache.Len())

	// Adding one more should evict the LRU entry
	cache.Put("overflow.example.com.|A|IN", &dnsCacheEntry{
		msg: &dns.Msg{},
	}, time.Hour)

	assert.Equal(t, maxCacheSize, cache.Len())

	// The first entry should have been evicted
	_, found := cache.Get("host0.example.com.|A|IN")
	assert.False(t, found, "LRU entry should have been evicted")
}

func TestServerStartStop(t *testing.T) {
	cfg := config.NewConfigManager()
	mockFw := new(firewall.MockFirewall)
	logger := slog.Default()

	// Use a random port to avoid conflicts
	server := NewServer(cfg, mockFw, "8.8.8.8:53", "127.0.0.1:0", logger)

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop the server
	cancel()

	// Wait for shutdown
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not shut down in time")
	}
}

func TestSetFirewall(t *testing.T) {
	cfg := config.NewConfigManager()
	mockFw1 := new(firewall.MockFirewall)
	mockFw2 := new(firewall.MockFirewall)
	logger := slog.Default()

	server := NewServer(cfg, mockFw1, "8.8.8.8:53", "127.0.0.1:53", logger)

	// Verify initial firewall
	assert.Equal(t, mockFw1, server.firewall)

	// Update firewall
	server.SetFirewall(mockFw2)

	// Verify firewall was updated
	assert.Equal(t, mockFw2, server.firewall)
}

func TestIPUpdateWithoutTTLRemoval(t *testing.T) {
	cfg := config.NewConfigManager()
	mockFw := new(firewall.MockFirewall)
	logger := slog.Default()

	server := &Server{
		config:      cfg,
		firewall:    mockFw,
		logger:      logger,
		hostnameIPs: make(map[string]map[string]bool),
		dnsCache:    newLRUCache[string, *dnsCacheEntry](10000),
	}

	// Setup config with a tracked hostname
	rules := []config.Rule{
		{
			Type:   config.RuleTypeHostname,
			Value:  "persistent.example.com",
			Action: config.ActionAllow,
			Ports:  []config.Port{{Port: 443, Protocol: config.ProtocolAll}},
		},
	}
	err := cfg.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	// Add an IP for the hostname
	ip := net.ParseIP("10.0.0.1")
	mockFw.On("AddIP", ip, config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

	err = server.addIPToBPFMaps(ip, "persistent.example.com", config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}) // 30 second TTL
	assert.NoError(t, err)

	// Track the IP
	server.hostnameIPsMutex.Lock()
	server.hostnameIPs["persistent.example.com"] = map[string]bool{
		"10.0.0.1": true,
	}
	server.hostnameIPsMutex.Unlock()

	// Wait more than the TTL (simulating time passing)
	time.Sleep(100 * time.Millisecond)

	// The IP should still be tracked (no automatic removal)
	server.hostnameIPsMutex.RLock()
	trackedIPs := server.hostnameIPs["persistent.example.com"]
	server.hostnameIPsMutex.RUnlock()

	assert.True(t, trackedIPs["10.0.0.1"], "IP should remain tracked regardless of TTL")

	// Verify that RemoveIP was NOT called (since we don't have TTL-based removal anymore)
	mockFw.AssertNotCalled(t, "RemoveIP", ip)

	mockFw.AssertExpectations(t)
}

func TestApplyRulesToTrackedHostnames(t *testing.T) {
	// Create config manager and mock firewall
	configMgr := config.NewConfigManager()
	mockFirewall := firewall.NewMockFirewall(t)
	logger := slog.Default()

	// Create DNS server
	server := NewServer(
		configMgr,
		mockFirewall,
		"8.8.8.8:53",
		"127.0.0.1:53",
		logger,
	)

	// Add something to DNS cache to verify it's NOT cleared
	cacheKey := "test.example.com.|A|IN"
	testMsg := &dns.Msg{}
	testMsg.SetQuestion("test.example.com.", dns.TypeA)
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{
		msg: testMsg,
	}, 5*time.Minute)

	// Simulate DNS resolution that happens BEFORE config is loaded
	// This mimics NATS hostname being resolved before we have rules
	configMgr.UpdateDNSMapping("nats.nats.svc.cluster.local", "10.15.1.105")

	// Now load config with rules for the NATS hostname
	rules := []config.Rule{
		{
			Type:   config.RuleTypeHostname,
			Value:  "nats.nats.svc.cluster.local",
			Ports:  []config.Port{{Port: 4222, Protocol: config.ProtocolAll}, {Port: 6222, Protocol: config.ProtocolAll}, {Port: 8222, Protocol: config.ProtocolAll}},
			Action: config.ActionAllow,
		},
	}
	err := configMgr.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	// Expect AddIP to be called for the cached NATS IP
	mockFirewall.On(
		"AddIP",
		net.ParseIP("10.15.1.105"),
		config.ActionAllow,
		[]config.Port{{Port: 4222, Protocol: config.ProtocolAll}, {Port: 6222, Protocol: config.ProtocolAll}, {Port: 8222, Protocol: config.ProtocolAll}},
	).Return(true, nil).Once()

	// Call ApplyRulesToTrackedHostnames - this should apply rules to the tracked DNS mapping
	server.ApplyRulesToTrackedHostnames()

	// Verify that the IP was added to the firewall
	mockFirewall.AssertExpectations(t)

	// Verify DNS cache was NOT cleared
	cached, found := server.dnsCache.Get(cacheKey)
	assert.True(t, found, "DNS cache should not have been cleared")
	assert.NotNil(t, cached, "Cached entry should still exist")
}

// Regression: when a DNS lookup for a name like "bastion.compute.internal"
// is tracked BEFORE the .compute.internal search domain is auto-added (the
// DNS proxy starts before config-loading + auto-allow), a follow-up
// ApplyRulesToTrackedHostnames after the suffix is configured must apply
// the short-name rule via search-domain stripping. Without the post-auto-allow
// reprocess call, the tracked IP stays out of BPF until a fresh DNS response.
func TestApplyRulesToTrackedHostnames_PicksUpLateAddedSearchDomain(t *testing.T) {
	configMgr := config.NewConfigManager()
	mockFirewall := firewall.NewMockFirewall(t)
	logger := slog.Default()

	server := NewServer(configMgr, mockFirewall, "8.8.8.8:53", "127.0.0.1:53", logger)

	// 1) Rule for the SHORT name exists from the start.
	require.NoError(t, configMgr.LoadConfigFromRules([]config.Rule{
		{
			Type:   config.RuleTypeHostname,
			Value:  "bastion",
			Ports:  []config.Port{{Port: 22, Protocol: config.ProtocolTCP}},
			Action: config.ActionAllow,
		},
	}, config.ActionDeny))

	// 2) DNS lookup arrives BEFORE the search domain is configured. The
	// full-form hostname doesn't match any rule yet (search-domain stripping
	// isn't active for ".compute.internal" until step 3).
	configMgr.UpdateDNSMapping("bastion.compute.internal", "10.0.0.5")

	// A pre-auto-allow reprocess pass finds no match (no search domain →
	// MatchHostnameRule("bastion.compute.internal") returns no action). No
	// AddIP is recorded; firewall.NewMockFirewall(t) would fail on any
	// unexpected call.
	server.ApplyRulesToTrackedHostnames()

	// 3) Auto-allow adds the search domain.
	configMgr.AddSearchDomains([]string{".compute.internal"}, logger)

	// 4) The post-auto-allow reprocess must now apply the short-name rule
	// to the cached IP via stripping.
	mockFirewall.On(
		"AddIP",
		net.ParseIP("10.0.0.5"),
		config.ActionAllow,
		[]config.Port{{Port: 22, Protocol: config.ProtocolTCP}},
	).Return(true, nil).Once()

	server.ApplyRulesToTrackedHostnames()

	mockFirewall.AssertExpectations(t)
}

// Mixed-verdict cross-form: full hostname matches a deny pattern on one
// port and the search-domain-stripped form matches an allow on a different
// port. The reprocess pass writes the non-default side to BPF; the side
// that matches the default action is skipped (BPF map size optimization —
// unlisted ports fall through to the default-action map at packet time).
//
// For a mixed verdict the default is always one of {allow, deny}, so
// exactly one side gets written. Pinning both directions catches the path
// where the wrong side is selected (e.g. if the short-circuit ever fired
// on the non-default side).
func TestApplyRulesToTrackedHostnames_MixedVerdict(t *testing.T) {
	rules := []config.Rule{
		{
			Type:   config.RuleTypeHostname,
			Value:  "*.compute.internal",
			Ports:  []config.Port{{Port: 80, Protocol: config.ProtocolTCP}},
			Action: config.ActionDeny,
		},
		{
			Type:   config.RuleTypeHostname,
			Value:  "bastion",
			Ports:  []config.Port{{Port: 22, Protocol: config.ProtocolTCP}},
			Action: config.ActionAllow,
		},
	}
	cases := []struct {
		name          string
		defaultAction config.Action
		writeAction   config.Action
		writePorts    []config.Port
	}{
		{
			name:          "default_deny_writes_allow_side",
			defaultAction: config.ActionDeny,
			writeAction:   config.ActionAllow,
			writePorts:    []config.Port{{Port: 22, Protocol: config.ProtocolTCP}},
		},
		{
			name:          "default_allow_writes_deny_side",
			defaultAction: config.ActionAllow,
			writeAction:   config.ActionDeny,
			writePorts:    []config.Port{{Port: 80, Protocol: config.ProtocolTCP}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configMgr := config.NewConfigManager()
			mockFirewall := firewall.NewMockFirewall(t)
			logger := slog.Default()
			server := NewServer(configMgr, mockFirewall, "8.8.8.8:53", "127.0.0.1:53", logger)

			require.NoError(t, configMgr.LoadConfigFromRules(rules, tc.defaultAction))
			configMgr.AddSearchDomains([]string{".compute.internal"}, logger)
			configMgr.UpdateDNSMapping("bastion.compute.internal", "10.0.0.5")

			mockFirewall.On(
				"AddIP",
				net.ParseIP("10.0.0.5"),
				tc.writeAction,
				tc.writePorts,
			).Return(true, nil).Once()

			server.ApplyRulesToTrackedHostnames()
			mockFirewall.AssertExpectations(t)
		})
	}
}

// ---------------------------------------------------------------------------
// isQueryAllowed unit tests
// ---------------------------------------------------------------------------

func TestIsQueryAllowed(t *testing.T) {
	tests := []struct {
		name          string
		filterEnabled bool
		defaultAction config.Action
		rules         []config.Rule
		domain        string
		qtype         uint16 // zero defaults to dns.TypeA below
		expected      bool
	}{
		{
			name:          "filtering disabled allows everything",
			filterEnabled: false,
			defaultAction: config.ActionDeny,
			domain:        "evil.example.com",
			expected:      true,
		},
		{
			name:          "deny-by-default, domain explicitly allowed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "allowed.example.com", Action: config.ActionAllow},
			},
			domain:   "allowed.example.com",
			expected: true,
		},
		{
			name:          "deny-by-default, domain not allowed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "allowed.example.com", Action: config.ActionAllow},
			},
			domain:   "other.example.com",
			expected: false,
		},
		{
			name:          "allow-by-default, domain explicitly denied",
			filterEnabled: true,
			defaultAction: config.ActionAllow,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "blocked.example.com", Action: config.ActionDeny},
			},
			domain:   "blocked.example.com",
			expected: false,
		},
		{
			name:          "allow-by-default, domain not explicitly denied",
			filterEnabled: true,
			defaultAction: config.ActionAllow,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "blocked.example.com", Action: config.ActionDeny},
			},
			domain:   "safe.example.com",
			expected: true,
		},
		{
			name:          "deny-by-default, subdomain of allowed parent",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow},
			},
			domain:   "sub.example.com",
			expected: true,
		},
		{
			name:          "PTR query for IPv4 reverse DNS (in-addr.arpa) is allowed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "16.129.63.168.in-addr.arpa",
			qtype:         dns.TypePTR,
			expected:      true,
		},
		{
			name:          "PTR query for IPv6 reverse DNS (ip6.arpa) is allowed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			qtype:         dns.TypePTR,
			expected:      true,
		},
		{
			// Non-PTR query against a PTR-shaped name does NOT bypass —
			// otherwise TXT/A/NS queries could carry tunneled data in
			// numeric labels under .in-addr.arpa.
			name:          "TXT query against canonical PTR name is NOT bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "16.129.63.168.in-addr.arpa",
			qtype:         dns.TypeTXT,
			expected:      false,
		},
		{
			// Same Qtype gate for IPv6.
			name:          "A query against canonical IPv6 PTR name is NOT bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			qtype:         dns.TypeA,
			expected:      false,
		},
		{
			// Reverse-DNS bypass requires the canonical PTR shape — a name
			// that merely ends in .in-addr.arpa with non-numeric labels is
			// rejected so the suffix can't be used to smuggle tunneled data.
			name:          "malformed in-addr.arpa (non-numeric label) is not bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "exfil.payload.in-addr.arpa",
			qtype:         dns.TypePTR,
			expected:      false,
		},
		{
			// Same shape check for IPv6.
			name:          "malformed ip6.arpa (multi-char label) is not bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "exfil.ip6.arpa",
			qtype:         dns.TypePTR,
			expected:      false,
		},
		{
			// IPv4 PTR with octet out of 0–255 range is rejected.
			name:          "in-addr.arpa with octet > 255 is not bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "999.0.0.0.in-addr.arpa",
			qtype:         dns.TypePTR,
			expected:      false,
		},
		{
			// strconv.Atoi accepts "+1" as 1 — but "+1" is not a valid
			// decimal octet label, so the strict digit-only check must
			// reject it before conversion.
			name:          "in-addr.arpa with sign-prefixed octet is not bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "+1.2.3.4.in-addr.arpa",
			qtype:         dns.TypePTR,
			expected:      false,
		},
		{
			name:          "in-addr.arpa with negative octet is not bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "-0.2.3.4.in-addr.arpa",
			qtype:         dns.TypePTR,
			expected:      false,
		},
		{
			// Canonical PTR is exactly 4 octets — shortened names (e.g. for
			// rDNS delegation discovery, which uses NS/SOA queries anyway)
			// must NOT pass the PTR bypass.
			name:          "shortened IPv4 PTR (1.in-addr.arpa) is not bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "1.in-addr.arpa",
			qtype:         dns.TypePTR,
			expected:      false,
		},
		{
			// Same for IPv6 — exactly 32 nibbles required.
			name:          "shortened IPv6 PTR is not bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "d.e.a.d.ip6.arpa",
			qtype:         dns.TypePTR,
			expected:      false,
		},
		{
			// Canonical PTR uses unpadded octets; "001" is rejected even
			// though strconv.Atoi would parse it as 1.
			name:          "in-addr.arpa with zero-padded octet is not bypassed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "001.2.3.4.in-addr.arpa",
			qtype:         dns.TypePTR,
			expected:      false,
		},
		{
			name:          "deny-by-default, hostname pattern allowed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "*.*.internal.cloudapp.net", Action: config.ActionAllow},
			},
			domain:   "abc.def.internal.cloudapp.net",
			expected: true,
		},
		{
			name:          "deny-by-default, hostname pattern not matched (too few labels)",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "*.*.internal.cloudapp.net", Action: config.ActionAllow},
			},
			domain:   "only1.internal.cloudapp.net",
			expected: false,
		},
		{
			name:          "allow-by-default, hostname pattern denied",
			filterEnabled: true,
			defaultAction: config.ActionAllow,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "evil.*.example.com", Action: config.ActionDeny},
			},
			domain:   "evil.anything.example.com",
			expected: false,
		},
		{
			// Rule values configured with uppercase characters must still
			// match — DNS names are case-insensitive and resolveRules now
			// normalizes Rule.Value to lowercase at load.
			name:          "uppercase rule value matches lowercase query",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "Example.COM", Action: config.ActionAllow},
			},
			domain:   "example.com",
			expected: true,
		},
		{
			// Mixed-case glob patterns work the same way — the literal
			// segments are lowercased at compile time.
			name:          "uppercase glob pattern matches lowercase query",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "*.GitHub.com", Action: config.ActionAllow},
			},
			domain:   "api.github.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewConfigManager()
			err := cfg.LoadConfigFromRules(tt.rules, tt.defaultAction)
			require.NoError(t, err)

			server := &Server{
				config:        cfg,
				filterQueries: tt.filterEnabled,
				logger:        slog.Default(),
			}

			qtype := tt.qtype
			if qtype == 0 {
				qtype = dns.TypeA
			}
			got := server.isQueryAllowed(tt.domain, qtype)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestIsQueryAllowed_SearchDomainBypass(t *testing.T) {
	tests := []struct {
		name          string
		searchDomains []string
		rules         []config.Rule
		defaultAction config.Action
		domain        string
		expected      bool
	}{
		{
			name:          "AWS suffix bypasses filter with no hostname rule",
			searchDomains: []string{".compute.internal"},
			defaultAction: config.ActionDeny,
			domain:        "ip-10-0-0-5.us-west-2.compute.internal",
			expected:      true,
		},
		{
			name:          "multiple suffixes — match second",
			searchDomains: []string{".compute.internal", ".ec2.internal"},
			defaultAction: config.ActionDeny,
			domain:        "bastion.ec2.internal",
			expected:      true,
		},
		{
			name:          "non-matching domain still blocked",
			searchDomains: []string{".compute.internal"},
			defaultAction: config.ActionDeny,
			domain:        "evil.example.com",
			expected:      false,
		},
		{
			// The leading-dot guard in the suffix prevents matching when the
			// "suffix" text appears in the middle or at the end of a different
			// label boundary.
			name:          "partial suffix match (missing leading-dot boundary) does not bypass",
			searchDomains: []string{".compute.internal"},
			defaultAction: config.ActionDeny,
			domain:        "evilnotcompute.internal",
			expected:      false,
		},
		{
			// Case-insensitive bypass: DNS responses can arrive with any case.
			name:          "case-insensitive bypass",
			searchDomains: []string{".compute.internal"},
			defaultAction: config.ActionDeny,
			domain:        "Bastion.EC2.Compute.Internal",
			expected:      true,
		},
		{
			// Explicit deny rule under a search-domain suffix must win — the
			// bypass is for unmatched names only, never a way around an
			// explicit policy.
			name:          "explicit deny rule under search-domain suffix wins over bypass",
			searchDomains: []string{".compute.internal"},
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "blocked.compute.internal", Action: config.ActionDeny},
			},
			defaultAction: config.ActionDeny,
			domain:        "blocked.compute.internal",
			expected:      false,
		},
		{
			// A deny rule on the SHORT name should also win once the suffix is
			// stripped. Otherwise the bypass would silently swallow the deny —
			// the second-order version of the precedence bug above.
			name:          "deny rule on stripped form wins over suffix bypass",
			searchDomains: []string{".compute.internal"},
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "blocked", Action: config.ActionDeny},
			},
			defaultAction: config.ActionDeny,
			domain:        "blocked.compute.internal",
			expected:      false,
		},
		{
			// Conversely, an allow rule on the SHORT name should be honored
			// when the suffixed form is queried — this is the K8s short-name
			// pattern, generalized to any configured search domain. isQueryAllowed
			// does the strip-and-retry internally now.
			name:          "allow rule on stripped form (short-name pattern) is honored via isQueryAllowed",
			searchDomains: []string{".compute.internal"},
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "bastion", Action: config.ActionAllow},
			},
			defaultAction: config.ActionDeny,
			domain:        "bastion.compute.internal",
			expected:      true,
		},
		{
			// Same pattern through the always-active Kubernetes suffixes —
			// no configured searchDomains needed.
			name:          "K8s suffix strip + allow rule on short name",
			searchDomains: nil,
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "myservice", Action: config.ActionAllow},
			},
			defaultAction: config.ActionDeny,
			domain:        "myservice.svc.cluster.local",
			expected:      true,
		},
		{
			// Case-bypass exploit guard: a mixed-case query must not route
			// around an explicit deny on the stripped form. Before the
			// case-insensitivity fix in MatchHostnameRule, "Blocked" wouldn't
			// match the rule for "blocked", so this domain would slip through
			// the search-domain bypass.
			name:          "mixed-case query does not bypass deny on stripped form",
			searchDomains: []string{".compute.internal"},
			rules: []config.Rule{
				{Type: config.RuleTypeHostname, Value: "blocked", Action: config.ActionDeny},
			},
			defaultAction: config.ActionDeny,
			domain:        "Blocked.Compute.Internal",
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewConfigManager()
			require.NoError(t, cfg.LoadConfigFromRules(tt.rules, tt.defaultAction))
			cfg.AddSearchDomains(tt.searchDomains, slog.Default())

			server := &Server{
				config:        cfg,
				filterQueries: true,
				logger:        slog.Default(),
			}

			got := server.isQueryAllowed(tt.domain, dns.TypeA)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// handleDNSQuery integration tests
// ---------------------------------------------------------------------------

// newTestServer creates a Server with sensible defaults for handler tests.
func newTestServer(t *testing.T, cfg *config.Manager, fw firewall.Firewall) *Server {
	t.Helper()
	return &Server{
		config:      cfg,
		firewall:    fw,
		logger:      slog.Default(),
		upstream:    "8.8.8.8:53",
		client:      &dns.Client{Timeout: 5 * time.Second},
		hostnameIPs: make(map[string]map[string]bool),
		dnsCache:    newLRUCache[string, *dnsCacheEntry](10000),
	}
}

// makeCachedResponse builds a minimal A-record response suitable for caching.
func makeCachedResponse(name string, ip string) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 9999, Response: true, Rcode: dns.RcodeSuccess},
		Question: []dns.Question{
			{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP(ip),
			},
		},
	}
}

func TestHandleDNSQuery_CacheHit(t *testing.T) {
	cfg := config.NewConfigManager()
	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)

	// Pre-populate cache
	cachedResp := makeCachedResponse("cached.example.com.", "10.0.0.1")
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: "cached.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: cachedResp.Copy()}, 5*time.Minute)

	// Build query with a different ID
	query := new(dns.Msg)
	query.SetQuestion("cached.example.com.", dns.TypeA)
	query.Id = 1111

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, uint16(1111), w.msg.Id, "response ID should match query ID")
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
	require.Len(t, w.msg.Answer, 1)
	aRecord, ok := w.msg.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.1", aRecord.A.String())
}

func TestHandleDNSQuery_FilteringEnforceBlocks(t *testing.T) {
	cfg := config.NewConfigManager()
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "allowed.example.com", Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	server.filterQueries = true

	query := new(dns.Msg)
	query.SetQuestion("evil.tunnel.example.com.", dns.TypeA)
	query.Id = 2222

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeRefused, w.msg.Rcode, "blocked domain should get REFUSED")
}

func TestHandleDNSQuery_FilteringAuditModePassesThrough(t *testing.T) {
	cfg := config.NewConfigManager()
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "allowed.example.com", Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	server.filterQueries = true

	// Create a real audit logger in audit mode
	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.json")
	require.NoError(t, err)
	tmpFile.Close()
	auditLogger, err := events.NewAuditLogger(tmpFile.Name(), true) // audit mode = true
	require.NoError(t, err)
	defer auditLogger.Close()
	server.auditLogger = auditLogger

	// Pre-populate cache so no upstream call is needed
	cachedResp := makeCachedResponse("evil.tunnel.example.com.", "1.2.3.4")
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: "evil.tunnel.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: cachedResp.Copy()}, 5*time.Minute)

	query := new(dns.Msg)
	query.SetQuestion("evil.tunnel.example.com.", dns.TypeA)
	query.Id = 3333

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode, "audit mode should not block the query")
}

func TestHandleDNSQuery_FilteringAllowedDomainPasses(t *testing.T) {
	cfg := config.NewConfigManager()
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	server.filterQueries = true

	// Pre-populate cache
	cachedResp := makeCachedResponse("example.com.", "93.184.216.34")
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: cachedResp.Copy()}, 5*time.Minute)

	// Expect firewall call since example.com is tracked with a rule
	mockFw.On("AddIP", net.ParseIP("93.184.216.34"), config.ActionAllow, []config.Port(nil)).Return(true, nil).Once()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 4444

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
}

// Bypass-only resolutions (a name allowed only by the search-domain bypass,
// with no matching hostname rule on either form) must not populate either
// the per-server hostnameIPs map or the config manager's reverse-lookup map.
// Otherwise ephemeral cloud-internal names (e.g. ip-X-X-X-X.compute.internal
// per EC2 instance) would grow these maps without bound.
func TestHandleDNSQuery_BypassOnlySkipsHostnameTracking(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules(nil, config.ActionDeny))
	cfg.AddSearchDomains([]string{".compute.internal"}, slog.Default())

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	server.filterQueries = true

	const fullName = "ip-10-0-0-5.us-west-2.compute.internal."
	cachedResp := makeCachedResponse(fullName, "10.0.0.5")
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: fullName, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: cachedResp.Copy()}, 5*time.Minute)

	query := new(dns.Msg)
	query.SetQuestion(fullName, dns.TypeA)
	query.Id = 5555

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode, "bypass-allowed query should succeed")

	// The query was allowed by the search-domain bypass with no matching
	// hostname rule, so neither per-host map should be populated.
	server.hostnameIPsMutex.RLock()
	assert.Empty(t, server.hostnameIPs,
		"hostnameIPs must not record bypass-only resolutions")
	server.hostnameIPsMutex.RUnlock()
	assert.Empty(t, cfg.GetIPToHostnameMap(),
		"config ipToHostname map must not record bypass-only resolutions")

	// No firewall AddIP should have been called (no matching rule);
	// firewall.NewMockFirewall(t) will fail the test if any unexpected call
	// happened, so this is an implicit assertion.
}

// Counterpoint to the above: when a rule matches the stripped form (the K8s
// or short-name pattern), per-host tracking SHOULD happen and the firewall
// SHOULD be updated.
func TestHandleDNSQuery_BypassWithMatchingShortRuleStillTracks(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "bastion", Action: config.ActionAllow,
			Ports: []config.Port{{Port: 22, Protocol: config.ProtocolAll}},
		},
	}, config.ActionDeny))
	cfg.AddSearchDomains([]string{".compute.internal"}, slog.Default())

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)
	server.filterQueries = true

	const fullName = "bastion.compute.internal."
	cachedResp := makeCachedResponse(fullName, "10.0.0.10")
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: fullName, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: cachedResp.Copy()}, 5*time.Minute)

	// The stripped form "bastion" matches the allow rule, so the BPF map
	// should get updated.
	mockFw.On("AddIP", net.ParseIP("10.0.0.10"), config.ActionAllow,
		[]config.Port{{Port: 22, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

	query := new(dns.Msg)
	query.SetQuestion(fullName, dns.TypeA)
	query.Id = 6666

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)
	require.NotNil(t, w.msg)

	// Reverse-mapping IS populated (used for audit attribution).
	assert.Equal(t, "bastion.compute.internal",
		cfg.GetIPToHostnameMap()["10.0.0.10"],
		"reverse mapping should include the bypass-but-rule-matched IP")
}

func TestHandleDNSQuery_FirewallUpdateOnCacheHit(t *testing.T) {
	cfg := config.NewConfigManager()
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "tracked.example.com", Action: config.ActionAllow, Ports: []config.Port{{Port: 443, Protocol: config.ProtocolAll}}},
	}, config.ActionDeny)
	require.NoError(t, err)

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)

	// Pre-populate cache with an A record for the tracked hostname
	cachedResp := makeCachedResponse("tracked.example.com.", "10.1.1.1")
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: "tracked.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: cachedResp.Copy()}, 5*time.Minute)

	// Expect AddIP for the tracked hostname
	mockFw.On("AddIP", net.ParseIP("10.1.1.1"), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

	query := new(dns.Msg)
	query.SetQuestion("tracked.example.com.", dns.TypeA)
	query.Id = 5555

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	// MockFirewall created with NewMockFirewall auto-asserts expectations on cleanup
	w.AssertExpectations(t)
}

func TestHandleDNSQuery_EmptyQuestion(t *testing.T) {
	cfg := config.NewConfigManager()
	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)

	// Pre-populate cache for the empty key (empty question => key "")
	server.dnsCache.Put("", &dnsCacheEntry{
		msg: &dns.Msg{MsgHdr: dns.MsgHdr{Id: 0, Response: true, Rcode: dns.RcodeSuccess}},
	}, 5*time.Minute)

	query := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 6666}}

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	// Should not panic
	server.handleDNSQuery(w, query)
	w.AssertExpectations(t)
}

func TestHandleDNSQuery_UpstreamExchangeFailure(t *testing.T) {
	cfg := config.NewConfigManager()
	mockFw := firewall.NewMockFirewall(t)

	server := &Server{
		config:      cfg,
		firewall:    mockFw,
		logger:      slog.Default(),
		upstream:    "127.0.0.1:1", // unreachable port
		client:      &dns.Client{Timeout: 50 * time.Millisecond},
		hostnameIPs: make(map[string]map[string]bool),
		dnsCache:    newLRUCache[string, *dnsCacheEntry](10000),
	}

	query := new(dns.Msg)
	query.SetQuestion("unreachable.example.com.", dns.TypeA)
	query.Id = 9999

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeServerFailure, w.msg.Rcode, "should return SERVFAIL on upstream failure")
}

// ---------------------------------------------------------------------------
// extractIPsFromResponse additional cases (table-driven)
// ---------------------------------------------------------------------------

func TestExtractIPsFromResponse_AdditionalCases(t *testing.T) {
	tests := []struct {
		name        string
		answers     []dns.RR
		expectedIPs []string
		expectedTTL uint32
	}{
		{
			name: "AAAA only",
			answers: []dns.RR{
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120},
					AAAA: net.ParseIP("2001:db8::1"),
				},
			},
			expectedIPs: []string{"2001:db8::1"},
			expectedTTL: 120,
		},
		{
			name: "mixed A and AAAA",
			answers: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 200},
					A:   net.ParseIP("192.168.1.1"),
				},
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 150},
					AAAA: net.ParseIP("2001:db8::2"),
				},
			},
			expectedIPs: []string{"192.168.1.1", "2001:db8::2"},
			expectedTTL: 150,
		},
		{
			name:        "empty answer",
			answers:     []dns.RR{},
			expectedIPs: nil,
			expectedTTL: 86400,
		},
		{
			name: "non-address records (CNAME and MX)",
			answers: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "example.com.",
				},
				&dns.MX{
					Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Preference: 10,
					Mx:         "mail.example.com.",
				},
			},
			expectedIPs: nil,
			expectedTTL: 300,
		},
		{
			// CNAME chain followed by the resolved A record. The CNAME RR
			// must be ignored when extracting IPs; only the A is extracted.
			// But the CNAME's TTL DOES count toward the response's min TTL
			// (300 < 600), matching standard DNS cache semantics.
			name: "CNAME chain followed by A — only A extracted, CNAME TTL counts",
			answers: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "example.com.",
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
					A:   net.ParseIP("192.0.2.5"),
				},
			},
			expectedIPs: []string{"192.0.2.5"},
			expectedTTL: 300, // min(CNAME 300, A 600)
		},
		{
			// SRV and TXT are not address records — must be skipped silently.
			name: "SRV and TXT records ignored",
			answers: []dns.RR{
				&dns.SRV{
					Hdr:    dns.RR_Header{Name: "_xmpp._tcp.example.com.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 100},
					Target: "xmpp.example.com.",
					Port:   5222,
				},
				&dns.TXT{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 100},
					Txt: []string{"v=spf1 -all"},
				},
			},
			expectedIPs: nil,
			expectedTTL: 100,
		},
		{
			// TTL=0 in the only answer. Pin current behavior: extracted TTL
			// is 0, not the 86400 default (the default applies only when
			// there are no answers at all).
			name: "single answer with TTL=0",
			answers: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "ephemeral.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   net.ParseIP("192.0.2.99"),
				},
			},
			expectedIPs: []string{"192.0.2.99"},
			expectedTTL: 0,
		},
		{
			// Multiple A records with mixed TTLs — returns the minimum,
			// so a downstream cache respects the shortest-lived record.
			name: "mixed TTLs across answers — min wins",
			answers: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.2"),
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 900},
					A:   net.ParseIP("192.0.2.3"),
				},
			},
			expectedIPs: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
			expectedTTL: 60,
		},
		{
			// Min-with-TTL-0: when any answer has TTL=0, the returned
			// minimum is 0 (no special-casing in this function — see
			// docstring; the cache Put path applies its own "treat 0 as
			// default-floor" policy separately).
			name: "TTL=0 among multiple answers propagates to returned min",
			answers: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
					A:   net.ParseIP("192.0.2.4"),
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   net.ParseIP("192.0.2.5"),
				},
			},
			expectedIPs: []string{"192.0.2.4", "192.0.2.5"},
			expectedTTL: 0,
		},
	}

	server := &Server{logger: slog.Default()}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &dns.Msg{Answer: tt.answers}
			ips, ttl := server.extractIPsFromResponse(msg)

			assert.Equal(t, tt.expectedTTL, ttl)

			if tt.expectedIPs == nil {
				assert.Empty(t, ips)
				return
			}

			require.Len(t, ips, len(tt.expectedIPs))
			ipStrings := make([]string, len(ips))
			for i, ip := range ips {
				ipStrings[i] = ip.String()
			}
			for _, expected := range tt.expectedIPs {
				assert.Contains(t, ipStrings, expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// addIPToBPFMaps error and duplicate paths
// ---------------------------------------------------------------------------

func TestAddIPToBPFMaps_FirewallError(t *testing.T) {
	mockFw := firewall.NewMockFirewall(t)
	server := &Server{firewall: mockFw, logger: slog.Default()}

	ip := net.ParseIP("10.0.0.1")
	expectedErr := errors.New("bpf map full")
	mockFw.On("AddIP", ip, config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(false, expectedErr)

	err := server.addIPToBPFMaps(ip, "example.com", config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}})
	assert.ErrorIs(t, err, expectedErr)
}

func TestAddIPToBPFMaps_DuplicateNoError(t *testing.T) {
	mockFw := firewall.NewMockFirewall(t)
	server := &Server{firewall: mockFw, logger: slog.Default()}

	ip := net.ParseIP("10.0.0.1")
	mockFw.On("AddIP", ip, config.ActionDeny, []config.Port(nil)).Return(false, nil)

	err := server.addIPToBPFMaps(ip, "dup.example.com", config.ActionDeny, nil)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// removeIPFromBPFMaps error path
// ---------------------------------------------------------------------------

func TestRemoveIPFromBPFMaps_FirewallError(t *testing.T) {
	mockFw := firewall.NewMockFirewall(t)
	server := &Server{firewall: mockFw, logger: slog.Default()}

	ip := net.ParseIP("10.0.0.1")
	expectedErr := errors.New("bpf map delete failed")
	mockFw.On("RemoveIP", ip).Return(expectedErr)

	err := server.removeIPFromBPFMaps(ip)
	assert.ErrorIs(t, err, expectedErr)
}

// ---------------------------------------------------------------------------
// Address family preservation in IP tracking (handleDNSQuery)
// ---------------------------------------------------------------------------

func TestHandleDNSQuery_PreservesIPv6WhenAResponseArrives(t *testing.T) {
	cfg := config.NewConfigManager()
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "dual.example.com", Action: config.ActionAllow, Ports: []config.Port{{Port: 443, Protocol: config.ProtocolAll}}},
	}, config.ActionDeny)
	require.NoError(t, err)

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)

	// Pre-seed existing IPv6 IPs for this hostname
	server.hostnameIPs["dual.example.com"] = map[string]bool{
		"2001:db8::1": true,
	}

	// Cache an A (IPv4) response
	cachedResp := makeCachedResponse("dual.example.com.", "10.2.3.4")
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: "dual.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: cachedResp.Copy()}, 5*time.Minute)

	// Expect AddIP for the new IPv4
	mockFw.On("AddIP", net.ParseIP("10.2.3.4"), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

	query := new(dns.Msg)
	query.SetQuestion("dual.example.com.", dns.TypeA)
	query.Id = 7777

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)

	// Verify the IPv6 IP was preserved
	server.hostnameIPsMutex.RLock()
	tracked := server.hostnameIPs["dual.example.com"]
	server.hostnameIPsMutex.RUnlock()

	assert.True(t, tracked["2001:db8::1"], "existing IPv6 should be preserved when A response arrives")
	assert.True(t, tracked["10.2.3.4"], "new IPv4 should be added")
}

func TestHandleDNSQuery_PreservesIPv4WhenAAAAResponseArrives(t *testing.T) {
	cfg := config.NewConfigManager()
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "dual6.example.com", Action: config.ActionAllow, Ports: []config.Port{{Port: 443, Protocol: config.ProtocolAll}}},
	}, config.ActionDeny)
	require.NoError(t, err)

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)

	// Pre-seed existing IPv4 IPs
	server.hostnameIPs["dual6.example.com"] = map[string]bool{
		"10.5.6.7": true,
	}

	// Cache an AAAA response
	aaaaResp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 9999, Response: true, Rcode: dns.RcodeSuccess},
		Question: []dns.Question{
			{Name: "dual6.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		},
		Answer: []dns.RR{
			&dns.AAAA{
				Hdr:  dns.RR_Header{Name: "dual6.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::99"),
			},
		},
	}
	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: "dual6.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}},
	})
	server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: aaaaResp.Copy()}, 5*time.Minute)

	// Expect AddIP for the new IPv6
	mockFw.On("AddIP", net.ParseIP("2001:db8::99"), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

	query := new(dns.Msg)
	query.SetQuestion("dual6.example.com.", dns.TypeAAAA)
	query.Id = 8888

	w := &MockResponseWriter{}
	w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

	server.handleDNSQuery(w, query)

	w.AssertExpectations(t)

	// Verify IPv4 was preserved
	server.hostnameIPsMutex.RLock()
	tracked := server.hostnameIPs["dual6.example.com"]
	server.hostnameIPsMutex.RUnlock()

	assert.True(t, tracked["10.5.6.7"], "existing IPv4 should be preserved when AAAA response arrives")
	assert.True(t, tracked["2001:db8::99"], "new IPv6 should be added")
}

// ---------------------------------------------------------------------------
// DNS round-robin IP accumulation
// ---------------------------------------------------------------------------

func TestHandleDNSQuery_RoundRobinIPsAccumulate(t *testing.T) {
	cfg := config.NewConfigManager()
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "cdn.example.com", Action: config.ActionAllow, Ports: []config.Port{{Port: 443, Protocol: config.ProtocolAll}}},
	}, config.ActionDeny)
	require.NoError(t, err)

	mockFw := firewall.NewMockFirewall(t)
	server := newTestServer(t, cfg, mockFw)

	cacheKey := server.generateCacheKey(&dns.Msg{
		Question: []dns.Question{{Name: "cdn.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	})

	// Simulate three successive round-robin DNS responses, each returning a
	// single IP. All three IPs should accumulate in hostnameIPs and the BPF
	// firewall — none should be removed.
	roundRobinIPs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}

	for i, ipStr := range roundRobinIPs {
		resp := makeCachedResponse("cdn.example.com.", ipStr)
		server.dnsCache.Put(cacheKey, &dnsCacheEntry{msg: resp.Copy()}, 5*time.Minute)

		mockFw.On("AddIP", net.ParseIP(ipStr), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

		query := new(dns.Msg)
		query.SetQuestion("cdn.example.com.", dns.TypeA)
		query.Id = uint16(3000 + i)

		w := &MockResponseWriter{}
		w.On("WriteMsg", mock.AnythingOfType("*dns.Msg")).Return(nil).Once()

		server.handleDNSQuery(w, query)
		w.AssertExpectations(t)
	}

	// Verify all three IPs are tracked
	server.hostnameIPsMutex.RLock()
	tracked := server.hostnameIPs["cdn.example.com"]
	server.hostnameIPsMutex.RUnlock()

	for _, ipStr := range roundRobinIPs {
		assert.True(t, tracked[ipStr], "round-robin IP %s should be accumulated", ipStr)
	}

	// Verify RemoveIP was never called
	mockFw.AssertNotCalled(t, "RemoveIP", mock.Anything)
}

// ---------------------------------------------------------------------------
// Setter method tests
// ---------------------------------------------------------------------------

func TestEnableQueryFiltering(t *testing.T) {
	server := &Server{}

	assert.False(t, server.filterQueries)
	server.EnableQueryFiltering(true)
	assert.True(t, server.filterQueries)
	server.EnableQueryFiltering(false)
	assert.False(t, server.filterQueries)
}

func TestAddListenAddr(t *testing.T) {
	server := &Server{}

	assert.Empty(t, server.additionalAddrs)
	server.AddListenAddr("172.17.0.1:53")
	server.AddListenAddr("10.0.0.1:53")
	assert.Equal(t, []string{"172.17.0.1:53", "10.0.0.1:53"}, server.additionalAddrs)
}

func TestSetAuditLogger(t *testing.T) {
	server := &Server{}
	assert.Nil(t, server.auditLogger)

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.json")
	require.NoError(t, err)
	tmpFile.Close()

	auditLogger, err := events.NewAuditLogger(tmpFile.Name(), false)
	require.NoError(t, err)
	defer auditLogger.Close()

	server.SetAuditLogger(auditLogger)
	assert.Equal(t, auditLogger, server.auditLogger)
}

// =============================================================================
// Direct unit table for isValidReverseDNS (H2)
//
// PTR validation is the security-relevant guard that prevents DNS-tunneling
// data exfiltration via PTR-shaped queries. Tested transitively via the
// TestIsQueryAllowed PTR rows, but a direct table is faster (no Server
// fixture) and makes the rejection branches explicit.
// =============================================================================

func TestIsValidReverseDNS(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		// IPv4 canonical PTR shape: exactly 4 unpadded decimal octets.
		{"IPv4 canonical", "16.129.63.168.in-addr.arpa", true},
		{"IPv4 all zeros (0.0.0.0)", "0.0.0.0.in-addr.arpa", true},
		{"IPv4 boundary (255.255.255.255)", "255.255.255.255.in-addr.arpa", true},
		{"IPv4 mixed magnitudes", "1.2.30.255.in-addr.arpa", true},

		// IPv4 rejections.
		{"IPv4 octet > 255", "999.0.0.0.in-addr.arpa", false},
		{"IPv4 octet 256 (one past max)", "256.0.0.0.in-addr.arpa", false},
		{"IPv4 zero-padded octet", "001.2.3.4.in-addr.arpa", false},
		{"IPv4 sign-prefixed", "+1.2.3.4.in-addr.arpa", false},
		{"IPv4 negative", "-0.2.3.4.in-addr.arpa", false},
		{"IPv4 shortened (1 octet)", "1.in-addr.arpa", false},
		{"IPv4 too many octets", "1.2.3.4.5.in-addr.arpa", false},
		{"IPv4 non-numeric label", "exfil.payload.in-addr.arpa", false},
		{"IPv4 empty leading label", ".2.3.4.in-addr.arpa", false},
		{"IPv4 4-digit octet", "1234.0.0.0.in-addr.arpa", false},

		// IPv6 canonical PTR shape: exactly 32 single-hex-nibble labels.
		{
			name:   "IPv6 canonical",
			domain: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			want:   true,
		},
		{
			name:   "IPv6 mixed-case hex (canonical)",
			domain: "F.E.D.C.B.A.9.8.7.6.5.4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
			want:   true,
		},

		// IPv6 rejections.
		{"IPv6 shortened (4 nibbles)", "d.e.a.d.ip6.arpa", false},
		{"IPv6 too many nibbles", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", false},
		{"IPv6 multi-char nibble", "ab.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", false},
		{"IPv6 invalid hex char (g)", "g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", false},

		// Non-PTR suffixes.
		{"not a reverse-DNS suffix", "github.com", false},
		{"empty input", "", false},
		{"only suffix (no octets)", ".in-addr.arpa", false},
		{"only ip6 suffix", ".ip6.arpa", false},

		// FQDN trailing dot — the handler always strips the trailing dot
		// before calling isValidReverseDNS, but pin behavior for the bare
		// function. Currently DOES NOT match (suffix is hardcoded without
		// trailing dot).
		{"FQDN trailing dot not accepted", "16.129.63.168.in-addr.arpa.", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isValidReverseDNS(tc.domain)
			assert.Equal(t, tc.want, got, "isValidReverseDNS(%q)", tc.domain)
		})
	}
}

// =============================================================================
// ApplyRulesToTrackedHostnames conflict path (M1)
//
// When a tracked hostname's resolved IP also falls inside a CIDR rule with a
// conflicting action, CheckIPRuleConflict returns (deny, hasConflict=true,
// cidr). ApplyRulesToTrackedHostnames must log the conflict AND apply the
// most-restrictive action (deny) to BPF, not the hostname's allow.
// =============================================================================

func TestApplyRulesToTrackedHostnames_ConflictDenyWins(t *testing.T) {
	configMgr := config.NewConfigManager()
	mockFirewall := firewall.NewMockFirewall(t)
	server := NewServer(configMgr, mockFirewall, "8.8.8.8:53", "127.0.0.1:53", slog.Default())

	// Resolution arrives before rules are loaded.
	configMgr.UpdateDNSMapping("example.com", "203.0.113.50")

	// Hostname allow on example.com AND a CIDR deny that covers the resolved
	// IP. The deny-wins precedence inside CheckIPRuleConflict must surface
	// here as a Deny call to the firewall, not Allow.
	err := configMgr.LoadConfigFromRules([]config.Rule{
		{
			Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow,
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
		},
		{
			Type: config.RuleTypeCIDR, Value: "203.0.113.0/24", Action: config.ActionDeny,
			Ports: []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
		},
	}, config.ActionAllow) // allow-by-default so the deny is meaningful
	require.NoError(t, err)

	// Expect AddIP with ActionDeny (the conflict-resolved final action),
	// using the hostname rule's ports.
	mockFirewall.On(
		"AddIP",
		net.ParseIP("203.0.113.50"),
		config.ActionDeny,
		[]config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
	).Return(true, nil).Once()

	server.ApplyRulesToTrackedHostnames()
	mockFirewall.AssertExpectations(t)
}
