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

func TestStripKubernetesSearchDomains(t *testing.T) {
	server := &Server{}

	tests := []struct {
		hostname string
		expected string
	}{
		{"myservice.default.svc.cluster.local", "myservice"},
		{"myservice.svc.cluster.local", "myservice"},
		{"myservice.cluster.local", "myservice"},
		{"myservice.example.com", "myservice.example.com"},
		{"myservice", "myservice"},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			result := server.stripKubernetesSearchDomains(tt.hostname)
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
	assert.Equal(t, uint32(600), ttl) // Returns the last TTL seen
}

func TestAddIPToBPFMaps(t *testing.T) {
	mockFw := new(firewall.MockFirewall)
	server := &Server{
		firewall: mockFw,
		logger:   slog.Default(),
	}

	ip := net.ParseIP("192.168.1.1")
	ports := []config.Port{{Value: 80, Protocol: config.ProtocolAll}, {Value: 443, Protocol: config.ProtocolAll}}

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
			Ports:  []config.Port{{Value: 4222, Protocol: config.ProtocolAll}},
			Action: config.ActionAllow,
		},
	}
	err := configMgr.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	// Expect AddIP to be called when we reprocess
	mockFirewall.On("AddIP",
		net.ParseIP("10.15.1.105"),
		config.ActionAllow,
		[]config.Port{{Value: 4222, Protocol: config.ProtocolAll}},
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
		{Type: config.RuleTypeHostname, Value: "example.com", Action: config.ActionAllow, Ports: []config.Port{{Value: 443, Protocol: config.ProtocolAll}}},
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
	mockFw.On("AddIP", net.ParseIP("192.168.1.1"), config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()
	mockFw.On("AddIP", net.ParseIP("192.168.1.2"), config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

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
	mockFw.On("AddIP", net.ParseIP("192.168.1.3"), config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

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

func TestGetHostnamePorts(t *testing.T) {
	cfg := config.NewConfigManager()
	server := &Server{
		config: cfg,
		logger: slog.Default(),
	}

	// Setup config with various rules
	rules := []config.Rule{
		{
			Type:   config.RuleTypeHostname,
			Value:  "api.example.com",
			Action: config.ActionAllow,
			Ports:  []config.Port{{Value: 443, Protocol: config.ProtocolAll}, {Value: 8443, Protocol: config.ProtocolAll}},
		},
		{
			Type:   config.RuleTypeHostname,
			Value:  "example.com",
			Action: config.ActionAllow,
			Ports:  []config.Port{{Value: 80, Protocol: config.ProtocolAll}, {Value: 443, Protocol: config.ProtocolAll}},
		},
	}
	err := cfg.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	tests := []struct {
		hostname string
		expected []config.Port
	}{
		{"api.example.com", []config.Port{{Value: 443, Protocol: config.ProtocolAll}, {Value: 8443, Protocol: config.ProtocolAll}}},
		{"example.com", []config.Port{{Value: 80, Protocol: config.ProtocolAll}, {Value: 443, Protocol: config.ProtocolAll}}},
		{"sub.example.com", []config.Port{{Value: 80, Protocol: config.ProtocolAll}, {Value: 443, Protocol: config.ProtocolAll}}}, // Should match parent domain
		{"other.com", nil},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			ports := server.getHostnamePorts(tt.hostname)
			assert.Equal(t, tt.expected, ports)
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
			Ports:  []config.Port{{Value: 443, Protocol: config.ProtocolAll}},
		},
	}
	err := cfg.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	// Add an IP for the hostname
	ip := net.ParseIP("10.0.0.1")
	mockFw.On("AddIP", ip, config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

	err = server.addIPToBPFMaps(ip, "persistent.example.com", config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}) // 30 second TTL
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
			Ports:  []config.Port{{Value: 4222, Protocol: config.ProtocolAll}, {Value: 6222, Protocol: config.ProtocolAll}, {Value: 8222, Protocol: config.ProtocolAll}},
			Action: config.ActionAllow,
		},
	}
	err := configMgr.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	// Expect AddIP to be called for the cached NATS IP
	mockFirewall.On("AddIP",
		net.ParseIP("10.15.1.105"),
		config.ActionAllow,
		[]config.Port{{Value: 4222, Protocol: config.ProtocolAll}, {Value: 6222, Protocol: config.ProtocolAll}, {Value: 8222, Protocol: config.ProtocolAll}},
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
			name:          "deny-by-default, IPv4 reverse DNS (in-addr.arpa) always allowed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "16.129.63.168.in-addr.arpa",
			expected:      true,
		},
		{
			name:          "deny-by-default, IPv6 reverse DNS (ip6.arpa) always allowed",
			filterEnabled: true,
			defaultAction: config.ActionDeny,
			domain:        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			expected:      true,
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

			got := server.isQueryAllowed(tt.domain)
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

func TestHandleDNSQuery_FirewallUpdateOnCacheHit(t *testing.T) {
	cfg := config.NewConfigManager()
	err := cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "tracked.example.com", Action: config.ActionAllow, Ports: []config.Port{{Value: 443, Protocol: config.ProtocolAll}}},
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
	mockFw.On("AddIP", net.ParseIP("10.1.1.1"), config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

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
	mockFw.On("AddIP", ip, config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(false, expectedErr)

	err := server.addIPToBPFMaps(ip, "example.com", config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}})
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
		{Type: config.RuleTypeHostname, Value: "dual.example.com", Action: config.ActionAllow, Ports: []config.Port{{Value: 443, Protocol: config.ProtocolAll}}},
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
	mockFw.On("AddIP", net.ParseIP("10.2.3.4"), config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

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
		{Type: config.RuleTypeHostname, Value: "dual6.example.com", Action: config.ActionAllow, Ports: []config.Port{{Value: 443, Protocol: config.ProtocolAll}}},
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
	mockFw.On("AddIP", net.ParseIP("2001:db8::99"), config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

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
		{Type: config.RuleTypeHostname, Value: "cdn.example.com", Action: config.ActionAllow, Ports: []config.Port{{Value: 443, Protocol: config.ProtocolAll}}},
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

		mockFw.On("AddIP", net.ParseIP(ipStr), config.ActionAllow, []config.Port{{Value: 443, Protocol: config.ProtocolAll}}).Return(true, nil).Once()

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
