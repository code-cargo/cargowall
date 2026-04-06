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
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/firewall"
	cargowallNet "github.com/code-cargo/cargowall/pkg/network"
)

// Server is a DNS proxy that intercepts queries and updates BPF maps
type Server struct {
	config     *config.Manager
	firewall   firewall.Firewall
	logger     *slog.Logger
	upstream   string
	listenAddr string
	client     *dns.Client
	server     *dns.Server

	// Additional listen addresses (e.g., docker bridge IP for container DNS)
	additionalAddrs []string
	servers         []*dns.Server // All running servers

	// DNS query filtering (blocks DNS tunneling)
	filterQueries bool // When true, only forward queries for allowed domains

	// Track hostname to IP mappings for updates (no automatic removal)
	hostnameIPs      map[string]map[string]bool // hostname -> set of IPs
	hostnameIPsMutex sync.RWMutex

	// DNS response cache (LRU with per-entry TTL)
	dnsCache *lruCache[string, *dnsCacheEntry]

	// Audit logger for DNS events
	auditLogger *events.AuditLogger
}

// dnsCacheEntry holds a cached DNS response
type dnsCacheEntry struct {
	msg *dns.Msg
}

// NewServer creates a new DNS proxy server
func NewServer(cfg *config.Manager, fw firewall.Firewall, upstream, listenAddr string, logger *slog.Logger) *Server {
	return &Server{
		config:     cfg,
		firewall:   fw,
		logger:     logger,
		upstream:   upstream,
		listenAddr: listenAddr,
		client: &dns.Client{
			Timeout: 5 * time.Second,
			Dialer: &net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					var sErr error
					c.Control(func(fd uintptr) {
						sErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_MARK, cargowallNet.DNSProxyFWMark)
					})
					return sErr
				},
			},
		},
		hostnameIPs: make(map[string]map[string]bool),
		dnsCache:    newLRUCache[string, *dnsCacheEntry](10000),
	}
}

// SetFirewall updates the firewall instance after server creation
func (s *Server) SetFirewall(fw firewall.Firewall) {
	s.firewall = fw
}

// SetAuditLogger sets the audit logger for DNS events
func (s *Server) SetAuditLogger(auditLogger *events.AuditLogger) {
	s.auditLogger = auditLogger
}

// AddListenAddr adds an additional address for the DNS server to listen on.
// This is used for Docker container DNS (listening on docker bridge IP).
func (s *Server) AddListenAddr(addr string) {
	s.additionalAddrs = append(s.additionalAddrs, addr)
}

// EnableQueryFiltering enables DNS query filtering.
// When enabled, only queries for domains that match allowed hostname rules will be forwarded.
// Queries for non-allowed domains will receive REFUSED responses.
// This prevents DNS tunneling attacks where data is exfiltrated via DNS queries.
func (s *Server) EnableQueryFiltering(enable bool) {
	s.filterQueries = enable
}

// isQueryAllowed checks if a DNS query for the given domain should be forwarded.
// Returns true if the domain matches an allowed hostname pattern or if filtering is disabled.
func (s *Server) isQueryAllowed(domain string) bool {
	if !s.filterQueries {
		return true // Filtering disabled, allow all
	}

	// Always allow reverse DNS lookups (PTR queries). The in-addr.arpa /
	// ip6.arpa name format is constrained to IP octets and cannot be used
	// for DNS tunneling data exfiltration.
	if strings.HasSuffix(domain, ".in-addr.arpa") || strings.HasSuffix(domain, ".ip6.arpa") {
		return true
	}

	// Check if the domain matches any allowed hostname pattern
	action := s.config.GetTrackedHostnameAction(domain)
	if action == config.ActionAllow {
		return true
	}

	// Also check if default action is "allow" (then we only block explicitly denied)
	if s.config.GetDefaultAction() == config.ActionAllow {
		// In allow-by-default mode, only block if explicitly denied
		return action != config.ActionDeny
	}

	// In deny-by-default mode, domain must be explicitly allowed
	return false
}

// ApplyRulesToTrackedHostnames applies newly loaded firewall rules to any hostnames we've already tracked
// This is called after loading config to handle hostnames that were resolved before rules were loaded
func (s *Server) ApplyRulesToTrackedHostnames() {
	// Process all tracked hostnames we've seen (stored in hostnameIPs map)
	s.hostnameIPsMutex.Lock()
	trackedHostnames := make(map[string]map[string]bool)
	for hostname, ips := range s.hostnameIPs {
		// Make a copy to avoid holding the lock
		ipCopy := make(map[string]bool)
		for ip := range ips {
			ipCopy[ip] = true
		}
		trackedHostnames[hostname] = ipCopy
	}
	s.hostnameIPsMutex.Unlock()

	// Also check for hostnames from DNS mappings that may use full names
	ipToHostname := s.config.GetIPToHostnameMap()
	for ip, fullHostname := range ipToHostname {
		// Check stripped versions too
		stripped := s.stripKubernetesSearchDomains(fullHostname)
		hostnamesToCheck := []string{fullHostname}
		if stripped != fullHostname {
			hostnamesToCheck = append(hostnamesToCheck, stripped)
		}

		for _, hostname := range hostnamesToCheck {
			if _, exists := trackedHostnames[hostname]; !exists {
				trackedHostnames[hostname] = make(map[string]bool)
			}
			trackedHostnames[hostname][ip] = true
		}
	}

	// Now re-process each tracked hostname with the newly loaded rules
	for hostname, ipSet := range trackedHostnames {
		// Check if this hostname now has rules
		hostnameAction := s.config.GetTrackedHostnameAction(hostname)
		if hostnameAction != "" && len(ipSet) > 0 && s.firewall != nil {
			s.logger.Info("Applying rules to tracked hostname",
				"hostname", hostname,
				"ip_count", len(ipSet),
				"action", hostnameAction)

			// Get ports for this hostname rule
			hostnamePorts := s.getHostnamePorts(hostname)

			// Add IPs to BPF maps
			for ipStr := range ipSet {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}

				// Check for conflicts
				finalAction, hasConflict, conflictingRule := s.config.CheckIPRuleConflict(
					ip, hostname, hostnameAction, hostnamePorts)

				if hasConflict {
					s.logger.Warn("Rule conflict detected during reprocess",
						"hostname", hostname,
						"ip", ipStr,
						"conflicting_rule", conflictingRule,
						"final_action", finalAction)
				}

				// Only add if different from default
				if finalAction != s.config.GetDefaultAction() {
					if err := s.addIPToBPFMaps(ip, hostname, finalAction, hostnamePorts); err != nil {
						s.logger.Error("Failed to add IP to BPF maps during reprocess",
							"hostname", hostname,
							"ip", ipStr,
							"error", err)
					}
				}
			}
		}
	}
}

// Start begins listening for DNS queries
func (s *Server) Start(ctx context.Context) error {
	// No TTL cleanup needed - IPs persist until updated by new DNS responses
	// DNS cache uses lazy expiration - no cleanup goroutine needed

	// Collect all addresses to listen on
	allAddrs := []string{s.listenAddr}
	allAddrs = append(allAddrs, s.additionalAddrs...)

	s.logger.Debug("DNS proxy server starting",
		"addresses", allAddrs,
		"upstream", s.upstream)

	// Create and start a server for each address (both UDP and TCP)
	for _, addr := range allAddrs {
		for _, proto := range []string{"udp4", "tcp4"} {
			server := &dns.Server{
				Addr:    addr,
				Net:     proto,
				Handler: dns.HandlerFunc(s.handleDNSQuery),
				NotifyStartedFunc: func() {
					s.logger.Debug("DNS server is now listening", "addr", addr, "proto", proto)
				},
			}
			s.servers = append(s.servers, server)

			// Start server in background
			go func(srv *dns.Server, address string) {
				if err := srv.ListenAndServe(); err != nil {
					s.logger.Error("DNS server error", "error", err, "addr", address)
				}
			}(server, addr)
		}
	}

	// Keep reference to primary server for compatibility
	if len(s.servers) > 0 {
		s.server = s.servers[0]
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown all servers
	var lastErr error
	for _, srv := range s.servers {
		if err := srv.Shutdown(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// handleDNSQuery processes DNS queries
func (s *Server) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	queryName := ""
	queryType := ""
	if len(r.Question) > 0 {
		queryName = r.Question[0].Name
		queryType = dns.TypeToString[r.Question[0].Qtype]
	}
	s.logger.Debug("DNS query received",
		"from", w.RemoteAddr().String(),
		"query", queryName,
		"type", queryType,
		"upstream", s.upstream)

	// DNS Query Filtering: Block queries for non-allowed domains (prevents DNS tunneling)
	if s.filterQueries && len(r.Question) > 0 {
		domain := strings.TrimSuffix(r.Question[0].Name, ".")
		// Also check stripped version for Kubernetes compatibility
		stripped := s.stripKubernetesSearchDomains(domain)

		if !s.isQueryAllowed(domain) && !s.isQueryAllowed(stripped) {
			// Check if we're in audit mode - log but don't block
			isAuditMode := s.auditLogger != nil && s.auditLogger.IsAuditMode()

			if isAuditMode {
				s.logger.Info("DNS query would be blocked (audit mode)",
					"domain", domain,
					"from", w.RemoteAddr().String())
			} else {
				s.logger.Info("DNS query blocked (domain not allowed)",
					"domain", domain,
					"from", w.RemoteAddr().String())
			}

			// Log to audit file if configured
			if s.auditLogger != nil {
				if err := s.auditLogger.LogDNSBlocked(domain); err != nil {
					s.logger.Error("Failed to write DNS audit log", "error", err)
				}
			}

			// In enforce mode, return REFUSED - don't forward to upstream
			// In audit mode, fall through to forward the query normally
			if !isAuditMode {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return
			}
		}
	}

	// Generate cache key from question
	cacheKey := s.generateCacheKey(r)

	// Check LRU cache (handles TTL expiry and capacity eviction internally)
	cached, found := s.dnsCache.Get(cacheKey)

	var resp *dns.Msg
	var rtt time.Duration

	if found {
		// Use cached response
		resp = cached.msg.Copy()
		resp.Id = r.Id // Update ID to match query
		s.logger.Debug("DNS cache hit",
			"query", queryName,
			"type", queryType)
	} else {
		// Forward query to upstream
		var err error
		resp, rtt, err = s.client.Exchange(r, s.upstream)
		if err != nil {
			s.logger.Error("Failed to forward DNS query",
				"error", err,
				"upstream", s.upstream,
				"query", r.Question)
			// Send SERVFAIL response
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		s.logger.Debug("Received DNS response from upstream",
			"rtt", rtt,
			"rcode", resp.Rcode)

		// Cache successful responses
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			// Find minimum TTL from answers
			minTTL := uint32(300) // Default 5 minutes
			for _, answer := range resp.Answer {
				if answer.Header().Ttl > 0 && answer.Header().Ttl < minTTL {
					minTTL = answer.Header().Ttl
				}
			}

			// Store in LRU cache with TTL based on minimum answer TTL
			s.dnsCache.Put(cacheKey, &dnsCacheEntry{
				msg: resp.Copy(),
			}, time.Duration(minTTL)*time.Second)

			s.logger.Debug("DNS response cached",
				"query", queryName,
				"type", queryType,
				"ttl", minTTL)
		}
	}

	// Process response before returning replying
	if len(r.Question) > 0 && resp.Rcode == dns.RcodeSuccess {
		fullHostname := strings.TrimSuffix(r.Question[0].Name, ".")

		// Extract IPs and TTLs from response
		ips, ttl := s.extractIPsFromResponse(resp)

		if len(ips) > 0 {
			s.logger.Debug("DNS resolution intercepted",
				"hostname", fullHostname,
				"ip_count", len(ips),
				"ttl", ttl)

			for _, ip := range ips {
				s.config.UpdateDNSMapping(fullHostname, ip.String())
			}

			// Check both full hostname and stripped version
			// This allows rules to match either "myservice" or "myservice.default.svc.cluster.local"
			hostnamesToCheck := []string{fullHostname}
			stripped := s.stripKubernetesSearchDomains(fullHostname)
			if stripped != fullHostname {
				hostnamesToCheck = append(hostnamesToCheck, stripped)
			}

			// Process firewall updates BEFORE returning DNS response
			for _, hostname := range hostnamesToCheck {
				// Always track the IPs we've seen for this hostname.
				// Accumulate IPs across DNS responses to handle round-robin DNS
				// correctly — old IPs remain valid even when new responses return
				// different IPs for the same hostname.
				s.hostnameIPsMutex.Lock()
				newIPSet := make(map[string]bool)

				// Preserve all existing IPs
				for ipStr := range s.hostnameIPs[hostname] {
					newIPSet[ipStr] = true
				}

				// Add new IPs from this response
				for _, ip := range ips {
					newIPSet[ip.String()] = true
				}

				s.hostnameIPs[hostname] = newIPSet
				s.hostnameIPsMutex.Unlock()

				// Check if we have rules for this hostname
				hostnameAction := s.config.GetTrackedHostnameAction(hostname)
				if hostnameAction != "" && s.firewall != nil {
					s.logger.Debug("Hostname tracked for BPF update",
						"hostname", hostname,
						"original", fullHostname,
						"action", hostnameAction,
						"ports", s.getHostnamePorts(hostname))

					// Get ports for this hostname rule
					hostnamePorts := s.getHostnamePorts(hostname)

					for _, ip := range ips {
						ipStr := ip.String()

						// Check for conflicts
						finalAction, hasConflict, conflictingRule := s.config.CheckIPRuleConflict(
							ip,
							hostname,
							hostnameAction,
							hostnamePorts)

						if hasConflict {
							s.logger.Warn("Rule conflict detected",
								"hostname", hostname,
								"ip", ipStr,
								"conflicting_rule", conflictingRule,
								"final_action", finalAction)
						}

						// Only add if different from default
						if finalAction != s.config.GetDefaultAction() {
							if err := s.addIPToBPFMaps(ip, hostname, finalAction, hostnamePorts); err != nil {
								s.logger.Error("Failed to add IP to BPF maps",
									"hostname", hostname,
									"ip", ipStr,
									"error", err)
							}
						}
					}

					break // Only process the first matching hostname
				} else if hostnameAction == "" {
					// No rules yet, but track that we've seen this hostname
					s.logger.Debug("DNS resolution tracked (no rules yet)",
						"hostname", hostname,
						"ip_count", len(ips))
				}
			}
		}
	}

	// Return response to client
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error("Failed to write DNS response", "error", err)
	}
}

// extractIPsFromResponse extracts IPv4 and IPv6 addresses and TTL from DNS response
func (s *Server) extractIPsFromResponse(msg *dns.Msg) ([]net.IP, uint32) {
	var ips []net.IP
	var ttl uint32 = 86400 // Default to 24 hours

	for _, answer := range msg.Answer {
		ttl = answer.Header().Ttl

		switch rr := answer.(type) {
		case *dns.A:
			ips = append(ips, rr.A)
		case *dns.AAAA:
			// NOTE: AAAA records are tracked for hostname-to-IP mapping but
			// IPv6 BPF map entries may not yet be applied on all code paths.
			ips = append(ips, rr.AAAA)
		}
	}

	return ips, ttl
}

// addIPToBPFMaps adds an IP to the BPF allow/deny maps
func (s *Server) addIPToBPFMaps(ip net.IP, hostname string, action config.Action, ports []config.Port) error {
	ipStr := ip.String()

	// Use firewall to add IP
	wasAdded, err := s.firewall.AddIP(ip, action, ports)
	if err != nil {
		return err
	}

	// Only log if the IP was actually added (not a duplicate)
	if wasAdded {
		s.logger.Info("DNS resolution: added to firewall",
			"hostname", hostname,
			"ip", ipStr,
			"action", action,
			"ports", ports)
	} else {
		s.logger.Debug("IP already in firewall with same config",
			"hostname", hostname,
			"ip", ipStr,
			"action", action)
	}

	return nil
}

// removeIPFromBPFMaps removes an IP from the BPF maps
func (s *Server) removeIPFromBPFMaps(ip net.IP) error {
	return s.firewall.RemoveIP(ip)
}

// getHostnamePorts retrieves port configuration for a hostname
func (s *Server) getHostnamePorts(hostname string) []config.Port {
	rules := s.config.GetResolvedRules()

	// First try exact match
	for _, rule := range rules {
		if rule.Type == config.RuleTypeHostname && rule.Pattern == nil && rule.Value == hostname {
			return rule.Ports
		}
	}

	// Check parent domain
	for _, rule := range rules {
		if rule.Type == config.RuleTypeHostname && rule.Pattern == nil && strings.HasSuffix(hostname, "."+rule.Value) {
			return rule.Ports
		}
	}

	// Check hostname patterns (glob matching)
	for _, rule := range rules {
		if rule.Type == config.RuleTypeHostname && rule.Pattern != nil && rule.MatchesHostname(hostname) {
			return rule.Ports
		}
	}

	return nil
}

// stripKubernetesSearchDomains removes common Kubernetes search domains
func (s *Server) stripKubernetesSearchDomains(hostname string) string {
	searchDomains := []string{
		".default.svc.cluster.local",
		".svc.cluster.local",
		".cluster.local",
	}

	for _, suffix := range searchDomains {
		if strings.HasSuffix(hostname, suffix) {
			return strings.TrimSuffix(hostname, suffix)
		}
	}

	return hostname
}

// generateCacheKey creates a unique key for caching DNS responses
func (s *Server) generateCacheKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}
