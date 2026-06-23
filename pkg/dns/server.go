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
	"strconv"
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

	// CNAME targets learned from rule-allowed responses (LRU with per-entry
	// TTL). Consulted only by the query filter: a separate query for a CNAME
	// target of an allowed host is permitted instead of REFUSED. Does not
	// affect IP enforcement, which already follows CNAME chains.
	cnameAllowed *lruCache[string, bool]

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
		hostnameIPs:  make(map[string]map[string]bool),
		dnsCache:     newLRUCache[string, *dnsCacheEntry](10000),
		cnameAllowed: newLRUCache[string, bool](10000),
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
//
// Precedence, in order:
//  1. Filtering disabled → allow.
//  2. Canonical PTR queries (Qtype=PTR and well-formed in-addr.arpa /
//     ip6.arpa name) → allow. The double gate (Qtype + shape) is what
//     prevents using PTR-shaped names as a tunneling channel via TXT/A/etc.
//  3. Explicit hostname rule. MatchHostnameRule handles search-domain
//     stripping internally and can return a mixed verdict (one form deny,
//     other form allow). At the DNS gate we allow the query if ANY allow
//     rule fires — the firewall layer enforces per-port deny separately.
//     A pure deny verdict (no allow) blocks the query. A deny rule for
//     "blocked" still blocks "blocked.compute.internal".
//  4. Derived CNAME-target allow: the name was learned as a CNAME target of
//     a rule-allowed response → allow. This lets CNAME-chasing clients query
//     the target directly (e.g. an Akamai edge name an allowed host CNAMEs
//     to) instead of being REFUSED. Checked AFTER the deny rule above, so an
//     explicit deny on the target still wins.
//  5. Search-domain bypass: full form ends in a configured suffix → allow.
//     This is the "let cloud-internal names resolve when no hostname rule
//     covers them" path; traffic is still governed by hostname/CIDR rules.
//  6. Default action.
func (s *Server) isQueryAllowed(domain string, qtype uint16) bool {
	if !s.filterQueries {
		return true
	}

	// Allow reverse DNS lookups, but only true PTR queries with the
	// canonical shape (exactly 4 numeric octets for IPv4, exactly 32 hex
	// nibbles for IPv6). The Qtype gate stops TXT/A/NS queries against
	// PTR-shaped names from slipping through this exception; the shape gate
	// stops shortened/padded labels from carrying tunneled data.
	if qtype == dns.TypePTR && isValidReverseDNS(domain) {
		return true
	}

	verdict := s.config.MatchHostnameRule(domain)
	if verdict.HasAllow() {
		return true
	}
	if verdict.HasDeny() {
		return false
	}

	// Derived CNAME-target allow. Populated in handleDNSQuery when a
	// rule-allowed response carries CNAME records (see s.cnameAllowed). The
	// nil guard keeps Server literals constructed without NewServer (some
	// tests) working. Checked after the deny rule above so a deny still wins.
	if s.cnameAllowed != nil {
		if _, ok := s.cnameAllowed.Get(strings.ToLower(domain)); ok {
			return true
		}
	}

	// No explicit rule — try the search-domain bypass. HasSearchDomainSuffix
	// is the non-allocating predicate (case-insensitive, no per-query slice
	// copy of the configured suffixes).
	if s.config.HasSearchDomainSuffix(domain) {
		return true
	}

	return s.config.GetDefaultAction() == config.ActionAllow
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

	// Track only the full hostname per IP. MatchHostnameRule (called per
	// tracked hostname below) evaluates both the full and stripped forms
	// internally with deny-anywhere precedence — adding the stripped form
	// here as a separate key would double-iterate the same IP and let
	// non-deterministic map-iteration order clobber the correct BPF action.
	ipToHostname := s.config.GetIPToHostnameMap()
	for ip, fullHostname := range ipToHostname {
		if _, exists := trackedHostnames[fullHostname]; !exists {
			trackedHostnames[fullHostname] = make(map[string]bool)
		}
		trackedHostnames[fullHostname][ip] = true
	}

	// Now re-process each tracked hostname with the newly loaded rules
	for hostname, ipSet := range trackedHostnames {
		verdict := s.config.MatchHostnameRule(hostname)
		if !verdict.Matched() || len(ipSet) == 0 || s.firewall == nil {
			continue
		}
		s.logger.Info("Applying rules to tracked hostname",
			"hostname", hostname,
			"ip_count", len(ipSet),
			"deny_rule", verdict.DenyRule,
			"allow_rule", verdict.AllowRule)

		for ipStr := range ipSet {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if verdict.HasDeny() {
				s.applyVerdictSide(ip, hostname, config.ActionDeny, verdict.DenyPorts, true)
			}
			if verdict.HasAllow() {
				s.applyVerdictSide(ip, hostname, config.ActionAllow, verdict.AllowPorts, true)
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

	// DNS Query Filtering: Block queries for non-allowed domains (prevents
	// DNS tunneling). isQueryAllowed handles both the full and the
	// search-domain-stripped form internally with the right precedence.
	if s.filterQueries && len(r.Question) > 0 {
		domain := strings.TrimSuffix(r.Question[0].Name, ".")
		if !s.isQueryAllowed(domain, r.Question[0].Qtype) {
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

		// Lowercase once for all canonical-form operations below; keep
		// fullHostname for log attribution so wire-case is preserved in
		// audit/debug output.
		canonicalHostname := strings.ToLower(fullHostname)

		// One MatchHostnameRule call per resolution — it internally evaluates
		// both the full and search-domain-stripped forms and folds the result
		// into a single HostnameVerdict. Calling it once per form here would be
		// redundant and unsafe: the resulting BPF map updates could be applied
		// in non-deterministic map-iteration order, letting the wrong form's
		// action win the last-write race.
		verdict := s.config.MatchHostnameRule(canonicalHostname)

		// Learn CNAME targets from rule-allowed responses so CNAME-chasing
		// clients can query them directly under query filtering instead of
		// being REFUSED (consulted by isQueryAllowed via s.cnameAllowed). Done
		// outside the len(ips)>0 guard below so CNAME-only responses (no
		// A/AAAA in the same message) still register their targets. Only
		// rule-allowed responses qualify: a single forwarded response already
		// carries every hop of the chain, so we never learn transitively from
		// derived-allowed queries — that keeps the surface bounded.
		//
		// cnameChainTargets follows the chain from the query name only, so
		// unrelated CNAME records in the same response (a misbehaving or
		// spoofed authoritative server for an allowed domain) are ignored
		// instead of registering arbitrary names. Each target is learned for
		// its own CNAME TTL (not the response-wide min, which would shorten it
		// to the final address record's TTL), floored by derivedCNAMETTL. A
		// target whose entry expires before its origin's dnsCache entry just
		// gets re-REFUSED until the next origin query re-learns it —
		// self-healing and TTL-bounded.
		if s.filterQueries && verdict.HasAllow() && s.cnameAllowed != nil {
			for _, link := range cnameChainTargets(canonicalHostname, resp.Answer) {
				ttl := time.Duration(derivedCNAMETTL(link.ttl)) * time.Second
				s.cnameAllowed.Put(link.target, true, ttl)
			}
		}

		if len(ips) > 0 {
			s.logger.Debug("DNS resolution intercepted",
				"hostname", fullHostname,
				"ip_count", len(ips),
				"ttl", ttl)

			// User-configured search-domain suffixes only — Kubernetes
			// suffixes are strip-only, not bypass, and live separately in
			// the config manager (see kubernetesSearchDomains).
			bypassOnly := s.config.HasSearchDomainSuffix(canonicalHostname)

			// bypassOnly && no rule match → skip ALL per-host tracking. The
			// bypass is by design "no per-host bookkeeping"; tracking
			// ephemeral cloud-internal names (e.g. ip-X-X-X-X.compute.internal
			// per EC2 instance) would grow our per-host maps without bound.
			if bypassOnly && !verdict.Matched() {
				s.logger.Debug("Skipping per-host tracking for bypass-only hostname",
					"hostname", fullHostname,
					"ip_count", len(ips))
			} else {
				for _, ip := range ips {
					s.config.UpdateDNSMapping(canonicalHostname, ip.String())
				}

				// Track the IPs we've seen for this hostname. Accumulate
				// across DNS responses to handle round-robin DNS — old IPs
				// remain valid even when new responses return different IPs.
				s.hostnameIPsMutex.Lock()
				newIPSet := make(map[string]bool)
				for ipStr := range s.hostnameIPs[canonicalHostname] {
					newIPSet[ipStr] = true
				}
				for _, ip := range ips {
					newIPSet[ip.String()] = true
				}
				s.hostnameIPs[canonicalHostname] = newIPSet
				s.hostnameIPsMutex.Unlock()

				switch {
				case verdict.Matched() && s.firewall != nil:
					s.logger.Debug("Hostname tracked for BPF update",
						"hostname", fullHostname,
						"deny_rule", verdict.DenyRule,
						"deny_ports", verdict.DenyPorts,
						"allow_rule", verdict.AllowRule,
						"allow_ports", verdict.AllowPorts)

					for _, ip := range ips {
						if verdict.HasDeny() {
							s.applyVerdictSide(ip, fullHostname, config.ActionDeny, verdict.DenyPorts, false)
						}
						if verdict.HasAllow() {
							s.applyVerdictSide(ip, fullHostname, config.ActionAllow, verdict.AllowPorts, false)
						}
					}
				case !verdict.Matched():
					// No rules yet, but track that we've seen this hostname
					// so ApplyRulesToTrackedHostnames can backfill if a rule
					// is added later.
					s.logger.Debug("DNS resolution tracked (no rules yet)",
						"hostname", fullHostname,
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

// cnameLink is one hop of a CNAME chain: the target name (lowercased, no
// trailing dot) and the TTL of the CNAME record that points to it.
type cnameLink struct {
	target string
	ttl    uint32
}

// cnameChainTargets walks the CNAME chain in answers starting from qname
// (which must already be lowercased and trailing-dot-trimmed) and returns the
// ordered targets actually reachable from qname. CNAME records whose owner is
// not on the chain — unrelated or attacker-injected records in an otherwise
// rule-allowed response — are ignored, so they can't register arbitrary names
// as queryable. A visited set bounds malicious loops (A→B→A). Each target
// carries its own CNAME record's TTL so the caller can expire it on the hop's
// lifetime rather than the response-wide minimum.
func cnameChainTargets(qname string, answers []dns.RR) []cnameLink {
	// Index CNAMEs by lowercased owner; first record for an owner wins so a
	// duplicate owner can't redirect the walk.
	byOwner := make(map[string]*dns.CNAME, len(answers))
	for _, ans := range answers {
		cn, ok := ans.(*dns.CNAME)
		if !ok {
			continue
		}
		owner := strings.ToLower(strings.TrimSuffix(cn.Header().Name, "."))
		if _, exists := byOwner[owner]; !exists {
			byOwner[owner] = cn
		}
	}

	var chain []cnameLink
	visited := make(map[string]bool)
	for cur := qname; ; {
		cn, ok := byOwner[cur]
		if !ok {
			break
		}
		target := strings.ToLower(strings.TrimSuffix(cn.Target, "."))
		if target == "" || visited[target] {
			break
		}
		visited[target] = true
		chain = append(chain, cnameLink{target: target, ttl: cn.Header().Ttl})
		cur = target
	}
	return chain
}

// derivedCNAMETTL floors a CNAME record's TTL for the derived CNAME-allow
// cache. A record's TTL can be 0 (some CDNs/load-balancers return TTL 0 to
// defeat caching), and lruCache treats a 0 duration as "never expires", so a
// literal 0 would pin the derived allow indefinitely — the opposite of the
// TTL-bounded guarantee. Floor it to the same default the dnsCache path uses
// (300s / 5 min).
func derivedCNAMETTL(ttl uint32) uint32 {
	if ttl == 0 {
		return 300
	}
	return ttl
}

// extractIPsFromResponse extracts IPv4 and IPv6 addresses from msg.Answer
// and returns the minimum TTL across all answers (or 86400 when there are
// no answers). The minimum is the safe choice: a cache or downstream
// consumer should respect the shortest-lived record in the response so
// stale data isn't kept past any single record's expiry.
//
// TTL=0 in an answer is treated as a legitimate value here (returns 0).
// The dnsCache Put path applies its own "treat 0 as a default-floor"
// policy separately (see server.go around line 380); this function is
// the literal-TTL view of the response.
func (s *Server) extractIPsFromResponse(msg *dns.Msg) ([]net.IP, uint32) {
	var ips []net.IP
	var minTTL uint32 = 86400 // Default to 24 hours when there are no answers.
	seen := false

	for _, answer := range msg.Answer {
		ttl := answer.Header().Ttl
		if !seen || ttl < minTTL {
			minTTL = ttl
			seen = true
		}

		switch rr := answer.(type) {
		case *dns.A:
			ips = append(ips, rr.A)
		case *dns.AAAA:
			// NOTE: AAAA records are tracked for hostname-to-IP mapping but
			// IPv6 BPF map entries may not yet be applied on all code paths.
			ips = append(ips, rr.AAAA)
		}
	}

	return ips, minTTL
}

// applyVerdictSide writes one side (deny or allow) of a HostnameVerdict to
// the BPF maps for a single IP. It runs the CIDR-rule conflict check, logs
// any conflict, and short-circuits when the resulting action equals the
// default. `isReprocess` annotates log wording so the rule-reprocess pass
// is distinguishable from resolution-time writes in audit logs.
func (s *Server) applyVerdictSide(ip net.IP, hostname string, action config.Action, ports []config.Port, isReprocess bool) {
	ipStr := ip.String()
	finalAction, hasConflict, conflictingRule := s.config.CheckIPRuleConflict(ip, hostname, action, ports)
	if hasConflict {
		s.logger.Warn(maybeReprocessMsg("Rule conflict detected", isReprocess),
			"hostname", hostname,
			"ip", ipStr,
			"conflicting_rule", conflictingRule,
			"final_action", finalAction)
	}
	if finalAction == s.config.GetDefaultAction() {
		return
	}
	if err := s.addIPToBPFMaps(ip, hostname, finalAction, ports); err != nil {
		s.logger.Error(maybeReprocessMsg("Failed to add IP to BPF maps", isReprocess),
			"hostname", hostname,
			"ip", ipStr,
			"error", err)
	}
}

func maybeReprocessMsg(base string, isReprocess bool) string {
	if isReprocess {
		return base + " during reprocess"
	}
	return base
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

// isValidReverseDNS reports whether domain is a well-formed canonical PTR
// name — exactly 4 unpadded decimal-octet labels under ".in-addr.arpa" or
// exactly 32 single-hex-nibble labels under ".ip6.arpa". Anything looser
// (partial PTR for delegation lookups, zero-padded octets, etc.) is
// rejected so this exception leaves no room for tunneled data in leading
// labels. Case-insensitive (DNS names are).
func isValidReverseDNS(domain string) bool {
	lower := strings.ToLower(domain)
	switch {
	case strings.HasSuffix(lower, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(lower, ".in-addr.arpa"), ".")
		if len(labels) != 4 {
			return false
		}
		for _, l := range labels {
			// Each label is a decimal octet 0–255. Reject sign prefixes
			// (strconv.Atoi would accept "+1" / "-0") and leading zeros
			// (canonical PTR is unpadded; "001" would otherwise pass).
			if len(l) < 1 || len(l) > 3 {
				return false
			}
			if len(l) > 1 && l[0] == '0' {
				return false
			}
			for i := 0; i < len(l); i++ {
				if l[i] < '0' || l[i] > '9' {
					return false
				}
			}
			n, err := strconv.Atoi(l)
			if err != nil || n > 255 {
				return false
			}
		}
		return true
	case strings.HasSuffix(lower, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(lower, ".ip6.arpa"), ".")
		if len(labels) != 32 {
			return false
		}
		for _, l := range labels {
			// Each label is exactly one hex nibble.
			if len(l) != 1 {
				return false
			}
			c := l[0]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	return false
}

// stripSearchDomains delegates to the config manager so all
// search-domain-aware code paths (rule lookup, tracked-hostname lookup,
// hostnameIPs tracking) consult the same canonical suffix list.
func (s *Server) stripSearchDomains(hostname string) string {
	return s.config.StripSearchDomains(hostname)
}

// generateCacheKey creates a unique key for caching DNS responses
func (s *Server) generateCacheKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}
