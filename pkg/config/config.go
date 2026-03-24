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

package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
)

// Action represents a firewall action (allow or deny).
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// AutoAddedType indicates why a rule was auto-added by CargoWall infrastructure.
type AutoAddedType string

const (
	AutoAddedTypeNone                AutoAddedType = ""
	AutoAddedTypeDNS                 AutoAddedType = "dns"
	AutoAddedTypeAzureInfrastructure AutoAddedType = "azure_infrastructure"
	AutoAddedTypeGitHubService       AutoAddedType = "github_service"
	AutoAddedTypeCodeCargoService    AutoAddedType = "codecargo_service"
)

// RuleType represents the type of a firewall rule.
type RuleType string

const (
	RuleTypeHostname RuleType = "hostname"
	RuleTypeCIDR     RuleType = "cidr"
)

type ProtocolType string

const (
	ProtocolAll ProtocolType = "all"
	ProtocolTCP ProtocolType = "tcp"
	ProtocolUDP ProtocolType = "udp"
)

// Common port definitions for infrastructure auto-allow rules.
var (
	PortHTTPS      = Port{Port: 443, Protocol: ProtocolTCP}
	PortHTTP       = Port{Port: 80, Protocol: ProtocolTCP}
	PortDNS        = Port{Port: 53, Protocol: ProtocolUDP}
	PortWireServer = Port{Port: 32526, Protocol: ProtocolTCP}
)

// FirewallConfig represents the configuration for the L4 firewall
type FirewallConfig struct {
	Rules []Rule `json:"rules"`
	// DefaultAction is the default action when no Rule matches (allow/deny)
	DefaultAction Action                `json:"defaultAction"`
	SudoLockdown  *SudoLockdownSettings `json:"sudoLockdown,omitempty"`
}

// Rule represents a firewall Rule
type Rule struct {
	// Type can be "hostname" or "cidr"
	Type RuleType `json:"type"`
	// Value is the hostname or CIDR block
	Value string `json:"value"`
	// Ports is optional list of Port (empty means all Ports on TCP and UDP)
	Ports []Port `json:"ports,omitempty"`
	// Action is "allow" or "deny"
	Action Action `json:"action"`
	// AutoAddedType indicates why this rule was auto-added (empty for user-configured rules)
	AutoAddedType AutoAddedType `json:"autoAddedType,omitempty"`
}

// Port represents a firewall Port entry
type Port struct {
	Port     uint16       `json:"port"`
	Protocol ProtocolType `json:"protocol"`
}

// SudoLockdownSettings holds policy-sourced sudo lockdown configuration.
type SudoLockdownSettings struct {
	Enable        bool     `json:"enable"`
	AllowCommands []string `json:"allowCommands,omitempty"`
}

// ResolvedRule represents a Rule with resolved IP addresses or CIDR blocks
type ResolvedRule struct {
	Type          RuleType   // "hostname" or "cidr"
	Value         string     // Original value (hostname or CIDR string)
	IPs           []net.IP   // For hostnames: resolved IPs. For CIDR: empty
	IPNet         *net.IPNet // For CIDR blocks only
	Ports         []Port
	Action        Action
	AutoAddedType AutoAddedType // Why this rule was auto-added (empty for user-configured rules)
}

// Manager manages the firewall configuration and hostname resolution
type Manager struct {
	mu               sync.RWMutex
	config           *FirewallConfig
	resolvedRules    []ResolvedRule
	hostnameCache    map[string][]net.IP
	ipToHostname     map[string]string    // Reverse lookup: IP -> hostname
	ipLastSeen       map[string]time.Time // Track when each IP was last seen
	trackedHostnames map[string]Action    // Track hostnames we have rules for (hostname -> action)
	maxCacheSize     int                  // Maximum number of IPs to cache
	dnsCacheTTL      time.Duration        // How long to keep DNS entries
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *Manager {
	return &Manager{
		hostnameCache:    make(map[string][]net.IP),
		ipToHostname:     make(map[string]string),
		ipLastSeen:       make(map[string]time.Time),
		trackedHostnames: make(map[string]Action),
		maxCacheSize:     10000,          // Default max cache size
		dnsCacheTTL:      24 * time.Hour, // Default DNS cache TTL
	}
}

// LoadConfigFromRules loads configuration from rules (for testing)
func (cm *Manager) LoadConfigFromRules(rules []Rule, defaultAction Action) error {
	cm.mu.Lock()
	cm.config = &FirewallConfig{
		Rules:         rules,
		DefaultAction: defaultAction,
	}
	cm.mu.Unlock()

	// Resolve all rules
	return cm.resolveRules()
}

// LoadConfigFromCargoWall loads configuration from a protobuf CargoWall message
func (cm *Manager) LoadConfigFromCargoWall(cargoWall *cargowallv1pb.CargoWallPolicy) error {
	// Convert protobuf CargoWall to internal config format
	var rules []Rule
	for _, pbRule := range cargoWall.Rules {
		rule := Rule{
			Value:  pbRule.Value,
			Action: convertAction(pbRule.Action),
		}

		// Convert rule type
		switch pbRule.Type {
		case datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_CIDR:
			rule.Type = RuleTypeCIDR
		case datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME:
			rule.Type = RuleTypeHostname
		default:
			return fmt.Errorf("unknown rule type: %v", pbRule.Type)
		}

		// Convert ports
		for _, pbPort := range pbRule.Ports {
			if pbPort.GetPort() > 65535 {
				return fmt.Errorf("invalid port number: %d", pbPort.GetPort())
			}
			proto, err := convertProtocol(pbPort.GetProtocol())
			if err != nil {
				return fmt.Errorf("port %d: %w", pbPort.GetPort(), err)
			}
			rule.Ports = append(rule.Ports, Port{
				Port:     uint16(pbPort.GetPort()),
				Protocol: proto,
			})
		}

		rules = append(rules, rule)
	}

	defaultAction := convertAction(cargoWall.DefaultAction)

	// Extract sudo lockdown settings
	var sudoLockdown *SudoLockdownSettings
	if sl := cargoWall.GetSudoLockdown(); sl != nil {
		sudoLockdown = &SudoLockdownSettings{
			Enable:        sl.Enable,
			AllowCommands: sl.AllowCommands,
		}
	}

	cm.mu.Lock()
	cm.config = &FirewallConfig{
		Rules:         rules,
		DefaultAction: defaultAction,
		SudoLockdown:  sudoLockdown,
	}
	cm.mu.Unlock()

	slog.Info("Loaded CargoWall config from state machine",
		"rules", len(rules),
		"defaultAction", defaultAction)

	// Resolve all rules
	return cm.resolveRules()
}

// convertProtocol converts protobuf Protocol enum to ProtocolType
func convertProtocol(proto datapb.CargoWallProtocol) (ProtocolType, error) {
	switch proto {
	case datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_ALL:
		return ProtocolAll, nil
	case datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_TCP:
		return ProtocolTCP, nil
	case datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_UDP:
		return ProtocolUDP, nil
	default:
		return "", fmt.Errorf("unknown protocol: %v", proto)
	}
}

// protocolsOverlap returns true if two protocol types can match the same traffic.
// ProtocolAll overlaps with everything; TCP and UDP only overlap with themselves.
func protocolsOverlap(a, b ProtocolType) bool {
	return a == ProtocolAll || b == ProtocolAll || a == b
}

// convertAction converts protobuf Action enum to Action
func convertAction(action datapb.CargoWallActionType) Action {
	switch action {
	case datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW:
		return ActionAllow
	case datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY:
		return ActionDeny
	default:
		return ActionDeny // Default to deny for safety
	}
}

// LoadConfig loads configuration from a file
func (cm *Manager) LoadConfig(path string) error {
	slog.Info("LoadConfig called", "path", path)

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var config FirewallConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	slog.Info("Config loaded successfully",
		"rules", len(config.Rules),
		"defaultAction", config.DefaultAction)

	cm.mu.Lock()
	cm.config = &config
	cm.mu.Unlock()

	// Resolve all rules
	return cm.resolveRules()
}

// LoadFromEnv loads configuration from environment variables.
// Environment variables:
//   - CARGOWALL_DEFAULT_ACTION: "allow" or "deny" (default: "deny")
//   - CARGOWALL_ALLOWED_HOSTS: comma-separated list of allowed hostnames (supports wildcards)
//   - CARGOWALL_ALLOWED_CIDRS: comma-separated list of allowed CIDR blocks
//   - CARGOWALL_BLOCKED_HOSTS: comma-separated list of blocked hostnames
//   - CARGOWALL_BLOCKED_CIDRS: comma-separated list of blocked CIDR blocks
func (cm *Manager) LoadFromEnv() error {
	// Check if any config environment variables are set
	defaultAction := os.Getenv("CARGOWALL_DEFAULT_ACTION")
	allowedHosts := os.Getenv("CARGOWALL_ALLOWED_HOSTS")
	allowedCIDRs := os.Getenv("CARGOWALL_ALLOWED_CIDRS")
	blockedHosts := os.Getenv("CARGOWALL_BLOCKED_HOSTS")
	blockedCIDRs := os.Getenv("CARGOWALL_BLOCKED_CIDRS")

	// If no env vars are set, return an error to fall back to file config
	if defaultAction == "" && allowedHosts == "" && allowedCIDRs == "" && blockedHosts == "" && blockedCIDRs == "" {
		return fmt.Errorf("no environment configuration found")
	}

	// Set default action
	parsedDefaultAction := Action(defaultAction)
	if parsedDefaultAction == "" {
		parsedDefaultAction = ActionDeny
	} else if parsedDefaultAction != ActionAllow && parsedDefaultAction != ActionDeny {
		return fmt.Errorf("invalid CARGOWALL_DEFAULT_ACTION: %q (must be 'allow' or 'deny')", defaultAction)
	}

	var rules []Rule

	// Parse allowed hosts
	if allowedHosts != "" {
		for _, entry := range splitAndTrim(allowedHosts) {
			if entry != "" {
				host, ports := parseHostWithPorts(entry)
				host = normalizeHostname(host)
				rules = append(rules, Rule{
					Type:   RuleTypeHostname,
					Value:  host,
					Ports:  ports,
					Action: ActionAllow,
				})
			}
		}
	}

	// Parse allowed CIDRs
	if allowedCIDRs != "" {
		for _, entry := range splitAndTrim(allowedCIDRs) {
			if entry != "" {
				cidr, ports := parseHostWithPorts(entry)
				rules = append(rules, Rule{
					Type:   RuleTypeCIDR,
					Value:  cidr,
					Ports:  ports,
					Action: ActionAllow,
				})
			}
		}
	}

	// Parse blocked hosts
	if blockedHosts != "" {
		for _, entry := range splitAndTrim(blockedHosts) {
			if entry != "" {
				host, ports := parseHostWithPorts(entry)
				host = normalizeHostname(host)
				rules = append(rules, Rule{
					Type:   RuleTypeHostname,
					Value:  host,
					Ports:  ports,
					Action: ActionDeny,
				})
			}
		}
	}

	// Parse blocked CIDRs
	if blockedCIDRs != "" {
		for _, entry := range splitAndTrim(blockedCIDRs) {
			if entry != "" {
				cidr, ports := parseHostWithPorts(entry)
				rules = append(rules, Rule{
					Type:   RuleTypeCIDR,
					Value:  cidr,
					Ports:  ports,
					Action: ActionDeny,
				})
			}
		}
	}

	slog.Info("Loaded config from environment variables",
		"rules", len(rules),
		"defaultAction", parsedDefaultAction)

	cm.mu.Lock()
	cm.config = &FirewallConfig{
		Rules:         rules,
		DefaultAction: parsedDefaultAction,
	}
	cm.mu.Unlock()

	// Resolve all rules
	return cm.resolveRules()
}

// splitAndTrim splits a string by comma and trims whitespace from each element
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// parseHostWithPorts parses a host or CIDR entry with optional port specifications.
// Format: "host:port1;port2" or "cidr:port1;port2"
// Examples: "github.com:443;80" -> ("github.com", [443, 80])
//
//	"10.0.0.0/8:443" -> ("10.0.0.0/8", [443])
//	"github.com" -> ("github.com", nil)
func parseHostWithPorts(entry string) (string, []Port) {
	idx := strings.LastIndex(entry, ":")
	if idx == -1 {
		return entry, nil
	}

	host := entry[:idx]
	portsPart := entry[idx+1:]

	// Parse each port separated by semicolons
	var ports []Port
	for _, p := range strings.Split(portsPart, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			// Not a valid port — treat the whole entry as a host with no ports
			return entry, nil
		}
		ports = append(ports, Port{Port: uint16(port), Protocol: ProtocolAll})
	}

	if len(ports) == 0 {
		return entry, nil
	}

	return host, ports
}

// normalizeHostname strips a leading "*." wildcard prefix from a hostname.
// Since parent domain matching already handles subdomains, *.github.com is
// equivalent to github.com.
func normalizeHostname(host string) string {
	return strings.TrimPrefix(host, "*.")
}

// GetResolvedRules returns the current resolved rules
func (cm *Manager) GetResolvedRules() []ResolvedRule {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return a copy to avoid race conditions
	rules := make([]ResolvedRule, len(cm.resolvedRules))
	copy(rules, cm.resolvedRules)
	return rules
}

// GetDefaultAction returns the default action
func (cm *Manager) GetDefaultAction() Action {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil || cm.config.DefaultAction == "" {
		return ActionDeny // Default to deny if not specified
	}
	return cm.config.DefaultAction
}

// LookupHostnameByIP finds the hostname associated with an IP address
func (cm *Manager) LookupHostnameByIP(ip string) string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Debug: show what we're looking for
	slog.Debug("Looking up hostname for IP", "ip", ip)

	// First check reverse lookup map
	if hostname, ok := cm.ipToHostname[ip]; ok {
		slog.Debug("Found hostname in reverse map", "hostname", hostname, "ip", ip)
		return hostname
	}

	// Check each hostname in our cache
	for hostname, ips := range cm.hostnameCache {
		for _, cachedIP := range ips {
			if cachedIP.String() == ip {
				slog.Debug("Found hostname", "hostname", hostname, "ip", ip)
				return hostname
			}
		}
	}

	slog.Debug("No hostname found for IP", "ip", ip)
	return ""
}

// UpdateDNSMapping adds a DNS mapping from an observed DNS response
func (cm *Manager) UpdateDNSMapping(hostname string, ip string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if ip != "" {
		cm.ipToHostname[ip] = hostname
		cm.ipLastSeen[ip] = time.Now()
	}

	// Also update the forward cache if this hostname is being tracked
	if ips, ok := cm.hostnameCache[hostname]; ok {
		// Check if IP is already in the list
		found := false
		for _, existingIP := range ips {
			if existingIP.String() == ip {
				found = true
				break
			}
		}

		// Add if not found
		if !found {
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				cm.hostnameCache[hostname] = append(ips, parsedIP)
				slog.Debug("Added IP to hostname cache", "ip", ip, "hostname", hostname)
			}
		}
	}

	// Clean up old entries if cache is too large
	if len(cm.ipToHostname) > cm.maxCacheSize {
		cm.cleanupOldEntries()
	}
}

// cleanupOldEntries removes old DNS cache entries (must be called with lock held)
func (cm *Manager) cleanupOldEntries() {
	now := time.Now()
	toDelete := []string{}

	// Find entries older than TTL
	for ip, lastSeen := range cm.ipLastSeen {
		if now.Sub(lastSeen) > cm.dnsCacheTTL {
			toDelete = append(toDelete, ip)
		}
	}

	// Delete old entries
	for _, ip := range toDelete {
		delete(cm.ipToHostname, ip)
		delete(cm.ipLastSeen, ip)
	}

	if len(toDelete) > 0 {
		slog.Info("Cleaned up old DNS cache entries", "count", len(toDelete))
	}
}

// GetTrackedHostnameAction returns the action (allow/deny) for a tracked hostname.
// Returns empty string if hostname is not tracked.
func (cm *Manager) GetTrackedHostnameAction(hostname string) Action {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Check exact match
	if action, ok := cm.trackedHostnames[hostname]; ok {
		slog.Debug("Found exact match", "hostname", hostname, "action", action)
		return action
	}

	// Check if it's a subdomain of a tracked hostname
	// For example, if "google.com" is tracked, then "www.google.com" should inherit the same action
	for trackedHost, action := range cm.trackedHostnames {
		if strings.HasSuffix(hostname, "."+trackedHost) {
			slog.Debug("Found parent domain match",
				"hostname", hostname,
				"parent", trackedHost,
				"action", action)
			return action
		}
	}

	slog.Debug("No tracked hostname found", "hostname", hostname)
	return ""
}

// CheckIPRuleConflict checks if an IP has conflicting rules and returns the most restrictive action
// Returns: (action Action, hasConflict bool, conflictingRule string)
func (cm *Manager) CheckIPRuleConflict(ip net.IP, hostname string, hostnameAction Action, hostnamePorts []Port) (Action, bool, string) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil {
		return hostnameAction, false, ""
	}

	// Track the most specific matching CIDR Rule
	var mostSpecificRule *Rule
	var mostSpecificBits int = -1

	// Check all CIDR rules
	for i := range cm.config.Rules {
		if cm.config.Rules[i].Type != RuleTypeCIDR {
			continue
		}

		// Parse CIDR
		_, ipnet, err := net.ParseCIDR(cm.config.Rules[i].Value)
		if err != nil {
			// Try as single IP
			if ruleIP := net.ParseIP(cm.config.Rules[i].Value); ruleIP != nil && ruleIP.Equal(ip) {
				// Exact match is most specific (32 bits)
				mostSpecificRule = &cm.config.Rules[i]
				mostSpecificBits = 32
			}
			continue
		}

		// Check if IP is in CIDR range
		if ipnet.Contains(ip) {
			ones, _ := ipnet.Mask.Size()
			if ones > mostSpecificBits {
				mostSpecificRule = &cm.config.Rules[i]
				mostSpecificBits = ones
			}
		}
	}

	// If we found a CIDR Rule that matches
	if mostSpecificRule != nil {
		// If both rules have specific ports, only conflict if ports overlap
		if len(mostSpecificRule.Ports) > 0 && len(hostnamePorts) > 0 {
			// Check if any ports overlap (same value + overlapping protocol)
			hasOverlap := false
			for _, hp := range hostnamePorts {
				for _, cp := range mostSpecificRule.Ports {
					if hp.Port == cp.Port && protocolsOverlap(hp.Protocol, cp.Protocol) {
						hasOverlap = true
						break
					}
				}
				if hasOverlap {
					break
				}
			}

			// No port overlap = no conflict
			if !hasOverlap {
				slog.Debug("No port overlap between hostname and CIDR Rule",
					"hostname", hostname,
					"hostname_ports", hostnamePorts,
					"cidr", mostSpecificRule.Value,
					"cidr_ports", mostSpecificRule.Ports)
				return hostnameAction, false, ""
			}
		}

		// Check if actions conflict (only relevant if ports overlap or no ports specified)
		if mostSpecificRule.Action != hostnameAction {
			// Conflict detected - deny wins
			if mostSpecificRule.Action == ActionDeny || hostnameAction == ActionDeny {
				return ActionDeny, true, mostSpecificRule.Value
			}
		}
	}

	return hostnameAction, false, ""
}

// FindTrackedHostname checks if name exactly matches a tracked hostname or is
// a subdomain of one (e.g. "lb-140-82-113-22-iad.github.com" → "github.com").
// Returns the tracked hostname if found, otherwise "".
func (cm *Manager) FindTrackedHostname(name string) string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Exact match
	if _, ok := cm.trackedHostnames[name]; ok {
		return name
	}

	// Subdomain match
	for trackedHost := range cm.trackedHostnames {
		if strings.HasSuffix(name, "."+trackedHost) {
			return trackedHost
		}
	}
	return ""
}

// GetTrackedHostnames returns a copy of the tracked hostnames map (hostname -> action).
// This is used to proactively resolve hostnames so the reverse lookup cache is populated.
func (cm *Manager) GetTrackedHostnames() map[string]Action {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make(map[string]Action, len(cm.trackedHostnames))
	for hostname, action := range cm.trackedHostnames {
		result[hostname] = action
	}
	return result
}

// ForwardMatchIP checks if any tracked hostname's cached IPs match the given IP.
// Uses the hostname cache instead of live DNS resolution to avoid blocking.
func (cm *Manager) ForwardMatchIP(ip string) string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for hostname := range cm.trackedHostnames {
		for _, cachedIP := range cm.hostnameCache[hostname] {
			if cachedIP.String() == ip {
				return hostname
			}
		}
	}
	return ""
}

// EnsureDNSAllowed adds CIDR allow rules on port 53 for the given IPs
// so DNS infrastructure traffic is never blocked by the firewall.
func (cm *Manager) EnsureDNSAllowed(ips []string) {
	cm.ensureAllowed(ips, []Port{PortDNS}, AutoAddedTypeDNS)
}

// EnsureInfraAllowed adds CIDR allow rules for the given IPs on the specified
// ports, so infrastructure traffic (e.g. Azure wireserver/IMDS) is allowed
// only on the ports it actually needs.
func (cm *Manager) EnsureInfraAllowed(ips []string, ports []Port) {
	cm.ensureAllowed(ips, ports, AutoAddedTypeAzureInfrastructure)
}

// ensureAllowed adds CIDR allow rules for the given IPs with the specified ports.
// If ports is nil, traffic on all ports is allowed.
func (cm *Manager) ensureAllowed(ips []string, ports []Port, autoAddedType AutoAddedType) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return
	}

	for _, ip := range ips {
		if ip == "" {
			continue
		}

		// Check if a rule already covers this IP
		if len(ports) == 0 {
			if cm.hasCIDRRuleAllPorts(ip) {
				slog.Debug("Allow rule already exists (all ports)", "ip", ip)
				continue
			}
		} else {
			covered := true
			for _, p := range ports {
				if !cm.hasCIDRRule(ip, p) {
					covered = false
					break
				}
			}
			if covered {
				slog.Debug("Allow rule already exists", "ip", ip, "ports", ports)
				continue
			}
		}

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}
		ip4 := parsedIP.To4()
		if ip4 == nil {
			continue // skip IPv6
		}

		cidr := ip + "/32"
		cm.config.Rules = append(cm.config.Rules, Rule{
			Type:          RuleTypeCIDR,
			Value:         cidr,
			Ports:         ports,
			Action:        ActionAllow,
			AutoAddedType: autoAddedType,
		})
		cm.resolvedRules = append(cm.resolvedRules, ResolvedRule{
			Type:          RuleTypeCIDR,
			Value:         cidr,
			Ports:         ports,
			Action:        ActionAllow,
			AutoAddedType: autoAddedType,
			IPNet: &net.IPNet{
				IP:   ip4,
				Mask: net.CIDRMask(32, 32),
			},
		})

		slog.Info("Auto-added allow rule", "cidr", cidr, "ports", ports, "autoAddedType", autoAddedType)
	}
}

// hasCIDRRuleAllPorts checks if an existing CIDR rule already covers the given
// IP on all ports (i.e. has an empty/nil Ports list). Must be called with cm.mu held.
func (cm *Manager) hasCIDRRuleAllPorts(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, rule := range cm.config.Rules {
		if rule.Type != RuleTypeCIDR || rule.Action != ActionAllow {
			continue
		}

		_, ipnet, err := net.ParseCIDR(rule.Value)
		if err != nil {
			ruleIP := net.ParseIP(rule.Value)
			if ruleIP == nil || !ruleIP.Equal(ip) {
				continue
			}
		} else if !ipnet.Contains(ip) {
			continue
		}

		// IP matches — only return true if this rule covers ALL ports
		if len(rule.Ports) == 0 {
			return true
		}
	}
	return false
}

// hasCIDRRule checks if an existing CIDR rule already covers the given IP and port+protocol.
// Must be called with cm.mu held.
func (cm *Manager) hasCIDRRule(ipStr string, port Port) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, rule := range cm.config.Rules {
		if rule.Type != RuleTypeCIDR {
			continue
		}

		_, ipnet, err := net.ParseCIDR(rule.Value)
		if err != nil {
			// Try single IP
			ruleIP := net.ParseIP(rule.Value)
			if ruleIP == nil || !ruleIP.Equal(ip) {
				continue
			}
		} else if !ipnet.Contains(ip) {
			continue
		}

		// IP matches — check if ports cover our target port+protocol
		if len(rule.Ports) == 0 {
			// No port restriction means all ports are covered
			return true
		}
		for _, p := range rule.Ports {
			if p.Port == port.Port && protocolsOverlap(p.Protocol, port.Protocol) {
				return true
			}
		}
	}
	return false
}

// EnsureHostnameAllowed adds an allow rule for a hostname so that it (and
// its subdomains) are permitted through the firewall. This is used in
// GitHub Actions mode to auto-allow infrastructure like the Actions service.
func (cm *Manager) EnsureHostnameAllowed(hostname string, ports []Port, autoAddedType AutoAddedType) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return
	}

	// Skip if already tracked as allowed
	if action, ok := cm.trackedHostnames[hostname]; ok && action == ActionAllow {
		return
	}

	rule := Rule{
		Type:          RuleTypeHostname,
		Value:         hostname,
		Ports:         ports,
		Action:        ActionAllow,
		AutoAddedType: autoAddedType,
	}
	cm.config.Rules = append(cm.config.Rules, rule)
	cm.trackedHostnames[hostname] = ActionAllow
	cm.hostnameCache[hostname] = []net.IP{}
	cm.resolvedRules = append(cm.resolvedRules, ResolvedRule{
		Type:          RuleTypeHostname,
		Value:         hostname,
		Ports:         ports,
		IPs:           []net.IP{},
		Action:        ActionAllow,
		AutoAddedType: autoAddedType,
	})

	slog.Info("Auto-added infrastructure hostname allow rule", "hostname", hostname, "ports", ports, "autoAddedType", autoAddedType)
}

// GetAutoAllowedTypeForHostname checks if a hostname matches a hostname-based
// auto-added rule, ignoring port restrictions. This is used for tagging existing
// connections from /proc/net/tcp where port info is lost after deduplication.
func (cm *Manager) GetAutoAllowedTypeForHostname(hostname string) AutoAddedType {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, rule := range cm.resolvedRules {
		if rule.Type != RuleTypeHostname || rule.AutoAddedType == AutoAddedTypeNone || rule.Action != ActionAllow {
			continue
		}
		if hostname == rule.Value || strings.HasSuffix(hostname, "."+rule.Value) {
			return rule.AutoAddedType
		}
	}
	return AutoAddedTypeNone
}

// GetIPToHostnameMap returns a copy of the IP to hostname mapping
// This is used by the DNS server to reprocess cached hostnames after config load
func (cm *Manager) GetIPToHostnameMap() map[string]string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string]string)
	for ip, hostname := range cm.ipToHostname {
		result[ip] = hostname
	}
	return result
}

// GetAutoAllowedType checks if a connection (ip, port, hostname) matches an
// auto-added rule and returns the AutoAddedType. Hostname rules are checked
// first, then CIDR rules. Returns AutoAddedTypeNone if no auto-added rule matches.
func (cm *Manager) GetAutoAllowedType(ip string, port uint16, hostname string) AutoAddedType {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	parsedIP := net.ParseIP(ip)

	for _, rule := range cm.resolvedRules {
		if rule.AutoAddedType == AutoAddedTypeNone || rule.Action != ActionAllow {
			continue
		}

		// Check port restriction
		if len(rule.Ports) > 0 {
			portMatch := false
			for _, p := range rule.Ports {
				if p.Port == port {
					portMatch = true
					break
				}
			}
			if !portMatch {
				continue
			}
		}

		switch rule.Type {
		case RuleTypeHostname:
			if hostname == rule.Value || strings.HasSuffix(hostname, "."+rule.Value) {
				return rule.AutoAddedType
			}
		case RuleTypeCIDR:
			if parsedIP != nil && rule.IPNet != nil && rule.IPNet.Contains(parsedIP) {
				return rule.AutoAddedType
			}
		}
	}
	return AutoAddedTypeNone
}

// GetSudoLockdown returns the policy-sourced sudo lockdown settings, or nil
// if no sudo lockdown configuration was provided.
func (cm *Manager) GetSudoLockdown() *SudoLockdownSettings {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil {
		return nil
	}
	return cm.config.SudoLockdown
}

// resolveRules resolves all hostname rules to IP addresses
func (cm *Manager) resolveRules() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	slog.Info("Resolving rules", "count", len(cm.config.Rules))

	if cm.config == nil {
		return fmt.Errorf("no config loaded")
	}

	cm.resolvedRules = nil

	for _, rule := range cm.config.Rules {
		resolved := ResolvedRule{
			Type:          rule.Type,
			Value:         rule.Value,
			Ports:         rule.Ports,
			Action:        rule.Action,
			AutoAddedType: rule.AutoAddedType,
		}

		switch rule.Type {
		case RuleTypeHostname:
			// Track ALL hostnames we have rules for - will resolve JIT when DNS queries arrive
			cm.trackedHostnames[rule.Value] = rule.Action

			// Check if we already have cached IPs for this hostname (from previous DNS intercepts)
			if cachedIPs, ok := cm.hostnameCache[rule.Value]; ok {
				resolved.IPs = cachedIPs
			} else {
				// Initialize the hostnameCache entry so UpdateDNSMapping can append IPs later
				cm.hostnameCache[rule.Value] = []net.IP{}
				resolved.IPs = []net.IP{}
			}

		case RuleTypeCIDR:
			_, ipnet, err := net.ParseCIDR(rule.Value)
			if err != nil {
				// Try parsing as single IP (treat as /32)
				ip := net.ParseIP(rule.Value)
				if ip == nil {
					slog.Error("Invalid CIDR/IP", "value", rule.Value, "error", err)
					continue
				}
				// Convert single IP to /32 CIDR
				if ip4 := ip.To4(); ip4 != nil {
					resolved.IPNet = &net.IPNet{
						IP:   ip4,
						Mask: net.CIDRMask(32, 32),
					}
				} else {
					// IPv6 /128
					resolved.IPNet = &net.IPNet{
						IP:   ip,
						Mask: net.CIDRMask(128, 128),
					}
				}
			} else {
				// Store the actual CIDR block
				resolved.IPNet = ipnet
			}

		default:
			slog.Error("Unknown Rule type", "type", rule.Type)
			continue
		}

		cm.resolvedRules = append(cm.resolvedRules, resolved)
	}

	return nil
}
