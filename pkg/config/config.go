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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

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
	AutoAddedTypeCloudMetadata       AutoAddedType = "cloud_metadata"
	AutoAddedTypeAzureInfrastructure AutoAddedType = "azure_infrastructure"
	AutoAddedTypeGitHubService       AutoAddedType = "github_service"
	AutoAddedTypeGitLabService       AutoAddedType = "gitlab_service"
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
	ProtocolAll  ProtocolType = "all"
	ProtocolTCP  ProtocolType = "tcp"
	ProtocolUDP  ProtocolType = "udp"
	ProtocolICMP ProtocolType = "icmp"
)

// Common port definitions for infrastructure auto-allow rules.
// PortICMP carries Port=0 because ICMP has no port concept; the protocol
// field alone drives the BPF lookup.
var (
	PortHTTPS      = Port{Port: 443, Protocol: ProtocolTCP}
	PortHTTP       = Port{Port: 80, Protocol: ProtocolTCP}
	PortDNS        = Port{Port: 53, Protocol: ProtocolUDP}
	PortWireServer = Port{Port: 32526, Protocol: ProtocolTCP}
	PortICMP       = Port{Port: 0, Protocol: ProtocolICMP}
)

// FirewallConfig represents the configuration for the L4 firewall
type FirewallConfig struct {
	Rules []Rule `json:"rules"`
	// DefaultAction is the default action when no Rule matches (allow/deny)
	DefaultAction Action                `json:"defaultAction"`
	SudoLockdown  *SudoLockdownSettings `json:"sudoLockdown,omitempty"`
	// SearchDomains are DNS suffixes (e.g. ".compute.internal") that the DNS
	// proxy strips before hostname-rule matching AND treats as allow-bypass
	// for query filtering. Used for cloud-internal DNS suffixes where the
	// network traffic is governed by a CIDR rule and per-hostname tracking
	// would be wasteful.
	SearchDomains []string `json:"searchDomains,omitempty"`
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
	Enabled       bool     `json:"enabled"`
	AllowCommands []string `json:"allowCommands,omitempty"`
}

// ResolvedRule represents a Rule with resolved IP addresses or CIDR blocks
type ResolvedRule struct {
	Type RuleType // "hostname" or "cidr"
	// Value is the canonical-lowercase hostname (or CIDR string).
	Value string
	// dotPrefix is "." + Value, precomputed at resolveRules time for
	// non-pattern hostname rules so the parent-domain suffix check on the
	// DNS hot path doesn't allocate per call. Empty for pattern / CIDR rules.
	dotPrefix string
	IPs       []net.IP         // For hostnames: resolved IPs. For CIDR: empty
	IPNet     *net.IPNet       // For CIDR blocks only
	Pattern   *hostnamePattern // Non-nil for hostname rules with glob wildcards
	Ports     []Port
	Action    Action
	// AutoAddedType indicates why this rule was auto-added (empty for user-configured rules)
	AutoAddedType AutoAddedType
}

// MatchesHostname returns true if the hostname matches this hostname rule
// via glob pattern, exact match, or parent domain (subdomain) match.
func (r *ResolvedRule) MatchesHostname(hostname string) bool {
	if r.Pattern != nil {
		return r.Pattern.Matches(hostname)
	}
	if hostname == r.Value {
		return true
	}
	if r.dotPrefix == "" {
		// Defensive: rules built outside resolveRules (none today, but
		// future maintainers) — fall back to the allocating form.
		return strings.HasSuffix(hostname, "."+r.Value)
	}
	return strings.HasSuffix(hostname, r.dotPrefix)
}

// Manager manages the firewall configuration and hostname resolution
type Manager struct {
	mu               sync.RWMutex
	config           *FirewallConfig
	resolvedRules    []ResolvedRule
	hostnameCache    map[string][]net.IP
	ipToHostname     map[string]string              // Reverse lookup: IP -> hostname
	ipToCNAMEOrigins map[string][]cnameOriginRecord // Reverse lookup: IP -> CNAME chains (one per origin) for derived-allow attribution
	ipLastSeen       map[string]time.Time           // Track when each IP was last seen
	trackedHostnames map[string]Action              // Track hostnames we have rules for (hostname -> action)
	maxCacheSize     int                            // Maximum number of IPs to cache
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *Manager {
	return &Manager{
		hostnameCache:    make(map[string][]net.IP),
		ipToHostname:     make(map[string]string),
		ipToCNAMEOrigins: make(map[string][]cnameOriginRecord),
		ipLastSeen:       make(map[string]time.Time),
		trackedHostnames: make(map[string]Action),
		maxCacheSize:     10000, // Default max cache size
	}
}

// LoadConfigFromRules loads configuration from rules (for testing)
func (cm *Manager) LoadConfigFromRules(rules []Rule, defaultAction Action) error {
	return cm.applyLoadedConfig(&FirewallConfig{
		Rules:         rules,
		DefaultAction: defaultAction,
	})
}

// isIPv6CIDR reports whether value parses as an IPv6 CIDR.
func isIPv6CIDR(value string) bool {
	ip, _, err := net.ParseCIDR(value)
	return err == nil && ip.To4() == nil
}

// canonicalCIDR returns the canonical string form of a CIDR or bare-IP rule
// value, so textually-different-but-equivalent values collapse to one entry:
//
//   - "2001:DB8::/32"     → "2001:db8::/32"   (IPv6 case-folded)
//   - "2001:db8:0:0::/64" → "2001:db8::/64"   (zero-compression canonicalised)
//   - "8.8.8.8"           → "8.8.8.8/32"      (bare IPv4 → explicit /32)
//   - "2001:db8::1"       → "2001:db8::1/128" (bare IPv6 → explicit /128)
//   - "10.0.0.5/8"        → "10.0.0.0/8"      (host bits masked to network)
//
// net.ParseCIDR already lower-cases IPv6, collapses zero runs, and masks host
// bits off the network address — exactly the canonical form ipnet.String()
// re-emits. Bare IPs (no prefix) are promoted to a single-host /32 or /128 so
// "8.8.8.8" and "8.8.8.8/32" dedup. Values that parse as neither are returned
// unchanged; resolveRules logs them as invalid and skips them.
func canonicalCIDR(value string) string {
	if _, ipnet, err := net.ParseCIDR(value); err == nil {
		return ipnet.String()
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return value
	}
	if ip4 := ip.To4(); ip4 != nil {
		return (&net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}).String()
	}
	return (&net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}).String()
}

// applyLoadedConfig is the shared tail of every Load* loader: normalize
// and validate the rule set, then atomically swap cm.config under the
// write lock and resolve rules. If normalization or validation fails the
// manager state is left untouched.
//
// Loaders own the upstream-format parsing (JSON, env vars, protobuf) and
// any source-specific validation (e.g. validateSearchDomains). They pass
// the assembled FirewallConfig here for the canonical tail.
func (cm *Manager) applyLoadedConfig(cfg *FirewallConfig) error {
	normalizeRules(cfg.Rules)
	if err := validateRules(cfg.Rules); err != nil {
		return err
	}
	cfg.Rules = mergeDuplicateRules(cfg.Rules)
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config = cfg
	return cm.resolveRulesLocked()
}

// normalizeRules canonicalises rule values in place so cm.config.Rules and
// cm.resolvedRules agree byte-for-byte, and so equivalent-but-differently-
// spelled values dedup in mergeDuplicateRules (which keys on the literal
// Value string):
//
//   - Hostname rules are lower-cased. DNS is case-insensitive but JSON /
//     proto / env can carry mixed case (e.g. "GitHub.com"), and
//     MatchHostnameRule lowercases the lookup key.
//   - CIDR rules are canonicalised via canonicalCIDR: IPv6 case-folded and
//     zero-compressed, bare IPs promoted to /32 or /128, host bits masked.
//     So "2001:DB8::/32" and "2001:db8::/32", or "8.8.8.8" and "8.8.8.8/32",
//     become one entry rather than two (issue #64).
//
// All four loaders call this before validateRules / mergeDuplicateRules /
// resolveRules, so any code reading cm.config.Rules directly (audit /
// introspection) sees the same canonical form that matching runs against.
func normalizeRules(rules []Rule) {
	for i := range rules {
		switch rules[i].Type {
		case RuleTypeHostname:
			rules[i].Value = strings.ToLower(rules[i].Value)
		case RuleTypeCIDR:
			rules[i].Value = canonicalCIDR(rules[i].Value)
		}
	}
}

// validateRules enforces cross-field constraints on parsed rules. Each loader
// entry point (LoadConfig, LoadConfigFromCargoWall, LoadConfigFromRules,
// LoadFromEnv) calls this so internal callers cannot bypass the checks.
func validateRules(rules []Rule) error {
	for _, rule := range rules {
		for _, p := range rule.Ports {
			if p.Protocol == ProtocolICMP && p.Port != 0 {
				return fmt.Errorf("ICMP rules must have port=0, got %d", p.Port)
			}
			if p.Protocol == ProtocolICMP && rule.Type == RuleTypeCIDR && isIPv6CIDR(rule.Value) {
				return fmt.Errorf("ICMP (proto 1) is IPv4-only; ICMPv6 is always allowed on IPv6 CIDR %q", rule.Value)
			}
		}
	}
	return nil
}

// ruleKey identifies rules that should have their ports unioned: rules that
// agree on type, value, AND action are the same rule expressed more than once,
// so their ports are additive. Opposite-action rules on the same value are a
// genuine allow/deny conflict (not a union) and are left intact for the
// matching-precedence logic — hence Action is part of the key.
type ruleKey struct {
	Type   RuleType
	Value  string
	Action Action
}

// mergeDuplicateRules collapses rules sharing (Type, Value, Action) into one
// rule whose Ports are the union of the duplicates' ports, so a policy that
// lists the same hostname (or CIDR) twice allows the sum of their ports rather
// than just the last/first entry's (issue #52). Rule values are already
// canonical when this runs (hostnames lowercased by normalizeRules). Output
// preserves first-occurrence order and keeps the first occurrence's
// AutoAddedType. The "empty Ports = all ports" sentinel is honoured by
// UnionPorts: any all-ports duplicate makes the whole group all-ports.
//
// Running this once at load time means every downstream consumer — hostname
// matching (cm.resolvedRules), CIDR conflict detection (cm.config.Rules), and
// firewall BPF writes — observes the same unioned port set.
func mergeDuplicateRules(rules []Rule) []Rule {
	merged := make([]Rule, 0, len(rules))
	idxByKey := make(map[ruleKey]int, len(rules))
	for _, rule := range rules {
		key := ruleKey{Type: rule.Type, Value: rule.Value, Action: rule.Action}
		if i, ok := idxByKey[key]; ok {
			merged[i].Ports = UnionPorts(merged[i].Ports, rule.Ports)
			continue
		}
		idxByKey[key] = len(merged)
		// Copy Ports so a later union (which reassigns merged[i].Ports) can
		// never alias or mutate the caller's backing array.
		rule.Ports = copyPorts(rule.Ports)
		merged = append(merged, rule)
	}
	return merged
}

// kubernetesSearchDomains are always-active suffixes that the DNS proxy
// strips before hostname-rule matching, mirroring how a Kubernetes pod's
// resolver appends them. Lives in the config package so all rule-matching
// helpers (MatchHostnameRule, FindTrackedHostname) consult the same list.
var kubernetesSearchDomains = []string{
	".default.svc.cluster.local",
	".svc.cluster.local",
	".cluster.local",
}

// StripSearchDomains returns hostname with its longest matching search-domain
// suffix removed — Kubernetes defaults plus any user-configured suffixes.
// Matching is case-insensitive; the case of the surviving prefix is
// preserved. Returns the original hostname when no suffix matches.
//
// The substring trick is safe because valid DNS names are ASCII (per
// RFC 1035; IDNs arrive as ASCII xn-- punycode), so strings.ToLower is
// byte-for-byte length-preserving.
func (cm *Manager) StripSearchDomains(hostname string) string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	lower := strings.ToLower(hostname)
	stripped := cm.stripSearchDomainsLocked(lower)
	if stripped == lower {
		return hostname
	}
	return hostname[:len(stripped)]
}

// stripSearchDomainsLocked returns name with its longest matching suffix
// removed. Caller must hold cm.mu.RLock and pass an already-lowercased name;
// the returned substring is also lowercase. The internal rule-matching
// helpers consume the lowercase form directly, so case preservation lives
// only on the public StripSearchDomains path.
func (cm *Manager) stripSearchDomainsLocked(name string) string {
	longest := 0
	for _, suffix := range kubernetesSearchDomains {
		if len(suffix) > longest && strings.HasSuffix(name, suffix) {
			longest = len(suffix)
		}
	}
	if cm.config != nil {
		for _, suffix := range cm.config.SearchDomains {
			if len(suffix) > longest && strings.HasSuffix(name, suffix) {
				longest = len(suffix)
			}
		}
	}
	if longest == 0 {
		return name
	}
	return name[:len(name)-longest]
}

// mergeNormalizedSearchDomains returns the dedup'd union of two
// already-normalized suffix slices. Used by AddSearchDomains so it doesn't
// redo case/leading-dot normalization on entries that are already canonical.
func mergeNormalizedSearchDomains(existing, addition []string) []string {
	if len(addition) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(addition))
	out := make([]string, 0, len(existing)+len(addition))
	for _, d := range existing {
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	for _, d := range addition {
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// normalizeSearchDomains lowercases, trims whitespace, ensures a leading dot,
// and deduplicates. Order is preserved by first occurrence.
//
// Empty/whitespace-only entries are PRESERVED (as "") so validateSearchDomains
// can reject them — silently dropping them would let explicit misconfigs like
// `searchDomains: [""]` or `CARGOWALL_SEARCH_DOMAINS=" "` pass unnoticed.
func normalizeSearchDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	normalized := make([]string, len(domains))
	for i, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !strings.HasPrefix(d, ".") {
			d = "." + d
		}
		normalized[i] = d
	}
	return mergeNormalizedSearchDomains(nil, normalized)
}

// validateSearchDomain rejects a single normalized suffix that would be too
// broad to safely bypass DNS query filtering.
//
// Three safety nets:
//  1. Multi-label hygiene: must have ≥ 2 labels (rejects ".com"); labels obey
//     RFC 1035 / 1123 (≤ 63 octets, characters [a-z 0-9 -], no leading or
//     trailing hyphen).
//  2. Public Suffix List: must not be a public suffix per Mozilla's PSL.
//     This catches multi-label TLDs like ".co.uk" and ".com.au" that pass
//     the 2-label hygiene but would bypass DNS filtering for huge swaths of
//     the public internet. Private internal suffixes like ".compute.internal"
//     are accepted because they extend beyond the PSL entry (".internal" is
//     on the PSL as a private-use TLD).
//  3. Kubernetes suffixes: the three default K8s search suffixes are
//     always-active for stripping (see kubernetesSearchDomains) but
//     intentionally NOT bypass-eligible. Adding them as a user search
//     domain would silently elevate them to bypass and let K8s service
//     names skip per-hostname DNS filtering — surface as a config error
//     so the operator decides explicitly.
func validateSearchDomain(d string) error {
	if d == "" || d == "." {
		return fmt.Errorf("search domain must not be empty")
	}
	if slices.Contains(kubernetesSearchDomains, d) {
		return fmt.Errorf("search domain %q is always active for stripping; do not add it to user search domains (would inadvertently grant DNS-filter bypass for all K8s service names)", d)
	}
	bare := strings.TrimPrefix(d, ".")
	labels := strings.Split(bare, ".")
	if len(labels) < 2 {
		return fmt.Errorf("search domain %q must have at least two labels (e.g. \".compute.internal\")", d)
	}
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("search domain %q has an empty label", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("search domain %q has label %q longer than 63 octets", d, label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("search domain %q label %q must not start or end with '-'", d, label)
		}
		for _, r := range label {
			if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
				return fmt.Errorf("search domain %q contains invalid character %q", d, r)
			}
		}
	}
	// publicsuffix.PublicSuffix returns the longest known public suffix
	// for the input. If the user's suffix IS that public suffix, they're
	// trying to use a TLD-equivalent as a bypass — reject.
	if eTLD, _ := publicsuffix.PublicSuffix(bare); eTLD == bare {
		return fmt.Errorf("search domain %q is a public suffix (per Mozilla PSL); use a more specific private suffix", d)
	}
	return nil
}

// validateSearchDomains validates a batch of normalized suffixes, returning
// on the first invalid entry. Used by user-supplied config paths (proto,
// JSON, env) where a typo should fail loudly. The in-process auto-allow path
// uses validateSearchDomain directly so it can skip-and-warn per entry.
func validateSearchDomains(domains []string) error {
	for _, d := range domains {
		if err := validateSearchDomain(d); err != nil {
			return err
		}
	}
	return nil
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

	searchDomains := normalizeSearchDomains(cargoWall.GetSearchDomains())
	if err := validateSearchDomains(searchDomains); err != nil {
		return err
	}

	defaultAction := convertAction(cargoWall.DefaultAction)

	// Extract sudo lockdown settings
	var sudoLockdown *SudoLockdownSettings
	if sl := cargoWall.GetSudoLockdown(); sl != nil {
		sudoLockdown = &SudoLockdownSettings{
			Enabled:       sl.Enabled,
			AllowCommands: sl.AllowCommands,
		}
	}

	if err := cm.applyLoadedConfig(&FirewallConfig{
		Rules:         rules,
		DefaultAction: defaultAction,
		SudoLockdown:  sudoLockdown,
		SearchDomains: searchDomains,
	}); err != nil {
		return err
	}
	slog.Info("Loaded CargoWall config from state machine",
		"rules", len(rules),
		"defaultAction", defaultAction,
		"searchDomains", len(searchDomains))
	return nil
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
	case datapb.CargoWallProtocol_CARGO_WALL_PROTOCOL_ICMP:
		return ProtocolICMP, nil
	default:
		return "", fmt.Errorf("unknown protocol: %v", proto)
	}
}

// ProtocolsOverlap returns true if two protocol types can match the same
// traffic. ProtocolAll overlaps with everything; TCP/UDP/ICMP only overlap
// with themselves.
//
// Exported for cross-package use: pkg/events relies on this to decide whether
// a BPF event's L4 protocol is in a configured rule's allow set. Treat as
// part of the package's public contract.
func ProtocolsOverlap(a, b ProtocolType) bool {
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
		// Defensive: an unknown enum value usually means proto/code skew
		// during an upgrade. Default to Deny for safety but log so the
		// drift is diagnosable rather than silently turning into deny-all.
		slog.Warn("Unknown CargoWallActionType, defaulting to deny", "value", action)
		return ActionDeny
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

	config.SearchDomains = normalizeSearchDomains(config.SearchDomains)
	if err := validateSearchDomains(config.SearchDomains); err != nil {
		return err
	}

	if err := cm.applyLoadedConfig(&config); err != nil {
		return err
	}
	slog.Info("Config loaded successfully",
		"rules", len(config.Rules),
		"defaultAction", config.DefaultAction,
		"searchDomains", len(config.SearchDomains))
	return nil
}

// LoadFromEnv loads configuration from environment variables.
// Environment variables:
//   - CARGOWALL_DEFAULT_ACTION: "allow" or "deny" (default: "deny")
//   - CARGOWALL_ALLOWED_HOSTS: comma-separated list of allowed hostnames (supports wildcards)
//   - CARGOWALL_ALLOWED_CIDRS: comma-separated list of allowed CIDR blocks
//   - CARGOWALL_BLOCKED_HOSTS: comma-separated list of blocked hostnames
//   - CARGOWALL_BLOCKED_CIDRS: comma-separated list of blocked CIDR blocks
//   - CARGOWALL_SEARCH_DOMAINS: comma-separated list of DNS search-domain suffixes
//     (e.g. ".compute.internal") that bypass DNS query filtering
func (cm *Manager) LoadFromEnv() error {
	// Check if any config environment variables are set
	defaultAction := os.Getenv("CARGOWALL_DEFAULT_ACTION")
	allowedHosts := os.Getenv("CARGOWALL_ALLOWED_HOSTS")
	allowedCIDRs := os.Getenv("CARGOWALL_ALLOWED_CIDRS")
	blockedHosts := os.Getenv("CARGOWALL_BLOCKED_HOSTS")
	blockedCIDRs := os.Getenv("CARGOWALL_BLOCKED_CIDRS")
	searchDomains := os.Getenv("CARGOWALL_SEARCH_DOMAINS")

	// If no env vars are set, return an error to fall back to file config
	if defaultAction == "" && allowedHosts == "" && allowedCIDRs == "" && blockedHosts == "" && blockedCIDRs == "" && searchDomains == "" {
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

	// Parse each env-var list into rules, propagating any malformed-entry
	// errors so a typo (e.g. `github.com:abc`) surfaces as a load failure
	// rather than a silently-preserved nonsense rule.
	envSources := []struct {
		envName  string
		raw      string
		ruleType RuleType
		action   Action
	}{
		{"CARGOWALL_ALLOWED_HOSTS", allowedHosts, RuleTypeHostname, ActionAllow},
		{"CARGOWALL_ALLOWED_CIDRS", allowedCIDRs, RuleTypeCIDR, ActionAllow},
		{"CARGOWALL_BLOCKED_HOSTS", blockedHosts, RuleTypeHostname, ActionDeny},
		{"CARGOWALL_BLOCKED_CIDRS", blockedCIDRs, RuleTypeCIDR, ActionDeny},
	}
	for _, src := range envSources {
		if src.raw == "" {
			continue
		}
		for _, entry := range splitAndTrim(src.raw) {
			if entry == "" {
				continue
			}
			value, ports, err := parseHostWithPorts(entry)
			if err != nil {
				return fmt.Errorf("invalid %s entry: %w", src.envName, err)
			}
			rules = append(rules, Rule{
				Type:   src.ruleType,
				Value:  value,
				Ports:  ports,
				Action: src.action,
			})
		}
	}

	// strings.Split (not splitAndTrim) so empty / whitespace-only entries
	// reach validation — CARGOWALL_SEARCH_DOMAINS=" " or a trailing comma
	// should fail loud rather than silently parse as no-config.
	var rawSearchDomains []string
	if searchDomains != "" {
		rawSearchDomains = strings.Split(searchDomains, ",")
	}
	parsedSearchDomains := normalizeSearchDomains(rawSearchDomains)
	if err := validateSearchDomains(parsedSearchDomains); err != nil {
		return fmt.Errorf("invalid CARGOWALL_SEARCH_DOMAINS: %w", err)
	}

	if err := cm.applyLoadedConfig(&FirewallConfig{
		Rules:         rules,
		DefaultAction: parsedDefaultAction,
		SearchDomains: parsedSearchDomains,
	}); err != nil {
		return err
	}
	slog.Info("Loaded config from environment variables",
		"rules", len(rules),
		"defaultAction", parsedDefaultAction,
		"searchDomains", len(parsedSearchDomains))
	return nil
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
//
// Formats accepted:
//   - "github.com" / "github.com:443" / "github.com:443;80"
//   - "10.0.0.0/8" / "10.0.0.0/8:443"
//   - "::1" / "2001:db8::1" — bare IPv6 (no ports); the colons inside
//     the address must NOT be parsed as host:port separators.
//   - "[::1]:443" / "[2001:db8::1]:443;80" — IPv6 with ports requires
//     brackets, matching Go stdlib's net.JoinHostPort convention.
//   - "2001:db8::/32" / "2001:db8::/32:443" — IPv6 CIDR, optionally with ports.
//
// Returns (host, nil, nil) when the entry has no port suffix (e.g. a bare
// hostname or CIDR). Returns a non-nil error when the entry has a `:port`
// suffix but the suffix isn't a valid `;`-separated port list — both in
// the bracketed form (`[::1]:abc`) and the trailing-colon form
// (`github.com:abc`). Malformed entries are rejected loudly so a typo
// surfaces as a config error rather than a silent allow/block-of-nothing.
func parseHostWithPorts(entry string) (string, []Port, error) {
	// Bare IP (v4 or v6) — colons inside an IPv6 address must not be
	// misread as host:port separators. ParseIP accepts both families.
	if net.ParseIP(entry) != nil {
		return entry, nil, nil
	}
	// Bare CIDR (v4 or v6) — same reasoning.
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return entry, nil, nil
	}
	// Bracketed IPv6 + port(s): "[ipv6]:port" or "[ipv6]:port;port".
	if strings.HasPrefix(entry, "[") {
		end := strings.Index(entry, "]")
		// Require "]:" immediately after the closing bracket to call it
		// a port suffix. Bracket-only forms like "[::1]" are preserved as
		// a literal entry (downstream validation rejects).
		if end > 0 && len(entry) > end+1 && entry[end+1] == ':' {
			host := entry[1:end]
			ports, ok := parsePortList(entry[end+2:])
			if !ok {
				return "", nil, fmt.Errorf("invalid port suffix in %q", entry)
			}
			return host, ports, nil
		}
		return entry, nil, nil
	}
	// Hostname / IPv4 / CIDR with ":port[;port]" suffix.
	idx := strings.LastIndex(entry, ":")
	if idx == -1 {
		return entry, nil, nil
	}
	host := entry[:idx]
	// Reject unbracketed IPv6-with-ports. A remaining `:` in the host
	// after the last-`:` split is either a multi-colon IPv6 address that
	// should have been bracketed (e.g. "2001:db8::1:443;80") or
	// malformed junk (e.g. "fe80::g:80"). The bare-IPv6 path at the top
	// already handles the no-ports case, and the bare-CIDR path handles
	// "2001:db8::/32" — but "2001:db8::/32:443" is the legitimate
	// "v6 CIDR + port" form whose host portion still contains colons,
	// so the ParseCIDR escape keeps it accepted.
	if strings.Contains(host, ":") {
		if _, _, cidrErr := net.ParseCIDR(host); cidrErr != nil {
			return "", nil, fmt.Errorf("ambiguous host:port in %q — use \"[ipv6]:port\" form for IPv6 addresses", entry)
		}
	}
	ports, ok := parsePortList(entry[idx+1:])
	if !ok {
		return "", nil, fmt.Errorf("invalid port suffix in %q", entry)
	}
	// Trailing colon with no parsable port tokens (e.g. "github.com:" or
	// stray whitespace like "github.com: ") — strip the colon. Otherwise
	// the malformed hostname "github.com:" enters the ruleset with an
	// implicit all-ports scope; matching no real DNS query but cluttering
	// the config and confusing audit output.
	return host, ports, nil
}

// parsePortList parses "port1;port2;..." into []Port (all ProtocolAll).
// The bool reports whether parsing was OK (`false` only when a token
// fails to ParseUint — signalling the caller's split was wrong, e.g. `:`
// appeared inside an unbracketed IPv6). A successful parse with zero
// tokens (empty suffix, whitespace-only, lone `;`) returns (nil, true).
func parsePortList(s string) ([]Port, bool) {
	var ports []Port
	for _, p := range strings.Split(s, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, false
		}
		ports = append(ports, Port{Port: uint16(port), Protocol: ProtocolAll})
	}
	return ports, true
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

// UpdateDNSMapping adds a DNS mapping from an observed DNS response. The
// hostname is stored canonical-lowercase so reverse lookups, FindTrackedHostname
// matches, and hostnameCache keys all share the same case-insensitive contract.
func (cm *Manager) UpdateDNSMapping(hostname string, ip string) {
	hostname = strings.ToLower(hostname)

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

// cnameOriginRecord is one origin's CNAME chain to a derived-allow IP, kept with
// freshness so the most recently-chased origin can be chosen at report time and
// stale ones (no longer chaining here) dropped. A single CDN/edge IP can be
// reached via the chains of several allowed origins; we retain a bounded,
// recency-ranked set rather than collapsing to one.
type cnameOriginRecord struct {
	chain    []string  // origin..target, origin = chain[0]
	lastSeen time.Time // when this origin last chained to the IP
	expiry   time.Time // chain TTL; after this the origin no longer "currently chains here"
}

// maxCNAMEOriginsPerIP bounds the per-IP origin set. A CDN edge is fronted by
// few of a user's allowed hostnames in practice, so a small cap is ample; the
// oldest entry is evicted on overflow.
const maxCNAMEOriginsPerIP = 8

// cnameOriginFloorTTL is the minimum expiry applied when a response carries a
// zero/absent TTL, so a TTL-0 CDN answer doesn't make an attribution expire
// instantly (which would drop us back to the opaque edge name).
const cnameOriginFloorTTL = 5 * time.Minute

// RecordCNAMEChain records that a derived-allow IP was reached through `chain`
// (origin..target, ordered), so connection events for that IP can be attributed
// to the origin hostname the user actually allowed rather than the opaque
// CDN/edge target. Multiple origins can reach the same IP; each is kept with its
// recency and `ttl`-derived freshness so LookupCNAMEChain can pick the origin the
// current request most likely chased. Stored lowercase and bounded by the shared
// ipLastSeen lifecycle (see cleanupOldEntries). A nil/empty chain is ignored.
func (cm *Manager) RecordCNAMEChain(ip string, chain []string, ttl time.Duration) {
	if ip == "" || len(chain) == 0 {
		return
	}

	stored := make([]string, len(chain))
	for i, h := range chain {
		stored[i] = strings.ToLower(h)
	}

	now := time.Now()
	if ttl < cnameOriginFloorTTL {
		ttl = cnameOriginFloorTTL
	}
	rec := cnameOriginRecord{chain: stored, lastSeen: now, expiry: now.Add(ttl)}
	origin := stored[0]

	cm.mu.Lock()
	defer cm.mu.Unlock()

	records := cm.ipToCNAMEOrigins[ip]
	// Upsert by origin: a repeat resolution of the same chain refreshes it in
	// place rather than adding a duplicate.
	replaced := false
	for i := range records {
		if len(records[i].chain) > 0 && records[i].chain[0] == origin {
			records[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		records = append(records, rec)
		// Evict the least-recently-seen entry if over the cap.
		if len(records) > maxCNAMEOriginsPerIP {
			oldest := 0
			for i := 1; i < len(records); i++ {
				if records[i].lastSeen.Before(records[oldest].lastSeen) {
					oldest = i
				}
			}
			records = append(records[:oldest], records[oldest+1:]...)
		}
	}
	cm.ipToCNAMEOrigins[ip] = records
	cm.ipLastSeen[ip] = now
}

// LookupCNAMEChain returns the CNAME chain (origin..target) for a derived-allow
// IP that the current request most likely chased: the most recently-seen origin
// whose chain has not yet expired ("still currently chains here"). If every
// recorded origin has expired it falls back to the most recent one so a stale
// IP still attributes to an allowed host rather than the opaque edge. Returns
// nil if nothing was recorded. The returned slice is a copy.
func (cm *Manager) LookupCNAMEChain(ip string) []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	records := cm.ipToCNAMEOrigins[ip]
	if len(records) == 0 {
		return nil
	}

	now := time.Now()
	best := -1       // most-recent non-expired
	mostRecent := -1 // most-recent overall (fallback when all expired)
	for i := range records {
		if mostRecent == -1 || records[i].lastSeen.After(records[mostRecent].lastSeen) {
			mostRecent = i
		}
		if now.Before(records[i].expiry) && (best == -1 || records[i].lastSeen.After(records[best].lastSeen)) {
			best = i
		}
	}
	pick := best
	if pick == -1 {
		pick = mostRecent // all expired → fall back to last-known
	}

	out := make([]string, len(records[pick].chain))
	copy(out, records[pick].chain)
	return out
}

// dnsCacheTTL is how long a DNS reverse mapping is kept before
// cleanupOldEntries can discard it. Set to a day so containers / long-lived
// connections aren't reverse-resolved repeatedly. Inlined here because no
// caller ever needs to override it.
const dnsCacheTTL = 24 * time.Hour

// cleanupOldEntries removes old DNS cache entries (must be called with lock held)
func (cm *Manager) cleanupOldEntries() {
	now := time.Now()
	toDelete := []string{}

	// Find entries older than TTL
	for ip, lastSeen := range cm.ipLastSeen {
		if now.Sub(lastSeen) > dnsCacheTTL {
			toDelete = append(toDelete, ip)
		}
	}

	// Delete old entries
	for _, ip := range toDelete {
		delete(cm.ipToHostname, ip)
		delete(cm.ipToCNAMEOrigins, ip)
		delete(cm.ipLastSeen, ip)
	}

	if len(toDelete) > 0 {
		slog.Info("Cleaned up old DNS cache entries", "count", len(toDelete))
	}
}

// HostnameVerdict is the result of evaluating a hostname against the
// configured hostname rule set, accounting for search-domain stripping.
//
// Two rules can fire on a single lookup: one against the full hostname and
// one against its search-domain-stripped form. When the actions match,
// the verdict carries one side (deny ports unioned via UnionPorts,
// allow form picked via narrower-exact-wins). When actions differ — e.g.
// `*.compute.internal: deny 80` + `bastion: allow 22` querying
// `bastion.compute.internal` — BOTH sides are recorded so the firewall
// layer can write per-port BPF entries faithfully (deny 80, allow 22,
// fall-through to default elsewhere).
//
// Presence is signalled by the Rule attribution strings: an empty DenyRule
// means no deny matched; an empty AllowRule means no allow matched. The
// Rule strings are the rule's canonical-lowercase Value field — the
// hostname for non-pattern rules, the original glob string for pattern
// rules. Use them as audit identifiers.
//
// Port-slice semantics follow the existing convention: a non-nil but empty
// slice means "all ports"; a non-empty slice means exactly those ports.
// Port slices are defensive copies.
type HostnameVerdict struct {
	DenyPorts  []Port
	DenyRule   string
	AllowPorts []Port
	AllowRule  string
}

// HasDeny reports whether any deny rule matched.
func (v HostnameVerdict) HasDeny() bool { return v.DenyRule != "" }

// HasAllow reports whether any allow rule matched.
func (v HostnameVerdict) HasAllow() bool { return v.AllowRule != "" }

// Matched reports whether any rule (deny or allow) matched.
func (v HostnameVerdict) Matched() bool { return v.HasDeny() || v.HasAllow() }

// MatchHostnameRule evaluates `hostname` against the configured hostname
// rule set and returns a HostnameVerdict capturing every rule that fires.
//
// Match types considered: exact non-pattern hostnames, parent-domain rules
// where `hostname` is a subdomain, and glob patterns.
//
// Precedence within a single form:
//  1. Exact non-pattern hostname match wins outright.
//  2. A deny pattern match wins over a parent-domain allow ("more specific wins").
//  3. Otherwise: parent-domain match if any, else first allow-pattern match.
//
// Among parent-domain matches the longest suffix wins (e.g. `foo.example.com`
// beats `example.com` for `bar.foo.example.com`). Among equal-length deny or
// allow patterns the first in config order wins.
//
// Matching is case-insensitive end-to-end: rule values are normalized to
// lowercase at construction time (resolveRules / EnsureHostnameAllowed) and
// the lookup hostname is lowercased here.
//
// Search-domain composition. The full hostname and its search-domain-stripped
// form are each evaluated against the rule set independently, then folded
// into one verdict:
//
//   - Both deny: union the port lists (UnionPorts); attribute the
//     deny rule via pickDenyForm (narrower-exact-wins, broader-port-wins).
//   - Both allow: pick the allow rule via pickAllowForm (narrower-exact-wins).
//   - Mixed (one deny, one allow): both sides are recorded on the verdict
//     so callers can write per-port BPF entries faithfully.
//   - One match, one no-match: the matched side is recorded.
//   - No matches: zero verdict (Matched() == false).
//
// This contract means a deny rule for "blocked" still rejects
// "blocked.compute.internal" even when a broader allow for
// "compute.internal" also matches the full form, and a `bastion: allow 22`
// rule still allows port 22 on `bastion.compute.internal` even when
// `*.compute.internal: deny 80` denies port 80 on the same name.
func (cm *Manager) MatchHostnameRule(hostname string) HostnameVerdict {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	hostname = strings.ToLower(hostname)

	actionFull, portsFull, valueFull := cm.matchHostnameRuleLocked(hostname)
	stripped := cm.stripSearchDomainsLocked(hostname)
	if stripped == hostname {
		return singleFormVerdict(actionFull, portsFull, valueFull)
	}

	actionStripped, portsStripped, valueStripped := cm.matchHostnameRuleLocked(stripped)

	// Same-action: collapse into one side of the verdict.
	if actionFull == ActionDeny && actionStripped == ActionDeny {
		mergedPorts := UnionPorts(portsFull, portsStripped)
		denyRule := valueFull
		if pickDenyForm(valueFull, hostname, portsFull, valueStripped, stripped, portsStripped) {
			denyRule = valueStripped
		}
		return HostnameVerdict{DenyPorts: mergedPorts, DenyRule: denyRule}
	}
	if actionFull == ActionAllow && actionStripped == ActionAllow {
		if pickAllowForm(valueFull, hostname, valueStripped, stripped) {
			return HostnameVerdict{AllowPorts: portsStripped, AllowRule: valueStripped}
		}
		return HostnameVerdict{AllowPorts: portsFull, AllowRule: valueFull}
	}

	// One form matched, the other didn't.
	if actionStripped == "" {
		return singleFormVerdict(actionFull, portsFull, valueFull)
	}
	if actionFull == "" {
		return singleFormVerdict(actionStripped, portsStripped, valueStripped)
	}

	// Mixed: one deny, one allow. Record both sides so port-aware callers
	// (firewall writes) can emit faithful BPF entries.
	var v HostnameVerdict
	if actionFull == ActionDeny {
		v.DenyPorts, v.DenyRule = portsFull, valueFull
		v.AllowPorts, v.AllowRule = portsStripped, valueStripped
	} else {
		v.AllowPorts, v.AllowRule = portsFull, valueFull
		v.DenyPorts, v.DenyRule = portsStripped, valueStripped
	}
	return v
}

// singleFormVerdict packages a single (action, ports, value) tuple from
// matchHostnameRuleLocked into the corresponding HostnameVerdict side.
func singleFormVerdict(action Action, ports []Port, value string) HostnameVerdict {
	switch action {
	case ActionDeny:
		return HostnameVerdict{DenyPorts: ports, DenyRule: value}
	case ActionAllow:
		return HostnameVerdict{AllowPorts: ports, AllowRule: value}
	default:
		return HostnameVerdict{}
	}
}

// matchedExactly reports whether the rule whose Value-field is `ruleValue`
// matched `hostname` via the exact-match path inside matchHostnameRuleLocked
// (rather than parent-suffix or pattern). Exact rules store the queried
// hostname verbatim as their Value; parent rules store a shorter parent
// domain; pattern rules store the raw glob (e.g. "*.foo.com"). String
// equality with the lookup key uniquely identifies the exact path.
func matchedExactly(ruleValue, hostname string) bool {
	return ruleValue == hostname
}

// pickDenyForm encodes the both-deny attribution tiebreak shared by
// MatchHostnameRule and FindTrackedHostname: when search-domain stripping
// produces two matching deny rules (one on the full hostname, one on the
// stripped form), which form should the result attribute to?
//
// Precedence:
//  1. Exact-name match wins over parent/pattern (more specific by name scope).
//  2. Within same name-specificity, broader port coverage wins
//     (all-ports — empty Ports — absorbs any port-scoped rule).
//  3. Otherwise full form wins (stable default).
//
// Port UNION across both rules is the caller's job (see UnionPorts);
// this helper only decides which form's value/name supplies attribution.
func pickDenyForm(
	valueFull, name string, portsFull []Port,
	valueStripped, stripped string, portsStripped []Port,
) (strippedWins bool) {
	fullExact := matchedExactly(valueFull, name)
	strippedExact := matchedExactly(valueStripped, stripped)
	switch {
	case strippedExact && !fullExact:
		return true
	case fullExact && !strippedExact:
		return false
	case len(portsStripped) == 0 && len(portsFull) > 0:
		return true
	case len(portsFull) == 0 && len(portsStripped) > 0:
		return false
	default:
		return false
	}
}

// pickAllowForm encodes the both-allow narrower-exact-wins tiebreak shared
// by MatchHostnameRule and FindTrackedHostname: prefer the stripped form
// only when its rule matched exactly AND the full form's rule didn't
// (i.e. the stripped exact rule is strictly narrower than a full-form
// parent-suffix or pattern).
func pickAllowForm(valueFull, name, valueStripped, stripped string) (strippedWins bool) {
	return matchedExactly(valueStripped, stripped) && !matchedExactly(valueFull, name)
}

// matchHostnameRuleLocked is the lock-free / single-form core of
// MatchHostnameRule. Caller must hold cm.mu.RLock and pass an
// already-lowercased hostname.
func (cm *Manager) matchHostnameRuleLocked(hostname string) (Action, []Port, string) {
	// Single pass: classify each hostname rule into one of four candidates,
	// then apply precedence at the end. Equivalent to the prior two-pass
	// implementation but halves iterations of resolvedRules. Note we can't
	// short-circuit on a deny-pattern match mid-iteration because an exact
	// match later in the slice would supersede it (rule 1 in the precedence
	// docstring); collecting all candidates first preserves correctness.
	var exactRule, parentRule, denyPatternRule, allowPatternRule *ResolvedRule

	for i := range cm.resolvedRules {
		r := &cm.resolvedRules[i]
		if r.Type != RuleTypeHostname {
			continue
		}
		if r.Pattern == nil {
			if r.Value == hostname {
				exactRule = r
			} else if strings.HasSuffix(hostname, r.dotPrefix) &&
				(parentRule == nil || len(r.Value) > len(parentRule.Value)) {
				parentRule = r
			}
			continue
		}
		// Pattern rule.
		if !r.Pattern.Matches(hostname) {
			continue
		}
		if r.Action == ActionDeny {
			if denyPatternRule == nil {
				denyPatternRule = r
			}
		} else if allowPatternRule == nil {
			allowPatternRule = r
		}
	}

	if exactRule != nil {
		slog.Debug("Found exact match", "hostname", hostname, "action", exactRule.Action)
		return exactRule.Action, copyPorts(exactRule.Ports), exactRule.Value
	}
	if denyPatternRule != nil {
		slog.Debug("Found deny pattern match",
			"hostname", hostname,
			"pattern", denyPatternRule.Pattern.Raw)
		return ActionDeny, copyPorts(denyPatternRule.Ports), denyPatternRule.Value
	}
	if parentRule != nil {
		slog.Debug("Found parent domain match",
			"hostname", hostname,
			"parent", parentRule.Value,
			"action", parentRule.Action)
		return parentRule.Action, copyPorts(parentRule.Ports), parentRule.Value
	}
	if allowPatternRule != nil {
		slog.Debug("Found allow pattern match",
			"hostname", hostname,
			"pattern", allowPatternRule.Pattern.Raw)
		return allowPatternRule.Action, copyPorts(allowPatternRule.Ports), allowPatternRule.Value
	}

	slog.Debug("No tracked hostname found", "hostname", hostname)
	return "", nil, ""
}

// copyPorts returns a defensive copy of `ports` so callers can't mutate the
// Manager's live ruleset. Returns nil for an empty input to keep the
// "no port restriction" sentinel cheap.
func copyPorts(ports []Port) []Port {
	if len(ports) == 0 {
		return nil
	}
	out := make([]Port, len(ports))
	copy(out, ports)
	return out
}

// UnionPorts returns the union of two port lists from overlapping rules of the
// same action. An empty input means "all ports" — the broader of the two
// absorbs the other, so the merge is also empty. Otherwise the result is the
// deduplicated concatenation of p1 then p2 (Port is a comparable struct, so
// map-based dedup is exact across both Port number AND Protocol). Exported for
// the DNS layer, which unions the allow ports a CNAME target inherits from
// multiple allowed origins.
func UnionPorts(p1, p2 []Port) []Port {
	if len(p1) == 0 || len(p2) == 0 {
		return nil
	}
	seen := make(map[Port]struct{}, len(p1)+len(p2))
	out := make([]Port, 0, len(p1)+len(p2))
	for _, p := range p1 {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range p2 {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
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

		// normalizeRules promotes bare IPs to explicit /32 or /128 prefixes at
		// load time, so every valid CIDR rule parses here; the only ParseCIDR
		// failure left is a malformed value that resolveRules already logged
		// and skipped, so skip it here too. A /32 or /128 host route matches
		// only its exact IP via Contains, ranking most-specific at ones==32/128
		// (an IPv6 single IP correctly ranks as 128, not 32).
		_, ipnet, err := net.ParseCIDR(cm.config.Rules[i].Value)
		if err != nil {
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
					if hp.Port == cp.Port && ProtocolsOverlap(hp.Protocol, cp.Protocol) {
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

// FindTrackedHostname returns the attribution name of the rule that
// MatchHostnameRule would fire for `name` — empty when no rule matches.
// Used by callers (events.go reverse-DNS, gateExistingConnections) that
// then either re-run MatchHostnameRule on the returned name or display
// it in audit output; the returned name must therefore (a) yield the same
// verdict when re-looked-up via MatchHostnameRule, and (b) identify the
// concrete rule that fired.
//
// Matching is case-insensitive end-to-end: tracked-hostname keys are stored
// canonical-lowercase, and the input is lowercased here.
//
// All attribution decisions are driven by matchHostnameRuleLocked +
// chosenAttributionName so the longest-parent precedence (and the
// deny-pattern > parent precedence) match MatchHostnameRule exactly. An
// earlier implementation read the parent from a separate Go-map walk,
// which iterated in nondeterministic order and could disagree with
// MatchHostnameRule when multiple parent rules overlapped (e.g.
// "github.com" allow vs. "internal.github.com" deny for an
// "api.internal.github.com" lookup).
//
// Search-domain stripping is applied as a fallback: both the full name and
// the stripped form are consulted, with deny-anywhere precedence
// (mirrors MatchHostnameRule). Critically, BOTH forms' actions are
// checked before attributing to an allow — otherwise a full-form deny
// pattern (e.g. `*.compute.internal`) combined with a stripped-form
// allow (e.g. `bastion`) would attribute to the stripped allow, and a
// downstream re-lookup would late-allow traffic that should have been
// blocked.
func (cm *Manager) FindTrackedHostname(name string) string {
	name = strings.ToLower(name)

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	actionFull, portsFull, valueFull := cm.matchHostnameRuleLocked(name)
	stripped := cm.stripSearchDomainsLocked(name)
	if stripped == name {
		if actionFull == "" {
			return ""
		}
		return chosenAttributionName(name, valueFull)
	}

	actionStripped, portsStripped, valueStripped := cm.matchHostnameRuleLocked(stripped)

	switch {
	case actionFull == ActionDeny && actionStripped == ActionDeny:
		// Both denies — pickDenyForm picks the same rule MatchHostnameRule
		// would attribute, so audit attribution matches the verdict.
		if pickDenyForm(valueFull, name, portsFull, valueStripped, stripped, portsStripped) {
			return chosenAttributionName(stripped, valueStripped)
		}
		return chosenAttributionName(name, valueFull)
	case actionFull == ActionDeny:
		// Full form denies (typically a parent or pattern rule covering
		// the suffixed name). Attribute to the full form so downstream
		// MatchHostnameRule re-lookups preserve the deny.
		return chosenAttributionName(name, valueFull)
	case actionStripped == ActionDeny:
		return chosenAttributionName(stripped, valueStripped)
	}

	// Allow case — attribution flows through chosenAttributionName so
	// overlapping allow parents resolve to the same longest-suffix winner
	// MatchHostnameRule picks.
	switch {
	case actionFull == "" && actionStripped == "":
		return ""
	case actionFull == "":
		return chosenAttributionName(stripped, valueStripped)
	case actionStripped == "":
		return chosenAttributionName(name, valueFull)
	}
	if pickAllowForm(valueFull, name, valueStripped, stripped) {
		return chosenAttributionName(stripped, valueStripped)
	}
	return chosenAttributionName(name, valueFull)
}

// chosenAttributionName returns the hostname that corresponds to the rule
// selected by matchHostnameRuleLocked, given the lookup `name` and the rule's
// stored Value. Exact rules store `name` itself, so attribution is `name`.
// Pattern rules store a raw glob (with wildcards); attribution is the
// queried `name`. Parent rules store the parent's value; attribution is the
// parent. This ensures callers that re-lookup via MatchHostnameRule on the
// returned name see the same rule fire.
func chosenAttributionName(name, ruleValue string) string {
	if matchedExactly(ruleValue, name) || isHostnamePattern(ruleValue) {
		return name
	}
	return ruleValue
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
// ports, tagged with the given AutoAddedType (e.g. AutoAddedTypeAzureInfrastructure
// for Azure wireserver/IMDS).
func (cm *Manager) EnsureInfraAllowed(ips []string, ports []Port, autoAddedType AutoAddedType) {
	cm.ensureAllowed(ips, ports, autoAddedType)
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

		// normalizeRules promotes bare IPs to explicit /32 or /128 prefixes at
		// load time, so every valid CIDR rule parses and host routes match via
		// Contains; the only remaining ParseCIDR failure is a malformed value
		// resolveRules already skipped, so skip it here too.
		_, ipnet, err := net.ParseCIDR(rule.Value)
		if err != nil || !ipnet.Contains(ip) {
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

		// normalizeRules promotes bare IPs to explicit /32 or /128 prefixes at
		// load time, so every valid CIDR rule parses and host routes match via
		// Contains; the only remaining ParseCIDR failure is a malformed value
		// resolveRules already skipped, so skip it here too.
		_, ipnet, err := net.ParseCIDR(rule.Value)
		if err != nil || !ipnet.Contains(ip) {
			continue
		}

		// IP matches — check if ports cover our target port+protocol
		if len(rule.Ports) == 0 {
			// No port restriction means all ports are covered
			return true
		}
		for _, p := range rule.Ports {
			if p.Port == port.Port && ProtocolsOverlap(p.Protocol, port.Protocol) {
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
	// DNS names are case-insensitive — store canonical lowercase so
	// MatchHostnameRule's case-insensitive lookup finds these entries.
	hostname = strings.ToLower(hostname)

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
		dotPrefix:     "." + hostname,
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
	// Rule values are stored canonical-lowercase by normalizeRules at load
	// time; MatchesHostname does exact / suffix string equality so the
	// lookup key must also be lowercased.
	hostname = strings.ToLower(hostname)

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, rule := range cm.resolvedRules {
		if rule.Type != RuleTypeHostname || rule.AutoAddedType == AutoAddedTypeNone || rule.Action != ActionAllow {
			continue
		}
		if rule.MatchesHostname(hostname) {
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

// GetAutoAllowedType checks if a connection (ip, port, proto, hostname)
// matches an auto-added rule and returns the AutoAddedType. Hostname rules
// are checked first, then CIDR rules. Returns AutoAddedTypeNone if no
// auto-added rule matches.
//
// Pass ProtocolAll for `proto` when the caller doesn't know the L4
// protocol — that matches any rule that also uses ProtocolAll, plus TCP
// and UDP rules with the same port. Passing a specific protocol (TCP /
// UDP / ICMP) narrows the match to rules whose protocol overlaps via
// ProtocolsOverlap (consistent with hasCIDRRule).
//
// Hostname rules are checked first, then CIDR rules. This matters when an
// IP is covered by BOTH (e.g. github.com's resolved IP also falls inside
// a broader allow CIDR): the hostname attribution is more informative for
// audit output than the CIDR's, so we prefer it.
func (cm *Manager) GetAutoAllowedType(ip string, port uint16, proto ProtocolType, hostname string) AutoAddedType {
	// Rule values are stored canonical-lowercase; the hostname-rule pass
	// below compares via MatchesHostname (exact / suffix string equality)
	// so the lookup key must also be lowercased.
	hostname = strings.ToLower(hostname)

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	parsedIP := net.ParseIP(ip)

	// Pass 1: hostname rules. Two-pass so a hostname match wins attribution
	// over a CIDR match earlier in resolvedRules' insertion order.
	for _, rule := range cm.resolvedRules {
		if rule.Type != RuleTypeHostname {
			continue
		}
		if rule.AutoAddedType == AutoAddedTypeNone || rule.Action != ActionAllow {
			continue
		}
		if !autoAllowedPortMatch(rule.Ports, port, proto) {
			continue
		}
		if rule.MatchesHostname(hostname) {
			return rule.AutoAddedType
		}
	}
	// Pass 2: CIDR rules.
	for _, rule := range cm.resolvedRules {
		if rule.Type != RuleTypeCIDR {
			continue
		}
		if rule.AutoAddedType == AutoAddedTypeNone || rule.Action != ActionAllow {
			continue
		}
		if !autoAllowedPortMatch(rule.Ports, port, proto) {
			continue
		}
		if parsedIP != nil && rule.IPNet != nil && rule.IPNet.Contains(parsedIP) {
			return rule.AutoAddedType
		}
	}
	return AutoAddedTypeNone
}

// autoAllowedPortMatch reports whether (port, proto) is covered by the
// rule's Ports list. Empty Ports means "all ports" — no restriction.
// Otherwise both the port number AND protocol must match
// (ProtocolsOverlap handles ProtocolAll on either side).
func autoAllowedPortMatch(rulePorts []Port, port uint16, proto ProtocolType) bool {
	if len(rulePorts) == 0 {
		return true
	}
	for _, p := range rulePorts {
		if p.Port == port && ProtocolsOverlap(p.Protocol, proto) {
			return true
		}
	}
	return false
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

// GetSearchDomains returns a copy of the configured DNS search-domain
// suffixes. Callers can safely mutate the returned slice; their changes
// will not affect manager state.
//
// Hot paths (per-query DNS filtering) should prefer HasSearchDomainSuffix —
// the copy here is wasteful when callers only need a yes/no answer.
func (cm *Manager) GetSearchDomains() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil || len(cm.config.SearchDomains) == 0 {
		return nil
	}
	out := make([]string, len(cm.config.SearchDomains))
	copy(out, cm.config.SearchDomains)
	return out
}

// HasSearchDomainSuffix reports whether hostname ends in any configured
// search-domain suffix. Locks once, iterates the live slice without
// copying, and lowercases the input for case-insensitive matching
// (configured suffixes are already canonical-lowercase from
// normalizeSearchDomains).
//
// Use this on the DNS query-filtering hot path instead of GetSearchDomains:
// that variant allocates a fresh slice every call regardless of input. This
// variant skips the per-call slice copy; strings.ToLower itself returns its
// input unchanged when the hostname is already lowercase (the common case
// for DNS), so most queries hit zero allocations.
func (cm *Manager) HasSearchDomainSuffix(hostname string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil || len(cm.config.SearchDomains) == 0 {
		return false
	}
	lower := strings.ToLower(hostname)
	for _, suffix := range cm.config.SearchDomains {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// AddSearchDomains merges suffixes into the config. Invalid entries are
// individually skipped and logged as warnings via the supplied logger; valid
// entries from the same batch are still added. Auto-allow callers are
// in-process and expected to pass only known-good values, so a warning here
// flags a programming error worth surfacing without losing the good entries
// that ride alongside it.
//
// Like EnsureDNSAllowed / EnsureInfraAllowed / EnsureHostnameAllowed, this
// silently no-ops when no config has been loaded. The auto-allow path runs
// only after a successful config load, so a nil config here means a fallback
// path skipped earlier — keep behaviors uniform across helpers.
func (cm *Manager) AddSearchDomains(domains []string, logger *slog.Logger) {
	// Iterate the caller's slice (not the post-merge normalized form) so the
	// warning reports the original input that the caller passed. The
	// normalizeSearchDomains path dedupes and could otherwise misalign
	// indices, attributing a validation error to the wrong entry.
	valid := make([]string, 0, len(domains))
	for _, raw := range domains {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d != "" && !strings.HasPrefix(d, ".") {
			d = "." + d
		}
		if err := validateSearchDomain(d); err != nil {
			logger.Warn("Skipping invalid auto-added search domain", "domain", raw, "error", err)
			continue
		}
		valid = append(valid, d)
	}
	if len(valid) == 0 {
		return
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return
	}
	cm.config.SearchDomains = mergeNormalizedSearchDomains(cm.config.SearchDomains, valid)
}

// resolveRules resolves all hostname rules to IP addresses. Public wrapper
// for callers (tests) that don't already hold the write lock; the loaders
// call resolveRulesLocked directly to keep the config write and rule
// resolution atomic under a single critical section.
func (cm *Manager) resolveRules() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.resolveRulesLocked()
}

// resolveRulesLocked is the lock-held core of resolveRules. Caller must
// hold cm.mu.Lock. Used by the four loaders so the new config and its
// resolved-rule view are published atomically; readers can never observe
// "new cm.config + old cm.resolvedRules".
func (cm *Manager) resolveRulesLocked() error {
	slog.Info("Resolving rules", "count", len(cm.config.Rules))

	cm.resolvedRules = nil
	// Repopulate trackedHostnames from the new ruleset. Otherwise stale
	// entries from a prior config (e.g. the SaaS API hostname added by
	// EnsureHostnameAllowed during the bootstrap before LoadConfigFromCargoWall
	// replaces cm.config.Rules) cause EnsureHostnameAllowed to short-circuit
	// when called again — leaving the hostname unmatched at DNS-filter time.
	cm.trackedHostnames = make(map[string]Action)

	for _, rule := range cm.config.Rules {
		// Hostname rule values are canonical-lowercase by load-time
		// normalizeRules — both cm.config.Rules and cm.resolvedRules share
		// the same byte sequence here.
		resolved := ResolvedRule{
			Type:          rule.Type,
			Value:         rule.Value,
			Ports:         rule.Ports,
			Action:        rule.Action,
			AutoAddedType: rule.AutoAddedType,
		}

		switch rule.Type {
		case RuleTypeHostname:
			if isHostnamePattern(rule.Value) {
				pattern, err := compileHostnamePattern(rule.Value)
				if err != nil {
					slog.Error("Invalid hostname pattern", "value", rule.Value, "error", err)
					continue
				}
				resolved.Pattern = &pattern
			} else {
				// Pre-compute ".<value>" once so parent-domain checks on the
				// DNS hot path don't allocate.
				resolved.dotPrefix = "." + rule.Value

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
			}

		case RuleTypeCIDR:
			_, ipnet, err := net.ParseCIDR(rule.Value)
			if err != nil {
				// Load-time normalizeRules canonicalises bare IPs to explicit
				// /32 or /128 prefixes, so the ParseCIDR above succeeds for
				// every config-sourced rule. This single-IP fallback only
				// fires when resolveRules is driven directly with un-normalized
				// rules (the public resolveRules() test wrapper) — production
				// loaders always normalize first.
				ip := net.ParseIP(rule.Value)
				if ip == nil {
					slog.Error("Invalid CIDR/IP", "value", rule.Value, "error", err)
					continue
				}
				// Convert single IP to a host route: /32 for IPv4, /128 for IPv6.
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
