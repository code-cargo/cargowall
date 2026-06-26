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

package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// Firewall defines the interface for managing eBPF-based network filtering
type Firewall interface {
	// SetDefaultAction sets the default allow/deny action for unmatched packets
	SetDefaultAction(action config.Action) error

	// SetAuditMode enables or disables audit mode (log without blocking)
	SetAuditMode(enabled bool) error

	// UpdateAllowlistTC updates the eBPF LPM trie and port maps for firewall rules
	UpdateAllowlistTC(configMgr *config.Manager) error

	// AddIP adds a single IP to the BPF maps with the specified action and ports.
	// Returns (changed bool, error). `changed` is true if this call made any
	// observable change to BPF state — either a new/different LPM entry, or at
	// least one new/different per-port entry. A duplicate call that re-writes
	// identical state returns (false, nil). Per-port entries accumulate across
	// calls (set semantics): the same IP added under two hostname rules with
	// disjoint port sets ends up with both port sets in the map, and RemoveIP
	// will clean up all of them. An all-ports add (empty ports) marks the IP as
	// all-ports; that PortSpecific=0 state is sticky, so a later port-specific
	// add for the same IP cannot silently narrow it back to specific ports.
	// Conflict precedence on a shared IP: all-ports deny beats all-ports allow,
	// and any all-ports grant beats a port-specific contribution of the opposite
	// action (the port entry is written-skipped and the dropped intent logged) —
	// see ipPortState.
	AddIP(ip net.IP, action config.Action, ports []config.Port) (bool, error)

	// RemoveIP removes a single IP from the BPF maps
	RemoveIP(ip net.IP) error
}

// mapOps abstracts eBPF map operations for testability.
type mapOps interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Lookup(key, valueOut any) error
	Delete(key any) error
}

// FirewallImpl manages the eBPF maps for network filtering
type FirewallImpl struct {
	cidrsMap         mapOps
	portsMap         mapOps
	cidrsV6Map       mapOps
	portsV6Map       mapOps
	defaultActionMap mapOps
	auditModeMap     mapOps
	logger           *slog.Logger
	mu               sync.RWMutex

	// Per-IP accumulated firewall state, keyed by IP string. Tracks the union of
	// port-specific entries (for cleanup) plus the sticky all-ports grant, so a
	// shared IP's effective LPM entry reflects every rule that resolved to it.
	ipPorts map[string]*ipPortState
}

// portProto carries a port number and its IANA protocol number for BPF map keys.
type portProto struct {
	Port  uint16
	Proto uint8 // protoTCP=6, protoUDP=17, protoICMP=1
}

const (
	protoICMP uint8 = 1
	protoTCP  uint8 = 6
	protoUDP  uint8 = 17
)

// ipPortState accumulates every firewall contribution for a single host IP
// (/32 or /128) across the AddIP and UpdateAllowlistTC write paths, so the
// effective BPF LPM entry reflects the union of all rules that resolved to it
// rather than only the most recent call.
//
// A shared CDN/edge IP is routinely added under several hostname rules with
// different port scopes — e.g. an all-ports OCSP/CRL responder and a
// port-specific content host. The LPM entry can express only "all ports"
// (PortSpecific=0, governed by Action) or "consult map_ports" (PortSpecific=1);
// it cannot say "these ports AND all ports". Tracking the contributors here lets
// addIPv4Locked/addIPv6Locked recompute the single correct LPM value on every
// call so an all-ports grant is not silently narrowed by a later port-specific
// add, and a port-specific grant's entries are not deleted by a later all-ports
// add (issue #71).
//
// Precedence when contributions conflict (inherent to the BPF model, which
// can't express "allow all except port N"):
//   - all-ports DENY wins over all-ports ALLOW: a host the policy denies
//     outright must not be re-opened by an unrelated hostname sharing the IP.
//   - an all-ports grant wins over a port-specific contribution of the opposite
//     action — the per-port entry is written but inert under PortSpecific=0.
//     This keeps issue #71's "don't block legitimately-allowed traffic"
//     guarantee, at the cost of a port-specific deny being unenforceable on a
//     shared all-ports-allowed IP. addIPv4Locked/addIPv6Locked log a Warn when
//     this drops a rule's intent so it isn't silent.
//
// Both flags are sticky for the IP's lifetime (cleared only by a whole-IP
// RemoveIP), matching the firewall's add-only model elsewhere (UpdateAllowlistTC
// never removes; RemoveIP has no runtime callers). They are bools, not counts,
// because DNS re-resolution re-issues the same AddIP on every TTL refresh — a
// count would inflate without bound while a single RemoveIP clears the whole IP.
type ipPortState struct {
	allPortsAllow bool
	allPortsDeny  bool
	// ports is the union of every port-specific (port, proto) entry written to
	// map_ports for this IP, retained so RemoveIP can delete the full set. Port
	// entries that would be inert (added while an all-ports grant is already
	// active) are neither written nor tracked here.
	ports []portProto
}

// seedFromLPM initializes the sticky all-ports flags from an LPM entry that
// already exists in BPF when this process first tracks the IP — e.g. one written
// by an earlier UpdateAllowlistTC pass. Without this, a port-specific add
// arriving before the all-ports hostname re-resolves would start from empty
// state and flip an existing PortSpecific=0 grant back to PortSpecific=1,
// re-introducing the narrowing bug.
func (st *ipPortState) seedFromLPM(existing bpf.TcBpfLpmVal) {
	if existing.PortSpecific != 0 {
		return
	}
	if existing.Action == 1 {
		st.allPortsAllow = true
	} else {
		st.allPortsDeny = true
	}
}

// hasAllPorts reports whether any all-ports grant is active for the IP, in which
// case a port-specific add would be inert (BPF ignores map_ports under
// PortSpecific=0).
func (st *ipPortState) hasAllPorts() bool {
	return st.allPortsAllow || st.allPortsDeny
}

// recordAllPorts marks an all-ports grant of the given action.
func (st *ipPortState) recordAllPorts(actionVal uint8) {
	if actionVal == 1 {
		st.allPortsAllow = true
	} else {
		st.allPortsDeny = true
	}
}

// effectiveLPMVal computes the single LPM value representing all accumulated
// contributors. callActionVal is used only for the port-specific case: BPF
// ignores the LPM action when PortSpecific=1 (it decides per packet from
// map_ports), so we carry the current call's action purely for a readable map.
func (st *ipPortState) effectiveLPMVal(callActionVal uint8) bpf.TcBpfLpmVal {
	switch {
	case st.allPortsDeny:
		return bpf.TcBpfLpmVal{Action: 0, PortSpecific: 0}
	case st.allPortsAllow:
		return bpf.TcBpfLpmVal{Action: 1, PortSpecific: 0}
	default:
		return bpf.TcBpfLpmVal{Action: callActionVal, PortSpecific: 1}
	}
}

// actionName renders a BPF action byte for human-readable logs.
func actionName(actionVal uint8) string {
	if actionVal == 1 {
		return "allow"
	}
	return "deny"
}

// NewFirewall creates a new firewall instance that owns the eBPF maps
func NewFirewall(cidrsMap, portsMap, cidrsV6Map, portsV6Map, defaultActionMap, auditModeMap *ebpf.Map, logger *slog.Logger) Firewall {
	return &FirewallImpl{
		cidrsMap:         cidrsMap,
		portsMap:         portsMap,
		cidrsV6Map:       cidrsV6Map,
		portsV6Map:       portsV6Map,
		defaultActionMap: defaultActionMap,
		auditModeMap:     auditModeMap,
		logger:           logger,
		ipPorts:          make(map[string]*ipPortState),
	}
}

// SetDefaultAction sets the default allow/deny action for unmatched packets
func (f *FirewallImpl) SetDefaultAction(action config.Action) error {
	var actionVal uint8 = 0
	if action == config.ActionAllow {
		actionVal = 1
	}

	key := uint32(0)
	if err := f.defaultActionMap.Update(key, actionVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to set default action: %w", err)
	}

	f.logger.Info("Set default action", "action", action)
	return nil
}

// SetAuditMode enables or disables audit mode (log without blocking)
func (f *FirewallImpl) SetAuditMode(enabled bool) error {
	var auditVal uint8 = 0
	if enabled {
		auditVal = 1
	}

	key := uint32(0)
	if err := f.auditModeMap.Update(key, auditVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to set audit mode: %w", err)
	}

	f.logger.Info("Set audit mode", "enabled", enabled)
	return nil
}

// UpdateAllowlistTC updates the eBPF LPM trie and port maps for firewall rules.
// NOTE: This is add-only — it does not remove stale entries from previous calls.
// Callers should be aware that entries accumulate across invocations.
func (f *FirewallImpl) UpdateAllowlistTC(configMgr *config.Manager) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Process all resolved rules - both CIDR and resolved hostnames
	for _, rule := range configMgr.GetResolvedRules() {
		// Determine action value
		var actionVal uint8 = 0
		if rule.Action == config.ActionAllow {
			actionVal = 1
		}

		// Process based on rule type
		switch rule.Type {
		case config.RuleTypeCIDR:
			if rule.IPNet == nil {
				continue // Skip invalid CIDR rules
			}

			ones, _ := rule.IPNet.Mask.Size()

			// Expand ports with protocol info for BPF maps
			portValues := expandPorts(rule.Ports)

			// Check if this is an IPv6 CIDR
			if ip4 := rule.IPNet.IP.To4(); ip4 != nil {
				// IPv4 CIDR

				// Special handling for 0.0.0.0/0 with specific ports
				// Don't add to LPM trie, only to port map
				if rule.Value == "0.0.0.0/0" && len(portValues) > 0 {
					for _, pp := range portValues {
						portKey := bpf.TcBpfPortKey{
							Ip:    0,
							Port:  pp.Port,
							Proto: pp.Proto,
						}
						portVal := bpf.TcBpfPortVal{
							Action: actionVal,
						}
						if err := f.portsMap.Update(&portKey, &portVal, ebpf.UpdateAny); err != nil {
							return fmt.Errorf("update port map for wildcard port %d proto %d: %w", pp.Port, pp.Proto, err)
						}
					}
					continue
				}

				if err := f.addCIDRv4(ip4, uint32(ones), actionVal, portValues, rule.Value); err != nil {
					return err
				}
			} else {
				// IPv6 CIDR
				ip6 := rule.IPNet.IP.To16()
				if ip6 == nil {
					continue
				}

				// Special handling for ::/0 with specific ports
				if rule.Value == "::/0" && len(portValues) > 0 {
					for _, pp := range portValues {
						portKey := bpf.TcBpfPortKeyV6{
							Port:  pp.Port,
							Proto: pp.Proto,
						}
						portVal := bpf.TcBpfPortVal{
							Action: actionVal,
						}
						if err := f.portsV6Map.Update(&portKey, &portVal, ebpf.UpdateAny); err != nil {
							return fmt.Errorf("update v6 port map for wildcard port %d proto %d: %w", pp.Port, pp.Proto, err)
						}
					}
					continue
				}

				if err := f.addCIDRv6(ip6, uint32(ones), actionVal, portValues, rule.Value); err != nil {
					return err
				}
			}

		case config.RuleTypeHostname:
			// Resolved hostnames are added as /32 or /128 entries
			hostPortValues := expandPorts(rule.Ports)
			for _, ip := range rule.IPs {
				if ip4 := ip.To4(); ip4 != nil {
					if err := f.addCIDRv4(ip4, 32, actionVal, hostPortValues, rule.Value); err != nil {
						return err
					}
				} else if ip6 := ip.To16(); ip6 != nil {
					if err := f.addCIDRv6(ip6, 128, actionVal, hostPortValues, rule.Value); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// addCIDRv4 adds an IPv4 CIDR to the BPF LPM trie and optional port maps.
// Must be called with f.mu held.
func (f *FirewallImpl) addCIDRv4(ip4 net.IP, prefixLen uint32, actionVal uint8, ports []portProto, label string) error {
	// Host routes (/32) share the per-IP accumulator with AddIP so a shared IP
	// contributed by both a static rule and a DNS resolution keeps the union of
	// all its rules instead of last-write-wins narrowing (issue #71). Genuine
	// subnets fall through to a direct LPM write — their port entries are keyed
	// by the network address, a separate pre-existing concern.
	if prefixLen == 32 {
		_, err := f.addIPv4Locked(ip4, ip4.String(), actionVal, ports)
		return err
	}

	// NativeEndian so the uint32 bytes in the map key are in network byte order,
	// which is required for LPM trie prefix matching.
	ipUint32 := binary.NativeEndian.Uint32(ip4)

	key := bpf.TcBpfLpmKey{
		Prefixlen: prefixLen,
		Ip:        ipUint32,
	}
	val := bpf.TcBpfLpmVal{
		Action:       actionVal,
		PortSpecific: 0,
	}

	if len(ports) > 0 {
		val.PortSpecific = 1
		for _, pp := range ports {
			portKey := bpf.TcBpfPortKey{
				Ip:    ipUint32,
				Port:  pp.Port,
				Proto: pp.Proto,
			}
			portVal := bpf.TcBpfPortVal{
				Action: actionVal,
			}
			if err := f.portsMap.Update(&portKey, &portVal, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update port map for %s port %d proto %d: %w", label, pp.Port, pp.Proto, err)
			}
		}
	}

	if err := f.cidrsMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update LPM trie for %s: %w", label, err)
	}
	return nil
}

// addCIDRv6 adds an IPv6 CIDR to the BPF v6 LPM trie and optional port maps.
// Must be called with f.mu held.
func (f *FirewallImpl) addCIDRv6(ip6 net.IP, prefixLen uint32, actionVal uint8, ports []portProto, label string) error {
	// Host routes (/128) share the per-IP accumulator with AddIP — see addCIDRv4.
	// addIPv6Locked applies prepV6Ports itself, so pass the unfiltered ports.
	if prefixLen == 128 {
		_, err := f.addIPv6Locked(ip6, ip6.String(), actionVal, ports)
		return err
	}

	ports, skip := f.prepV6Ports(ports, "label", label)
	if skip {
		return nil
	}

	var key bpf.TcBpfLpmKeyV6
	key.Prefixlen = prefixLen
	copy(key.Ip[:], ip6)

	val := bpf.TcBpfLpmVal{
		Action:       actionVal,
		PortSpecific: 0,
	}

	if len(ports) > 0 {
		val.PortSpecific = 1
		for _, pp := range ports {
			var portKey bpf.TcBpfPortKeyV6
			copy(portKey.Ip[:], ip6)
			portKey.Port = pp.Port
			portKey.Proto = pp.Proto
			portVal := bpf.TcBpfPortVal{
				Action: actionVal,
			}
			if err := f.portsV6Map.Update(&portKey, &portVal, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update v6 port map for %s port %d proto %d: %w", label, pp.Port, pp.Proto, err)
			}
		}
	}

	if err := f.cidrsV6Map.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update v6 LPM trie for %s: %w", label, err)
	}
	return nil
}

// expandPorts converts config.Port entries into portProto values for BPF map keys.
// ProtocolAll expands to ICMP, TCP, and UDP entries so that the BPF lookup
// (which always uses the packet's exact protocol) matches correctly.
func expandPorts(ports []config.Port) []portProto {
	if len(ports) == 0 {
		return nil
	}
	result := make([]portProto, 0, len(ports)*3)
	for _, p := range ports {
		switch p.Protocol {
		case config.ProtocolTCP:
			result = append(result, portProto{Port: p.Port, Proto: protoTCP})
		case config.ProtocolUDP:
			result = append(result, portProto{Port: p.Port, Proto: protoUDP})
		case config.ProtocolICMP:
			result = append(result, portProto{Port: 0, Proto: protoICMP})
		case config.ProtocolAll:
			result = append(result, portProto{Port: 0, Proto: protoICMP})
			result = append(result, portProto{Port: p.Port, Proto: protoTCP})
			result = append(result, portProto{Port: p.Port, Proto: protoUDP})
		default:
			slog.Warn("Unknown protocol in port rule, skipping", "port", p.Port, "protocol", p.Protocol)
		}
	}
	return result
}

// stripICMPForV6 removes ICMP entries from a port list destined for the v6 BPF
// maps. The v6 BPF data path (bpf/tcbpf.c, IPPROTO_ICMPV6 early-return)
// unconditionally allows ICMPv6 before consulting the port map for NDP, so a
// v6 port-map entry with proto=ICMP is dead and leaving PortSpecific=1 on the
// LPM entry silently blackholes TCP/UDP. Returns the input slice unchanged in
// the common case where no ICMP entries are present; otherwise allocates a
// new slice (rule-load is not a hot path).
func stripICMPForV6(ports []portProto) ([]portProto, bool) {
	hasICMP := false
	for _, pp := range ports {
		if pp.Proto == protoICMP {
			hasICMP = true
			break
		}
	}
	if !hasICMP {
		return ports, false
	}
	filtered := make([]portProto, 0, len(ports)-1)
	for _, pp := range ports {
		if pp.Proto == protoICMP {
			continue
		}
		filtered = append(filtered, pp)
	}
	return filtered, true
}

// prepV6Ports applies stripICMPForV6, logs when entries are dropped, and
// reports whether the caller should skip the v6 write entirely (ICMP-only
// rule — ICMPv6 is already unconditionally allowed by BPF, so writing a
// PortSpecific=0 LPM entry would silently broaden to allow-all TCP/UDP and
// PortSpecific=1 with no port entries would blackhole TCP/UDP).
func (f *FirewallImpl) prepV6Ports(ports []portProto, labelKey, labelVal string) ([]portProto, bool) {
	filtered, dropped := stripICMPForV6(ports)
	skip := dropped && len(filtered) == 0
	switch {
	case skip:
		// Whole rule is ICMP-only on v6: user's explicit intent is being satisfied
		// only by the unconditional ICMPv6 allow in BPF. Worth surfacing so an
		// operator debugging "why does v6 ICMP still work with cargowall?" or
		// "why doesn't my ICMP rule restrict anything?" sees why.
		f.logger.Warn("Skipping v6 rule: ICMP-only and ICMPv6 is unconditionally allowed", labelKey, labelVal)
	case dropped:
		// ICMP mixed with TCP/UDP — common under ProtocolAll expansion; noisy.
		f.logger.Debug("Dropping ICMP port(s) from v6 rule; ICMPv6 is always allowed", labelKey, labelVal)
	}
	return filtered, skip
}

// AddIP adds a single IP to the BPF maps with the specified action and ports.
// Returns (changed bool, error). `changed` is true if the call made an
// observable change to BPF state — a new/different LPM entry, or at least one
// new/different effective per-port entry. A duplicate call that re-writes
// identical state, or a port-specific add that is inert under an existing
// all-ports grant, returns (false, nil). See the Firewall interface for the
// accumulation and all-ports-stickiness semantics.
func (f *FirewallImpl) AddIP(ip net.IP, action config.Action, ports []config.Port) (bool, error) {
	pp := expandPorts(ports)
	var actionVal uint8 = 0
	if action == config.ActionAllow {
		actionVal = 1
	}
	if ip4 := ip.To4(); ip4 != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.addIPv4Locked(ip4, ip.String(), actionVal, pp)
	}
	if ip6 := ip.To16(); ip6 != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.addIPv6Locked(ip6, ip.String(), actionVal, pp)
	}
	return false, fmt.Errorf("invalid IP: %s", ip.String())
}

// addIPv4Locked is the shared accumulator core for IPv4 /32 host entries, used
// by both AddIP and UpdateAllowlistTC (via addCIDRv4). Must be called with
// f.mu held.
func (f *FirewallImpl) addIPv4Locked(ip4 net.IP, ipStr string, actionVal uint8, ports []portProto) (bool, error) {
	ipUint32 := binary.NativeEndian.Uint32(ip4)

	key := bpf.TcBpfLpmKey{
		Prefixlen: 32,
		Ip:        ipUint32,
	}

	var existingVal bpf.TcBpfLpmVal
	ipExists := f.cidrsMap.Lookup(&key, &existingVal) == nil

	// Fetch or create this IP's accumulator. On first touch, seed the sticky
	// all-ports flags from any pre-existing LPM entry so a PortSpecific=0 grant
	// isn't flipped back to PortSpecific=1 by this add.
	st := f.ipPorts[ipStr]
	if st == nil {
		st = &ipPortState{}
		if ipExists {
			st.seedFromLPM(existingVal)
		}
		f.ipPorts[ipStr] = st
	}

	portsChanged, err := f.writePortsV4(ipUint32, ipStr, actionVal, ports, st)
	if err != nil {
		return false, err
	}

	val := st.effectiveLPMVal(actionVal)
	if ipExists && existingVal.Action == val.Action && existingVal.PortSpecific == val.PortSpecific {
		return portsChanged, nil
	}

	if err := f.cidrsMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("failed to add IP to LPM trie: %w", err)
	}

	return true, nil
}

// writePortsV4 folds one contribution's ports into st and writes the effective
// per-port entries to map_ports, returning whether any were new/different.
//
// An empty port set marks an all-ports grant. A port-specific set whose entries
// would be inert (an all-ports grant is already active, so BPF ignores
// map_ports under PortSpecific=0) is neither written nor tracked — writing it
// would be a wasted syscall, a permanent inert slot in the bounded map, and a
// spurious `changed=true`. When such a contribution's action conflicts with the
// active grant, the dropped intent is logged so it isn't silent (issue #71).
//
// Otherwise the per-port entries are written unconditionally, before the LPM
// no-op check: a shared IP added under two rules with disjoint port sets must
// still get the second rule's entries even when the LPM value is unchanged, or
// the retry on the new port is blackholed. Map writes are idempotent.
func (f *FirewallImpl) writePortsV4(ipUint32 uint32, ipStr string, actionVal uint8, ports []portProto, st *ipPortState) (bool, error) {
	if len(ports) == 0 {
		st.recordAllPorts(actionVal)
		return false, nil
	}
	if st.hasAllPorts() {
		f.warnInertPorts(ipStr, actionVal, ports, st)
		return false, nil
	}

	var portsChanged bool
	for _, pp := range ports {
		portKey := bpf.TcBpfPortKey{
			Ip:    ipUint32,
			Port:  pp.Port,
			Proto: pp.Proto,
		}
		var existingPortVal bpf.TcBpfPortVal
		if errLookup := f.portsMap.Lookup(&portKey, &existingPortVal); errLookup != nil || existingPortVal.Action != actionVal {
			portsChanged = true
		}
		portVal := bpf.TcBpfPortVal{
			Action: actionVal,
		}
		if err := f.portsMap.Update(&portKey, &portVal, ebpf.UpdateAny); err != nil {
			return false, fmt.Errorf("failed to add port %d proto %d to map: %w", pp.Port, pp.Proto, err)
		}
	}
	st.ports = mergePorts(st.ports, ports)
	return portsChanged, nil
}

// warnInertPorts logs when a port-specific contribution is dropped because an
// all-ports grant already governs the IP and its action conflicts with that
// grant (the BPF model can't express "allow all except port N"). A same-action
// contribution (e.g. a port-specific allow under an all-ports allow) is a
// harmless no-op and stays silent.
func (f *FirewallImpl) warnInertPorts(ipStr string, actionVal uint8, ports []portProto, st *ipPortState) {
	effective := uint8(1)
	if st.allPortsDeny {
		effective = 0
	}
	if effective == actionVal {
		return
	}
	f.logger.Warn("Port-specific rule has no effect: IP already has an all-ports grant",
		"ip", ipStr,
		"all_ports_action", actionName(effective),
		"rule_action", actionName(actionVal),
		"ignored_ports", ports)
}

// mergePorts returns the union of two []portProto slices (set semantics),
// preserving existing-first ordering and appending only entries not already
// present. Used by writePortsV4/writePortsV6 to track the cumulative port set
// written for an IP across multiple AddIP calls.
//
// Always returns a freshly-allocated slice — never aliases the inputs — so a
// future caller that retains either input can't accidentally observe mutations
// when the result grows.
func mergePorts(existing, additions []portProto) []portProto {
	out := make([]portProto, 0, len(existing)+len(additions))
	out = append(out, existing...)
	if len(existing) == 0 {
		return append(out, additions...)
	}
	seen := make(map[portProto]bool, len(existing))
	for _, pp := range existing {
		seen[pp] = true
	}
	for _, pp := range additions {
		if !seen[pp] {
			out = append(out, pp)
			seen[pp] = true
		}
	}
	return out
}

// addIPv6Locked is the shared accumulator core for IPv6 /128 host entries, used
// by both AddIP and UpdateAllowlistTC (via addCIDRv6). Must be called with
// f.mu held.
func (f *FirewallImpl) addIPv6Locked(ip6 net.IP, ipStr string, actionVal uint8, ports []portProto) (bool, error) {
	ports, skip := f.prepV6Ports(ports, "ip", ipStr)
	if skip {
		return false, nil
	}

	var key bpf.TcBpfLpmKeyV6
	key.Prefixlen = 128
	copy(key.Ip[:], ip6)

	var existingVal bpf.TcBpfLpmVal
	ipExists := f.cidrsV6Map.Lookup(&key, &existingVal) == nil

	// See addIPv4Locked for the accumulator/seeding rationale.
	st := f.ipPorts[ipStr]
	if st == nil {
		st = &ipPortState{}
		if ipExists {
			st.seedFromLPM(existingVal)
		}
		f.ipPorts[ipStr] = st
	}

	portsChanged, err := f.writePortsV6(ip6, ipStr, actionVal, ports, st)
	if err != nil {
		return false, err
	}

	val := st.effectiveLPMVal(actionVal)
	if ipExists && existingVal.Action == val.Action && existingVal.PortSpecific == val.PortSpecific {
		return portsChanged, nil
	}

	if err := f.cidrsV6Map.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("failed to add IPv6 to LPM trie: %w", err)
	}

	return true, nil
}

// writePortsV6 is the IPv6 twin of writePortsV4 — see it for the inert-port
// skip, conflict warning, and disjoint-port rationale.
func (f *FirewallImpl) writePortsV6(ip6 net.IP, ipStr string, actionVal uint8, ports []portProto, st *ipPortState) (bool, error) {
	if len(ports) == 0 {
		st.recordAllPorts(actionVal)
		return false, nil
	}
	if st.hasAllPorts() {
		f.warnInertPorts(ipStr, actionVal, ports, st)
		return false, nil
	}

	var portsChanged bool
	for _, pp := range ports {
		var portKey bpf.TcBpfPortKeyV6
		copy(portKey.Ip[:], ip6)
		portKey.Port = pp.Port
		portKey.Proto = pp.Proto
		var existingPortVal bpf.TcBpfPortVal
		if errLookup := f.portsV6Map.Lookup(&portKey, &existingPortVal); errLookup != nil || existingPortVal.Action != actionVal {
			portsChanged = true
		}
		portVal := bpf.TcBpfPortVal{
			Action: actionVal,
		}
		if err := f.portsV6Map.Update(&portKey, &portVal, ebpf.UpdateAny); err != nil {
			return false, fmt.Errorf("failed to add v6 port %d proto %d to map: %w", pp.Port, pp.Proto, err)
		}
	}
	st.ports = mergePorts(st.ports, ports)
	return portsChanged, nil
}

// RemoveIP removes a single IP from the BPF maps
func (f *FirewallImpl) RemoveIP(ip net.IP) error {
	if ip4 := ip.To4(); ip4 != nil {
		return f.removeIPv4(ip4, ip)
	}
	if ip6 := ip.To16(); ip6 != nil {
		return f.removeIPv6(ip6, ip)
	}
	return fmt.Errorf("invalid IP: %s", ip.String())
}

func (f *FirewallImpl) removeIPv4(ip4 net.IP, origIP net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	ipUint32 := binary.NativeEndian.Uint32(ip4)

	key := bpf.TcBpfLpmKey{
		Prefixlen: 32,
		Ip:        ipUint32,
	}

	if err := f.cidrsMap.Delete(&key); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to remove IP from LPM trie: %w", err)
		}
	}

	ipStr := origIP.String()
	if st, exists := f.ipPorts[ipStr]; exists {
		for _, pp := range st.ports {
			portKey := bpf.TcBpfPortKey{
				Ip:    ipUint32,
				Port:  pp.Port,
				Proto: pp.Proto,
			}
			if err := f.portsMap.Delete(&portKey); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					f.logger.Debug("Failed to remove port entry",
						"ip", ipStr,
						"port", pp.Port,
						"proto", pp.Proto,
						"error", err)
				}
			}
		}
		delete(f.ipPorts, ipStr)
	}

	return nil
}

func (f *FirewallImpl) removeIPv6(ip6 net.IP, origIP net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var key bpf.TcBpfLpmKeyV6
	key.Prefixlen = 128
	copy(key.Ip[:], ip6)

	if err := f.cidrsV6Map.Delete(&key); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to remove IPv6 from LPM trie: %w", err)
		}
	}

	ipStr := origIP.String()
	if st, exists := f.ipPorts[ipStr]; exists {
		for _, pp := range st.ports {
			var portKey bpf.TcBpfPortKeyV6
			copy(portKey.Ip[:], ip6)
			portKey.Port = pp.Port
			portKey.Proto = pp.Proto
			if err := f.portsV6Map.Delete(&portKey); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					f.logger.Debug("Failed to remove v6 port entry",
						"ip", ipStr,
						"port", pp.Port,
						"proto", pp.Proto,
						"error", err)
				}
			}
		}
		delete(f.ipPorts, ipStr)
	}

	return nil
}
