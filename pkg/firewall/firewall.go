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
	// will clean up all of them.
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

	// Track which ports are associated with each IP for proper cleanup
	ipPorts map[string][]portProto // IP string -> port+protocol pairs
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
		ipPorts:          make(map[string][]portProto),
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

// AddIP adds a single IP to the BPF maps with the specified action and ports
// Returns (wasAdded bool, error) - wasAdded is true if the IP was newly added, false if it was a duplicate
func (f *FirewallImpl) AddIP(ip net.IP, action config.Action, ports []config.Port) (bool, error) {
	pp := expandPorts(ports)
	if ip4 := ip.To4(); ip4 != nil {
		return f.addIPv4(ip4, ip, action, pp)
	}
	if ip6 := ip.To16(); ip6 != nil {
		return f.addIPv6(ip6, ip, action, pp)
	}
	return false, fmt.Errorf("invalid IP: %s", ip.String())
}

func (f *FirewallImpl) addIPv4(ip4 net.IP, origIP net.IP, action config.Action, ports []portProto) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	ipUint32 := binary.NativeEndian.Uint32(ip4)
	ipStr := origIP.String()

	key := bpf.TcBpfLpmKey{
		Prefixlen: 32,
		Ip:        ipUint32,
	}

	var existingVal bpf.TcBpfLpmVal
	err := f.cidrsMap.Lookup(&key, &existingVal)
	ipExists := err == nil

	var actionVal uint8 = 0
	if action == config.ActionAllow {
		actionVal = 1
	}

	val := bpf.TcBpfLpmVal{
		Action:       actionVal,
		PortSpecific: 0,
	}

	if len(ports) > 0 {
		val.PortSpecific = 1
	}

	// Write per-port entries unconditionally (before the LPM no-op check). When
	// an IP is shared across hostname rules with disjoint port sets — e.g.
	// foo.example.com→:443 and bar.example.com→:8080 both resolving to the same
	// cloud IP — the LPM (Action, PortSpecific) check would otherwise short-
	// circuit the second call and silently leave the new (port, proto) entries
	// missing from map_ports, blackholing the retry. Map writes are idempotent.
	//
	// portsChanged tracks whether any per-port entry was new or had a
	// different value — feeds the `changed` return so callers' INFO logs
	// fire on shared-IP-different-ports calls (LPM unchanged, ports new).
	var portsChanged bool
	if len(ports) > 0 {
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
		// Track every (port, proto) we've written for this IP across all
		// AddIP calls (set semantics) so RemoveIP cleans up the full set.
		// Without this, a second call with disjoint ports leaves the first
		// call's entries orphaned in map_ports after RemoveIP.
		f.ipPorts[ipStr] = mergePorts(f.ipPorts[ipStr], ports)
	}

	if ipExists && existingVal.Action == val.Action && existingVal.PortSpecific == val.PortSpecific {
		return portsChanged, nil
	}

	if err := f.cidrsMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("failed to add IP to LPM trie: %w", err)
	}

	// Transitioning to PortSpecific=0 (no port restrictions): the new LPM
	// entry tells BPF to ignore map_ports for this IP, so any per-port entries
	// we previously wrote are dead. Delete them now — once we drop ipPorts
	// below, RemoveIP loses all knowledge of them and they'd leak forever.
	if len(ports) == 0 {
		for _, pp := range f.ipPorts[ipStr] {
			portKey := bpf.TcBpfPortKey{
				Ip:    ipUint32,
				Port:  pp.Port,
				Proto: pp.Proto,
			}
			if err := f.portsMap.Delete(&portKey); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					f.logger.Debug("Failed to remove stale port entry on PortSpecific=0 transition",
						"ip", ipStr, "port", pp.Port, "proto", pp.Proto, "error", err)
				}
			}
		}
		delete(f.ipPorts, ipStr)
	}

	return true, nil
}

// mergePorts returns the union of two []portProto slices (set semantics),
// preserving existing-first ordering and appending only entries not already
// present. Used by addIPv4/addIPv6 to track the cumulative port set written
// for an IP across multiple AddIP calls.
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

func (f *FirewallImpl) addIPv6(ip6 net.IP, origIP net.IP, action config.Action, ports []portProto) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	ports, skip := f.prepV6Ports(ports, "ip", origIP.String())
	if skip {
		return false, nil
	}

	ipStr := origIP.String()

	var key bpf.TcBpfLpmKeyV6
	key.Prefixlen = 128
	copy(key.Ip[:], ip6)

	var existingVal bpf.TcBpfLpmVal
	err := f.cidrsV6Map.Lookup(&key, &existingVal)
	ipExists := err == nil

	var actionVal uint8 = 0
	if action == config.ActionAllow {
		actionVal = 1
	}

	val := bpf.TcBpfLpmVal{
		Action:       actionVal,
		PortSpecific: 0,
	}

	if len(ports) > 0 {
		val.PortSpecific = 1
	}

	// Per-port writes before the LPM no-op check; portsChanged tracks
	// new/different per-port entries — see addIPv4 for the full rationale.
	var portsChanged bool
	if len(ports) > 0 {
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
		f.ipPorts[ipStr] = mergePorts(f.ipPorts[ipStr], ports)
	}

	if ipExists && existingVal.Action == val.Action && existingVal.PortSpecific == val.PortSpecific {
		return portsChanged, nil
	}

	if err := f.cidrsV6Map.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("failed to add IPv6 to LPM trie: %w", err)
	}

	// Transitioning to PortSpecific=0 — delete tracked v6 port entries before
	// dropping ipPorts. See addIPv4 for the full rationale.
	if len(ports) == 0 {
		for _, pp := range f.ipPorts[ipStr] {
			var portKey bpf.TcBpfPortKeyV6
			copy(portKey.Ip[:], ip6)
			portKey.Port = pp.Port
			portKey.Proto = pp.Proto
			if err := f.portsV6Map.Delete(&portKey); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					f.logger.Debug("Failed to remove stale v6 port entry on PortSpecific=0 transition",
						"ip", ipStr, "port", pp.Port, "proto", pp.Proto, "error", err)
				}
			}
		}
		delete(f.ipPorts, ipStr)
	}

	return true, nil
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
	if ports, exists := f.ipPorts[ipStr]; exists {
		for _, pp := range ports {
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
	if ports, exists := f.ipPorts[ipStr]; exists {
		for _, pp := range ports {
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
