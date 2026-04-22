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

	// AddIP adds a single IP to the BPF maps with the specified action and ports
	// Returns (wasAdded bool, error) - wasAdded is true if the IP was newly added, false if it was a duplicate
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
// ProtocolAll expands to both ICMP, TCP and UDP entries so that the BPF lookup
// (which always uses the packet's exact protocol) matches correctly.
func expandPorts(ports []config.Port) []portProto {
	if len(ports) == 0 {
		return nil
	}
	result := make([]portProto, 0, len(ports)*2)
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

	if ipExists && existingVal.Action == val.Action && existingVal.PortSpecific == val.PortSpecific {
		return false, nil
	}

	if len(ports) > 0 {
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
				return false, fmt.Errorf("failed to add port %d proto %d to map: %w", pp.Port, pp.Proto, err)
			}
		}
	}

	if err := f.cidrsMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("failed to add IP to LPM trie: %w", err)
	}

	ipStr := origIP.String()
	if len(ports) > 0 {
		f.ipPorts[ipStr] = ports
	} else {
		delete(f.ipPorts, ipStr)
	}

	return true, nil
}

func (f *FirewallImpl) addIPv6(ip6 net.IP, origIP net.IP, action config.Action, ports []portProto) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

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

	if ipExists && existingVal.Action == val.Action && existingVal.PortSpecific == val.PortSpecific {
		return false, nil
	}

	if len(ports) > 0 {
		for _, pp := range ports {
			var portKey bpf.TcBpfPortKeyV6
			copy(portKey.Ip[:], ip6)
			portKey.Port = pp.Port
			portKey.Proto = pp.Proto
			portVal := bpf.TcBpfPortVal{
				Action: actionVal,
			}
			if err := f.portsV6Map.Update(&portKey, &portVal, ebpf.UpdateAny); err != nil {
				return false, fmt.Errorf("failed to add v6 port %d proto %d to map: %w", pp.Port, pp.Proto, err)
			}
		}
	}

	if err := f.cidrsV6Map.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("failed to add IPv6 to LPM trie: %w", err)
	}

	ipStr := origIP.String()
	if len(ports) > 0 {
		f.ipPorts[ipStr] = ports
	} else {
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
