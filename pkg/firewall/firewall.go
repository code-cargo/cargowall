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
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/tcmaps"
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

	// unspecifiedWarned holds the unspecified addresses already refused and
	// logged (unspecified.go).
	unspecifiedWarned map[string]struct{}
}

// portProto is one port entry's port and IANA protocol number.
type portProto = tcmaps.PortProto

const (
	protoICMP = tcmaps.ProtoICMP
	protoTCP  = tcmaps.ProtoTCP
	protoUDP  = tcmaps.ProtoUDP
)

// ipPortState accumulates every contribution to one host entry (/32 or
// /128), across UpdateAllowlistTC and AddIP: see tcmaps.Host for the
// precedence. UpdateAllowlistTC installs the compile's accumulators, so a
// later AddIP folds into the same state the rules produced.
type ipPortState = tcmaps.Host

func actionVal(allow bool) uint8 {
	if allow {
		return 1
	}
	return 0
}

func lpmVal(v tcmaps.LPM) bpf.TcBpfLpmVal {
	val := bpf.TcBpfLpmVal{Action: actionVal(v.Allow)}
	if v.PortSpecific {
		val.PortSpecific = 1
	}
	return val
}

func fromLPMVal(v bpf.TcBpfLpmVal) tcmaps.LPM {
	return tcmaps.LPM{Allow: v.Action == 1, PortSpecific: v.PortSpecific != 0}
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

// UpdateAllowlistTC writes the maps tcmaps.Compile builds from the resolved
// rules, and installs the compile's host accumulators so a later AddIP folds
// into them. It is add-only: keys a previous call wrote and this rule set
// doesn't are left in place.
func (f *FirewallImpl) UpdateAllowlistTC(configMgr *config.Manager) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	maps := tcmaps.Compile(configMgr.TCRules())
	f.logNotesLocked(maps.Notes)

	for prefix, v := range maps.Subnets {
		if err := f.writeLPM(prefix, v); err != nil {
			return err
		}
	}
	for addr, h := range maps.Hosts {
		if h.Installed {
			if err := f.writeLPM(netip.PrefixFrom(addr, addr.BitLen()), h.LPM); err != nil {
				return err
			}
		}
	}
	for k, allow := range maps.Ports {
		if err := f.writePort(k, allow); err != nil {
			return err
		}
	}

	f.ipPorts = make(map[string]*ipPortState, len(maps.Hosts))
	for addr, h := range maps.Hosts {
		f.ipPorts[addr.String()] = h
	}
	return nil
}

func (f *FirewallImpl) writeLPM(prefix netip.Prefix, v tcmaps.LPM) error {
	val := lpmVal(v)
	if prefix.Addr().Is4() {
		key := bpf.TcBpfLpmKey{Prefixlen: uint32(prefix.Bits()), Ip: addrU32(prefix.Addr())}
		if err := f.cidrsMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update LPM trie for %s: %w", prefix, err)
		}
		return nil
	}
	key := bpf.TcBpfLpmKeyV6{Prefixlen: uint32(prefix.Bits()), Ip: prefix.Addr().As16()}
	if err := f.cidrsV6Map.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update v6 LPM trie for %s: %w", prefix, err)
	}
	return nil
}

func (f *FirewallImpl) writePort(k tcmaps.PortKey, allow bool) error {
	val := bpf.TcBpfPortVal{Action: actionVal(allow)}
	if k.Addr.Is4() {
		key := bpf.TcBpfPortKey{Ip: addrU32(k.Addr), Port: k.Port, Proto: k.Proto}
		if err := f.portsMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update port map for %s port %d proto %d: %w", k.Addr, k.Port, k.Proto, err)
		}
		return nil
	}
	key := bpf.TcBpfPortKeyV6{Ip: k.Addr.As16(), Port: k.Port, Proto: k.Proto}
	if err := f.portsV6Map.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update v6 port map for %s port %d proto %d: %w", k.Addr, k.Port, k.Proto, err)
	}
	return nil
}

// addrU32 is an IPv4 address as the maps key it: its bytes in network order,
// read natively, which LPM prefix matching requires.
func addrU32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.NativeEndian.Uint32(b[:])
}

// logNotesLocked logs the contributions the compile dropped, as the per-rule
// writers did. Must be called with f.mu held.
func (f *FirewallImpl) logNotesLocked(notes []tcmaps.Note) {
	for _, n := range notes {
		switch n.Kind {
		case tcmaps.NoteUnspecified:
			f.warnUnspecifiedLocked(n.Label)
		case tcmaps.NoteV6ICMPOnly:
			key := "label"
			if n.Host {
				key = "ip"
			}
			f.logger.Warn("Skipping v6 rule: ICMP-only and ICMPv6 is unconditionally allowed", key, n.Label)
		case tcmaps.NoteInertPorts:
			f.logger.Warn("Port-specific rule has no effect: IP already has an all-ports grant",
				"ip", n.Label,
				"all_ports_action", actionName(actionVal(n.HostAllow)),
				"rule_action", actionName(actionVal(n.Allow)),
				"ignored_ports", n.Ports)
		}
	}
}

// expandPorts converts config.Port entries into port entries (config.TCPorts).
func expandPorts(ports []config.Port) []portProto {
	return config.TCPorts(ports)
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
	allow := action == config.ActionAllow
	if ip4 := ip.To4(); ip4 != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.addIPv4Locked(ip4, ip.String(), allow, pp)
	}
	if ip6 := ip.To16(); ip6 != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.addIPv6Locked(ip6, ip.String(), allow, pp)
	}
	return false, fmt.Errorf("invalid IP: %s", ip.String())
}

// existingLocked is the LPM's answer for a host before an add: its own entry
// if this firewall installed one, else the map's longest covering entry.
// Must be called with f.mu held.
func (f *FirewallImpl) existingLocked(st *ipPortState, lookup func(*bpf.TcBpfLpmVal) error) (tcmaps.LPM, bool) {
	if st != nil && st.Installed {
		return st.LPM, true
	}
	var v bpf.TcBpfLpmVal
	if lookup(&v) != nil {
		return tcmaps.LPM{}, false
	}
	return fromLPMVal(v), true
}

// addIPv4Locked folds one contribution into an IPv4 host entry through its
// tcmaps.Host, the accumulator UpdateAllowlistTC installs. Must be called
// with f.mu held.
func (f *FirewallImpl) addIPv4Locked(ip4 net.IP, ipStr string, allow bool, ports []portProto) (bool, error) {
	if f.refuseUnspecifiedLocked(ip4, ipStr) {
		return false, nil
	}
	ipUint32 := binary.NativeEndian.Uint32(ip4)
	key := bpf.TcBpfLpmKey{Prefixlen: 32, Ip: ipUint32}

	st := f.ipPorts[ipStr]
	existing, exists := f.existingLocked(st, func(v *bpf.TcBpfLpmVal) error { return f.cidrsMap.Lookup(&key, v) })
	if st == nil {
		st = tcmaps.NewHost(existing, exists)
		f.ipPorts[ipStr] = st
	}
	w := st.Add(allow, ports, existing, exists)
	if w.Inert {
		f.warnInertPorts(ipStr, allow, ports, st)
	}

	var portsChanged bool
	for _, pp := range w.Ports {
		portKey := bpf.TcBpfPortKey{Ip: ipUint32, Port: pp.Port, Proto: pp.Proto}
		changed, err := f.updatePort(f.portsMap, &portKey, allow)
		if err != nil {
			return false, fmt.Errorf("failed to add port %d proto %d to map: %w", pp.Port, pp.Proto, err)
		}
		portsChanged = portsChanged || changed
	}

	if !w.WriteLPM {
		return portsChanged, nil
	}
	val := lpmVal(w.LPM)
	if err := f.cidrsMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("failed to add IP to LPM trie: %w", err)
	}
	st.LPM, st.Installed = w.LPM, true
	return true, nil
}

// addIPv6Locked is the IPv6 twin of addIPv4Locked. Must be called with f.mu
// held.
func (f *FirewallImpl) addIPv6Locked(ip6 net.IP, ipStr string, allow bool, ports []portProto) (bool, error) {
	if f.refuseUnspecifiedLocked(ip6, ipStr) {
		return false, nil
	}
	ports, skip := f.prepV6Ports(ports, "ip", ipStr)
	if skip {
		return false, nil
	}
	key := bpf.TcBpfLpmKeyV6{Prefixlen: 128, Ip: [16]byte(ip6.To16())}

	st := f.ipPorts[ipStr]
	existing, exists := f.existingLocked(st, func(v *bpf.TcBpfLpmVal) error { return f.cidrsV6Map.Lookup(&key, v) })
	if st == nil {
		st = tcmaps.NewHost(existing, exists)
		f.ipPorts[ipStr] = st
	}
	w := st.Add(allow, ports, existing, exists)
	if w.Inert {
		f.warnInertPorts(ipStr, allow, ports, st)
	}

	var portsChanged bool
	for _, pp := range w.Ports {
		portKey := bpf.TcBpfPortKeyV6{Ip: key.Ip, Port: pp.Port, Proto: pp.Proto}
		changed, err := f.updatePort(f.portsV6Map, &portKey, allow)
		if err != nil {
			return false, fmt.Errorf("failed to add v6 port %d proto %d to map: %w", pp.Port, pp.Proto, err)
		}
		portsChanged = portsChanged || changed
	}

	if !w.WriteLPM {
		return portsChanged, nil
	}
	val := lpmVal(w.LPM)
	if err := f.cidrsV6Map.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("failed to add IPv6 to LPM trie: %w", err)
	}
	st.LPM, st.Installed = w.LPM, true
	return true, nil
}

// updatePort writes one port entry, reporting whether it was new or
// different. The entry is written unconditionally: a shared IP added under
// two rules with disjoint port sets must get the second rule's entries even
// when its LPM entry is unchanged.
func (f *FirewallImpl) updatePort(m mapOps, key any, allow bool) (bool, error) {
	var existing bpf.TcBpfPortVal
	changed := m.Lookup(key, &existing) != nil || existing.Action != actionVal(allow)
	if err := m.Update(key, &bpf.TcBpfPortVal{Action: actionVal(allow)}, ebpf.UpdateAny); err != nil {
		return false, err
	}
	return changed, nil
}

// warnInertPorts logs a port-specific contribution dropped because an
// all-ports grant of the opposite action already governs the IP (the BPF
// model can't express "allow all except port N").
func (f *FirewallImpl) warnInertPorts(ipStr string, allow bool, ports []portProto, st *ipPortState) {
	f.logger.Warn("Port-specific rule has no effect: IP already has an all-ports grant",
		"ip", ipStr,
		"all_ports_action", actionName(actionVal(!st.AllPortsDeny)),
		"rule_action", actionName(actionVal(allow)),
		"ignored_ports", ports)
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

	// Nothing is installed at the unspecified address, and its port keys are
	// the any-destination wildcard's (unspecified.go).
	if ip4.IsUnspecified() {
		return nil
	}

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
		for _, pp := range st.Ports {
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

	if ip6.IsUnspecified() {
		return nil
	}

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
		for _, pp := range st.Ports {
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
