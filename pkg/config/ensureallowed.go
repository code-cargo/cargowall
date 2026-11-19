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
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/code-cargo/cargowall/pkg/tcmaps"
)

// ensureAllowed adds /32 allow rules for the given IPs with the specified
// ports. If ports is nil, traffic on all ports is allowed. Empty, malformed
// and IPv6 entries are skipped.
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
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}
		ip4 := parsedIP.To4()
		if ip4 == nil {
			continue // skip IPv6
		}

		cidr := ip4.String() + "/32"
		rule := ResolvedRule{
			Type:          RuleTypeCIDR,
			Value:         cidr,
			Ports:         ports,
			Action:        ActionAllow,
			AutoAddedType: autoAddedType,
			IPNet: &net.IPNet{
				IP:   ip4,
				Mask: net.CIDRMask(32, 32),
			},
		}
		if !cm.autoAllowNeededLocked(rule, autoAddedType) {
			continue
		}

		cm.config.Rules = append(cm.config.Rules, Rule{
			Type:          RuleTypeCIDR,
			Value:         cidr,
			Ports:         ports,
			Action:        ActionAllow,
			AutoAddedType: autoAddedType,
		})
		cm.resolvedRules = append(cm.resolvedRules, rule)

		slog.Info("Auto-added allow rule", "cidr", cidr, "ports", ports, "autoAddedType", autoAddedType)
	}
}

// autoAllowNeededLocked decides whether the /32 allow in rule should be added,
// by the verdict the TC program would give (tcmaps, the compile the firewall
// writes) rather than by whether some rule's network contains the address:
//   - Already allowed on every port the rule names, or on all ports for an
//     all-ports rule: nothing to add.
//   - Denied by a port entry keyed on this address and port, which the add
//     would overwrite, or still denied with the rule added (a covering
//     all-ports deny the host folds in): the deny is kept, and the skip is
//     logged.
//
// Otherwise the /32 only gains the named ports. A covering all-ports grant
// is folded into the host on first touch, a port-specific /32 that already
// shadows a broader rule only gains new port keys, and a port-specific subnet
// answers for no address but its own, so no other port's verdict moves.
//
// Must be called with cm.mu held.
func (cm *Manager) autoAllowNeededLocked(rule ResolvedRule, autoAddedType AutoAddedType) bool {
	defaultAllow := cm.config.DefaultAction == ActionAllow
	before := tcmaps.Compile(tcRules(cm.resolvedRules))
	after := tcmaps.Compile(tcRules(append(slices.Clip(cm.resolvedRules), rule)))
	addr, _ := tcAddr(rule.IPNet.IP)

	ports := TCPorts(rule.Ports)
	var covered, denied bool
	if len(ports) == 0 {
		covered = allowsAllPorts(before, addr)
		denied = !allowsAllPorts(after, addr)
	} else {
		covered = !slices.ContainsFunc(ports, func(p tcmaps.PortProto) bool { return !before.Allows(addr, p, defaultAllow) })
		denied = slices.ContainsFunc(ports, func(p tcmaps.PortProto) bool {
			return before.PortDenied(addr, p) || !after.Allows(addr, p, defaultAllow)
		})
	}
	switch {
	case covered:
		slog.Debug("Allow rule already exists", "cidr", rule.Value, "ports", rule.Ports)
		return false
	case denied:
		slog.Warn("Skipping auto-allow: a deny rule covers this address",
			"cidr", rule.Value, "ports", rule.Ports, "autoAddedType", autoAddedType)
		return false
	}
	return true
}

// allowsAllPorts reports whether the LPM answers addr with an all-ports allow.
func allowsAllPorts(m *tcmaps.Maps, addr netip.Addr) bool {
	e, ok := m.Lookup(addr)
	return ok && !e.PortSpecific && e.Allow
}
