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
	"slices"
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
// by the verdict the TC program would give (tcModel) rather than by whether
// some rule's network contains the address:
//   - Already allowed on every port the rule names: nothing to add.
//   - Denied by a rule keyed on this address and port, or still denied with
//     the rule added (a covering all-ports deny holds for every host inside
//     it): the deny is kept, and the skip is logged.
//   - Otherwise the rule is added only if it changes nothing but the ports it
//     names, since a /32 written for the address decides its other ports too.
//
// Must be called with cm.mu held.
func (cm *Manager) autoAllowNeededLocked(rule ResolvedRule, autoAddedType AutoAddedType) bool {
	defaultAction := cm.config.DefaultAction
	if defaultAction == "" {
		defaultAction = ActionDeny
	}
	before := newTCModel(cm.resolvedRules, defaultAction)
	after := newTCModel(append(slices.Clip(cm.resolvedRules), rule), defaultAction)
	addr, _ := tcAddr(rule.IPNet.IP)

	want := tcProbes(rule.Ports)
	if len(want) == 0 {
		want = after.probes()
	}

	if !slices.ContainsFunc(want, func(p tcProbe) bool { return !before.allows(addr, p) }) {
		slog.Debug("Allow rule already exists", "cidr", rule.Value, "ports", rule.Ports)
		return false
	}
	if slices.ContainsFunc(want, func(p tcProbe) bool { return before.portDenied(addr, p) || !after.allows(addr, p) }) {
		slog.Warn("Skipping auto-allow: a deny rule covers this address",
			"cidr", rule.Value, "ports", rule.Ports, "autoAddedType", autoAddedType)
		return false
	}
	for _, p := range append(before.probes(), after.probes()...) {
		if !slices.Contains(want, p) && before.allows(addr, p) != after.allows(addr, p) {
			slog.Warn("Skipping auto-allow: it would change the verdict for other traffic to this address",
				"cidr", rule.Value, "ports", rule.Ports, "autoAddedType", autoAddedType,
				"port", p.port, "proto", p.proto)
			return false
		}
	}
	return true
}
