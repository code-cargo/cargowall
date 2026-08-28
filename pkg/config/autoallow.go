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
	"slices"
)

// The auto-allow replay layer (issue #119).
//
// Rules added by the Ensure*Allowed helpers and AddSearchDomains are not
// policy — they are the infrastructure a run needs to function at all: the
// cloud metadata endpoint, the Azure wireserver, the CI control plane, the
// SaaS API, loopback. Every loader replaces cm.config wholesale, so those
// rules used to survive only by being installed AFTER the last load. That
// is why the auto-allow helpers ran behind the policy fetch — and why the
// DNS proxy armed query filtering against an empty ruleset for the length
// of an API round trip, refusing infrastructure hostnames (issue #119).
//
// Recording each call and replaying it after every load inverts that: the
// helpers can run before the proxy starts, and a later policy load
// re-applies them instead of wiping them. Replay drives the same locked
// cores as the original call, in the original order, so a loaded policy
// that denies an auto-allowed network still vetoes it exactly as it did
// when the helpers ran last.

// autoAllowKind distinguishes the three shapes of auto-add the helpers
// record. Kept internal: nothing outside this package needs to enumerate
// them, and the recorded form is an implementation detail of replay.
type autoAllowKind uint8

const (
	autoAllowCIDR autoAllowKind = iota
	autoAllowHostname
	autoAllowSearchDomain
)

// autoAllowEntry is one recorded Ensure*Allowed / AddSearchDomains call.
// It stores the helper's INPUT rather than the rule it produced, so a
// replay re-runs the deny-veto and dedup checks against whatever ruleset is
// loaded at that moment instead of resurrecting a decision made against an
// older one.
type autoAllowEntry struct {
	kind     autoAllowKind
	values   []string // CIDRs/IPs, one hostname, or normalized search domains
	ports    []Port
	autoType AutoAddedType
}

func (e autoAllowEntry) equal(other autoAllowEntry) bool {
	return e.kind == other.kind &&
		e.autoType == other.autoType &&
		slices.Equal(e.values, other.values) &&
		slices.Equal(e.ports, other.ports)
}

// recordAutoAllowLocked appends an entry to the replay layer, ignoring an
// exact repeat: call sites that predate this layer still invoke the helpers
// more than once (loadCIConfig allows the API hostname so its own fetch can
// resolve, and the auto-allow pass names it again), and each repeat would
// otherwise grow the replay list and re-log on every load. Clones the
// caller's slices — the layer outlives the call. Caller holds cm.mu.
func (cm *Manager) recordAutoAllowLocked(entry autoAllowEntry) {
	entry.values = slices.Clone(entry.values)
	entry.ports = slices.Clone(entry.ports)
	for _, existing := range cm.autoAllows {
		if existing.equal(entry) {
			return
		}
	}
	cm.autoAllows = append(cm.autoAllows, entry)
}

// replayAutoAllowsLocked re-applies every recorded auto-add onto the config
// a loader just installed. applyLoadedConfig calls it after
// resolveRulesLocked so the cores see the new resolvedRules — their dedup
// and deny-veto checks then run against the freshly loaded policy, which is
// the same precedence the helpers had when they ran after the load.
// Caller holds cm.mu.
func (cm *Manager) replayAutoAllowsLocked() {
	for _, entry := range cm.autoAllows {
		switch entry.kind {
		case autoAllowCIDR:
			cm.ensureAllowedLocked(entry.values, entry.ports, entry.autoType, true)
		case autoAllowHostname:
			// One hostname per entry; a malformed record would mean a bug in
			// EnsureHostnameAllowed, so skip rather than index blindly.
			if len(entry.values) == 1 {
				cm.ensureHostnameAllowedLocked(entry.values[0], entry.ports, entry.autoType, true)
			}
		case autoAllowSearchDomain:
			cm.addSearchDomainsLocked(entry.values)
		}
	}
}

// EnsureBaseConfig installs an empty deny-default config when no loader has
// run yet, so the Ensure*Allowed helpers — which no-op on a nil config —
// can install the infrastructure allows before the first policy source is
// read (issue #119). Idempotent: a config from any loader is left alone.
//
// Deny-default matches every other pre-policy posture in the daemon
// (GetDefaultAction already reports deny for a nil config), so this changes
// what is ALLOWED during startup, never what is denied.
func (cm *Manager) EnsureBaseConfig() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config != nil {
		return
	}
	cm.config = &FirewallConfig{DefaultAction: ActionDeny}
	// An empty ruleset resolves to an empty resolvedRules; the replay below
	// is what actually populates it when helpers already recorded entries
	// against the nil config.
	if err := cm.resolveRulesLocked(); err != nil {
		slog.Error("Failed to resolve base config", "error", err)
		return
	}
	cm.replayAutoAllowsLocked()
}
