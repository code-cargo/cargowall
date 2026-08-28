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

// The auto-allow journal (issue #119).
//
// Rules added by the Ensure*Allowed helpers and AddSearchDomains are not
// policy — they are the infrastructure a run needs to function at all: cloud
// metadata, the Azure wireserver, the CI control plane, the SaaS API,
// loopback. Every loader replaces cm.config wholesale, so before this layer
// they survived only by being installed after the last load, which is why
// they ran behind the policy fetch — leaving the DNS proxy filtering against
// an empty ruleset for the length of an API round trip.
//
// The contract: record each call's INPUT, re-run the same locked cores after
// every load. Re-running the cores (rather than re-appending the rules they
// produced) is what keeps the verdict identical to the old auto-allow-runs-
// last ordering — a CIDR auto-allow is still vetoed by a loaded deny that
// covers it, and a hostname auto-allow still wins over a policy deny for the
// same exact name (#121). This layer moves WHEN rules are installed, never
// WHICH rule wins.

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

// recordAutoAllowLocked journals an entry, ignoring an exact repeat — some
// call sites name the same hostname twice, and each repeat would otherwise
// grow the list replayed on every load. Clones the caller's slices: the
// journal outlives the call. Caller holds cm.mu.
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

// replayAutoAllowsLocked re-applies every journalled auto-add onto the config
// a loader just installed. applyLoadedConfig calls it after
// resolveRulesLocked, so the cores' dedup and deny-veto checks see the new
// ruleset. Caller holds cm.mu.
//
// The cores run in replay mode: an auto-allow is announced in the ops log
// once, where it is installed. Re-announcing every rule on every load would
// misdate the install and — since the CI gate for #119 keys on that
// announcement preceding the DNS proxy arming — would also make a replay
// indistinguishable from a late install. One summary line covers the pass.
func (cm *Manager) replayAutoAllowsLocked() {
	if len(cm.autoAllows) == 0 {
		return
	}
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
	slog.Debug("Re-applied journalled auto-allows onto the loaded config", "count", len(cm.autoAllows))
}

// seedBaseConfigLocked gives an auto-allow somewhere to land when no loader
// has run yet. Deny-default is already what GetDefaultAction reports for a
// nil config, so seeding changes what is ALLOWED before a policy arrives,
// never what is denied. Caller holds cm.mu.
func (cm *Manager) seedBaseConfigLocked() {
	if cm.config == nil {
		cm.config = &FirewallConfig{DefaultAction: ActionDeny}
	}
}
