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
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// The step gate: the job's CIDR denies decide first, in userspace too.
//
// The kernel's job lookup takes the longest match under policy 0. When that
// match is a port-specific entry and the port misses it, the lookup ends in
// silence, never the shorter prefix around the entry. So a job entry nested
// inside a job CIDR deny (a hostname rule's address the sync wrote before
// the deny, say) hides the deny on every port the entry doesn't list, and a
// step's rules are asked there. Writing nothing that lets a step allow what
// a job CIDR deny covers keeps "the job's deny wins" however the job's
// entries were ordered, as the DNS path's withholding does for the names the
// job denies. Port by port, as the kernel judges, where an entry can say it:
//   - a step write inside a job CIDR deny is withheld on the ports the deny
//     covers. A deny on all ports withholds it whole. One on some ports
//     takes them out of the step's port list and writes them as deny entries
//     beside the rest, so a miss can't fall through to a step wildcard; and
//     it withholds a step write on all ports, which no entry can express as
//     all ports but those (fail-closed).
//   - a job CIDR deny inside a step's prefix is carved out of the step's
//     policy: an entry at the deny's prefix that denies what the job denies
//     there and allows what the step's rules around it still allow. Inside
//     a step prefix on all ports, a deny on some ports can only be carved
//     whole (fail-closed). A step policy's deny only ever withholds its
//     allow.
//
// The denies the gate reads are the ones the last sync wrote, and the sync
// rebuilds the step tier against them, so a step write made before a sync
// never outlives it ungated. Two kinds of job CIDR deny can't be hidden and
// need no gate: one on the whole address space with ports, a wildcard entry
// the job's lookup reaches after any port miss; and a host route, which
// nothing is longer than, so the job's lookup always meets it.

// jobDeny is one of the job's CIDR denies, as the sync wrote it to the trie:
// its prefix and the ports it denies (nil: all).
type jobDeny struct {
	net   *net.IPNet
	ports []portProto
}

// jobCIDRDenies returns the job's CIDR deny rules the job's trie holds.
func jobCIDRDenies(rules []config.ResolvedRule) []jobDeny {
	var out []jobDeny
	for _, r := range rules {
		if r.Type != config.RuleTypeCIDR || r.Action != config.ActionDeny || r.IPNet == nil {
			continue
		}
		ones, bits := r.IPNet.Mask.Size()
		ports := expandPorts(r.Ports)
		if ones == 0 && len(ports) > 0 || ones == bits {
			continue // a wildcard entry, or a host route: never hidden
		}
		out = append(out, jobDeny{net: r.IPNet, ports: ports})
	}
	return out
}

// within reports whether prefix a lies within prefix b (b contains all of a).
func within(a, b *net.IPNet) bool {
	aOnes, aBits := a.Mask.Size()
	bOnes, bBits := b.Mask.Size()
	return aBits == bBits && bOnes <= aOnes && b.Contains(a.IP)
}

// gateStepLocked trims a step write to dst on ports (nil: all) to what the
// job's CIDR denies around dst leave it. It returns the ports to write as
// allows, those the job denies there, to write as denies beside them, and
// false when nothing is left to write.
func (f *FirewallImpl) gateStepLocked(policy uint32, dst *net.IPNet, ports []portProto) (allow, deny []portProto, ok bool) {
	var denied []portProto
	var by *jobDeny
	for i := range f.jobDenies {
		jd := &f.jobDenies[i]
		if !within(dst, jd.net) {
			continue
		}
		if len(jd.ports) == 0 {
			f.noteGatedLocked(policy, dst, jd, "withheld")
			return nil, nil, false
		}
		denied, by = append(denied, jd.ports...), jd
	}
	if by == nil {
		return ports, nil, true
	}
	// A write on all ports keeps none: no entry says all ports but those.
	kept := slices.DeleteFunc(slices.Clone(ports), func(pp portProto) bool { return slices.Contains(denied, pp) })
	if len(kept) == 0 {
		f.noteGatedLocked(policy, dst, by, "withheld")
		return nil, nil, false
	}
	if len(kept) < len(ports) {
		f.noteGatedLocked(policy, dst, by, "trimmed")
	}
	return kept, denied, true
}

// noteGatedLocked logs a gated step write once per (policy, destination,
// outcome), while maxGatedNotes allow.
func (f *FirewallImpl) noteGatedLocked(policy uint32, dst *net.IPNet, jd *jobDeny, outcome string) {
	key := fmt.Sprintf("%d/%s/%s", policy, dst, outcome)
	if _, seen := f.gated[key]; seen || len(f.gated) >= maxGatedNotes {
		return
	}
	if f.gated == nil {
		f.gated = make(map[string]struct{})
	}
	f.gated[key] = struct{}{}
	f.logger.Info("Step rule entry "+outcome+": a job CIDR deny covers it, and the job decides first",
		"policy", policy, "destination", dst.String(), "job_deny", jd.net.String(), "job_deny_ports", jd.ports)
}

// maxGatedNotes bounds the set of gated writes logged.
const maxGatedNotes = 1024

// syncStepsLocked rebuilds the step tier against the job's rules the sync
// just wrote: it clears every step entry, takes the job's CIDR denies for
// the gate, writes each step's CIDR rules, gated, and then carves out of
// each step's prefixes the job's denies inside them. A step's hostname rules
// get their IPs from the DNS path alone, which the tracked-hostname backfill
// that follows every sync re-installs. A step rule that can't be installed
// is a Warn, not an error: it costs only that step's extra reach, which
// fails closed to the job's rules. Requirement: anything that reloads step
// rules at runtime clears the step entries first, as this does, DNS
// installs included: policies are numbered per load, so a kept entry would
// be another step's. Must be called with f.mu held.
func (f *FirewallImpl) syncStepsLocked(jobRules []config.ResolvedRule, steps []config.StepRules) {
	f.clearStepsLocked()
	f.jobDenies = jobCIDRDenies(jobRules)
	for _, sr := range steps {
		var written []stepPrefix
		for _, rule := range sr.Rules {
			if rule.Type == config.RuleTypeCIDR && rule.IPNet != nil {
				if w, ok := f.installStepCIDRLocked(sr, rule); ok {
					written = append(written, w)
				}
			}
		}
		f.carveLocked(sr, written)
	}
}

// stepPrefix is a step CIDR rule as written: its prefix and allowed ports
// (nil: all).
type stepPrefix struct {
	net   *net.IPNet
	ports []portProto
}

// installStepCIDRLocked writes one step CIDR rule, gated, and reports what
// it wrote.
func (f *FirewallImpl) installStepCIDRLocked(sr config.StepRules, rule config.ResolvedRule) (stepPrefix, bool) {
	allow, deny, ok := f.gateStepLocked(sr.Policy, rule.IPNet, expandPorts(rule.Ports))
	if !ok {
		return stepPrefix{}, false
	}
	// Denies first, as AddPolicyIP writes them.
	var err error
	if len(deny) > 0 {
		err = f.stepWriteErrLocked(sr.Policy, rule.Value, f.addCIDRPortsLocked(sr.Policy, rule.IPNet, 0, deny))
	}
	if err == nil {
		err = f.stepWriteErrLocked(sr.Policy, rule.Value, f.addCIDRPortsLocked(sr.Policy, rule.IPNet, 1, allow))
	}
	f.warnStepRuleLocked(sr, rule.Value, err)
	return stepPrefix{net: rule.IPNet, ports: allow}, err == nil
}

// carveLocked carves out of a step's written prefixes each job CIDR deny
// strictly inside one of them: at the deny's prefix, deny entries for what
// the job denies there, by every job deny around it, and allows for what the
// step's port-listed prefixes around it still allow (a wildcard's allow
// reaches through a deny entry's misses on its own). Where the job denies
// every port there, it is carved whole. A step prefix on all ports around
// it keeps nothing inside it, save what a wildcard reaches: no entry can say
// all ports but those (fail-closed).
func (f *FirewallImpl) carveLocked(sr config.StepRules, written []stepPrefix) {
	for i := range f.jobDenies {
		jd := &f.jobDenies[i]
		denied, whole := f.jobDeniedWithinLocked(jd.net)
		var keep []portProto
		inside := false
		for _, w := range written {
			if !within(jd.net, w.net) || within(w.net, jd.net) {
				continue
			}
			inside = true
			if len(w.ports) == 0 || isWholeSpace(w.net) {
				continue // all ports, or a wildcard, which reaches through on its own
			}
			for _, pp := range w.ports {
				if !slices.Contains(denied, pp) && !slices.Contains(keep, pp) {
					keep = append(keep, pp)
				}
			}
		}
		if !inside {
			continue
		}
		label := jd.net.String()
		if whole {
			f.warnStepRuleLocked(sr, label, f.stepWriteErrLocked(sr.Policy, label, f.addCIDRPortsLocked(sr.Policy, jd.net, 0, nil)))
			continue
		}
		err := f.stepWriteErrLocked(sr.Policy, label, f.addCIDRPortsLocked(sr.Policy, jd.net, 0, denied))
		if err == nil && len(keep) > 0 {
			err = f.stepWriteErrLocked(sr.Policy, label, f.addCIDRPortsLocked(sr.Policy, jd.net, 1, keep))
		}
		f.warnStepRuleLocked(sr, label, err)
	}
}

// jobDeniedWithinLocked returns the ports the job's CIDR denies deny all of
// prefix n on, and whether one denies every port there. A deny nested inside
// another hides the outer one in the job's lookup as a nested allow does, so
// a carve has to say all of them.
func (f *FirewallImpl) jobDeniedWithinLocked(n *net.IPNet) (denied []portProto, all bool) {
	for i := range f.jobDenies {
		jd := &f.jobDenies[i]
		if !within(n, jd.net) {
			continue
		}
		if len(jd.ports) == 0 {
			return nil, true
		}
		for _, pp := range jd.ports {
			if !slices.Contains(denied, pp) {
				denied = append(denied, pp)
			}
		}
	}
	return denied, false
}

// isWholeSpace reports a prefix of length 0.
func isWholeSpace(n *net.IPNet) bool {
	ones, _ := n.Mask.Size()
	return ones == 0
}

// warnStepRuleLocked warns of a step rule write that failed for a reason
// other than room, which warnNoRoomLocked reports.
func (f *FirewallImpl) warnStepRuleLocked(sr config.StepRules, label string, err error) {
	if err != nil && !errors.Is(err, ErrStepBudget) {
		f.logger.Warn("Step rule not installed; the step gets the job's rules there",
			"step", sr.StepID, "policy", sr.Policy, "rule", label, "error", err)
	}
}

// clearStepsLocked deletes every step entry from the rule maps, by the
// ledger, which holds each, and empties the step accumulators and ledger.
func (f *FirewallImpl) clearStepsLocked() {
	for m := range numRuleMaps {
		for key := range f.steps.keys[m] {
			if err := f.deleteKeyLocked(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				f.logger.Warn("Failed to clear a step rule entry", "map", m.String(), "error", err)
			}
		}
		f.steps.keys[m] = nil
	}
	f.steps.fresh = nil
	f.stepIPs = nil
}

// deleteKeyLocked deletes key from the rule map its type names.
func (f *FirewallImpl) deleteKeyLocked(key any) error {
	switch k := key.(type) {
	case bpf.TcBpfRuleKey:
		return f.cidrsMap.Delete(&k)
	case bpf.TcBpfRuleKeyV6:
		return f.cidrsV6Map.Delete(&k)
	case bpf.TcBpfRulePortKey:
		return f.portsMap.Delete(&k)
	case bpf.TcBpfRulePortKeyV6:
		return f.portsV6Map.Delete(&k)
	}
	return fmt.Errorf("not a rule-map key: %T", key)
}
