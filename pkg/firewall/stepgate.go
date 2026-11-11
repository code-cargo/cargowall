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
// the gate, and writes each step's CIDR rules, gated, with the job's denies
// inside them carved out (writeStepCIDRsLocked). A step's hostname rules
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
		f.warnWholeSpaceDeniesLocked(sr)
		f.writeStepCIDRsLocked(sr)
	}
}

// warnWholeSpaceDeniesLocked warns that a job deny on a family's whole
// address space, on all ports, leaves a step's rules nothing to allow in
// that family: the gate withholds every step write inside it. It is often
// written beside a deny default, where it adds nothing for the job.
func (f *FirewallImpl) warnWholeSpaceDeniesLocked(sr config.StepRules) {
	for i := range f.jobDenies {
		jd := &f.jobDenies[i]
		if !isWholeSpace(jd.net) {
			continue // the whole space is here on all ports only: with ports it is a wildcard
		}
		family := "IPv4"
		if jd.net.IP.To4() == nil {
			family = "IPv6"
		}
		f.logger.Warn("A step's rules allow nothing in "+family+": the job's rules deny all of it, on every port, "+
			"and the job decides first",
			"step", sr.StepID, "policy", sr.Policy, "job_deny", jd.net.String())
	}
}

// stepPrefix is a step CIDR rule as the gate leaves it: its prefix, the
// ports it allows (nil: all) and those a job deny around it takes back.
type stepPrefix struct {
	label       string
	net         *net.IPNet
	allow, deny []portProto
}

// carve is one job CIDR deny strictly inside a step's prefixes: what the job
// denies there, by every job deny around it, and whether that is all ports.
type carve struct {
	jd     *jobDeny
	denied []portProto
	whole  bool
	landed bool
}

// writeStepCIDRsLocked writes one step's CIDR rules, gated, and carves out
// of them the job's denies inside them, so no prefix is ever live without
// its carves. In order:
//  1. the carves, as deny entries alone, for every job deny strictly inside
//     a prefix the gate lets through;
//  2. each prefix, only if every carve inside it landed (a refused carve
//     costs the step the prefix, never the job its deny);
//  3. each landed carve's allows, for what the written prefixes around it
//     still allow there (a wildcard's allow reaches through a deny entry's
//     misses on its own); a landed carve no written prefix needs is removed
//     again, unless a written prefix sits at its own prefix, whose entries
//     those are too.
//
// Carves and prefixes are written all or none (writeStepEntriesLocked): a
// refused one is taken out again, and one whose removal a failed delete
// leaves unconfirmed keeps the carves inside it, as a written one does.
//
// A carve where the job denies every port is a deny entry on all ports; so,
// in effect, is one inside a prefix on all ports, which keeps nothing inside
// it, save what a wildcard reaches: no entry can say all ports but those
// (fail-closed).
func (f *FirewallImpl) writeStepCIDRsLocked(sr config.StepRules) {
	var planned []stepPrefix
	for _, rule := range sr.Rules {
		if rule.Type != config.RuleTypeCIDR || rule.IPNet == nil {
			continue
		}
		if allow, deny, ok := f.gateStepLocked(sr.Policy, rule.IPNet, expandPorts(rule.Ports)); ok {
			planned = append(planned, stepPrefix{label: rule.Value, net: rule.IPNet, allow: allow, deny: deny})
		}
	}

	var carves []carve
	for i := range f.jobDenies {
		jd := &f.jobDenies[i]
		if !slices.ContainsFunc(planned, func(p stepPrefix) bool { return strictlyWithin(jd.net, p.net) }) {
			continue
		}
		c := carve{jd: jd}
		c.denied, c.whole = f.jobDeniedWithinLocked(jd.net)
		c.landed, _ = f.writeStepEntriesLocked(sr, jd.net.String(), jd.net, entryWrite{0, c.denied})
		carves = append(carves, c)
	}

	var written, unconfirmed []stepPrefix
	for _, p := range planned {
		if i := slices.IndexFunc(carves, func(c carve) bool { return !c.landed && strictlyWithin(c.jd.net, p.net) }); i >= 0 {
			f.noteGatedLocked(sr.Policy, p.net, carves[i].jd, "withheld")
			continue
		}
		// Denies first, as AddPolicyIP writes them.
		writes := []entryWrite{{1, p.allow}}
		if len(p.deny) > 0 {
			writes = []entryWrite{{0, p.deny}, {1, p.allow}}
		}
		switch ok, removed := f.writeStepEntriesLocked(sr, p.label, p.net, writes...); {
		case ok:
			written = append(written, p)
		case !removed:
			unconfirmed = append(unconfirmed, p)
		}
	}

	for _, c := range carves {
		if !c.landed {
			continue
		}
		label := c.jd.net.String()
		// A prefix a failed delete may have left partly live needs its carves.
		needed := slices.ContainsFunc(unconfirmed, func(p stepPrefix) bool { return strictlyWithin(c.jd.net, p.net) })
		var keep []portProto
		for _, w := range written {
			if !strictlyWithin(c.jd.net, w.net) {
				continue
			}
			needed = true
			if len(w.allow) == 0 || isWholeSpace(w.net) {
				continue // all ports, or a wildcard, which reaches through on its own
			}
			for _, pp := range w.allow {
				if !slices.Contains(c.denied, pp) && !slices.Contains(keep, pp) {
					keep = append(keep, pp)
				}
			}
		}
		atOwn := slices.ContainsFunc(written, func(w stepPrefix) bool { return within(w.net, c.jd.net) && within(c.jd.net, w.net) })
		switch {
		case !needed && !atOwn:
			f.removeCarveLocked(sr.Policy, c)
		case !c.whole && len(keep) > 0:
			f.warnStepRuleLocked(sr, label, f.stepWriteErrLocked(sr.Policy, label, f.addCIDRPortsLocked(sr.Policy, c.jd.net, 1, keep)))
		}
	}
}

// entryWrite is one write of a prefix's entries: an action on ports (nil:
// all).
type entryWrite struct {
	action uint8
	ports  []portProto
}

// writeStepEntriesLocked makes a step's writes to prefix n, in order, all or
// none: once one fails, every entry they added comes out again, uncharged.
// What lands of a write the map refuses part-way can be live without the
// rest: a wildcard's port entries are read as each lands, and a prefix's
// allows under the LPM entry its denies wrote. Left in, they would reach
// inside a job deny whose carve is then removed as unneeded. It reports
// whether all landed and, if not, whether every delete was confirmed.
func (f *FirewallImpl) writeStepEntriesLocked(sr config.StepRules, label string, n *net.IPNet, writes ...entryWrite) (ok, removed bool) {
	var allows, lpms, denies []any // the keys added, which no step write held before
	var err error
	for _, w := range writes {
		err = f.addCIDRPortsLocked(sr.Policy, n, w.action, w.ports)
		for _, k := range f.steps.fresh {
			switch {
			case k.m == ruleMapCIDRs || k.m == ruleMapCIDRsV6:
				lpms = append(lpms, k.key)
			case w.action == 1:
				allows = append(allows, k.key)
			default:
				denies = append(denies, k.key)
			}
		}
		if err = f.stepWriteErrLocked(sr.Policy, label, err); err != nil {
			break
		}
	}
	f.warnStepRuleLocked(sr, label, err)
	if err == nil {
		return true, true
	}
	gone := func(keys []any) bool {
		all := true
		for _, k := range keys {
			all = f.deleteStepKeyLocked(k) && all
		}
		return all
	}
	// The denies go last, and only once the LPM entries are gone: a port
	// entry without its LPM entry is never read, but an LPM entry without
	// its denies lets a miss fall through to a step wildcard.
	allowsGone := gone(allows)
	return false, gone(lpms) && gone(denies) && allowsGone
}

// removeCarveLocked takes out a carve no written prefix needs, and uncharges
// what it took out.
func (f *FirewallImpl) removeCarveLocked(policy uint32, c carve) {
	ones, bits := c.jd.net.Mask.Size()
	hostBits := uint8(bits - ones)
	var keys []any
	if ip4 := c.jd.net.IP.To4(); ip4 != nil {
		network := binary.NativeEndian.Uint32(ip4)
		keys = append(keys, bpf.RuleKey(policy, uint32(ones), network))
		for _, pp := range c.denied {
			keys = append(keys, bpf.RulePortKey(policy, network, pp.Port, pp.Proto, hostBits))
		}
	} else {
		var network [16]byte
		copy(network[:], c.jd.net.IP.To16())
		keys = append(keys, bpf.RuleKeyV6(policy, uint32(ones), network))
		denied, _ := stripICMPForV6(c.denied)
		for _, pp := range denied {
			keys = append(keys, bpf.RulePortKeyV6(policy, network, pp.Port, pp.Proto, hostBits))
		}
	}
	for _, key := range keys {
		f.deleteStepKeyLocked(key)
	}
}

// strictlyWithin reports whether prefix a lies within b and is narrower.
func strictlyWithin(a, b *net.IPNet) bool {
	return within(a, b) && !within(b, a)
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
// ledger, which holds each, and empties the step accumulators. A key whose
// delete fails stays in the ledger: still charged, and retried by the next
// clear, never left in the map untracked. The rebuild after it plans as if
// it cleared all; design.md's reload requirement covers one that can't.
func (f *FirewallImpl) clearStepsLocked() {
	for m := range numRuleMaps {
		for key := range f.steps.keys[m] {
			f.deleteStepKeyLocked(key)
		}
	}
	f.steps.fresh = nil
	f.stepIPs = nil
}

// deleteStepKeyLocked deletes a step key from its map and, once it is gone,
// from the ledger, and reports whether it is gone.
func (f *FirewallImpl) deleteStepKeyLocked(key any) bool {
	m, ok := ledgerMap(key)
	if !ok {
		return false
	}
	if err := f.deleteKeyLocked(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		f.logger.Warn("Failed to clear a step rule entry; it stays charged, and the next sync retries it",
			"map", m.String(), "error", err)
		return false
	}
	delete(f.steps.keys[m], key)
	return true
}

// ledgerMap names the rule map a key belongs to, by its type.
func ledgerMap(key any) (ruleMap, bool) {
	switch key.(type) {
	case bpf.TcBpfRuleKey:
		return ruleMapCIDRs, true
	case bpf.TcBpfRuleKeyV6:
		return ruleMapCIDRsV6, true
	case bpf.TcBpfRulePortKey:
		return ruleMapPorts, true
	case bpf.TcBpfRulePortKeyV6:
		return ruleMapPortsV6, true
	}
	return 0, false
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
