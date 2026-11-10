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
	"time"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// The rule maps hold the job's rules, under policy 0, and each step's, under
// a policy of its own. A map's max_entries covers all of them, so the split
// is kept here: step writes may never take the room the job had before step
// policies existed, so what the job can install doesn't depend on steps.
const (
	// ruleMapEntries is max_entries of each of the four rule maps in
	// bpf/verdict.h; a test pins it against the generated spec.
	ruleMapEntries = 16384
	// jobReservedEntries is the room in each rule map no step write may
	// take: the maps' whole size before step policies.
	jobReservedEntries = 4096
	// stepEntryBudget is what the step policies together may hold in each
	// rule map.
	stepEntryBudget = ruleMapEntries - jobReservedEntries
)

// ErrStepBudget refuses a step write that would take some of the job's
// reservation in a rule map. Nothing of the write is installed, so the
// step's traffic there gets the job's rules alone: fail-closed.
var ErrStepBudget = errors.New("the step policies' share of a rule map is full")

// stepBudgetWarnInterval rate-limits the refusal Warn: a full budget refuses
// every new step destination, and DNS refreshes retry each one.
const stepBudgetWarnInterval = time.Minute

// ruleMap names one of the four rule maps for the step ledger.
type ruleMap int

const (
	ruleMapCIDRs ruleMap = iota
	ruleMapPorts
	ruleMapCIDRsV6
	ruleMapPortsV6
	numRuleMaps
)

func (m ruleMap) String() string {
	return [...]string{"map_cidrs", "map_ports", "map_cidrs_v6", "map_ports_v6"}[m]
}

// policyIP keys a step policy's per-IP accumulator.
type policyIP struct {
	policy uint32
	ip     string
}

// stepLedger is the step budget's books: every key a step policy holds in
// each rule map, so a key is charged once however often it is rewritten. A
// key is charged when its write is admitted, before the write itself, so a
// failed write can only overcount, the safe direction; its retry is free.
type stepLedger struct {
	keys [numRuleMaps]map[any]struct{}
	// budget overrides stepEntryBudget, for tests; 0 means stepEntryBudget.
	budget  int
	refused int       // refusals since the last Warn
	warned  time.Time // when the last refusal Warn was logged
}

func (l *stepLedger) limit() int {
	if l.budget > 0 {
		return l.budget
	}
	return stepEntryBudget
}

// used reports how many entries step policies hold in m.
func (l *stepLedger) used(m ruleMap) int { return len(l.keys[m]) }

// plannedKey is one key a step write is about to write.
type plannedKey struct {
	m   ruleMap
	key any
}

// AddPolicyIP adds an allow for ip on ports under a step policy. See the
// Firewall interface.
func (f *FirewallImpl) AddPolicyIP(policy uint32, ip net.IP, ports []config.Port) (bool, error) {
	if policy == bpf.PolicyJob {
		return false, fmt.Errorf("AddPolicyIP writes step policies only; the job's rules are written by AddIP")
	}
	pp := expandPorts(ports)
	if ip4 := ip.To4(); ip4 != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.addIPv4Locked(policy, ip4, ip.String(), 1, pp)
	}
	if ip6 := ip.To16(); ip6 != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.addIPv6Locked(policy, ip6, ip.String(), 1, pp)
	}
	return false, fmt.Errorf("invalid IP: %s", ip.String())
}

// installStepRulesLocked writes each step policy's CIDR rules, after the
// job's. A step's hostname rules get their IPs from the DNS path alone. A
// step rule that can't be installed is a Warn, not an error: it costs only
// that step's extra reach, which fails closed to the job's rules. Must be
// called with f.mu held.
func (f *FirewallImpl) installStepRulesLocked(steps []config.StepRules) {
	for _, sr := range steps {
		for _, rule := range sr.Rules {
			if rule.Type != config.RuleTypeCIDR {
				continue
			}
			if err := f.addCIDRRuleLocked(sr.Policy, rule, 1); err != nil && !errors.Is(err, ErrStepBudget) {
				f.logger.Warn("Step rule not installed; the step gets the job's rules there",
					"step", sr.StepID, "policy", sr.Policy, "rule", rule.Value, "error", err)
			}
		}
	}
}

// ipStateLocked fetches or creates the accumulator for (policy, ip). On
// first touch it seeds the sticky all-ports flags from an existing LPM entry
// (existing, if exists). The job's accumulators live in ipPorts, keyed by IP
// alone; a step policy's in stepIPs. Must be called with f.mu held.
func (f *FirewallImpl) ipStateLocked(policy uint32, ipStr string, exists bool, existing bpf.TcBpfLpmVal) *ipPortState {
	var st *ipPortState
	if policy == bpf.PolicyJob {
		st = f.ipPorts[ipStr]
	} else {
		st = f.stepIPs[policyIP{policy, ipStr}]
	}
	if st != nil {
		return st
	}
	st = &ipPortState{}
	if exists {
		st.seedFromLPM(existing)
	}
	if policy == bpf.PolicyJob {
		f.ipPorts[ipStr] = st
		return st
	}
	if f.stepIPs == nil {
		f.stepIPs = make(map[policyIP]*ipPortState)
	}
	f.stepIPs[policyIP{policy, ipStr}] = st
	return st
}

// hostPortsPlanned reports whether a host write's port entries will be
// written: the write has ports, and no all-ports grant already makes them
// inert (writePortsV4/V6 skip those).
func (f *FirewallImpl) hostPortsPlanned(policy uint32, ipStr string, ports []portProto) bool {
	st := f.stepIPs[policyIP{policy, ipStr}]
	return len(ports) > 0 && (st == nil || !st.hasAllPorts())
}

// admitHostV4Locked charges a step's /32 write before addIPv4Locked makes
// it: the LPM entry key, and the port entries it will write.
func (f *FirewallImpl) admitHostV4Locked(policy uint32, key bpf.TcBpfRuleKey, ip uint32, ipStr string, ports []portProto) error {
	keys := []plannedKey{{ruleMapCIDRs, key}}
	if f.hostPortsPlanned(policy, ipStr, ports) {
		for _, pp := range ports {
			keys = append(keys, plannedKey{ruleMapPorts, bpf.RulePortKey(policy, ip, pp.Port, pp.Proto, 0)})
		}
	}
	return f.admitStepLocked(policy, ipStr, keys)
}

// admitHostV6Locked is the IPv6 twin of admitHostV4Locked, given the ports
// prepV6Ports left.
func (f *FirewallImpl) admitHostV6Locked(policy uint32, key bpf.TcBpfRuleKeyV6, ip [16]byte, ipStr string, ports []portProto) error {
	keys := []plannedKey{{ruleMapCIDRsV6, key}}
	if f.hostPortsPlanned(policy, ipStr, ports) {
		for _, pp := range ports {
			keys = append(keys, plannedKey{ruleMapPortsV6, bpf.RulePortKeyV6(policy, ip, pp.Port, pp.Proto, 0)})
		}
	}
	return f.admitStepLocked(policy, ipStr, keys)
}

// admitSubnetV4Locked charges a step's subnet write before addCIDRv4 makes
// it: the LPM entry, and a port entry per port.
func (f *FirewallImpl) admitSubnetV4Locked(policy uint32, key bpf.TcBpfRuleKey, network uint32, hostBits uint8, ports []portProto, label string) error {
	keys := []plannedKey{{ruleMapCIDRs, key}}
	for _, pp := range ports {
		keys = append(keys, plannedKey{ruleMapPorts, bpf.RulePortKey(policy, network, pp.Port, pp.Proto, hostBits)})
	}
	return f.admitStepLocked(policy, label, keys)
}

// admitSubnetV6Locked is the IPv6 twin of admitSubnetV4Locked.
func (f *FirewallImpl) admitSubnetV6Locked(policy uint32, key bpf.TcBpfRuleKeyV6, network [16]byte, hostBits uint8, ports []portProto, label string) error {
	keys := []plannedKey{{ruleMapCIDRsV6, key}}
	for _, pp := range ports {
		keys = append(keys, plannedKey{ruleMapPortsV6, bpf.RulePortKeyV6(policy, network, pp.Port, pp.Proto, hostBits)})
	}
	return f.admitStepLocked(policy, label, keys)
}

// admitWildcardLocked charges a step's wildcard port entries (a 0.0.0.0/0 or
// ::/0 rule with ports) before they are written.
func (f *FirewallImpl) admitWildcardLocked(policy uint32, m ruleMap, ports []portProto, label string) error {
	keys := make([]plannedKey, 0, len(ports))
	for _, pp := range ports {
		var key any
		if m == ruleMapPortsV6 {
			key = bpf.RulePortKeyV6(policy, [16]byte{}, pp.Port, pp.Proto, 0)
		} else {
			key = bpf.RulePortKey(policy, 0, pp.Port, pp.Proto, 0)
		}
		keys = append(keys, plannedKey{m, key})
	}
	return f.admitStepLocked(policy, label, keys)
}

// admitStepLocked admits one step write's keys, all or none: the write is
// refused with ErrStepBudget, and a rate-limited Warn, if its new keys would
// take any map past the step budget. Admitted keys are charged at once.
func (f *FirewallImpl) admitStepLocked(policy uint32, label string, keys []plannedKey) error {
	l := &f.steps
	var fresh [numRuleMaps]int
	for _, k := range keys {
		if _, held := l.keys[k.m][k.key]; !held {
			fresh[k.m]++
		}
	}
	for m := range numRuleMaps {
		if fresh[m] > 0 && l.used(m)+fresh[m] > l.limit() {
			f.warnStepBudgetLocked(policy, label, m)
			return ErrStepBudget
		}
	}
	for _, k := range keys {
		if l.keys[k.m] == nil {
			l.keys[k.m] = make(map[any]struct{})
		}
		l.keys[k.m][k.key] = struct{}{}
	}
	return nil
}

// warnStepBudgetLocked logs a refusal, at most once per
// stepBudgetWarnInterval, with the count since the last Warn.
func (f *FirewallImpl) warnStepBudgetLocked(policy uint32, label string, m ruleMap) {
	l := &f.steps
	l.refused++
	now := time.Now()
	if !l.warned.IsZero() && now.Sub(l.warned) < stepBudgetWarnInterval {
		return
	}
	f.logger.Warn("Step rule entry not installed: the step policies' share of a rule map is full, "+
		"so the step gets the job's rules there",
		"policy", policy,
		"destination", label,
		"map", m.String(),
		"step_budget", l.limit(),
		"job_reserved", jobReservedEntries,
		"refused", l.refused)
	l.warned, l.refused = now, 0
}
