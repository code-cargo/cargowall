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
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// The rule maps hold the job's rules, under policy 0, and each step's, under
// a policy of its own. A map's max_entries covers all of them, so the split
// is kept here. The maps are sized at load for the policy in hand
// (bpf.SizeRuleMaps): bpf.RuleMapEntriesJobOnly without steps, and
// bpf.RuleMapEntries with them. Step writes may never take the room the job
// had before step policies existed, so what the job can install doesn't
// depend on steps. The job comes first past that too: its own policy may
// hold more, and room it takes past its reservation is room the steps'
// share loses.
const (
	// jobReservedEntries is the room in each rule map no step write may
	// take: the maps' whole size before step policies, and their size for a
	// policy without steps.
	jobReservedEntries = int(bpf.RuleMapEntriesJobOnly)
	// stepEntryBudget is what the step policies together may hold in each
	// rule map, at its size for a policy with steps.
	stepEntryBudget = int(bpf.RuleMapEntries) - jobReservedEntries
)

// ErrStepBudget refuses a step write the rule maps have no room for: the
// steps' share of a map is full, or the job's own entries have taken it.
// The step's traffic there gets the job's rules alone: fail-closed. Nothing
// of a step CIDR rule's refused write stays installed (the sync takes out
// what landed); a DNS install the kernel refused part-way keeps what landed,
// its denies first, so less than it asked for.
var ErrStepBudget = errors.New("no room for step entries in a rule map")

// Why a step write found no room, for the refusal Warn.
const (
	noRoomStepShare = "the step policies' share of the map is full"
	noRoomJob       = "the map is full: the job's own entries have taken room past its reservation, and the job comes first"
)

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
// key is charged when its write is admitted, before the write itself, and a
// write that then fails is refunded what it charged and didn't write, so the
// books stay what the maps hold.
type stepLedger struct {
	keys [numRuleMaps]map[any]struct{}
	// fresh are the keys the step write under way was charged for new.
	fresh []plannedKey
	// budget is each map's room for step entries: its size less the job's
	// reservation, so none at the size for a policy without steps, and no
	// more than the steps hold once the map itself refused one for room.
	budget [numRuleMaps]int
	// jobFull marks a map that refused a step write for room: the job's own
	// entries took the rest (shrinkBudget).
	jobFull [numRuleMaps]bool
	refused int       // refusals since the last Warn
	warned  time.Time // when the last refusal Warn was logged
}

// sizeBudget sets each map's step budget from the map's size.
func (l *stepLedger) sizeBudget(maps ...*ebpf.Map) {
	for m, em := range maps {
		if em != nil {
			l.budget[m] = max(int(em.MaxEntries())-jobReservedEntries, 0)
		}
	}
}

// setBudget sets every map's step budget to n.
func (l *stepLedger) setBudget(n int) {
	for m := range l.budget {
		l.budget[m] = n
	}
}

// used reports how many entries step policies hold in m.
func (l *stepLedger) used(m ruleMap) int { return len(l.keys[m]) }

// shrinkBudget holds m's step budget to what the steps hold, once m itself
// refused a step write for room: the job's entries, which only grow, have
// taken the rest. A later write is then refused at admission, before it
// scopes or writes anything, rather than by the map.
func (l *stepLedger) shrinkBudget(m ruleMap) {
	l.budget[m] = min(l.budget[m], l.used(m))
	l.jobFull[m] = true
}

// plannedKey is one key a step write is about to write.
type plannedKey struct {
	m   ruleMap
	key any
}

// AddPolicyIP adds an allow for ip on ports under a step policy. See the
// Firewall interface.
func (f *FirewallImpl) AddPolicyIP(policy uint32, ip net.IP, ports []config.Port, scope func() error) (bool, error) {
	if policy == bpf.PolicyJob {
		return false, fmt.Errorf("AddPolicyIP writes step policies only; the job's rules are written by AddIP")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ip4, ip6 := ip.To4(), ip.To16()
	var dst *net.IPNet
	switch {
	case ip4 != nil:
		dst = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	case ip6 != nil:
		dst = &net.IPNet{IP: ip6, Mask: net.CIDRMask(128, 128)}
	default:
		return false, fmt.Errorf("invalid IP: %s", ip.String())
	}
	ipStr := ip.String()
	allow, deny, ok := f.gateStepLocked(policy, dst, expandPorts(ports))
	if !ok {
		return false, f.stepWriteErrLocked(policy, ipStr, nil)
	}
	// The whole write is admitted before any of it is written, and scoped
	// then: a write the budget refuses scopes nothing, and one whose scope
	// fails writes nothing.
	keys, writes := f.hostWriteKeysLocked(policy, ip4, ip6, ipStr, deny, allow)
	if !writes {
		return false, nil
	}
	if err := f.admitStepLocked(policy, ipStr, keys); err != nil {
		return false, f.stepWriteErrLocked(policy, ipStr, err)
	}
	if scope != nil {
		if err := scope(); err != nil {
			return false, f.stepWriteErrLocked(policy, ipStr, err)
		}
	}
	add := func(actionVal uint8, pp []portProto) (bool, error) {
		if ip4 != nil {
			return f.addIPv4Locked(policy, ip4, ipStr, actionVal, pp)
		}
		return f.addIPv6Locked(policy, ip6, ipStr, actionVal, pp)
	}
	// The ports the job denies here go in first, as denies, so a miss can't
	// fall through to a step wildcard, and a write the map refuses part-way
	// leaves fewer allows, never an allow without them.
	var changed bool
	var err error
	if len(deny) > 0 {
		changed, err = add(0, deny)
	}
	if err == nil {
		var allowed bool
		allowed, err = add(1, allow)
		changed = changed || allowed
	}
	if err = f.stepWriteErrLocked(policy, ipStr, err); err != nil {
		return false, err
	}
	return changed, nil
}

// RemovePolicyIP takes out every entry step policy holds at ip's host route.
// See the Firewall interface.
func (f *FirewallImpl) RemovePolicyIP(policy uint32, ip net.IP) error {
	if policy == bpf.PolicyJob {
		return fmt.Errorf("RemovePolicyIP takes out step policies' entries only")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var lpm any
	var ports []any
	if ip4 := ip.To4(); ip4 != nil {
		network := binary.NativeEndian.Uint32(ip4)
		lpm = bpf.RuleKey(policy, 32, network)
		for key := range f.steps.keys[ruleMapPorts] {
			if k := key.(bpf.TcBpfRulePortKey); k.Policy == policy && k.Ip == network && k.HostBits == 0 {
				ports = append(ports, key)
			}
		}
	} else if ip6 := ip.To16(); ip6 != nil {
		var network [16]byte
		copy(network[:], ip6)
		lpm = bpf.RuleKeyV6(policy, 128, network)
		for key := range f.steps.keys[ruleMapPortsV6] {
			if k := key.(bpf.TcBpfRulePortKeyV6); k.Policy == policy && k.Ip == network && k.HostBits == 0 {
				ports = append(ports, key)
			}
		}
	} else {
		return fmt.Errorf("invalid IP: %s", ip.String())
	}
	// The LPM entry first: its port entries are never read without it, so a
	// failed delete after it leaves nothing open.
	if !f.deleteStepKeyLocked(lpm) {
		return fmt.Errorf("could not take out the step entry for %s", ip)
	}
	for _, key := range ports {
		f.deleteStepKeyLocked(key)
	}
	delete(f.stepIPs, policyIP{policy, ip.String()})
	return nil
}

// hostWriteKeysLocked is every key a step host write to ip writes, its
// denies' and its allows', as admitHostV4Locked and admitHostV6Locked plan
// each, and whether it writes anything at all: an IPv6 write whose ports are
// all ICMP writes nothing (prepV6Ports).
func (f *FirewallImpl) hostWriteKeysLocked(policy uint32, ip4, ip6 net.IP, ipStr string, deny, allow []portProto) ([]plannedKey, bool) {
	if ip4 != nil {
		network := binary.NativeEndian.Uint32(ip4)
		keys := []plannedKey{{ruleMapCIDRs, bpf.RuleKey(policy, 32, network)}}
		for _, pp := range [][]portProto{deny, allow} {
			if f.hostPortsPlanned(policy, ipStr, pp) {
				for _, p := range pp {
					keys = append(keys, plannedKey{ruleMapPorts, bpf.RulePortKey(policy, network, p.Port, p.Proto, 0)})
				}
			}
		}
		return keys, true
	}
	var network [16]byte
	copy(network[:], ip6)
	keys := []plannedKey{{ruleMapCIDRsV6, bpf.RuleKeyV6(policy, 128, network)}}
	writes := false
	for i, pp := range [][]portProto{deny, allow} {
		stripped, dropped := stripICMPForV6(pp)
		if dropped && len(stripped) == 0 || i == 0 && len(pp) == 0 {
			continue // no write, ICMP alone; or no denies
		}
		writes = true
		if f.hostPortsPlanned(policy, ipStr, stripped) {
			for _, p := range stripped {
				keys = append(keys, plannedKey{ruleMapPortsV6, bpf.RulePortKeyV6(policy, network, p.Port, p.Proto, 0)})
			}
		}
	}
	return keys, writes
}

// stepWriteErrLocked ends a step write, given its error. A failed write is
// refunded what it was charged for and didn't write. One the kernel refused
// for room becomes ErrStepBudget, with the refusal Warn: the ledger admitted
// it, so the steps' share had room, and the job's own entries took it.
func (f *FirewallImpl) stepWriteErrLocked(policy uint32, label string, err error) error {
	var refused ruleMap
	var refunded bool
	if err != nil {
		refused, refunded = f.refundLocked()
	}
	f.steps.fresh = nil
	if err == nil || errors.Is(err, ErrStepBudget) || !(errors.Is(err, unix.E2BIG) || errors.Is(err, unix.ENOSPC)) {
		f.flushNoRoomLocked()
		return err
	}
	if refunded {
		f.steps.shrinkBudget(refused)
	}
	f.warnNoRoomLocked(policy, label, noRoomJob)
	return fmt.Errorf("%w: %w", ErrStepBudget, err)
}

// refundLocked uncharges the keys the failed write was charged for new that
// its map doesn't hold, and names the map that refused it. A write the
// kernel refused part-way keeps the charge for what it did write. Every
// writer writes a prefix's port entries before its LPM entry, so a refunded
// port key names its port map as the refuser, and otherwise the trie is.
func (f *FirewallImpl) refundLocked() (refused ruleMap, ok bool) {
	for _, k := range f.steps.fresh {
		if f.holdsLocked(k.key) {
			continue
		}
		delete(f.steps.keys[k.m], k.key)
		if !ok || isPortMap(k.m) && !isPortMap(refused) {
			refused, ok = k.m, true
		}
	}
	return refused, ok
}

// isPortMap reports whether m holds port entries.
func isPortMap(m ruleMap) bool { return m == ruleMapPorts || m == ruleMapPortsV6 }

// holdsLocked reports whether a rule map holds key, by the key's type.
func (f *FirewallImpl) holdsLocked(key any) bool {
	var lpm bpf.TcBpfLpmVal
	var port bpf.TcBpfPortVal
	switch k := key.(type) {
	case bpf.TcBpfRuleKey:
		return f.cidrsMap.Lookup(&k, &lpm) == nil
	case bpf.TcBpfRuleKeyV6:
		return f.cidrsV6Map.Lookup(&k, &lpm) == nil
	case bpf.TcBpfRulePortKey:
		return f.portsMap.Lookup(&k, &port) == nil
	case bpf.TcBpfRulePortKeyV6:
		return f.portsV6Map.Lookup(&k, &port) == nil
	}
	return true
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
// take any map past its step budget. Admitted keys are charged at once.
func (f *FirewallImpl) admitStepLocked(policy uint32, label string, keys []plannedKey) error {
	l := &f.steps
	var fresh [numRuleMaps]int
	var charged []plannedKey
	for _, k := range keys {
		if _, held := l.keys[k.m][k.key]; held || slices.Contains(charged, k) {
			continue
		}
		fresh[k.m]++
		charged = append(charged, k)
	}
	for m := range numRuleMaps {
		if fresh[m] > 0 && l.used(m)+fresh[m] > l.budget[m] {
			reason := noRoomStepShare
			if l.jobFull[m] {
				reason = noRoomJob
			}
			f.warnNoRoomLocked(policy, label, reason, "map", m.String(), "step_budget", l.budget[m])
			return ErrStepBudget
		}
	}
	for _, k := range charged {
		if l.keys[k.m] == nil {
			l.keys[k.m] = make(map[any]struct{})
		}
		l.keys[k.m][k.key] = struct{}{}
	}
	l.fresh = append(l.fresh, charged...)
	return nil
}

// warnNoRoomLocked logs a refusal for want of room, whatever the reason, at
// most once per stepBudgetWarnInterval, with the count since the last Warn.
func (f *FirewallImpl) warnNoRoomLocked(policy uint32, label, reason string, attrs ...any) {
	l := &f.steps
	l.refused++
	now := time.Now()
	if !l.warned.IsZero() && now.Sub(l.warned) < stepBudgetWarnInterval {
		return
	}
	f.logger.Warn("Step rule entry not installed: no room in a rule map, so the step gets the job's rules there",
		append([]any{
			"reason", reason,
			"policy", policy,
			"destination", label,
			"job_reserved", jobReservedEntries,
			"refused", l.refused,
		}, attrs...)...)
	l.warned, l.refused = now, 0
}

// flushNoRoomLocked logs the refusals the rate limit held back once their
// interval is over, so a count is reported even when no refusal follows.
func (f *FirewallImpl) flushNoRoomLocked() {
	l := &f.steps
	if l.refused == 0 || time.Since(l.warned) < stepBudgetWarnInterval {
		return
	}
	f.logger.Warn("Step rule entries not installed for want of room in the rule maps since the last Warn; "+
		"those steps get the job's rules there",
		"refused", l.refused)
	l.warned, l.refused = time.Now(), 0
}
