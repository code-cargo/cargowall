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

package dns

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// The step tier of the DNS path. A name a step's own rules allow, or one a
// CNAME chain rooted at such a rule leads to, has its IPs installed under
// that step's policy, never the job's: an IP in policy 0 would hand a step's
// allowance to every step and to untagged traffic. The answer's IPs go into
// every step policy that allows the name, whichever step asked: which step
// asked is not known causally (see "DNS and per-step policy" in design.md),
// and isn't needed, since a step's entries serve that step's sockets alone.
//
// The job's verdict decides first, as it does in the kernel: a name the
// job's rules deny, on any port, gets no step installs and teaches no step
// chain, on any port. Under a deny default the job writes nothing for a name
// it denies, it only withholds the allow, and a step entry for the name's
// IPs would fill that silence, letting a step past the job's deny. The same
// goes for a CNAME hop: a step's chain stops at the first name the job's
// rules deny, teaching nothing at or past it and installing none of the
// addresses it leads to, however the chain is split across answers (the
// backfill reads the hops an answer's addresses came through from via).
// Each step allow withheld so is logged once, by step and denied name.
//
// The query filter takes the union: a name passes if the job's rules allow
// it, or, short of a job deny, any step's rules or step chains do.
//
// Requirement: a step may not be bound to its policy (map_step_policy)
// unless step installs are L7-scoped, or a step's own entries would open a
// shared edge IP to it on any SNI. They are (stepl7.go).

// stepTier is the DNS proxy's step-policy state: what step policies' CNAME
// chains have taught it, by target name. The job's derived allows stay in
// cnameAllowed, which only the job's paths read, so a chain rooted at a
// step's rule can never open its targets for the job.
type stepTier struct {
	cname *lruCache[string, stepDerived]
	// withheld holds the (step, name, denied name) triples logged as
	// withheld by a job deny, so each is logged once while it stays in the
	// LRU.
	withheld *lruCache[string, struct{}]
	// via holds the CNAME hops answers' addresses came through, for the
	// backfill's hop check (viaStore).
	via *viaStore
	// l7 is the tier's L7 scopes and late-allow bindings (stepl7.go).
	l7 *stepL7
}

// viaStore holds, by answered name, the CNAME hops each of the name's
// addresses came through, from the latest chained answer that carried it.
//
// It lives as long as the hostnameIPs entries the backfill reads beside it,
// with no TTL and no eviction: a missing record reads as no chain at all,
// and would let the backfill install an address whose chain ran through a
// hop the job denies. A record can only withhold an address, never vouch
// for one (a clean record reads as no record), so a stale one costs at most
// an install the next answer for the name makes live.
//
// It is kept only while a backfill may still read it, and dropped for good,
// its memory with it, at whichever comes first:
//   - step rules final and none: a policy without them, or startup settling
//     a run that loaded none (config.Manager.SettleStepRules). Nothing loads
//     a policy after startup, so no backfill will find a step to install
//     for;
//   - the end of the first backfill with the firewall set (seal): every
//     answer since installs at answer time, checked against its own
//     chain. A later backfill finds the store dropped and installs nothing
//     for steps, so an answer that raced the startup load, and that
//     neither installed, waits for its name's next answer (fail-closed).
type viaStore struct {
	mu      sync.Mutex
	hops    map[string]stepVia // nil once dropped
	dropped bool
}

// stepVia maps an address to the CNAME hops it was reached through.
type stepVia map[string][]string

// dropLocked drops the store once the loaded policy has no step rules, and
// reports whether it is dropped. Caller holds v.mu.
func (v *viaStore) dropLocked(known, has bool) bool {
	if !v.dropped && known && !has {
		v.dropped, v.hops = true, nil
	}
	return v.dropped
}

// seal drops the store at the end of the startup backfill (viaStore).
func (v *viaStore) seal() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dropped, v.hops = true, nil
}

func newStepTier() stepTier {
	return stepTier{
		cname:    newLRUCache[string, stepDerived](10000),
		withheld: newLRUCache[string, struct{}](1000),
		via:      &viaStore{hops: make(map[string]stepVia)},
		l7:       newStepL7(),
	}
}

// viaFor returns a copy of name's via record, and false once the store is
// dropped.
func (s *Server) viaFor(name string) (stepVia, bool) {
	v := s.steps.via
	if v == nil {
		return nil, true
	}
	known, has := s.config.StepRulesKnown()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dropLocked(known, has) {
		return nil, false
	}
	return maps.Clone(v.hops[strings.ToLower(name)]), true
}

// stepDerived is one CNAME target's derived allows, by step id. Keyed by id,
// not policy number, so an entry learned under one load names the same step
// under the next, or none (a step the new policy dropped).
type stepDerived map[string]derivedAllow

// mergeStepDerived composes a target's entries step by step, as
// mergeDerivedAllow does across origins. A step new to the target takes the
// incoming entry as it is: unioning with a missing one would read as all
// ports.
func mergeStepDerived(existing, incoming stepDerived) stepDerived {
	out := make(stepDerived, len(existing)+len(incoming))
	for id, d := range existing {
		out[id] = d
	}
	for id, d := range incoming {
		if prev, ok := out[id]; ok {
			d = mergeDerivedAllow(prev, d)
		}
		out[id] = d
	}
	return out
}

// stepAllow is one step policy's allow for a name: by its own rule, or
// derived from a CNAME chain rooted at one.
type stepAllow struct {
	stepID string
	policy uint32
	ports  []config.Port
	// chain runs from the step's origin down to the name, for a derived
	// allow; nil for a rule's.
	chain []string
	rule  string // the rule's value, or "derived"
}

// stepAllowsFor returns each step policy that allows name, given the job's
// verdict on it, in policy order, and the remaining life of name's step
// chain entry for chain extension (as derivedReach is for the job's). A step
// whose own rule matches is decided by the rule; its chain entry for the
// name, if any, is the fallback, as the job's derived tier is.
func (s *Server) stepAllowsFor(name string, verdict config.HostnameVerdict) ([]stepAllow, uint32) {
	if verdict.HasDeny() {
		s.noteWithheld(name, verdict)
		return nil, 0
	}
	name = strings.ToLower(name)
	var allows []stepAllow
	for _, m := range s.config.MatchStepHostname(name) {
		allows = append(allows, stepAllow{stepID: m.StepID, policy: m.Policy, ports: m.Ports, rule: m.Rule})
	}
	if s.steps.cname == nil {
		return allows, 0
	}
	entry, exp, ok := s.steps.cname.GetWithExpiry(name)
	if !ok {
		return allows, 0
	}
	ruled := len(allows)
	for id, d := range entry {
		if slices.ContainsFunc(allows[:ruled], func(a stepAllow) bool { return a.stepID == id }) {
			continue
		}
		policy, ok := s.config.StepPolicy(id)
		if !ok {
			continue
		}
		if hop, _ := s.jobDeniedHop(d.chain); hop >= 0 {
			continue // learned through a name the job's rules have come to deny
		}
		allows = append(allows, stepAllow{stepID: id, policy: policy, ports: d.ports, chain: d.chain, rule: "derived"})
	}
	slices.SortFunc(allows, func(a, b stepAllow) int { return cmp.Compare(a.policy, b.policy) })
	return allows, chainReach(exp)
}

// noteWithheld logs, once per (step, name), each step allow for name, by
// rule or chain, that the job's deny on it withholds, so an operator can see
// why a step's allow didn't take.
func (s *Server) noteWithheld(name string, verdict config.HostnameVerdict) {
	if s.steps.withheld == nil {
		return
	}
	name = strings.ToLower(name)
	var steps []stepAllow
	for _, m := range s.config.MatchStepHostname(name) {
		steps = append(steps, stepAllow{stepID: m.StepID, rule: m.Rule})
	}
	if s.steps.cname != nil {
		if entry, ok := s.steps.cname.Get(name); ok {
			for id := range entry {
				if _, ok := s.config.StepPolicy(id); ok {
					steps = append(steps, stepAllow{stepID: id, rule: "derived"})
				}
			}
		}
	}
	s.logWithheld(steps, name, name, verdict)
}

// logWithheld logs, once per (step, name, denied name), each step allow for
// name the job's deny on denied withholds: name itself, or a CNAME hop it
// leads through.
func (s *Server) logWithheld(steps []stepAllow, name, denied string, verdict config.HostnameVerdict) {
	if s.steps.withheld == nil {
		return
	}
	for _, a := range steps {
		if s.steps.withheld.Merge(a.stepID+"\x00"+name+"\x00"+denied, struct{}{}, 0, func(e, _ struct{}) struct{} { return e }) {
			continue
		}
		attrs := []any{
			"step", a.stepID,
			"hostname", name,
			"step_rule", a.rule,
			"job_deny_rule", verdict.DenyRule,
			"job_deny_ports", verdict.DenyPorts,
		}
		if denied != name {
			attrs = append(attrs, "via", denied)
		}
		s.logger.Info("Step allow withheld: the job's rules deny the name, or a CNAME hop it leads through, "+
			"and the job decides first", attrs...)
	}
}

// jobDeniedHop returns the first of hops the job's rules deny, on any port,
// and the job's verdict on it, or -1.
func (s *Server) jobDeniedHop(hops []string) (int, config.HostnameVerdict) {
	for i, hop := range hops {
		if v := s.config.MatchHostnameRule(hop); v.HasDeny() {
			return i, v
		}
	}
	return -1, config.HostnameVerdict{}
}

// recordVia records the hops an answer's addresses came through.
func (s *Server) recordVia(name string, links []cnameLink, ips []net.IP) {
	v := s.steps.via
	if v == nil || len(links) == 0 || len(ips) == 0 {
		return
	}
	known, has := s.config.StepRulesKnown()
	hops := make([]string, len(links))
	for i, link := range links {
		hops[i] = link.target
	}
	name = strings.ToLower(name)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dropLocked(known, has) {
		return
	}
	entry := v.hops[name]
	if entry == nil {
		entry = make(stepVia, len(ips))
		v.hops[name] = entry
	}
	for _, ip := range ips {
		entry[ip.String()] = hops
	}
}

// chainReach is how long a chain entry expiring at exp can still point
// clients at its targets, capped at maxDerivedCNAMETTL (see the job's
// derivedReach in enforceDNSResponse).
func chainReach(exp time.Time) uint32 {
	rem := time.Until(exp)
	switch {
	case exp.IsZero() || rem > maxDerivedCNAMETTL*time.Second:
		return maxDerivedCNAMETTL
	case rem > 0:
		return uint32(rem / time.Second)
	}
	return 0
}

// learnStepTier works out the step allows for one answer's name and learns
// each one's CNAME targets, with the TTL rules of the job's chain learning,
// so a step's chain split across queries still reaches its targets. It
// returns the allows, for installStepTier: none when the chain leads through
// a name the job's rules deny, whose addresses are past the job's deny. It
// learns the targets before that hop alone, and records the answer's hops
// for the backfill.
func (s *Server) learnStepTier(name string, verdict config.HostnameVerdict, links []cnameLink, ips []net.IP) []stepAllow {
	s.recordVia(name, links, ips)
	allows, derivedReach := s.stepAllowsFor(name, verdict)
	if len(allows) == 0 || len(links) == 0 {
		return allows
	}
	hops := make([]string, len(links))
	for i, link := range links {
		hops[i] = link.target
	}
	hop, hopVerdict := s.jobDeniedHop(hops)
	learn := links
	if hop >= 0 {
		learn = links[:hop]
	}
	for _, a := range allows {
		if s.steps.cname == nil {
			break
		}
		path := []string{name}
		var reach uint32
		if a.chain != nil {
			path = append([]string{}, a.chain...)
			reach = derivedReach
		}
		for _, link := range learn {
			reach = min(max(reach, derivedCNAMETTL(link.ttl)), maxDerivedCNAMETTL)
			ttl := time.Duration(reach) * time.Second
			path = append(path, link.target)
			chain := append([]string{}, path...)
			existed := s.steps.cname.Merge(link.target,
				stepDerived{a.stepID: {ports: a.ports, chain: chain}}, ttl, mergeStepDerived)
			msg, level := "Learned CNAME target for a step", slog.LevelInfo
			if existed {
				msg, level = "Refreshed CNAME target for a step", slog.LevelDebug
			}
			s.logger.Log(context.Background(), level, msg,
				"target", link.target,
				"step", a.stepID,
				"origin", chain[0],
				"chain", chain,
				"inherited_ports", a.ports,
				"ttl", ttl)
		}
	}
	if hop >= 0 {
		s.logWithheld(allows, name, hops[hop], hopVerdict)
		return nil
	}
	return allows
}

// installStepTier installs ips under each allowing step's policy. A refusal
// fails closed for that step there: the step gets the job's rules alone.
func (s *Server) installStepTier(allows []stepAllow, name string, ips []net.IP) {
	if s.firewall == nil {
		return
	}
	for _, a := range allows {
		for _, ip := range ips {
			s.installStepAllow(a, name, ip)
		}
	}
}

// installStepAllow installs ip under a's policy, for name: scoped once the
// firewall admits the install and before it writes any of it, and
// recorded, under one hold (stepl7.go). Caller checks s.firewall.
func (s *Server) installStepAllow(a stepAllow, name string, ip net.IP) {
	release := s.steps.l7.holdInstalls()
	admitted, scoped, fresh := false, false, false
	changed, err := s.firewall.AddPolicyIP(a.policy, ip, a.ports, func() error {
		admitted = true
		var err error
		scoped, fresh, err = s.scopeStepInstall(name, ip, a.ports)
		return err
	})
	switch {
	case err == nil && scoped:
		s.recordStepScope(a.policy, name, a.chain == nil, ip, a.ports)
	case err != nil && scoped:
		s.unscopeStepInstall(ip, a.ports, fresh) // scoped, then refused
	}
	release()
	if err == nil && admitted {
		s.reconcileStepBlocks(a, name, ip)
	}
	switch {
	case errors.Is(err, firewall.ErrStepBudget):
		// The firewall warns, rate-limited.
	case errors.Is(err, errStepScope):
		s.warnStepScope(a, name, ip, err)
	case err != nil:
		s.logger.Warn("Step rule install failed; the step gets the job's rules there",
			"step", a.stepID, "policy", a.policy, "hostname", name, "ip", ip.String(), "error", err)
	case changed:
		s.logger.Info("DNS resolution: added to step policy",
			"step", a.stepID, "policy", a.policy, "hostname", name, "ip", ip.String(),
			"ports", a.ports, "rule", a.rule)
	}
}

// backfillStepTier is ApplyRulesToTrackedHostnames' step tier: a name the
// proxy answered before the rules allowing it loaded, or before the firewall
// was set, gets its IPs installed now. Only the addresses the proxy itself
// answered for the name: their hops are known, and checked. Never one a
// system-resolver or reverse lookup put to the name (the job's replay takes
// those too): the first carries no chain to check, and a reverse lookup's
// name is whatever the address's owner says. A step starts after cargowall,
// so it has no connection from before that such an address could serve.
func (s *Server) backfillStepTier(name string, verdict config.HostnameVerdict, ipSet map[string]bool) {
	via, kept := s.viaFor(name)
	allows, _ := s.stepAllowsFor(name, verdict)
	if len(allows) == 0 {
		return
	}
	if !kept {
		// Past the startup backfill, or steps after step rules settled
		// without any: the hops of answers since were never kept to
		// check, so nothing is backfilled.
		return
	}
	name = strings.ToLower(name)
	s.hostnameIPsMutex.RLock()
	answered := make(map[string]bool, len(s.hostnameIPs[name]))
	for ipStr := range s.hostnameIPs[name] {
		answered[ipStr] = true
	}
	s.hostnameIPsMutex.RUnlock()
	ips := make([]net.IP, 0, len(ipSet))
	for ipStr := range ipSet {
		ip := net.ParseIP(ipStr)
		if ip == nil || !answered[ipStr] {
			continue
		}
		if hops := via[ipStr]; len(hops) > 0 {
			if hop, hv := s.jobDeniedHop(hops); hop >= 0 {
				s.logWithheld(allows, name, hops[hop], hv)
				continue
			}
		}
		ips = append(ips, ip)
	}
	s.installStepTier(allows, name, ips)
}

// stepAllowRule names what allows domain for a step, for a report that
// would otherwise show no rule: the first step whose own rule allows it,
// and that rule, or the first step a chain leads it to, and "derived". It
// returns empty strings when no step allows domain.
func (s *Server) stepAllowRule(domain string) (step, rule string) {
	if m := s.config.MatchStepHostname(domain); len(m) > 0 {
		return m[0].StepID, m[0].Rule
	}
	if s.steps.cname == nil {
		return "", ""
	}
	entry, _ := s.steps.cname.Get(strings.ToLower(domain))
	ids := make([]string, 0, len(entry))
	for id := range entry {
		if _, ok := s.config.StepPolicy(id); ok {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return "", ""
	}
	slices.Sort(ids)
	return ids[0], "derived"
}

// stepAllowsQuery is the query filter's step tier, consulted once the job's
// rules haven't allowed domain: any step's rules, or a live step chain to
// domain for a step the policy still has. Never past a job deny, which it
// notes as withholding the steps' allows.
func (s *Server) stepAllowsQuery(domain string, verdict config.HostnameVerdict) bool {
	if verdict.HasDeny() {
		s.noteWithheld(domain, verdict)
		return false
	}
	if s.config.StepAllowsHostname(domain) {
		return true
	}
	if s.steps.cname == nil {
		return false
	}
	entry, ok := s.steps.cname.Get(strings.ToLower(domain))
	if !ok {
		return false
	}
	for id := range entry {
		if _, ok := s.config.StepPolicy(id); ok {
			return true
		}
	}
	return false
}
