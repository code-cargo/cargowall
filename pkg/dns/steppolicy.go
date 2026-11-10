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
	"net"
	"slices"
	"strings"
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
// chain. Under a deny default the job writes nothing for a name it denies,
// it only withholds the allow, and a step entry for the name's IPs would
// fill that silence, letting a step past the job's deny.
//
// The query filter takes the union: a name passes if the job's rules allow
// it, or, short of a job deny, any step's rules or step chains do.
//
// L7 scoping of step installs, and step-aware late-allows, are not done
// here: nothing binds a step to its policy yet, so no traffic is judged by
// these entries.

// stepTier is the DNS proxy's step-policy state: what step policies' CNAME
// chains have taught it, by target name. The job's derived allows stay in
// cnameAllowed, which only the job's paths read, so a chain rooted at a
// step's rule can never open its targets for the job.
type stepTier struct {
	cname *lruCache[string, stepDerived]
}

func newStepTier() stepTier {
	return stepTier{cname: newLRUCache[string, stepDerived](10000)}
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
		allows = append(allows, stepAllow{stepID: id, policy: policy, ports: d.ports, chain: d.chain, rule: "derived"})
	}
	slices.SortFunc(allows, func(a, b stepAllow) int { return cmp.Compare(a.policy, b.policy) })
	return allows, chainReach(exp)
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
// returns the allows, for installStepTier.
func (s *Server) learnStepTier(name string, verdict config.HostnameVerdict, links []cnameLink) []stepAllow {
	allows, derivedReach := s.stepAllowsFor(name, verdict)
	if len(links) == 0 || s.steps.cname == nil {
		return allows
	}
	for _, a := range allows {
		path := []string{name}
		var reach uint32
		if a.chain != nil {
			path = append([]string{}, a.chain...)
			reach = derivedReach
		}
		for _, link := range links {
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
			changed, err := s.firewall.AddPolicyIP(a.policy, ip, a.ports)
			switch {
			case errors.Is(err, firewall.ErrStepBudget):
				// The firewall warns, rate-limited.
			case err != nil:
				s.logger.Warn("Step rule install failed; the step gets the job's rules there",
					"step", a.stepID, "policy", a.policy, "hostname", name, "ip", ip.String(), "error", err)
			case changed:
				s.logger.Info("DNS resolution: added to step policy",
					"step", a.stepID, "policy", a.policy, "hostname", name, "ip", ip.String(),
					"ports", a.ports, "rule", a.rule)
			}
		}
	}
}

// backfillStepTier is ApplyRulesToTrackedHostnames' step tier: a name the
// proxy saw before the rules allowing it loaded gets its IPs installed now.
func (s *Server) backfillStepTier(name string, verdict config.HostnameVerdict, ipSet map[string]bool) {
	allows, _ := s.stepAllowsFor(name, verdict)
	if len(allows) == 0 {
		return
	}
	ips := make([]net.IP, 0, len(ipSet))
	for ipStr := range ipSet {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	s.installStepTier(allows, name, ips)
}

// stepAllowsQuery is the query filter's step tier, consulted only once the
// job's rules have neither allowed nor denied domain: any step's rules, or
// a live step chain to domain for a step the policy still has.
func (s *Server) stepAllowsQuery(domain string) bool {
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
