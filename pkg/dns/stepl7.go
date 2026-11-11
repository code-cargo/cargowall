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
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
)

// The step tier at L7, and its late-allows. A step's DNS install is
// L7-scoped as the job's are: once the firewall admits the install, and
// before any of it is written, the address is scoped for the name, so a
// flow to it must present a name its own policy allows there; an install
// whose scope cannot be written is withheld, so no step install is ever
// open unscoped. The oracle judges that name by the policy the kernel
// stamped on the punt (config.L7Request.Policy): the job's rules and chains
// first, then the step's (StepAllowPorts). A step bound to its policy
// therefore reaches a shared edge address by the names its rules allow and
// no others, which is what binding a step requires.

// errStepScope withholds a step install whose address the L7 scope map
// would not take: open unscoped, it would reach a shared edge address on
// any name.
var errStepScope = errors.New("step install withheld: its address could not be L7-scoped")

// stepScopeWarnInterval rate-limits the withheld-install Warn: a full scope
// map refuses every new step address, and DNS refreshes retry each one.
const stepScopeWarnInterval = time.Minute

// stepL7 is the step tier's L7 and late-allow state.
type stepL7 struct {
	mu sync.Mutex
	// scoped holds, by address, the L7 scope of every step install the
	// firewall admitted and wrote, for the rewarm after a scope flush
	// (rescopeStepTier). Kept only while L7 is on, one entry an address,
	// so it is bounded by the addresses the steps' share of the trie
	// admits: 12288 of each family.
	scoped map[string]stepScope
	// bindings resolves a step ordinal to the policy it is bound to, for
	// the per-step late-allow; nil until something binds steps.
	bindings func(ordinal uint32) (policy uint32, ok bool)
	// withheld counts the installs withheld for want of a scope since the
	// last Warn, logged at warned.
	withheld int
	warned   time.Time
}

// stepScope is one address's step scope: a name bound to it, which scoping
// requires, and the ports every step installed it on.
type stepScope struct {
	name  string
	ports []config.Port
}

// SetStepBindings installs the ordinal-to-policy lookup a step's late-allow
// reconciles by: a step policy's install re-reports only the blocks of the
// steps bound to it. Until it is set, a step install re-reports none.
// Requirement: bindings runs under the recent-blocks buffer's lock
// (events.RecentBlocks.TakeMatchingFor), so it must not take a lock that
// is held while blocks are consumed.
func (s *Server) SetStepBindings(bindings func(ordinal uint32) (policy uint32, ok bool)) {
	if s.steps.l7 == nil {
		return
	}
	s.steps.l7.mu.Lock()
	defer s.steps.l7.mu.Unlock()
	s.steps.l7.bindings = bindings
}

// scopeStepInstall scopes ip for name on ports, as applyVerdictSide does a
// job install's: the firewall runs it once it admits a step install, and
// before it writes any of it. An address no forward resolution bound to
// name stays unscoped, L4-governed as the job's (SCOPE IFF BOUND). A scope
// the registrar fails to write, the map full say, withholds the install
// (errStepScope).
func (s *Server) scopeStepInstall(name string, ip net.IP, ports []config.Port) error {
	if err := scopeL7Identity(s.l7Registrar(), s.config, name, ip, ports, s.logger); err != nil {
		return fmt.Errorf("%w: %w", errStepScope, err)
	}
	return nil
}

// recordStepScope records an admitted, written step install's scope for
// the rewarm, its ports joined to those of any other step's install there.
func (s *Server) recordStepScope(name string, ip net.IP, ports []config.Port) {
	if s.l7Registrar() == nil || s.steps.l7 == nil {
		return
	}
	l := s.steps.l7
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.scoped == nil {
		l.scoped = make(map[string]stepScope)
	}
	key := ip.String()
	if prev, ok := l.scoped[key]; ok {
		ports = config.UnionPorts(prev.ports, ports)
		name = prev.name
	}
	l.scoped[key] = stepScope{name: name, ports: ports}
}

// rescopeStepTier scopes every recorded step install again. The tracked-
// hostname replay flushes every L7 scope before it rebuilds them, and a
// step's installs from after the startup backfill are never backfilled
// again. It runs first, into the emptied maps, which the steps' share,
// bounded as the record is, always fits; a scope that fails even so is a
// Warn.
func (s *Server) rescopeStepTier() {
	if s.steps.l7 == nil {
		return
	}
	s.steps.l7.mu.Lock()
	todo := make(map[string]stepScope, len(s.steps.l7.scoped))
	for ipStr, sc := range s.steps.l7.scoped {
		todo[ipStr] = sc
	}
	s.steps.l7.mu.Unlock()
	for ipStr, sc := range todo {
		if err := scopeL7Identity(s.l7Registrar(), s.config, sc.name, net.ParseIP(ipStr), sc.ports, s.logger); err != nil {
			s.logger.Warn("L7: a step install's scope could not be restored after the flush; "+
				"the address is open to its steps without name enforcement",
				"ip", ipStr, "hostname", sc.name, "error", err)
		}
	}
}

// warnStepScope logs an install withheld for want of a scope, at most once
// per stepScopeWarnInterval, with the count since the last Warn.
func (s *Server) warnStepScope(a stepAllow, name string, ip net.IP, err error) {
	l := s.steps.l7
	if l == nil {
		return
	}
	l.mu.Lock()
	l.withheld++
	if !l.warned.IsZero() && time.Since(l.warned) < stepScopeWarnInterval {
		l.mu.Unlock()
		return
	}
	withheld := l.withheld
	l.warned, l.withheld = time.Now(), 0
	l.mu.Unlock()
	s.logger.Warn("Step rule install withheld: its address could not be L7-scoped, so the step gets the job's rules there",
		"step", a.stepID, "policy", a.policy, "hostname", name, "ip", ip.String(),
		"withheld", withheld, "error", err)
}

// StepAllowPorts reports the ports step policy's own rules, or else its
// chain to name, allow name on, past the job's rules: the L7 oracle's step
// tier (config.L7Policy.WithSteps). A name the job's rules deny on any port
// is no step's (stepAllowsFor).
func (s *Server) StepAllowPorts(policy uint32, name string) ([]config.Port, bool) {
	allows, _ := s.stepAllowsFor(name, s.config.MatchHostnameRule(name))
	for _, a := range allows {
		if a.policy == policy {
			return a.ports, true
		}
	}
	return nil, false
}

// reconcileStepBlocks re-reports as late-allowed the recent blocks to ip
// that a's install opened: on its ports less those a job CIDR deny holds
// there, which the job decides first, and of the steps bound to its policy
// alone, never another step's.
func (s *Server) reconcileStepBlocks(a stepAllow, name string, ip net.IP) {
	if s.recentBlocks == nil || s.auditLogger == nil || s.steps.l7 == nil {
		return
	}
	denied, all := s.config.JobCIDRDeniesAt(ip)
	if all {
		return
	}
	s.steps.l7.mu.Lock()
	bindings := s.steps.l7.bindings
	s.steps.l7.mu.Unlock()
	if bindings == nil {
		return
	}
	bound := func(ordinal uint32) bool {
		policy, ok := bindings(ordinal)
		return ok && policy == a.policy
	}
	s.reportLateAllowed(s.recentBlocks.TakeMatchingFor(ip.String(), bound, a.ports, denied, len(denied) > 0), name, a.rule, a.chain)
}

// reportLateAllowed re-reports blocks, taken from the recent-blocks buffer
// for a destination the firewall has just opened, as late-allowed: under
// hostname, by matchedRule, with cnameChain the resolution that opened it.
func (s *Server) reportLateAllowed(blocks []events.RecentBlock, hostname, matchedRule string, cnameChain []string) {
	for _, b := range blocks {
		s.logger.Info("Connection late-allowed (reconciled after DNS resolution)",
			"dst", hostname,
			"dst_ip", b.DstIP,
			"dst_port", b.DstPort,
			"process", b.Process,
			"pid", b.PID,
			"matched_rule", matchedRule)
		// The caller's chain (from the resolution that opened the firewall)
		// wins when present; otherwise the chain recorded with the original
		// blocked attempt is preserved rather than dropped.
		chain := cnameChain
		if len(chain) == 0 {
			chain = b.CNAMEChain
		}
		// Dated at the original blocked attempt (b.At), not reconcile time,
		// so the event supersedes every blocked record at or before it and
		// step correlation reflects when the connection actually happened.
		if err := s.auditLogger.LogEvent(events.AuditEvent{
			Timestamp:       b.At,
			EventType:       events.EventConnectionLateAllowed,
			SrcIP:           b.SrcIP,
			DstIP:           b.DstIP,
			DstHostname:     hostname,
			DstPort:         b.DstPort,
			Protocol:        b.Protocol,
			Process:         b.Process,
			PID:             b.PID,
			MatchedRule:     matchedRule,
			CNAMEChain:      chain,
			StepOrdinal:     b.StepOrdinal,
			ContainerID:     b.ContainerID,
			ContainerOrigin: b.ContainerOrigin,
		}); err != nil {
			s.logger.Error("Failed to write audit log", "error", err)
		}
	}
}
