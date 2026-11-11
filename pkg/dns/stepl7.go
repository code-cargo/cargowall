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
	"net"
	"sync"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
)

// The step tier at L7, and its late-allows. A step's DNS install is
// L7-scoped as the job's are: before its address opens under the step's
// policy, the address is scoped for the name, so a flow to it must present
// a name its own policy allows there. The oracle judges that name by the
// policy the kernel stamped on the punt (config.L7Request.Policy): the
// job's rules and chains first, then the step's (StepAllowPorts). A step
// bound to its policy therefore reaches a shared edge address by the names
// its rules allow and no others, which is what binding a step requires.

// stepL7 is the step tier's L7 and late-allow state.
type stepL7 struct {
	mu sync.Mutex
	// scoped holds, by address, every step install's L7 scope, for the
	// rewarm after a scope flush (rescopeStepTier). Kept only while L7 is
	// on, and bounded by the step installs the rule maps' step budget
	// admits, one entry an address.
	scoped map[string]stepScope
	// bindings resolves a step ordinal to the policy it is bound to, for
	// the per-step late-allow; nil until something binds steps.
	bindings func(ordinal uint32) (policy uint32, ok bool)
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
func (s *Server) SetStepBindings(bindings func(ordinal uint32) (policy uint32, ok bool)) {
	if s.steps.l7 == nil {
		return
	}
	s.steps.l7.mu.Lock()
	defer s.steps.l7.mu.Unlock()
	s.steps.l7.bindings = bindings
}

// scopeStepInstall scopes ip for name on ports before a step install opens
// it, as applyVerdictSide does the job's, and records the scope for the
// rewarm. Scoping an address whose install then fails only narrows it.
func (s *Server) scopeStepInstall(name string, ip net.IP, ports []config.Port) {
	if s.l7Registrar() == nil || s.steps.l7 == nil {
		return
	}
	s.registerL7(name, ip, ports)
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

// rescopeStepTier scopes again the step installs among ipSet: the tracked-
// hostname replay flushes every L7 scope before it rebuilds them, and a
// step's installs from after the startup backfill are not backfilled again.
func (s *Server) rescopeStepTier(ipSet map[string]bool) {
	if s.steps.l7 == nil {
		return
	}
	type rescope struct {
		ip net.IP
		stepScope
	}
	var todo []rescope
	s.steps.l7.mu.Lock()
	for ipStr := range ipSet {
		if sc, ok := s.steps.l7.scoped[ipStr]; ok {
			todo = append(todo, rescope{net.ParseIP(ipStr), sc})
		}
	}
	s.steps.l7.mu.Unlock()
	for _, r := range todo {
		s.registerL7(r.name, r.ip, r.ports)
	}
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
