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
	"strings"

	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/events"
)

// The step tier's late-allows once steps are bound. A step is bound to its
// policy only once it is identified, after its program has started: until
// then its connections are judged as the job's, and a block among them that
// its own rules would have let through is re-reported once it is bound
// (ReconcileBoundStep). After it, the event pipeline's late-allow asks the
// step tier too (LateAllowStep), for a block the job's rules don't open.

// boundPolicy is the policy step ordinal is bound to, by the binder's
// lookup (SetStepBindings).
func (s *Server) boundPolicy(ordinal uint32) (uint32, bool) {
	l := s.steps.l7
	if l == nil {
		return 0, false
	}
	l.mu.Lock()
	bindings := l.bindings
	l.mu.Unlock()
	if bindings == nil {
		return 0, false
	}
	return bindings(ordinal)
}

// ReconcileBoundStep re-reports as late-allowed the recent blocks of step
// ordinal, just bound to policy, that the rule maps now let through for it
// (firewall.Firewall.Allows): connections the step made before its binding
// landed, judged as the job's then. A container's blocks stay
// (events.RecentBlocks.TakeStep). Each is reported under the name its
// address maps to, by the step's rule for that name where the proxy itself
// answered the name for the address, and otherwise by stepID: a name a
// reverse lookup put to the address is whatever its owner says, and never
// names the rule.
func (s *Server) ReconcileBoundStep(ordinal, policy uint32, stepID string) {
	if s.recentBlocks == nil || s.auditLogger == nil || s.firewall == nil {
		return
	}
	blocks := s.recentBlocks.TakeStep(ordinal, func(b events.RecentBlock) bool {
		proto, ok := ipProto(b.Protocol)
		ip := net.ParseIP(b.DstIP)
		return ok && ip != nil && s.firewall.Allows(policy, ip, b.DstPort, proto)
	})
	for _, b := range blocks {
		hostname := s.config.LookupHostnameByIP(b.DstIP)
		rule := "step " + stepID
		if s.config.NameResolvedToIP(hostname, b.DstIP) {
			if a, ok := s.stepAllowFor(policy, hostname); ok {
				rule = a.rule
			}
		}
		s.reportLateAllowed([]events.RecentBlock{b}, hostname, rule, nil)
	}
}

// LateAllowStep is the event pipeline's step tier (events.StepLateAllower):
// for a block by step ordinal, bound to a policy whose own rules allow
// hostname at ip, it installs ip under that policy, as the proxy does on
// answering, and reports whether the step's retry on port passes now, and
// by what rule. hostname must be a name the proxy itself answered ip for,
// by its forward-resolution evidence: never one a reverse lookup put to the
// address, which is whatever the address's owner says.
func (s *Server) LateAllowStep(ordinal uint32, hostname string, ip net.IP, port uint16, proto uint8) (bool, string) {
	policy, ok := s.boundPolicy(ordinal)
	if !ok || s.firewall == nil || ip == nil {
		return false, ""
	}
	name := strings.ToLower(hostname)
	if !s.config.NameResolvedToIP(name, ip.String()) {
		return false, ""
	}
	a, ok := s.stepAllowFor(policy, name)
	if !ok {
		return false, ""
	}
	s.installStepAllow(a, name, ip)
	return s.firewall.Allows(policy, ip, port, proto), a.rule
}

// ipProto is the protocol number of an audit protocol name, for the TCP and
// UDP blocks recent-blocks keeps.
func ipProto(name string) (uint8, bool) {
	switch name {
	case "TCP":
		return unix.IPPROTO_TCP, true
	case "UDP":
		return unix.IPPROTO_UDP, true
	}
	return 0, false
}
