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
	"net/netip"
	"strings"
)

// L7Request is one destination identity recovered from an L7 handshake (SNI,
// Host, QUIC) awaiting a policy decision.
type L7Request struct {
	Name    string
	DstIP   string // destination address, string form (the DNS/audit vocabulary)
	DstPort uint16
	Proto   uint8 // L4 protocol number
	// Policy is the step policy the flow's socket is judged by, as the
	// kernel read it with the punt; 0 (the job's) for none.
	Policy uint32
	// SNI marks Name as a TLS or QUIC server name; false for an HTTP Host.
	SNI bool
}

// L7Match is the answer MatchName gives. Three states rather than a bool
// because "allowed somewhere" and "allowed HERE" must be distinguishable: the
// per-IP binding rolls out on its own gate, so the caller needs to tell them
// apart to choose between denying and merely reporting the narrowing.
type L7Match uint8

const (
	// L7NoMatch: no rule or derived allow covers this name on this port.
	L7NoMatch L7Match = iota
	// L7MatchOK: allowed, and the name is bound to this destination.
	L7MatchOK
	// L7MatchElsewhere: allowed by name and port, but never seen resolving to
	// this destination.
	L7MatchElsewhere
	// L7MatchBareLabel: the name is a single-label SNI no tier allows, at a
	// public address that a name the policy allows here forward-resolved to.
	// See bareLabelAdmitted.
	L7MatchBareLabel
)

// L7Policy is the whole L7 name authority: the rules a Manager holds plus the
// proxy-owned derived-CNAME set, in one value the oracle can call. Its only
// method is the decision — deliberately NOT an embedded *Manager, which would
// promote rule loading, DNS-mapping mutation, and cache flushing onto a type
// whose job is to answer one question.
type L7Policy struct {
	cm *Manager
	// derived resolves a name learned as a CNAME target of an allowed host to
	// its inherited allow ports. Nil when there is no DNS proxy, in which case
	// no name could have been derived in the first place.
	derived func(name string) ([]Port, bool)
	// steps resolves the ports a step policy's own rules or chains allow a
	// name on, past the job's. Nil without step rules.
	steps func(policy uint32, name string) ([]Port, bool)
}

// NewL7Policy binds a Manager to the proxy's derived-target lookup. Pass a nil
// derived when there is no DNS proxy.
func NewL7Policy(cm *Manager, derived func(name string) ([]Port, bool)) L7Policy {
	return L7Policy{cm: cm, derived: derived}
}

// WithSteps binds the step tier: the ports step policy's own rules or
// chains allow a name on.
func (p L7Policy) WithSteps(steps func(policy uint32, name string) ([]Port, bool)) L7Policy {
	p.steps = steps
	return p
}

// MatchName decides whether a recovered destination name is admitted ON THIS
// FLOW'S PORT, and whether it is bound to THIS destination. It is the ONE
// entry point for that decision.
//
// The policy is the same two-tier set the DNS query gate applies
// (Server.isQueryAllowed) plus a port dimension: a name allowed only on a
// non-web port (an ssh host on :22) must not validate as an SNI on a shared
// edge IP that some 443 rule scoped, or an attacker presents it and the flow
// is admitted. A name no tier allows is L7NoMatch, unless it passes as a
// bare label (bareLabelAdmitted).
func (p L7Policy) MatchName(q L7Request) L7Match {
	allowed, denied := p.nameAllowed(q.Name, q)
	if denied {
		return L7NoMatch
	}
	if !allowed {
		if p.bareLabelAdmitted(q) {
			return L7MatchBareLabel
		}
		return L7NoMatch
	}

	// The name passes policy. Now: is it bound to THIS destination? Without
	// this an allowed name is a passphrase that opens every L7-scoped IP,
	// including one where an attacker runs a server that ignores SNI.
	if p.cm.NameResolvedToIP(q.Name, q.DstIP) {
		return L7MatchOK
	}
	return L7MatchElsewhere
}

// nameAllowed applies the allow tiers to name on q's port, protocol and step
// policy: allowed when a tier admits it there, denied when a deny rule
// covers it on this port, which beats every tier. THE one implementation,
// shared by the presented name and the bound names bareLabelAdmitted tries,
// so the two can never be judged by different rules.
func (p L7Policy) nameAllowed(name string, q L7Request) (allowed, denied bool) {
	v := p.cm.MatchHostnameRule(name)

	// A deny rule wins ON THE PORTS IT NAMES (empty = all ports), exactly as
	// tryLateAllow and the BPF per-port entries resolve a mixed verdict:
	// `example.com: allow 443` + `example.com: deny 80` must still admit TLS.
	// A covering deny beats every allow tier, including a derived one.
	if v.HasDeny() && DstPortAllowedByRule(q.DstPort, q.Proto, v.DenyPorts) {
		return false, true
	}

	// The allow tiers COMPOSE: a rule whose ports don't cover this flow does
	// not shadow a derived allow that does (a name can be both — an :22-only
	// rule for a host that is also a learned CNAME target of an allowed web
	// origin inheriting all ports).
	allowed = v.HasAllow() && DstPortAllowedByRule(q.DstPort, q.Proto, v.AllowPorts)
	if !allowed && p.derived != nil {
		if ports, ok := p.derived(name); ok {
			allowed = DstPortAllowedByRule(q.DstPort, q.Proto, ports)
		}
	}
	// Then the flow's step, as its packets are judged: its own rules and
	// chains add to the job's, never past a job deny. A name the job's
	// rules deny on any port is no step's, as the DNS path withholds it.
	if !allowed && q.Policy != 0 && p.steps != nil && !v.HasDeny() {
		if ports, ok := p.steps(q.Policy, name); ok {
			allowed = DstPortAllowedByRule(q.DstPort, q.Proto, ports)
		}
	}
	return allowed, false
}

// bareLabelAdmitted reports whether a presented name no tier allows passes
// anyway as a bare label: a client that dials a dedicated host by address
// and presents an opaque per-machine label as its SNI (Depot's CLI dials its
// builders that way). Such a label is no DNS name, so no rule can name it,
// and a shared edge routes by DNS name, so it cannot select another tenant
// there. All of these must hold:
//
//   - the name is a single label. pkg/sni has already normalized it to
//     lowercase [a-z0-9._-] without a trailing dot, so no dot is the whole
//     test;
//   - it is a TLS or QUIC SNI, not an HTTP Host: a plain-HTTP shared edge
//     can route a single-label Host to another tenant (an S3 website
//     endpoint serves the bucket the Host names);
//   - the destination is globally routable. Inside a private network a
//     shared ingress commonly serves single-label virtual hosts (vault,
//     grafana) by SNI, and admitting a bare label there would reopen the
//     very swap this layer closes;
//   - some name that forward-resolved to this destination is allowed on
//     this port and protocol by the same tiers, deny rules included. A
//     reverse name never mints binding evidence, so it cannot satisfy this.
func (p L7Policy) bareLabelAdmitted(q L7Request) bool {
	if !q.SNI || q.Name == "" || strings.Contains(q.Name, ".") {
		return false
	}
	addr, err := netip.ParseAddr(q.DstIP)
	if err != nil || !addr.Unmap().IsGlobalUnicast() || LocalAddress(addr) {
		return false
	}
	// The store is keyed by the spelling the DNS layer recorded, which is
	// the spelling q carries (the same lookup the L7MatchOK check makes).
	_, ok := p.cm.BoundNameAllowed(q.DstIP, func(name string) bool {
		allowed, _ := p.nameAllowed(name, q)
		return allowed
	})
	return ok
}
