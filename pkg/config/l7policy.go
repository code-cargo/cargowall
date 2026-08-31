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

// L7Request is one destination identity recovered from an L7 handshake (SNI,
// Host, QUIC) awaiting a policy decision.
type L7Request struct {
	Name    string
	DstIP   string // destination address, string form (the DNS/audit vocabulary)
	DstPort uint16
	Proto   uint8 // L4 protocol number
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
}

// NewL7Policy binds a Manager to the proxy's derived-target lookup. Pass a nil
// derived when there is no DNS proxy.
func NewL7Policy(cm *Manager, derived func(name string) ([]Port, bool)) L7Policy {
	return L7Policy{cm: cm, derived: derived}
}

// MatchName decides whether a recovered destination name is admitted ON THIS
// FLOW'S PORT, and whether it is bound to THIS destination. It is the ONE
// entry point for that decision.
//
// The policy is the same two-tier set the DNS query gate applies
// (Server.isQueryAllowed) plus a port dimension: a name allowed only on a
// non-web port (an ssh host on :22) must not validate as an SNI on a shared
// edge IP that some 443 rule scoped, or an attacker presents it and the flow
// is admitted.
func (p L7Policy) MatchName(q L7Request) L7Match {
	cm, derived := p.cm, p.derived
	v := cm.MatchHostnameRule(q.Name)

	// A deny rule wins ON THE PORTS IT NAMES (empty = all ports), exactly as
	// tryLateAllow and the BPF per-port entries resolve a mixed verdict:
	// `example.com: allow 443` + `example.com: deny 80` must still admit TLS.
	// A covering deny beats every allow tier, including a derived one.
	if v.HasDeny() && DstPortAllowedByRule(q.DstPort, q.Proto, v.DenyPorts) {
		return L7NoMatch
	}

	// The allow tiers COMPOSE: a rule whose ports don't cover this flow does
	// not shadow a derived allow that does (a name can be both — an :22-only
	// rule for a host that is also a learned CNAME target of an allowed web
	// origin inheriting all ports).
	allowedByName := v.HasAllow() && DstPortAllowedByRule(q.DstPort, q.Proto, v.AllowPorts)
	if !allowedByName && derived != nil {
		if ports, ok := derived(q.Name); ok {
			allowedByName = DstPortAllowedByRule(q.DstPort, q.Proto, ports)
		}
	}
	if !allowedByName {
		return L7NoMatch
	}

	// The name passes policy. Now: is it bound to THIS destination? Without
	// this an allowed name is a passphrase that opens every L7-scoped IP,
	// including one where an attacker runs a server that ignores SNI.
	if cm.NameResolvedToIP(q.Name, q.DstIP) {
		return L7MatchOK
	}
	return L7MatchElsewhere
}
