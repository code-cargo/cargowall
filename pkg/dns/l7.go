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
	"log/slog"
	"net"
	"strings"

	"github.com/code-cargo/cargowall/pkg/config"
)

// L7Registrar is the seam onto the oracle (pkg/origin.L7): as the proxy
// resolves an allowed hostname, it marks the resolved IP L7-scoped. There is
// deliberately no name-registration method — the matcher is the only name
// authority. An interface so pkg/dns does not depend on pkg/origin.
type L7Registrar interface {
	// ScopeIP marks a destination IP L7-scoped for the dimensions its rule's
	// ports open. Deliberately ports, not a scope bitmask: L7_SCOPE_* is the
	// value layout of a kernel map this package has no business knowing.
	ScopeIP(ip net.IP, ports []config.Port) error
	// FlushScopes empties the scope maps. Called on policy reload as one step
	// with the tracked-hostname replay that re-warms them; scope entries have
	// no expiry and no reverse index.
	FlushScopes() error
}

// SetL7Registrar installs the L7 registrar. Safe to call after the server is
// already answering queries.
func (s *Server) SetL7Registrar(r L7Registrar) { s.l7.Store(r) }

// DerivedAllowPorts reports whether name was learned as a CNAME target of an
// allowed response, returning the allow ports it inherited from its origin(s)
// (unioned across origins; empty means all ports). It is the L7 slow path's
// view of the same derived-allow set the query gate consults in isQueryAllowed
// — without it, the oracle's matcher sees only hostname RULES, and a client
// that legitimately dialed a CNAME target directly (an Akamai/Cloudflare edge
// label the origin chains to) presents that target as its SNI/Host, matches no
// rule, and is DENIED.
//
// Returns ok=false for an unknown or expired target. Callers apply the port
// check themselves, so the L7 path keeps exactly one port-coverage
// implementation.
func (s *Server) DerivedAllowPorts(name string) ([]config.Port, bool) {
	if s == nil || s.cnameAllowed == nil || name == "" {
		return nil, false
	}
	entry, ok := s.cnameAllowed.Get(strings.ToLower(name))
	if !ok {
		return nil, false
	}
	return entry.ports, true
}

func (s *Server) l7Registrar() L7Registrar {
	if v := s.l7.Load(); v != nil {
		if r, ok := v.(L7Registrar); ok {
			return r
		}
	}
	return nil
}

// registerL7 scopes an allowed hostname's resolved IP. Called from
// applyVerdictSide's allow path — rule hostnames with the rule's ports,
// derived CNAME targets with the ports they inherited.
func (s *Server) registerL7(hostname string, ip net.IP, ports []config.Port) {
	RegisterL7Identity(s.l7Registrar(), s.config, hostname, ip, ports, s.logger)
}

// RegisterL7Identity scopes one resolved IP for the L7 dimensions its ports
// open. THE one implementation, and the only writer of map_l7_scope — the DNS
// allow path and cmd's late-allow registrar both call it. A nil registrar (L7
// off) is a no-op.
//
// SCOPE IFF BOUND. An IP is L7-governed only because a name FORWARD-resolved
// to it, so this refuses to scope one the binding store cannot vouch for.
// Enforcing it here rather than per caller is what makes it an invariant: a
// caller with a PTR-derived name (reverse lookups, ForwardMatchIP attribution)
// cannot scope an IP that --tls-sni=enforce-pinned would then deny every flight to,
// and cannot launder attacker-controlled attribution into L7 coverage.
// Un-bindable destinations stay L4-governed; design-l7.md states that residual.
func RegisterL7Identity(r L7Registrar, cm *config.Manager, hostname string, ip net.IP, ports []config.Port, logger *slog.Logger) {
	if r == nil || cm == nil || ip == nil {
		return
	}
	if !cm.NameResolvedToIP(hostname, ip.String()) {
		if logger != nil {
			logger.Debug("L7: not scoping an IP with no forward-resolution evidence",
				"ip", ip.String(), "hostname", hostname)
		}
		return
	}
	if err := r.ScopeIP(ip, ports); err != nil && logger != nil {
		logger.Debug("L7: scoping IP", "ip", ip.String(), "hostname", hostname, "error", err)
	}
}
