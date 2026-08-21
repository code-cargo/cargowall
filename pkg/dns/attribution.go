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

	"github.com/miekg/dns"

	"github.com/code-cargo/cargowall/pkg/events"
)

// Attribution of blocked queries to the client that sent them: every
// listener carries a mode fixed at creation, the mode picks one of two
// lookups, and clientAttribution is the single projection of the result
// onto audit events and log lines.

// StepLookup resolves a host DNS client address to its step attribution
// (steps.Tracker.StepForClient's sock_diag path) — the host-listener
// counterpart of ContainerLookup. An installed lookup always yields an
// Outcome, even on failure; only an absent lookup leaves events untouched.
type StepLookup func(addr net.Addr) events.StepAttribution

// SetStepLookup installs the host-client step resolver used to attribute
// dns_blocked events.
func (s *Server) SetStepLookup(lookup StepLookup) {
	if lookup == nil {
		return // atomic.Value cannot store nil; absent leaves events untouched anyway
	}
	s.stepLookup.Store(lookup)
}

// ContainerLookup resolves a container-origin DNS client address (the
// container's veth IP — the source of both direct bridge queries and the
// embedded resolver's external forwards) to its step attribution.
type ContainerLookup func(addr net.Addr) (stepOrdinal uint32, containerID string, ok bool)

// SetContainerLookup installs the container-client resolver
// (containers.Tracker.LookupClient). Same late-install contract as
// SetStepLookup.
func (s *Server) SetContainerLookup(lookup ContainerLookup) {
	if lookup == nil {
		return // atomic.Value cannot store nil; absent means unattributed anyway
	}
	s.containerLookup.Store(lookup)
}

// listenerAttribution is how a listener's blocked queries are attributed —
// a property of the listen ADDRESS, fixed at creation, so the query path
// asks the listener instead of re-deriving feature state per query.
type listenerAttribution int

const (
	// attributeHostSockdiag resolves the querying step from the client
	// socket via sock_diag — correct only for host-netns clients.
	attributeHostSockdiag listenerAttribution = iota
	// attributeContainerIP marks queries container-origin and resolves
	// attribution by client IP via the container lookup. The sockdiag path
	// NEVER runs for these listeners: it cannot see a container-netns
	// socket, and its single-wildcard fallback can hand a container query
	// an unrelated HOST process's ordinal — a wrong attribution rather
	// than a coarse one. When the lookup is absent (installed late, after
	// the dockerd restart — or never, when --docker-dns-interception runs
	// without --container-attribution), queries file as container-origin
	// with no ordinal: the unattributed container tier. That residual is
	// accepted and pinned by test.
	attributeContainerIP
)

// AddContainerListenAddr adds a listen address AND marks it as
// container-serving, so queries arriving there are attributed via the
// container lookup instead of the host-netns sockdiag path (which cannot see
// a container's client socket, and whose wildcard fallback could even
// mis-hit an unrelated host socket on the same ephemeral port). Explicit
// marking rather than inference: a future non-container extra listener must
// not silently classify its clients as containers. Call before Start.
func (s *Server) AddContainerListenAddr(addr string) {
	s.AddListenAddr(addr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		s.listenerModes[host] = attributeContainerIP
	}
}

// attributionMode returns the listener's attribution mode for a query —
// attributeHostSockdiag unless the listen address was created
// container-serving.
func (s *Server) attributionMode(w dns.ResponseWriter) listenerAttribution {
	if len(s.listenerModes) == 0 || w.LocalAddr() == nil {
		return attributeHostSockdiag
	}
	host, _, err := net.SplitHostPort(w.LocalAddr().String())
	if err != nil {
		return attributeHostSockdiag
	}
	return s.listenerModes[host]
}

// clientAttribution is one blocked query's resolved origin — the host step
// attribution or the container identity, per the listener's mode. step is
// the host sockdiag result ONLY: a container hit carries its ordinal on its
// own field, because StepAttribution's Outcome vocabulary (ok = resolved
// via sockdiag) must never be implied for a container lookup.
type clientAttribution struct {
	step             events.StepAttribution
	containerOrigin  bool
	containerID      string
	containerOrdinal uint32
}

// ordinal is the step ordinal from whichever lookup ran.
func (a clientAttribution) ordinal() uint32 {
	if a.containerOrigin {
		return a.containerOrdinal
	}
	return a.step.Ordinal
}

// attributeClient resolves who sent the query. A host client's step is
// resolved from its socket while it is still parked in recv awaiting the
// answer, so the sock_diag lookup sees a live socket; a container client
// has no visible socket in the host netns and is keyed on its IP instead.
func (s *Server) attributeClient(w dns.ResponseWriter) clientAttribution {
	var a clientAttribution
	switch s.attributionMode(w) {
	case attributeContainerIP:
		a.containerOrigin = true
		if lookup, ok := s.containerLookup.Load().(ContainerLookup); ok {
			if ordinal, containerID, found := lookup(w.RemoteAddr()); found {
				a.containerOrdinal = ordinal
				a.containerID = containerID
			}
		}
	case attributeHostSockdiag:
		if lookup, ok := s.stepLookup.Load().(StepLookup); ok {
			a.step = lookup(w.RemoteAddr())
		}
	}
	return a
}

// apply stamps the attribution onto an audit event.
func (a clientAttribution) apply(ev *events.AuditEvent) {
	ev.StepOrdinal = a.ordinal()
	ev.StepAttrOutcome = a.step.Outcome
	ev.PID = a.step.PID
	ev.Process = a.step.Process
	ev.ContainerOrigin = a.containerOrigin
	ev.ContainerID = a.containerID
}

// logAttrs appends the attribution to leading slog key/values, omitting
// zero fields — the ops-log line must carry the attribution, or it reads
// as an unattributed event beside the summary's buckets.
func (a clientAttribution) logAttrs(kv ...any) []any {
	attrs := kv
	if ordinal := a.ordinal(); ordinal != 0 {
		attrs = append(attrs, "step_ordinal", ordinal)
	}
	if a.step.Outcome != "" {
		attrs = append(attrs, "step_attr_outcome", a.step.Outcome)
	}
	if a.step.Process != "" {
		attrs = append(attrs, "process", a.step.Process)
	}
	if a.step.PID != 0 {
		attrs = append(attrs, "pid", a.step.PID)
	}
	if a.containerOrigin {
		attrs = append(attrs, "container_origin", true)
	}
	if a.containerID != "" {
		attrs = append(attrs, "container_id", a.containerID)
	}
	return attrs
}
