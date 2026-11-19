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

package tcmaps

// Host accumulates every contribution to one host entry (/32 or /128), so the
// entry reflects the union of every rule that names or resolved to the
// address rather than the latest one. A shared CDN or edge address is often
// added under several hostname rules with different ports, and the LPM entry
// can say only "all ports" or "consult the port map", not both.
//
// Precedence, which the program's model can't express otherwise:
//   - An all-ports deny beats an all-ports allow: an address the policy
//     denies outright is not re-opened by an unrelated name sharing it.
//   - An all-ports grant beats a port-specific contribution of the opposite
//     action. The port entry would be inert under it, so it is not written.
//
// Both flags are sticky for the host's lifetime, like the rest of the maps,
// which are add-only. They are flags, not counts, because DNS re-resolution
// re-adds the same contribution on every TTL refresh.
type Host struct {
	AllPortsAllow bool
	AllPortsDeny  bool
	// Ports is every port entry written for the host, kept so a removal can
	// delete them all.
	Ports []PortProto
	// LPM is the host's entry as last written, valid once Installed.
	LPM       LPM
	Installed bool
}

// NewHost starts a host's accumulator on its first contribution. existing is
// the LPM's answer for its address, if any: the longest covering entry, whose
// all-ports grant the host folds in.
func NewHost(existing LPM, exists bool) *Host {
	h := &Host{}
	if exists && !existing.PortSpecific {
		h.grantAllPorts(existing.Allow)
	}
	return h
}

// HostWrite is what one contribution writes.
type HostWrite struct {
	// Ports are the port entries to write, under the contribution's action.
	Ports []PortProto
	// Inert reports a port-specific contribution of the opposite action
	// dropped under an all-ports grant.
	Inert bool
	// LPM is the host's entry after the contribution. WriteLPM reports
	// whether it differs from existing, the LPM's answer before it, so it
	// must be written.
	LPM      LPM
	WriteLPM bool
}

// Add folds one contribution of the given action and ports (empty for all
// ports) into the host. existing is the LPM's answer for the address before
// it: the host's own entry if installed, else the longest covering one. The
// caller writes the result, and marks the host Installed when it writes LPM.
func (h *Host) Add(allow bool, ports []PortProto, existing LPM, exists bool) HostWrite {
	var w HostWrite
	switch {
	case len(ports) == 0:
		h.grantAllPorts(allow)
	case h.AllPortsAllow || h.AllPortsDeny:
		w.Inert = h.AllPortsDeny == allow // the grant is the opposite action
	default:
		w.Ports = ports
		h.Ports = mergePorts(h.Ports, ports)
	}
	w.LPM = h.value(allow)
	w.WriteLPM = !exists || existing != w.LPM
	return w
}

func (h *Host) grantAllPorts(allow bool) {
	if allow {
		h.AllPortsAllow = true
	} else {
		h.AllPortsDeny = true
	}
}

// value is the host's LPM entry. A port-specific entry carries the latest
// contribution's action; the program ignores it there.
func (h *Host) value(allow bool) LPM {
	switch {
	case h.AllPortsDeny:
		return LPM{Allow: false}
	case h.AllPortsAllow:
		return LPM{Allow: true}
	}
	return LPM{Allow: allow, PortSpecific: true}
}

// mergePorts returns the union of two port lists, existing first, as a new
// slice that aliases neither input.
func mergePorts(existing, additions []PortProto) []PortProto {
	out := make([]PortProto, 0, len(existing)+len(additions))
	out = append(out, existing...)
	seen := make(map[PortProto]bool, len(existing))
	for _, p := range existing {
		seen[p] = true
	}
	for _, p := range additions {
		if !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	return out
}
