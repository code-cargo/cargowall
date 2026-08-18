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

// The local-networks carve-out: which prefixes may be PERMANENTLY exempted
// from this hook's adjudication. The write and its safety policy live
// together, on purpose — AllowLocalNetwork is a one-shot, workload-
// influenced exemption with no delete path, so a validation that sat in a
// caller would be bypassed by the next caller. Callers own only what they
// genuinely know (pkg/containers: docker driver gating); everything a
// hostile prefix could abuse is checked here, at the write.

package origin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/code-cargo/cargowall/bpf"
)

// ErrLocalNetworkRefused marks a prefix the carve-out policy rejected — a
// DECISION, not a failure: callers must not retry (the tracker stamps the
// subnet seen), and the operator can still allow the range explicitly in
// policy. Any other error from AllowLocalNetwork is transient and safe to
// retry.
var ErrLocalNetworkRefused = errors.New("local network refused by carve-out policy")

// AllowLocalNetwork carves a local-only network (a docker bridge subnet)
// out of THIS hook's adjudication, exactly as loopback is carved out. The
// entry lands in map_local_nets, owned by the origin collection and
// deliberately not shared with TC: carving a subnet here returns its
// traffic to the pre-3b posture (bridge-local flows were never policed);
// traffic leaving via the TC-attached interface still meets TC's untouched
// verdict.
//
// Every prefix is validated HERE, fail-closed: subnet values are
// workload-influenced (`docker network create --subnet` is unprivileged
// and skips docker's reserved-network check), the write is permanent, and
// TC's single-interface attachment leaves multi-interface hosts with
// pre-existing blind spots — see validateLocalSubnet for the policy.
// Refusals return ErrLocalNetworkRefused; interface-enumeration failures
// return an ordinary error (retryable — a validation that silently didn't
// run must never be indistinguishable from one that passed).
func (o *Observer) AllowLocalNetwork(prefix netip.Prefix) error {
	prefix = prefix.Masked()
	ifaces, err := gatherHostIfaces()
	if err != nil {
		return fmt.Errorf("cannot validate local subnet %s: %w", prefix, err)
	}
	if reason := validateLocalSubnet(prefix, ifaces); reason != "" {
		o.logger.Warn("Refusing local-network carve-out",
			"subnet", prefix.String(), "reason", reason)
		return fmt.Errorf("%w: %s: %s", ErrLocalNetworkRefused, prefix, reason)
	}
	if prefix.Addr().Is4() {
		a4 := prefix.Addr().As4()
		key := bpf.OriginBpfLpmKey{
			Prefixlen: uint32(prefix.Bits()),
			// NativeEndian: the uint32's bytes must sit in network byte
			// order in the map key, matching the firewall's LPM writes.
			Ip: binary.NativeEndian.Uint32(a4[:]),
		}
		if err := o.objs.MapLocalNets.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("failed to allow local network %s: %w", prefix, err)
		}
	} else {
		key := bpf.OriginBpfLpmKeyV6{Prefixlen: uint32(prefix.Bits())}
		a16 := prefix.Addr().As16()
		copy(key.Ip[:], a16[:])
		if err := o.objs.MapLocalNetsV6.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("failed to allow local network %s: %w", prefix, err)
		}
	}
	o.logger.Info("Local-only network carved out of cgroup adjudication", "subnet", prefix.String())
	return nil
}

// hostIface is the slice of interface state subnet validation consumes,
// separated so the policy is testable without real interfaces.
type hostIface struct {
	name     string
	isBridge bool
	addrs    []*net.IPNet
}

// validateLocalSubnet returns the reason prefix must NOT be carved, or ""
// when it may be. The policy:
//   - width cap: nothing broader than /16 (v4) or /64 (v6) — a wider claim
//     exempts address space no real docker bridge needs;
//   - locality: the subnet must not contain any non-loopback host interface
//     address. The one exemption is the subnet's OWN bridge (its gateway
//     address, whose interface network equals the prefix exactly) — and the
//     device must genuinely be a linux bridge: tun0 = 10.8.0.5/16 makes
//     own == prefix for a claimed 10.8.0.0/16, and exempting it would carve
//     a VPN's range out of the hook.
//
// Known residual (documented, not solved here): the check consults
// addresses, not routes — an aggregate routed via a tunnel the host has no
// address inside still passes, and a prefix claimed before a VPN comes up
// is carved permanently (there is no delete path or re-validation).
func validateLocalSubnet(prefix netip.Prefix, ifaces []hostIface) string {
	if (prefix.Addr().Is4() && prefix.Bits() < 16) || (!prefix.Addr().Is4() && prefix.Bits() < 64) {
		return "wider than any real docker bridge needs"
	}
	for _, ifc := range ifaces {
		for _, ipn := range ifc.addrs {
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !prefix.Contains(addr) {
				continue
			}
			ones, _ := ipn.Mask.Size()
			own, perr := addr.Prefix(ones)
			if perr == nil && own == prefix && ifc.isBridge {
				continue // the subnet's own bridge gateway
			}
			return "contains host interface address " + ifc.name + "=" + addr.String()
		}
	}
	return ""
}

// gatherHostIfaces snapshots non-loopback interfaces for validation. Any
// enumeration error is returned — the caller fails closed on it.
func gatherHostIfaces() ([]hostIface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("interface enumeration: %w", err)
	}
	out := make([]hostIface, 0, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, fmt.Errorf("addresses of %s: %w", ifc.Name, err)
		}
		hi := hostIface{name: ifc.Name, isBridge: isBridgeInterface(ifc.Name)}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				hi.addrs = append(hi.addrs, ipn)
			}
		}
		out = append(out, hi)
	}
	return out, nil
}

// isBridgeInterface reports whether the named device is a linux bridge
// (docker0, br-*): /sys/class/net/<name>/bridge exists only for bridges —
// no name pattern, no route lookup, works for renamed bridges and rejects
// tun/physical devices alike.
func isBridgeInterface(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name + "/bridge")
	return err == nil
}
