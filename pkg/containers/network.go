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

// Bridge-subnet discovery for the cgroup hook's local-network carve-out:
// the inspect-payload walkers, the driver-gated per-subnet pipeline, the
// network-create event handler, and the startup pre-scan. Every subnet that
// leaves this file is bridge-driver only — macvlan/ipvlan address space is
// physical network space and must stay adjudicated (see
// Options.AllowLocalSubnet for the whole contract).

package containers

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// forEachInspectAddr visits every address docker reported for a container:
// the legacy top-level fields (the default bridge; network name "") and
// each named network's entry. THE one walker of the NetworkSettings shape —
// both DNS attribution (collectIPs) and the enforce-mode subnet carve-out
// (collectSubnets) ride it, so a new address source added here reaches
// both, and a source added elsewhere is a bug.
func forEachInspectAddr(insp containerInspect, visit func(network, ip string, prefixLen int)) {
	visit("", insp.NetworkSettings.IPAddress, insp.NetworkSettings.IPPrefixLen)
	visit("", insp.NetworkSettings.GlobalIPv6Address, insp.NetworkSettings.GlobalIPv6PrefixLen)
	for name, nw := range insp.NetworkSettings.Networks {
		visit(name, nw.IPAddress, nw.IPPrefixLen)
		visit(name, nw.GlobalIPv6Address, nw.GlobalIPv6PrefixLen)
	}
}

// collectIPs gathers every address docker assigned the container, v4 and
// v6 alike: the DNS client lookup keys on whichever family the container's
// resolver socket uses, so an IPv6-enabled bridge must not silently lose
// DNS attribution while the TC join (cgroup-id based) keeps working.
func collectIPs(insp containerInspect) []string {
	ips := []string{}
	forEachInspectAddr(insp, func(_, ip string, _ int) {
		if ip != "" && !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	})
	return ips
}

// localSubnet is one candidate carve-out: a subnet plus the network it was
// seen on ("" = the default bridge, which is bridge-driver by definition).
type localSubnet struct {
	network string
	prefix  netip.Prefix
}

// collectSubnets derives the subnets docker attached the container to, v4
// and v6, masked. Entries with no prefix length (host networking, daemons
// that omit it) are dropped — a zero prefix would shape into a catch-all.
// Driver gating happens later, in allowSubnetOnce: this function only
// reads the inspect payload.
func collectSubnets(insp containerInspect) []localSubnet {
	var subnets []localSubnet
	forEachInspectAddr(insp, func(network, ipStr string, prefixLen int) {
		if ipStr == "" || prefixLen <= 0 {
			return
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return
		}
		prefix, err := addr.Prefix(prefixLen)
		if err != nil {
			return // prefixLen wider than the address family
		}
		for _, s := range subnets {
			if s.prefix == prefix {
				return
			}
		}
		subnets = append(subnets, localSubnet{network: network, prefix: prefix})
	})
	return subnets
}

// allowSubnetOnce runs the once-per-subnet carve-out pipeline: resolve the
// network's driver (bridge-driver networks are local-only by construction —
// their routes are on-link; a macvlan/ipvlan subnet is physical-network
// space and MUST stay adjudicated), then hand the subnet to the callback.
// seenSubnets is stamped only once the decision is final — a failed driver
// inspect or a failed carve-out write is retried by the next container on
// the network.
func (t *Tracker) allowSubnetOnce(ctx context.Context, s localSubnet) {
	key := s.prefix.String()
	t.mu.Lock()
	seen := t.seenSubnets[key]
	t.mu.Unlock()
	if seen {
		return
	}
	// The legacy top-level inspect fields (network "") are resolved to the
	// literal "bridge" network and driver-checked like any other: stock
	// moby only populates them from the default bridge, but nothing
	// guarantees that across docker-compatible daemons, and the macvlan
	// protection must not rest on undocumented daemon behavior.
	netName := s.network
	if netName == "" {
		netName = "bridge"
	}
	t.mu.Lock()
	isBridge, known := t.netDrivers[netName]
	t.mu.Unlock()
	if !known {
		ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
		nw, err := t.client.inspectNetwork(ictx, netName)
		cancel()
		if err != nil {
			t.logger.Warn("Cannot inspect network for subnet carve-out; subnet stays adjudicated for now",
				"network", netName, "subnet", key, "error", err)
			return // unresolved: retried by the next container, not cached
		}
		isBridge = nw.Driver == "bridge"
		t.mu.Lock()
		t.netDrivers[netName] = isBridge
		t.mu.Unlock()
	}
	if !isBridge {
		t.mu.Lock()
		t.seenSubnets[key] = true
		t.mu.Unlock()
		t.logger.Info("Non-bridge network subnet stays adjudicated (not local-only)",
			"network", netName, "subnet", key)
		return
	}
	if err := t.opts.AllowLocalSubnet(s.prefix); err != nil {
		t.logger.Warn("Local subnet carve-out failed; will retry on the network's next container",
			"subnet", key, "error", err)
		return
	}
	t.mu.Lock()
	t.seenSubnets[key] = true
	t.mu.Unlock()
}

// handleNetworkCreate carves a just-created bridge network's subnets
// BEFORE its first container can produce traffic — container-driven
// discovery alone misses networks whose containers exit faster than an
// inspect (docker run --rm ... true), and under enforce an uncarved bridge
// is a broken network.
func (t *Tracker) handleNetworkCreate(ctx context.Context, ev dockerEvent) {
	if t.opts.AllowLocalSubnet == nil {
		return
	}
	name := ev.Actor.Attributes["name"]
	if name == "" {
		name = ev.Actor.ID
	}
	ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
	nw, err := t.client.inspectNetwork(ictx, name)
	cancel()
	if err != nil {
		t.logger.Warn("Cannot inspect created network; its subnets stay adjudicated until a container appears",
			"network", name, "error", err)
		return
	}
	isBridge := nw.Driver == "bridge"
	t.mu.Lock()
	t.netDrivers[name] = isBridge
	t.mu.Unlock()
	if !isBridge {
		return
	}
	for _, cfg := range nw.IPAM.Config {
		prefix, perr := netip.ParsePrefix(cfg.Subnet)
		if perr != nil {
			continue
		}
		prefix = prefix.Masked()
		key := prefix.String()
		t.mu.Lock()
		seen := t.seenSubnets[key]
		t.mu.Unlock()
		if seen {
			continue
		}
		if aerr := t.opts.AllowLocalSubnet(prefix); aerr != nil {
			t.logger.Warn("Local subnet carve-out failed; will retry via container discovery",
				"subnet", key, "error", aerr)
			continue
		}
		t.mu.Lock()
		t.seenSubnets[key] = true
		t.mu.Unlock()
	}
}

// DiscoverBridgeSubnets returns every bridge-driver network's IPAM
// subnets. cmd/start.go runs this BEFORE raising the cgroup hook out of
// observe: docker-event tracking starts only after the dockerd restart, and
// networks that predate cargowall — including ones whose containers are
// stopped, or are stopped by that very restart — must not lose bridge-local
// traffic in the window before tracking begins. Enumerating networks
// rather than containers means one API call, no per-container inspects on
// the timing-sensitive startup path, and no dependency on anything being
// alive to inspect.
func DiscoverBridgeSubnets(ctx context.Context, socket string) ([]netip.Prefix, error) {
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	c := newDockerClient(socket)
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	err := c.ping(pingCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("docker daemon unreachable: %w", err)
	}
	lctx, cancel := context.WithTimeout(ctx, unaryTimeout)
	nets, err := c.listNetworks(lctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, nw := range nets {
		if nw.Driver != "bridge" {
			continue
		}
		for _, cfg := range nw.IPAM.Config {
			prefix, perr := netip.ParsePrefix(cfg.Subnet)
			if perr != nil {
				continue
			}
			prefix = prefix.Masked()
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	return out, nil
}
