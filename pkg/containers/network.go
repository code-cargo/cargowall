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
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/code-cargo/cargowall/pkg/origin"
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

// carvePrefix is THE apply path for the carve-out — every discovery source
// funnels here (network-create events and per-container discovery directly;
// the pre-enableMode pre-scan feeds candidates through the same callback in
// cmd, before a Tracker exists). Pipeline: seen-check → resolve the
// network's driver (cached; network "" means the legacy top-level inspect
// fields, resolved to the literal "bridge" network and verified like any
// other — the macvlan protection must not rest on undocumented daemon
// behavior) → hand the prefix to AllowLocalSubnet → stamp seenSubnets.
//
// Stamping carries the refused-vs-failed distinction end to end: a policy
// refusal (origin.ErrLocalNetworkRefused, logged at the write) is a
// DECISION and stamps seen; any transient failure — driver inspect, host
// interface enumeration, map write — leaves the subnet unstamped so the
// network's next container retries.
func (t *Tracker) carvePrefix(ctx context.Context, networkName string, prefix netip.Prefix) {
	if t.opts.AllowLocalSubnet == nil {
		return
	}
	prefix = prefix.Masked()
	key := prefix.String()
	t.mu.Lock()
	seen := t.seenSubnets[key]
	t.mu.Unlock()
	if seen {
		return
	}

	name := networkName
	if name == "" {
		name = "bridge"
	}
	t.mu.Lock()
	isBridge, known := t.netDrivers[name]
	t.mu.Unlock()
	if !known {
		ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
		nw, err := t.client.inspectNetwork(ictx, name)
		cancel()
		if err != nil {
			t.logger.Warn("Cannot inspect network for subnet carve-out; subnet stays adjudicated for now",
				"network", name, "subnet", key, "error", err)
			return
		}
		isBridge = nw.Driver == "bridge"
		t.mu.Lock()
		t.netDrivers[name] = isBridge
		t.mu.Unlock()
	}
	if !isBridge {
		t.mu.Lock()
		t.seenSubnets[key] = true
		t.mu.Unlock()
		t.logger.Info("Non-bridge network subnet stays adjudicated (not local-only)",
			"network", name, "subnet", key)
		return
	}

	if err := t.opts.AllowLocalSubnet(prefix); err != nil {
		if errors.Is(err, origin.ErrLocalNetworkRefused) {
			t.mu.Lock()
			t.seenSubnets[key] = true
			t.mu.Unlock()
			return
		}
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
	// Prime the driver cache so carvePrefix below (and later per-container
	// discovery) never re-inspects this network.
	t.mu.Lock()
	t.netDrivers[name] = nw.Driver == "bridge"
	t.mu.Unlock()
	for _, cfg := range nw.IPAM.Config {
		prefix, perr := netip.ParsePrefix(cfg.Subnet)
		if perr != nil {
			continue
		}
		t.carvePrefix(ctx, name, prefix)
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
