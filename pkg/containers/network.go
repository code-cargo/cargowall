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
// Driver gating happens later, in carvePrefix: this function only
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
// network's next container retries. A non-bridge resolution is also NOT
// stamped: it is a decision about the network, not the prefix, and lives
// in the driver cache (see the comment at the gate below).
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
		if !isBridge {
			t.logger.Info("Non-bridge network subnet stays adjudicated (not local-only)",
				"network", name, "subnet", key)
		}
	}
	if !isBridge {
		// Deliberately NOT stamped into seenSubnets: that map records
		// allow-path decisions for a PREFIX, but non-bridge is a property of
		// this NETWORK. The same subnet can legitimately reappear on a later
		// bridge network (docker releases the pool at destroy — e.g. a
		// compose stack whose driver is edited between down and up) and must
		// re-evaluate then. The driver cache keeps the repeat cost at a map
		// hit, and its destroy-eviction / reconcile-clear is the recovery
		// point a prefix-keyed stamp would not have.
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
	isBridge := nw.Driver == "bridge"
	t.mu.Lock()
	t.netDrivers[name] = isBridge
	t.mu.Unlock()
	if !isBridge {
		// carvePrefix would refuse each subnet silently (the cache is
		// already primed); say it once here instead.
		t.logger.Info("Non-bridge network created; its subnets stay adjudicated (not local-only)",
			"network", name, "driver", nw.Driver)
		return
	}
	for _, cfg := range nw.IPAM.Config {
		prefix, perr := netip.ParsePrefix(cfg.Subnet)
		if perr != nil {
			continue
		}
		t.carvePrefix(ctx, name, prefix)
	}
}

// handleNetworkAddrChange refreshes a tracked container's address index
// after a `network connect`/`disconnect` on a running container — the only
// address-changing events that arrive without a container start. Without
// it a gained address never attributes (DNS queries from it stay
// unattributed until the next PID-changing reconcile, i.e. typically
// forever), and a released address keeps mapping to its old holder until
// docker IPAM hands it to a new container — whose traffic would then be
// stamped with the WRONG identity. Connect also feeds the subnet
// carve-out: the container may be the first onto a bridge network
// cargowall has not yet carved.
func (t *Tracker) handleNetworkAddrChange(ctx context.Context, ev dockerEvent) {
	containerID := ev.Actor.Attributes["container"]
	if containerID == "" {
		return
	}
	t.mu.Lock()
	info := t.containers[containerID]
	t.mu.Unlock()
	if info == nil {
		// Untracked: start/reconcile own first registration (docker fires a
		// connect for the default network before "start" — that one is this
		// no-op), and a death-racing disconnect is remove()'s job.
		return
	}

	ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
	insp, err := t.client.inspectContainer(ictx, containerID)
	cancel()
	if err != nil {
		t.logger.Debug("Container inspect failed after network change",
			"container", shortID(containerID), "error", err)
		return
	}

	if t.opts.AllowLocalSubnet != nil && ev.Action == "connect" {
		for _, s := range collectSubnets(insp) {
			t.carvePrefix(ctx, s.network, s.prefix)
		}
	}

	var ips []netip.Addr
	for _, ipStr := range collectIPs(insp) {
		if ip, perr := netip.ParseAddr(ipStr); perr == nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 && ev.Action == "connect" {
		// A connect cannot leave the container with FEWER addresses: an
		// empty set here is a racy or incomplete inspect (teardown
		// mid-flight), not truth — adopting it would drop addresses the
		// container still holds. Disconnect is different: empty is a
		// legitimate final state there, and clearing is load-bearing (a
		// stale mapping misattributes the address's next holder).
		t.logger.Debug("Ignoring empty inspect after network connect",
			"container", shortID(containerID))
		return
	}

	t.mu.Lock()
	if t.containers[containerID] != info {
		// Removed (die/destroy) or re-adopted while the inspect ran: this
		// handler runs async, and indexing a dead info would resurrect
		// entries remove() just cleaned.
		t.mu.Unlock()
		return
	}
	// Drop index entries this container no longer holds, then (re)index the
	// current set — newest inspect wins a conflicted address, matching
	// handleStart's semantics.
	held := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		held[ip] = true
	}
	for _, ip := range info.ips {
		if !held[ip] && t.byIP[ip] == info {
			delete(t.byIP, ip)
		}
	}
	info.ips = ips
	for _, ip := range ips {
		t.byIP[ip] = info
	}
	t.mu.Unlock()

	t.logger.Info("Container addresses refreshed after network change",
		"container", shortID(containerID), "action", ev.Action, "addrs", len(ips))
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
