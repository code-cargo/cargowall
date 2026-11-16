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

package events

import (
	"log/slog"
	"net/netip"
	"sync"
)

// reverseDNSBudget decides which denied destinations a run may look up the
// reverse name of: at most perNetwork distinct addresses in each IPv4 /24 or
// IPv6 /48, and max in all (reverseDNSPerNetwork, reverseDNSRunMax). An
// address it has let through is let through again, so its retries cost
// nothing more, even after the tracker evicted it. One past a cap goes
// unnamed, with no lookup, and the cap is logged at Info once: once per
// network, and once for the run's. Each of its maps holds at most max
// entries, since a network is logged only once it holds perNetwork
// addresses, so a run's denials can't grow it.
type reverseDNSBudget struct {
	mu         sync.Mutex
	perNetwork int
	max        int
	looked     map[netip.Addr]struct{}   // addresses let through
	networks   map[netip.Prefix]int      // addresses let through, per network
	logged     map[netip.Prefix]struct{} // networks whose cap was logged
	loggedRun  bool                      // the run's cap was logged
}

func newReverseDNSBudget(perNetwork, maxAddrs int) *reverseDNSBudget {
	b := &reverseDNSBudget{perNetwork: perNetwork, max: maxAddrs}
	b.resetLocked()
	return b
}

// take reports whether ip, a denied destination, may be looked up, and
// counts it against the caps when it is the first time.
func (b *reverseDNSBudget) take(ip string, logger *slog.Logger) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.looked[addr]; ok {
		return true
	}
	if len(b.looked) >= b.max {
		if !b.loggedRun {
			b.loggedRun = true
			logger.Info("Reverse DNS lookups of denied destinations reached the run's cap; further ones go unnamed",
				"cap", b.max)
		}
		return false
	}
	network := reverseDNSNetwork(addr)
	if b.networks[network] >= b.perNetwork {
		if _, ok := b.logged[network]; !ok {
			b.logged[network] = struct{}{}
			logger.Info("Reverse DNS lookups of denied destinations reached the cap for a network; further ones there go unnamed",
				"network", network.String(), "cap", b.perNetwork)
		}
		return false
	}
	b.looked[addr] = struct{}{}
	b.networks[network]++
	return true
}

// reset forgets what was spent. Tests use it to keep runs independent.
func (b *reverseDNSBudget) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resetLocked()
}

func (b *reverseDNSBudget) resetLocked() {
	b.looked = make(map[netip.Addr]struct{})
	b.networks = make(map[netip.Prefix]int)
	b.logged = make(map[netip.Prefix]struct{})
	b.loggedRun = false
}

// reverseDNSNetwork is the network addr's cap counts in: its IPv4 /24, or
// its IPv6 /48.
func reverseDNSNetwork(addr netip.Addr) netip.Prefix {
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	p, _ := addr.Prefix(bits)
	return p
}
