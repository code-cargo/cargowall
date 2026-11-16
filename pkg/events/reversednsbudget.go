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

// reverseDNSFamily indexes the budget's per-family counts.
type reverseDNSFamily int

const (
	reverseDNSIPv4 reverseDNSFamily = iota
	reverseDNSIPv6
)

func (f reverseDNSFamily) String() string {
	if f == reverseDNSIPv4 {
		return "IPv4"
	}
	return "IPv6"
}

// reverseDNSBudget decides which denied destinations a run may look up the
// reverse name of: at most perNetwork distinct addresses in each IPv4 /24 or
// IPv6 /48, and max[family] of each family in all (reverseDNSPerNetwork,
// reverseDNSRunMaxV4, reverseDNSRunMaxV6). An address it has let through is
// let through again, so its retries cost nothing more, even after the
// tracker evicted it. One past a cap goes unnamed, with no lookup, and the
// cap is logged at Info once: once per network, and once per family's run
// cap. Each of its maps holds at most the two run caps' entries, since a
// network is logged only once it holds perNetwork addresses, so a run's
// denials can't grow it.
type reverseDNSBudget struct {
	mu         sync.Mutex
	perNetwork int
	max        [2]int
	looked     map[netip.Addr]struct{}   // addresses let through
	perFamily  [2]int                    // addresses let through, per family
	networks   map[netip.Prefix]int      // addresses let through, per network
	logged     map[netip.Prefix]struct{} // networks whose cap was logged
	loggedRun  [2]bool                   // the family's run cap was logged
}

func newReverseDNSBudget(perNetwork, maxV4, maxV6 int) *reverseDNSBudget {
	b := &reverseDNSBudget{perNetwork: perNetwork, max: [2]int{maxV4, maxV6}}
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
	family := reverseDNSIPv6
	if addr.Is4() {
		family = reverseDNSIPv4
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.looked[addr]; ok {
		return true
	}
	if b.perFamily[family] >= b.max[family] {
		if !b.loggedRun[family] {
			b.loggedRun[family] = true
			logger.Info("Reverse DNS lookups of denied destinations reached the run's cap for the family; further ones go unnamed",
				"family", family.String(), "cap", b.max[family])
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
	b.perFamily[family]++
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
	b.perFamily = [2]int{}
	b.networks = make(map[netip.Prefix]int)
	b.logged = make(map[netip.Prefix]struct{})
	b.loggedRun = [2]bool{}
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
