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
	"net"
	"net/netip"
	"sync"
	"time"
)

// hostAddrsTTL is how long a snapshot of the namespace's addresses serves.
const hostAddrsTTL = 5 * time.Second

// hostAddrSet is the addresses of the network namespace cargowall runs in,
// snapshotted at most every hostAddrsTTL. A cgroup hook verdict whose
// pre-NAT source is one of them is a socket of that namespace, whose
// packets TC reads by their socket; one from any other address is a
// container's, a nested namespace's or another runtime's, whose packets TC
// may judge by the job's rules alone. On an ARC pod the namespace is the
// pod's, which dind's dockerd shares: its containers still send from their
// own namespaces' addresses. A stale snapshot only misses an address added
// since, which then reads as not the host's: the safe way round.
type hostAddrSet struct {
	mu   sync.Mutex
	at   time.Time
	set  map[netip.Addr]struct{} // nil until the first listing that worked
	now  func() time.Time
	list func() ([]net.Addr, error)
}

var hostAddrs = &hostAddrSet{now: time.Now, list: net.InterfaceAddrs}

// has reports whether ip is one of the namespace's addresses, a v4-mapped
// address as its v4 one and a zone ignored. A snapshot older than
// hostAddrsTTL is listed again; a listing that fails keeps the last one,
// and with none, no address is the host's.
func (h *hostAddrSet) has(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	h.mu.Lock()
	defer h.mu.Unlock()
	if now := h.now(); h.at.IsZero() || now.Sub(h.at) >= hostAddrsTTL {
		h.at = now
		if addrs, err := h.list(); err == nil {
			h.set = make(map[netip.Addr]struct{}, len(addrs))
			for _, a := range addrs {
				var raw net.IP
				switch a := a.(type) {
				case *net.IPNet:
					raw = a.IP
				case *net.IPAddr:
					raw = a.IP
				}
				if p, ok := netip.AddrFromSlice(raw); ok {
					h.set[p.Unmap().WithZone("")] = struct{}{}
				}
			}
		}
	}
	_, ok := h.set[addr]
	return ok
}
