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

package origin

import (
	"testing"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

func tcpPorts(ps ...uint16) []config.Port {
	out := make([]config.Port, len(ps))
	for i, p := range ps {
		out[i] = config.Port{Port: p, Protocol: config.ProtocolTCP}
	}
	return out
}

func udpPorts(ps ...uint16) []config.Port {
	out := make([]config.Port, len(ps))
	for i, p := range ps {
		out[i] = config.Port{Port: p, Protocol: config.ProtocolUDP}
	}
	return out
}

// TestL7ScopeFromPorts pins the ports->dimension mapping that decides which
// flows the kernel adjudicates at all. It lives beside map_l7_scope because
// L7_SCOPE_* is that map's value layout; the DNS proxy hands over a rule's
// ports and never sees the bitmask.
func TestL7ScopeFromPorts(t *testing.T) {
	all := func(p uint16) []config.Port {
		return []config.Port{{Port: p, Protocol: config.ProtocolAll}}
	}

	tests := []struct {
		name  string
		ports []config.Port
		want  uint8
	}{
		{"empty is all-ports", nil, bpf.L7ScopeTLS | bpf.L7ScopeHTTP | bpf.L7ScopeQUIC},
		{"443 tcp is TLS", tcpPorts(443), bpf.L7ScopeTLS},
		{"443 udp is QUIC", udpPorts(443), bpf.L7ScopeQUIC},
		{"80 tcp is HTTP", tcpPorts(80), bpf.L7ScopeHTTP},
		{"443 all is TLS+QUIC", all(443), bpf.L7ScopeTLS | bpf.L7ScopeQUIC},
		{"443+80 tcp", tcpPorts(443, 80), bpf.L7ScopeTLS | bpf.L7ScopeHTTP},
		{"unrelated port is unscoped", tcpPorts(22), 0},
		// The CDN alternate ports terminate the SAME shared edge as 443/80, so
		// they carry the same dimension.
		{"8443 tcp is TLS", tcpPorts(8443), bpf.L7ScopeTLS},
		{"2053 tcp is TLS", tcpPorts(2053), bpf.L7ScopeTLS},
		{"8080 tcp is HTTP", tcpPorts(8080), bpf.L7ScopeHTTP},
		{"8880 all is HTTP", all(8880), bpf.L7ScopeHTTP},
		// UDP alt ports stay unscoped: the QUIC walk fails closed on an
		// uncertain datagram in every state, so widening it there would carve
		// a hole in that invariant rather than close one.
		{"8443 udp is unscoped", udpPorts(8443), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := l7ScopeFromPorts(tc.ports); got != tc.want {
				t.Errorf("l7ScopeFromPorts(%v) = %#x, want %#x", tc.ports, got, tc.want)
			}
		})
	}
}
