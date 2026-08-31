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

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/sni"
	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// allowSet is a test matcher that allows an explicit set of names on any port,
// treating every allowed name as bound to whatever destination it is asked
// about (the pre-binding behavior).
type allowSet map[string]bool

func (a allowSet) MatchName(q config.L7Request) config.L7Match {
	if a[q.Name] {
		return config.L7MatchOK
	}
	return config.L7NoMatch
}

// portAllowSet is a test matcher that allows a name only on a specific port,
// exercising the port-aware matcher contract.
type portAllowSet map[string]uint16

func (a portAllowSet) MatchName(q config.L7Request) config.L7Match {
	if p, ok := a[q.Name]; ok && p == q.DstPort {
		return config.L7MatchOK
	}
	return config.L7NoMatch
}

// boundAllowSet allows a name only at the destinations it lists, so the
// per-IP binding dimension can be exercised: a listed name at an unlisted IP
// comes back L7MatchElsewhere, not L7NoMatch.
type boundAllowSet map[string][]string

func (a boundAllowSet) MatchName(q config.L7Request) config.L7Match {
	ips, ok := a[q.Name]
	if !ok {
		return config.L7NoMatch
	}
	for _, ip := range ips {
		if ip == q.DstIP {
			return config.L7MatchOK
		}
	}
	return config.L7MatchElsewhere
}

// TestL7Adjudicate covers the pure decision core: parse a reassembled handshake
// and map it onto a verdict. No maps, no kernel.
func TestL7Adjudicate(t *testing.T) {
	m := allowSet{"auth.docker.io": true, "ocsp.sectigo.com": true}

	tests := []struct {
		name         string
		proto        sni.Protocol
		port         uint16
		buf          []byte
		wantNeedMore bool
		wantAllowed  bool
		wantName     string
		wantWhy      L7Reason
	}{
		{"tls allowed", sni.ProtoTLS, 443, snitest.BuildClientHello("auth.docker.io"), false, true, "auth.docker.io", L7Allowed},
		{"tls mismatch", sni.ProtoTLS, 443, snitest.BuildClientHello("evil.attacker.example"), false, false, "evil.attacker.example", L7Mismatch},
		{"tls no sni", sni.ProtoTLS, 443, snitest.BuildClientHello(""), false, false, "", L7NoName},
		{"tls incomplete", sni.ProtoTLS, 443, snitest.BuildClientHello("auth.docker.io")[:8], true, false, "", ""},
		{"tls not tls", sni.ProtoTLS, 443, []byte("SSH-2.0-x\r\n"), false, false, "", L7NotProtocol},
		{"http allowed", sni.ProtoHTTP, 80, []byte("GET / HTTP/1.1\r\nHost: ocsp.sectigo.com\r\n\r\n"), false, true, "ocsp.sectigo.com", L7Allowed},
		{"http mismatch", sni.ProtoHTTP, 80, []byte("GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"), false, false, "evil.example", L7Mismatch},
		{"http no host", sni.ProtoHTTP, 80, []byte("GET / HTTP/1.0\r\n\r\n"), false, false, "", L7NoName},
		{"http incomplete", sni.ProtoHTTP, 80, []byte("GET / HTTP/1.1\r\nHost: oc"), true, false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := config.L7Request{DstIP: "140.82.114.30", DstPort: tc.port, Proto: 6}
			needMore, out := adjudicate(tc.proto, tc.buf, q, m, false)
			require.Equal(t, tc.wantNeedMore, needMore, "needMore")
			require.Equal(t, tc.wantAllowed, out.Allowed, "allowed")
			require.Equal(t, tc.wantName, out.Name, "name")
			require.Equal(t, tc.wantWhy, out.Reason, "reason")
		})
	}
}

// TestL7AdjudicatePortScoped: a name allowed only on a non-web port must NOT
// validate as an SNI on 443 — the shared-edge over-admit the port-aware
// matcher closes.
func TestL7AdjudicatePortScoped(t *testing.T) {
	m := portAllowSet{"ssh.example.com": 22} // allowed only on :22

	q := config.L7Request{DstIP: "140.82.114.30", DstPort: 443, Proto: 6}
	_, out := adjudicate(sni.ProtoTLS, snitest.BuildClientHello("ssh.example.com"), q, m, false)
	require.False(t, out.Allowed, "a :22-only name must not pass as an SNI on 443")
	require.Equal(t, L7Mismatch, out.Reason)

	// The same name presented on its own port would match (sanity check).
	q.DstPort = 22
	_, out = adjudicate(sni.ProtoTLS, snitest.BuildClientHello("ssh.example.com"), q, m, false)
	require.True(t, out.Allowed)
	require.Equal(t, L7Allowed, out.Reason)
}

// TestL7AdjudicatePerIPBinding covers the per-IP narrowing dimension: an
// allowed name presented at a destination it never resolved to is admitted
// with a would-narrow decision while the dimension is only measured, and
// denied once pinning is on. Without it an allowed name is a passphrase that
// opens any L7-scoped IP.
func TestL7AdjudicatePerIPBinding(t *testing.T) {
	m := boundAllowSet{"good.example": {"104.16.1.1"}}
	hello := snitest.BuildClientHello("good.example")

	bound := config.L7Request{DstIP: "104.16.1.1", DstPort: 443, Proto: 6}
	unbound := config.L7Request{DstIP: "203.0.113.7", DstPort: 443, Proto: 6}

	// Bound destination: a plain allow, in both postures.
	for _, pin := range []bool{false, true} {
		_, out := adjudicate(sni.ProtoTLS, hello, bound, m, pin)
		require.True(t, out.Allowed, "bound name must allow (pin=%v)", pin)
		require.False(t, out.WouldNarrow, "a bound name narrows nothing")
		require.Equal(t, L7Allowed, out.Reason)
	}

	// Unbound destination, measuring only: the packet passes, but the
	// would-have-denied is reported with its own reason.
	_, out := adjudicate(sni.ProtoTLS, hello, unbound, m, false)
	require.True(t, out.Allowed, "unpinned must admit")
	require.True(t, out.WouldNarrow, "...but flag the flow")
	require.Equal(t, "good.example", out.Name)
	require.Equal(t, L7NameNotAtIP, out.Reason)

	// Unbound destination, pinning on: a real deny, distinguishable from a
	// name that no rule allows at all.
	_, out = adjudicate(sni.ProtoTLS, hello, unbound, m, true)
	require.False(t, out.Allowed, "pinning must deny a name not bound here")
	require.False(t, out.WouldNarrow, "an enforced deny is not a would-narrow")
	require.Equal(t, L7NameNotAtIP, out.Reason)
	require.NotEqual(t, L7Mismatch, out.Reason, "must stay distinct from an unallowed name")
}
