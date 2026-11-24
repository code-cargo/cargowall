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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/sni"
	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// bareLabelMatcher answers L7MatchBareLabel for any name it is asked about
// as a server name, recording which dimension each request carried.
type bareLabelMatcher struct{ sni []bool }

func (m *bareLabelMatcher) MatchName(q config.L7Request) config.L7Match {
	m.sni = append(m.sni, q.SNI)
	if q.SNI {
		return config.L7MatchBareLabel
	}
	return config.L7NoMatch
}

// A bare-label pass is an allowed outcome with its own reason in every L7
// mode, pinned or not, and the matcher is told the name is a server name
// only for TLS and QUIC.
func TestL7AdjudicateBareLabel(t *testing.T) {
	tlsHello := snitest.BuildClientHello("kq563vfqzm")
	// The QUIC CRYPTO stream carries the handshake message without the TLS
	// record header.
	quicHello := tlsHello[5:]
	q := config.L7Request{DstIP: "54.80.12.34", DstPort: 443, Proto: 6}

	for _, pin := range []bool{false, true} {
		m := &bareLabelMatcher{}
		for _, tc := range []struct {
			proto sni.Protocol
			buf   []byte
		}{{sni.ProtoTLS, tlsHello}, {sni.ProtoQUIC, quicHello}} {
			needMore, out := adjudicate(tc.proto, tc.buf, q, m, pin)
			require.False(t, needMore)
			assert.True(t, out.Allowed, "%v pin=%v", tc.proto, pin)
			assert.Equal(t, L7BareLabel, out.Reason, "%v pin=%v", tc.proto, pin)
			assert.Equal(t, "kq563vfqzm", out.Name)
			assert.False(t, out.WouldNarrow, "a bare-label pass is no would-deny")
		}

		_, out := adjudicate(sni.ProtoHTTP, []byte("GET / HTTP/1.1\r\nHost: kq563vfqzm\r\n\r\n"),
			config.L7Request{DstIP: "54.80.12.34", DstPort: 80, Proto: 6}, m, pin)
		assert.False(t, out.Allowed, "an HTTP Host is never a bare-label pass")
		assert.Equal(t, L7Mismatch, out.Reason)
		assert.Equal(t, []bool{true, true, false}, m.sni, "SNI is set for TLS and QUIC only")
	}
}

// End to end through the production matcher: the builder's address was
// bound by a forward resolution of an allowed name, so the opaque label
// passes; the same label at an address nothing allowed resolved to is a
// mismatch.
func TestL7AdjudicateBareLabelWithPolicy(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "*.compute-1.amazonaws.com", Action: config.ActionAllow},
	}, config.ActionDeny))
	cm.RecordForwardResolution("ec2-54-80-12-34.compute-1.amazonaws.com", "54.80.12.34")
	m := config.NewL7Policy(cm, nil)
	hello := snitest.BuildClientHello("kq563vfqzm")

	_, out := adjudicate(sni.ProtoTLS, hello, config.L7Request{DstIP: "54.80.12.34", DstPort: 443, Proto: 6}, m, true)
	assert.True(t, out.Allowed)
	assert.Equal(t, L7BareLabel, out.Reason)

	_, out = adjudicate(sni.ProtoTLS, hello, config.L7Request{DstIP: "54.80.99.1", DstPort: 443, Proto: 6}, m, true)
	assert.False(t, out.Allowed)
	assert.Equal(t, L7Mismatch, out.Reason)
}
