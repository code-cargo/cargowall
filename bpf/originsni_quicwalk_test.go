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

package bpf

import (
	"testing"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/sni"
	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// rfc9001DCID is the Destination Connection ID of the RFC 9001 client Initial
// each case coalesces behind its leading header. A conformant datagram carries
// ONE connection ID, so the leading headers reuse it.
var rfc9001DCID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

// quicLongHeader builds a coalesced non-Initial long header: version, packet
// type bits, the given DCID, a zero-filled SCID, a 1-byte Length varint and
// that many filler bytes. bodyLen must be < 64.
func quicLongHeader(version uint32, typeBits byte, dcid []byte, scidLen, bodyLen int) []byte {
	pkt := []byte{
		0xc0 | typeBits<<4, // long header + fixed bit + type
		byte(version >> 24), byte(version >> 16), byte(version >> 8), byte(version),
		byte(len(dcid)),
	}
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(scidLen))
	pkt = append(pkt, make([]byte, scidLen)...)
	pkt = append(pkt, byte(bodyLen))
	return append(pkt, make([]byte, bodyLen)...)
}

// TestOriginL7QUICWalkContract feeds ONE datagram to both coalesced walks —
// the kernel's (l7_quic_one/l7_quic_find_initial) and pkg/sni's
// (skipLongHeader/decodeOneInitial) — and requires them to agree on whether
// the Initial behind the leading header is reachable. The rules themselves are
// stated once, at skipLongHeader in pkg/sni/quic.go; without this test the two
// implementations only happen to match.
func TestOriginL7QUICWalkContract(t *testing.T) {
	overCap := make([]byte, 21) // one past the RFC 9000 §17.2 connection ID cap
	otherCID := []byte{7, 7, 7, 7, 6, 6, 6, 6}

	tests := []struct {
		name string
		lead []byte
		// refused: the leading header is unskippable, so NEITHER walk reaches
		// the Initial behind it.
		refused bool
		// kernelOnly: the kernel refuses where pkg/sni adjudicates — the one
		// intentional asymmetry, on the mixed-CID case below.
		kernelOnly bool
	}{
		{name: "0-RTT skipped by its Length", lead: quicLongHeader(0x00000001, 0b01, rfc9001DCID, 0, 4)},
		{name: "DCID over the cap", lead: quicLongHeader(0x00000001, 0b01, overCap, 0, 4), refused: true},
		{name: "SCID over the cap", lead: quicLongHeader(0x00000001, 0b01, rfc9001DCID, 21, 4), refused: true},
		{name: "Retry carries no Length", lead: quicLongHeader(0x00000001, 0b11, rfc9001DCID, 0, 4), refused: true},
		{name: "unknown version cannot be sized", lead: quicLongHeader(0x0a0a0a0a, 0b01, rfc9001DCID, 0, 4), refused: true},
		// RFC 9000 §12.2 forbids coalescing across connection IDs. The kernel
		// holds EVERY long header to one identity and refuses this datagram;
		// pkg/sni compares only across decodable Initials, so it would
		// adjudicate it — safe precisely because the kernel refusal here is the
		// only path to the oracle.
		{name: "mixed connection IDs", lead: quicLongHeader(0x00000001, 0b01, otherCID, 0, 4), kernelOnly: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			datagram := append(append([]byte{}, tc.lead...), snitest.RFC9001ClientInitial()...)

			// Userspace: reaching the Initial yields its CRYPTO chunks.
			chunks, err := sni.DecodeInitialCrypto(datagram)
			if tc.refused {
				require.Error(t, err, "the userspace walk must not reach the Initial")
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, chunks, "the userspace walk must recover the Initial's CRYPTO")
			}

			objs := loadOriginObjects(t)
			seedOriginRules(t, objs)
			setOriginMode(t, objs, originModeEnforce)

			const edgeIP = "140.82.114.26"
			require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
			require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeQUIC)))

			rd, err := ringbuf.NewReader(objs.MapL7Events)
			require.NoError(t, err)
			defer rd.Close()

			ret, _, err := objs.CgOriginEgress.Test(craftIPv4UDPData(edgeIP, 443, datagram))
			require.NoError(t, err)
			require.Equal(t, 0, int(ret), "under enforce a punt and a refusal both drop the datagram")

			ev := readL7Sample(t, rd)
			if tc.refused || tc.kernelOnly {
				require.NotZero(t, ev.Flags&l7PuntFlagRefused, "the kernel walk must refuse this datagram")
				require.Empty(t, dumpL7Flows(t, objs), "an uncertain refusal must not park flow state")
				return
			}
			require.NotZero(t, ev.Flags&l7PuntFlagQUIC, "the kernel walk must punt for adjudication")
			require.Equal(t, rfc9001DCID, append([]byte(nil), ev.Dcid[:ev.DcidLen]...),
				"the punt must carry the buried Initial's DCID")
		})
	}
}
