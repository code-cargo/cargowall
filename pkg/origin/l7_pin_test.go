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
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/sni"
)

// Kernel<->userspace pin tests. The two sides of this feature are separate
// implementations of one contract — the C datapath cannot include Go, and
// the verifier cannot eat a shared header — so every constant, version
// table and port table they both depend on is asserted equal here. A drift
// these catch is silent in production: the kernel stops punting something
// userspace would have denied.

// TestL7KernelConstantsMatchSniSource pins the Go mirrors of sni.h's
// constants against the C source, the way TestOriginConstantsMatchBpfSource
// pins originbpf.c's: the stat slots feed logStats' hardcoded indices, the
// state/flag values cross the ringbuf, and a silent renumber on either side
// would misread every one of them.
func TestL7KernelConstantsMatchSniSource(t *testing.T) {
	src := kernelL7Source(t)

	defines := map[string]uint64{
		"ORIGIN_CFG_KEY_L7_MODE": uint64(l7CfgKeyMode),
		"L7_MODE_OFF":            uint64(L7ModeOff),
		"L7_MODE_OBSERVE":        uint64(L7ModeObserve),
		"L7_MODE_ENFORCE":        uint64(L7ModeEnforce),
		"L7_SCOPE_TLS":           uint64(bpf.L7ScopeTLS),
		"L7_SCOPE_HTTP":          uint64(bpf.L7ScopeHTTP),
		"L7_SCOPE_QUIC":          uint64(bpf.L7ScopeQUIC),
		"L7_STATE_ALLOWED":       uint64(l7StateAllowed),
		"L7_STATE_DENIED":        uint64(l7StateDenied),
		"L7_PUNT_F_NO_STATE":     uint64(l7PuntNoState),
		"L7_PUNT_F_OBSERVE":      uint64(l7PuntObserve),
		"L7_PUNT_F_TRUNCATED":    uint64(l7PuntTruncated),
		"L7_PUNT_F_QUIC":         uint64(l7PuntQUIC),
		"L7_PUNT_F_REPIN":        uint64(l7PuntRepin),
		"L7_PUNT_F_REFUSED":      uint64(l7PuntRefused),
		// The stat slots the Go mirror (l7Stat*) reads in logStats.
		"L7_STAT_PUNT":          uint64(l7StatPunt),
		"L7_STAT_PUNT_DROPPED":  uint64(l7StatPuntDropped),
		"L7_STAT_QUIC":          uint64(l7StatQUIC),
		"L7_STAT_BUDGET":        uint64(l7StatBudget),
		"L7_STAT_ALLOWED":       uint64(l7StatAllowed),
		"L7_STAT_DENIED":        uint64(l7StatDenied),
		"L7_STAT_GATE_REFUSED":  uint64(l7StatGateRefused),
		"L7_STAT_PENDING_NO_ID": uint64(l7StatPendingNoID),
		"L7_STAT_GATE_NO_STATE": uint64(l7StatGateNoState),
		"L7_STAT_ALT_UNGATED":   uint64(l7StatAltUngated),
	}
	for name, want := range defines {
		re := regexp.MustCompile(`(?m)^#define ` + name + `\s+(0x[0-9A-Fa-f]+|\d+)\b`)
		m := re.FindStringSubmatch(src)
		require.NotNil(t, m, "sni.h must #define %s", name)
		got, err := strconv.ParseUint(m[1], 0, 64)
		require.NoError(t, err)
		require.Equal(t, want, got, "%s drifted between sni.h and the Go mirror", name)
	}
}

// TestKernelQUICVersionsMatchParser pins the kernel's QUIC version table
// (l7_quic_one in sni.h) against pkg/sni's initialVersions: a
// version userspace decrypts but the kernel misses yields no
// connection-attempt identity, so a second connection in that version on one
// UDP socket would ride the first's verdict with its SNI never parsed — the
// draft-29 shape of exactly the reuse the DCID identity exists to close.
func TestKernelQUICVersionsMatchParser(t *testing.T) {
	src := kernelL7Source(t)

	re := regexp.MustCompile(`(?m)^#define QUIC_VER_\w+\s+(0x[0-9A-Fa-f]+)\b`)
	kernel := map[uint32]bool{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		v, err := strconv.ParseUint(m[1], 0, 32)
		require.NoError(t, err)
		kernel[uint32(v)] = true
	}
	require.NotEmpty(t, kernel, "sni.h must #define QUIC_VER_* versions")

	for _, v := range sni.InitialVersions() {
		require.True(t, kernel[v], "kernel version table is missing QUIC version %#x", v)
		delete(kernel, v)
	}
	require.Empty(t, kernel, "kernel version table has versions pkg/sni cannot decrypt: %v", kernel)
}

// TestKernelQUICVersionTypeBitsMatchParser pins the kernel's per-version
// Initial/Retry packet-type bits (QUIC_V*_{INITIAL,RETRY}_TYPE in sni.h)
// against pkg/sni's initialVersions table. The version-number pin above is not
// enough: v2 rotated these bits, and a version present with the WRONG bits
// classifies the wrong coalesced packets — the kernel would stamp no identity
// (a real Initial read as a skippable 0-RTT) and a second connection would
// ride the first's verdict, or deny datagrams it should have punted.
func TestKernelQUICVersionTypeBitsMatchParser(t *testing.T) {
	src := kernelL7Source(t)

	def := func(name string) byte {
		re := regexp.MustCompile(`(?m)^#define ` + name + `\s+(\d+)\b`)
		m := re.FindStringSubmatch(src)
		require.NotNil(t, m, "sni.h must #define %s", name)
		v, err := strconv.ParseUint(m[1], 0, 8)
		require.NoError(t, err)
		return byte(v)
	}

	// The kernel maps v1 AND draft-29 onto the "v1" bit macros, v2 onto its own.
	kInit := map[uint32]byte{
		0x00000001: def("QUIC_V1_INITIAL_TYPE"),
		0xff00001d: def("QUIC_V1_INITIAL_TYPE"),
		0x6b3343cf: def("QUIC_V2_INITIAL_TYPE"),
	}
	kRetry := map[uint32]byte{
		0x00000001: def("QUIC_V1_RETRY_TYPE"),
		0xff00001d: def("QUIC_V1_RETRY_TYPE"),
		0x6b3343cf: def("QUIC_V2_RETRY_TYPE"),
	}
	for _, v := range sni.InitialVersions() {
		it, rt, ok := sni.InitialTypeBits(v)
		require.True(t, ok)
		require.Equal(t, kInit[v], it, "Initial type bits drifted for version %#x", v)
		require.Equal(t, kRetry[v], rt, "Retry type bits drifted for version %#x", v)
	}
}

// TestKernelHTTPMethodsMatchParser pins the kernel identity gate's token
// table (l7_http_request_line in sni.h) against pkg/sni's — the two lists
// decide the same question in two places (does this segment open an HTTP
// identity?), and a method present in one but not the other either silently
// fail-closes a legal first flight on a NEED_HELLO flow or passes a no-state
// request as established body traffic.
func TestKernelHTTPMethodsMatchParser(t *testing.T) {
	src := kernelL7Source(t)

	re := regexp.MustCompile(`l7_http_tok\(b, n, "([A-Z]+) "`)
	kernel := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		kernel[m[1]] = true
	}
	require.NotEmpty(t, kernel, "sni.h must contain l7_http_tok method tokens")

	for _, method := range sni.HTTPMethods() {
		require.True(t, kernel[method], "kernel token table is missing method %q", method)
		delete(kernel, method)
	}
	require.Empty(t, kernel, "kernel token table has methods pkg/sni does not: %v", kernel)
}

// TestKernelAltPortsMatchScopeTables pins the kernel's alternate-port tables
// (l7_alt_https_port / l7_alt_http_port in sni.h) against pkg/bpf's, which is
// what pkg/dns derives a rule's scope bits from. A port in one table but not
// the other is silent: scoped-but-never-narrowed is a hole (the flow reaches
// the shared edge unadjudicated, the exact tenant swap this layer closes), and
// narrowed-but-never-scoped is dead code that can only mislead.
func TestKernelAltPortsMatchScopeTables(t *testing.T) {
	src := kernelL7Source(t)

	kernelPorts := func(fn string) []uint16 {
		body := regexp.MustCompile(`(?s)int ` + fn + `\(__u16 port\) \{(.*?)\n\}`).FindStringSubmatch(src)
		require.NotNil(t, body, "sni.h must define %s", fn)
		var out []uint16
		for _, m := range regexp.MustCompile(`port == (\d+)`).FindAllStringSubmatch(body[1], -1) {
			v, err := strconv.ParseUint(m[1], 10, 16)
			require.NoError(t, err)
			out = append(out, uint16(v))
		}
		require.NotEmpty(t, out, "%s must list ports", fn)
		return out
	}

	require.ElementsMatch(t, bpf.AltHTTPSPorts, kernelPorts("l7_alt_https_port"),
		"alternate HTTPS ports drifted between sni.h and bpf.AltHTTPSPorts")
	require.ElementsMatch(t, bpf.AltHTTPPorts, kernelPorts("l7_alt_http_port"),
		"alternate HTTP ports drifted between sni.h and bpf.AltHTTPPorts")
}

// TestKernelCoalescedCapMatchesParser pins L7_QUIC_MAX_COALESCED against
// pkg/sni's MaxCoalescedPackets. The kernel refuses a datagram whose walk it
// could not finish within the cap, so a userspace walk that read FURTHER would
// only ever be decoding packets the datapath never punted — and one that
// stopped SOONER would discard CRYPTO from a datagram the kernel admitted.
func TestKernelCoalescedCapMatchesParser(t *testing.T) {
	src := kernelL7Source(t)

	m := regexp.MustCompile(`(?m)^#define L7_QUIC_MAX_COALESCED\s+(\d+)\b`).FindStringSubmatch(src)
	require.NotNil(t, m, "sni_quic.h must #define L7_QUIC_MAX_COALESCED")
	got, err := strconv.ParseUint(m[1], 10, 32)
	require.NoError(t, err)
	require.Equal(t, uint64(sni.MaxCoalescedPackets), got,
		"the coalesced-walk cap drifted between sni_quic.h and pkg/sni")
}
