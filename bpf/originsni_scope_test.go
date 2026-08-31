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

	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// Which flows the L7 layer governs AT ALL: the mode gate, the scope map,
// port narrowing (canonical and CDN alternate), and the carve-out classes
// this hook never denies. Split from originsni_test.go, which keeps the
// identity gate — these decide whether the gate is consulted, not what it
// concludes.

// TestOriginL7ModeOffIsInert confirms L7 defaults to a no-op: with L7 mode
// unset, even a disallowed SNI on a scoped IP passes, so the feature can be
// dark-launched without changing behavior.
func TestOriginL7ModeOffIsInert(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.11"
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))
	// L7 mode left OFF (unset).

	ret, _, err := objs.CgOriginEgress.Test(craftIPv4TLSData(edgeIP, "evil.attacker.example"))
	require.NoError(t, err)
	require.Equal(t, 1, int(ret), "L7 OFF must pass everything the L4 verdict allowed")
}

// TestOriginL7UnscopedIPUntouched confirms an IP with no scope entry is never
// subject to L7, so static-CIDR and non-hostname traffic is unaffected.
func TestOriginL7UnscopedIPUntouched(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))

	// 140.82.114.12 is L4-allowed but NOT in map_l7_scope.
	ret, _, err := objs.CgOriginEgress.Test(craftIPv4TLSData("140.82.114.12", "evil.attacker.example"))
	require.NoError(t, err)
	require.Equal(t, 1, int(ret), "an unscoped IP must pass regardless of SNI")
}

// TestOriginL7PortScoped proves adjudication is port-scoped: the scope bits
// mean exactly TCP/443 = TLS (and TCP/80 = Host, UDP/443 = QUIC), so every
// OTHER port on a scoped IP stays governed by the L4 verdict alone. Without
// the port predicate, an all-ports hostname rule (ssh.github.com) would have
// its non-web ports parsed as TLS and fail-closed.
func TestOriginL7PortScoped(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.13"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	sshBanner := []byte("SSH-2.0-OpenSSH_9.7\r\n")

	// Non-web ports on the scoped IP: never adjudicated, the L4 allow stands.
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 22, sshBanner)),
		"port 22 on a TLS-scoped IP must stay L4-governed")
	// Port 80 with only the TLS bit set: the HTTP dimension was not scoped.
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 80, []byte("GET / HTTP/1.1\r\n"))),
		"port 80 without the HTTP scope bit must stay L4-governed")
	// UDP to a non-443 port (plain DNS shape): the QUIC dimension never applies.
	require.Equal(t, 1, run(craftIPv4UDP(t, edgeIP, 53)),
		"UDP/53 to a scoped IP must stay L4-governed")

	// The scoped port itself keeps the fail-closed posture: a non-TLS first
	// flight on 443 punts and is dropped pending adjudication.
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 443, sshBanner)),
		"non-TLS bytes on the scoped 443 must still fail closed")
}

// TestOriginL7CarveOutExempt proves the L7 tail honors the carve-out classes:
// a scoped destination inside a carved class (here the 127/8 literal — the
// DNS-rebinding shape, where an allowed hostname resolves to loopback and the
// registrar scopes it) must never be denied by L7, because the carve-outs
// define traffic this hook never denies.
func TestOriginL7CarveOutExempt(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const loIP = "127.0.0.1"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(loIP), uint8(L7ScopeTLS)))

	ret, _, err := objs.CgOriginEgress.Test(craftIPv4TLSData(loIP, "evil.attacker.example"))
	require.NoError(t, err)
	require.Equal(t, 1, int(ret), "a carved-class destination must never be L7-denied")
}

// TestOriginL7AlternateHTTPSPortAdjudicated closes the alternate-port hole:
// Cloudflare and the other big CDNs terminate the SAME shared edge on 2053,
// 2083, 2087, 2096 and 8443, so scoping only TCP/443 left the tenant swap this
// layer exists to stop fully reachable — an all-ports hostname allow opens the
// edge /32 on every port, and a flow presenting an attacker's SNI on :8443 was
// never adjudicated at all.
//
// The port is governed to pin the SNI of flows that DO speak TLS; a non-TLS
// service there is the same L4-governed residual as ssh:22, so it passes
// rather than fail-closing traffic the rule deliberately allows. The canonical
// 443 keeps its fail-closed posture (TestOriginL7PortScoped).
func TestOriginL7AlternateHTTPSPortAdjudicated(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.31"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	for _, port := range AltHTTPSPorts {
		hello := snitest.BuildClientHello("evil.attacker.example")
		require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, port, hello)),
			"a ClientHello on alternate HTTPS port %d must be adjudicated, not passed", port)
		ev := readL7Sample(t, rd)
		require.Equal(t, uint8(L7ScopeTLS), ev.Scope,
			"an alternate HTTPS port must punt under the TLS dimension")
		require.Equal(t, port, ev.DstPort)
	}

	// Non-TLS bytes on the same port ride the L4 verdict: nothing there routes
	// by SNI, so refusing them would only fail-close an allowed service.
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 8443, []byte("SSH-2.0-OpenSSH_9.7\r\n"))),
		"non-TLS bytes on an alternate HTTPS port must ride the L4 verdict")
	requireNoL7Sample(t, rd)

	// An unlisted high port stays entirely L4-governed.
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 9443,
		snitest.BuildClientHello("evil.attacker.example"))),
		"a port outside the alternate table must stay L4-governed")
	requireNoL7Sample(t, rd)
}

// TestOriginL7AlternateHTTPPortAdjudicated is the cleartext twin: the CDN
// alternate HTTP ports carry the Host dimension exactly as :80 does.
func TestOriginL7AlternateHTTPPortAdjudicated(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.32"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeHTTP)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	for _, port := range AltHTTPPorts {
		req := []byte("GET / HTTP/1.1\r\nHost: evil.attacker.example\r\n\r\n")
		require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, port, req)),
			"an HTTP request on alternate port %d must be adjudicated, not passed", port)
		ev := readL7Sample(t, rd)
		require.Equal(t, uint8(L7ScopeHTTP), ev.Scope)
		require.Equal(t, port, ev.DstPort)
	}

	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 8080, []byte("SSH-2.0-OpenSSH_9.7\r\n"))),
		"non-HTTP bytes on an alternate HTTP port must ride the L4 verdict")
	requireNoL7Sample(t, rd)
}
