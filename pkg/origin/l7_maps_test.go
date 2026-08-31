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
	"encoding/binary"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
)

// The scope maps the DNS path writes and the reload flushes: what gets
// scoped, what survives a flush, and the fail-open a full or half-drained
// map would become.

func TestL7RegistrarWritesMaps(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{}}, nil)

	// ScopeIP unions bits across calls.
	ip := net.ParseIP("104.16.1.1")
	require.NoError(t, l.ScopeIP(ip, tcpPorts(443)))
	require.NoError(t, l.ScopeIP(ip, tcpPorts(80)))
	var flags uint8
	require.NoError(t, objs.MapL7Scope.Lookup(binary.NativeEndian.Uint32(ip.To4()), &flags))
	require.Equal(t, bpf.L7ScopeTLS|bpf.L7ScopeHTTP, flags, "ScopeIP must union scope bits")
}

// TestL7FlushScopes: policy reload empties BOTH scope maps wholesale. Scope
// entries have no expiry and no reverse index, so a dropped rule's IPs would
// otherwise stay L7-governed forever — and, the maps being fixed-size with no
// eviction, dead entries would eventually fill them and silently fail OPEN
// every newly resolved destination.
func TestL7FlushScopes(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{}}, nil)

	ip4 := net.ParseIP("104.16.1.1")
	ip6 := net.ParseIP("2606:4700::7")
	require.NoError(t, l.ScopeIP(ip4, tcpPorts(443)))
	require.NoError(t, l.ScopeIP(ip6, udpPorts(443)))

	require.NoError(t, l.FlushScopes())
	var flags uint8
	require.Error(t, objs.MapL7Scope.Lookup(binary.NativeEndian.Uint32(ip4.To4()), &flags),
		"flush must drain the v4 scope map")
	var k6 [16]byte
	copy(k6[:], ip6.To16())
	require.Error(t, objs.MapL7ScopeV6.Lookup(k6, &flags), "flush must drain the v6 scope map")

	// Idempotent on empty maps, and re-warming works normally afterwards.
	require.NoError(t, l.FlushScopes())
	require.NoError(t, l.ScopeIP(ip4, tcpPorts(80)))
	require.NoError(t, objs.MapL7Scope.Lookup(binary.NativeEndian.Uint32(ip4.To4()), &flags))
	require.Equal(t, bpf.L7ScopeHTTP, flags, "the scope maps must re-warm after a flush")
}

// TestL7FlushScopesDrainsV6DespiteV4Failure: the flush returned on the v4
// drain's error without ever touching the v6 map, and its only caller logs a
// warning and re-warms on top of whatever survived. A single v4 failure
// therefore left every v6 entry from before the reload in place — dropped
// rules' IPs L7-governed forever, and dead entries accumulating until the
// fixed-size map filled and scopeFull's fail-OPEN took over.
func TestL7FlushScopesDrainsV6DespiteV4Failure(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{}}, nil)

	ip6 := net.ParseIP("2606:4700::7")
	require.NoError(t, l.ScopeIP(ip6, udpPorts(443)))

	// Break the v4 map so its drain fails, the way a transient batch/NextKey
	// error would.
	require.NoError(t, objs.MapL7Scope.Close())

	require.Error(t, l.FlushScopes(), "the v4 failure must still be reported")

	var flags uint8
	var k6 [16]byte
	copy(k6[:], ip6.To16())
	require.Error(t, objs.MapL7ScopeV6.Lookup(k6, &flags),
		"a v4 drain failure must not leave the v6 scope map stale")
}

// TestL7ScopeIPv6 covers the v6 scope path and union, which the v4-only
// registrar test left uncovered.
func TestL7ScopeIPv6(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{}}, nil)
	ip := net.ParseIP("2606:4700::1")
	if err := l.ScopeIP(ip, tcpPorts(443)); err != nil {
		t.Fatal(err)
	}
	if err := l.ScopeIP(ip, udpPorts(443)); err != nil {
		t.Fatal(err)
	}
	var key [16]byte
	copy(key[:], ip.To16())
	var flags uint8
	if err := objs.MapL7ScopeV6.Lookup(key, &flags); err != nil {
		t.Fatal(err)
	}
	if flags != bpf.L7ScopeTLS|bpf.L7ScopeQUIC {
		t.Errorf("v6 scope = %#x, want TLS|QUIC", flags)
	}
}

// TestL7ScopeIPConcurrentUnion: concurrent registrations for one edge IP
// (two hostnames resolving at once) must union their scope bits — the
// unserialized read-modify-write this guards against let the last Put drop
// the other dimension, leaving that protocol L7-unscoped (fail-open).
func TestL7ScopeIPConcurrentUnion(t *testing.T) {
	objs := loadL7Objects(t)
	l := newL7(objs, L7Options{Matcher: allowSet{}}, nil)
	ip := net.ParseIP("104.16.9.9")
	key := binary.NativeEndian.Uint32(ip.To4())

	for i := 0; i < 100; i++ {
		_ = objs.MapL7Scope.Delete(key)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = l.ScopeIP(ip, tcpPorts(443)) }()
		go func() { defer wg.Done(); _ = l.ScopeIP(ip, udpPorts(443)) }()
		wg.Wait()
		var flags uint8
		require.NoError(t, objs.MapL7Scope.Lookup(key, &flags))
		require.Equal(t, bpf.L7ScopeTLS|bpf.L7ScopeQUIC, flags, "iteration %d dropped a scope bit", i)
	}
}
