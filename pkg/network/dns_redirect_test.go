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

package network

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// installFakeResolvectl drops an executable `resolvectl` running the given
// /bin/sh script into a fresh temp dir and makes it the FIRST entry on PATH.
// The existing PATH is preserved after it so LookPath resolves the fake yet the
// script can still invoke real utilities (e.g. `sleep`).
func installFakeResolvectl(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "resolvectl"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake resolvectl: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// withResolvedRunning points resolvedRuntimeDir at an existing dir so the
// "resolved running" gate passes, restoring it on cleanup.
func withResolvedRunning(t *testing.T) {
	t.Helper()
	prev := resolvedRuntimeDir
	resolvedRuntimeDir = t.TempDir()
	t.Cleanup(func() { resolvedRuntimeDir = prev })
}

// TestFlushResolvedCache_NotInstalled: resolvectl absent from PATH → quiet skip.
func TestFlushResolvedCache_NotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir, no resolvectl
	if err := FlushResolvedCache(context.Background(), discardLogger()); err != nil {
		t.Fatalf("expected nil when resolvectl not installed, got %v", err)
	}
}

// TestFlushResolvedCache_ResolvedNotRunning: resolvectl present but the runtime
// dir is absent → quiet skip, and the fake (which would exit 1) must not run.
func TestFlushResolvedCache_ResolvedNotRunning(t *testing.T) {
	installFakeResolvectl(t, "exit 1")
	prev := resolvedRuntimeDir
	resolvedRuntimeDir = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { resolvedRuntimeDir = prev })

	if err := FlushResolvedCache(context.Background(), discardLogger()); err != nil {
		t.Fatalf("expected nil when systemd-resolved not running, got %v", err)
	}
}

// TestFlushResolvedCache_FlushFails: resolved running + non-zero exit → error.
func TestFlushResolvedCache_FlushFails(t *testing.T) {
	installFakeResolvectl(t, "echo boom >&2; exit 1")
	withResolvedRunning(t)

	if err := FlushResolvedCache(context.Background(), discardLogger()); err == nil {
		t.Fatal("expected error when resolvectl flush-caches fails, got nil")
	}
}

// TestFlushResolvedCache_Success: resolved running + zero exit → nil.
func TestFlushResolvedCache_Success(t *testing.T) {
	installFakeResolvectl(t, "exit 0")
	withResolvedRunning(t)

	if err := FlushResolvedCache(context.Background(), discardLogger()); err != nil {
		t.Fatalf("expected nil on successful flush, got %v", err)
	}
}

// TestDNSRedirectRules_Shape pins the rule slice: mark RETURN exemptions
// first (the proxy's upstream client and startup stub peeks), then the
// systemd-resolved stub DNAT (#110 — makes the querying process's own
// socket visible to the proxy instead of resolved's), then the generic
// DNAT that still excludes the rest of 127.0.0.0/8 (the proxy listen must
// never be DNAT'd), then the INPUT anti-resurrection guards. Order is
// load-bearing: install order is slice order and teardown reverses it, so
// the exemptions outlive every DNAT they exempt from.
func TestDNSRedirectRules_Shape(t *testing.T) {
	want := []string{
		"OUTPUT -t nat -p udp --dport 53 -m mark --mark 0xCA12 -j RETURN",
		"OUTPUT -t nat -p tcp --dport 53 -m mark --mark 0xCA12 -j RETURN",
		"OUTPUT -t nat -p udp -d 127.0.0.53 --dport 53 -j DNAT --to-destination 127.0.0.1:53",
		"OUTPUT -t nat -p tcp -d 127.0.0.53 --dport 53 -j DNAT --to-destination 127.0.0.1:53",
		"OUTPUT -t nat -p udp --dport 53 ! -d 127.0.0.0/8 -j DNAT --to-destination 127.0.0.1:53",
		"OUTPUT -t nat -p tcp --dport 53 ! -d 127.0.0.0/8 -j DNAT --to-destination 127.0.0.1:53",
		"INPUT -p udp ! -i lo --sport 53 -m conntrack --ctstate NEW -j DROP",
		"INPUT -p tcp ! -i lo --sport 53 -m conntrack --ctstate NEW -j DROP",
	}
	if len(dnsRedirectRules) != len(want) {
		t.Fatalf("dnsRedirectRules has %d rules, want %d", len(dnsRedirectRules), len(want))
	}
	for i, r := range dnsRedirectRules {
		got := r.chain + " " + strings.Join(r.args, " ")
		if got != want[i] {
			t.Errorf("rule %d:\n  got  %q\n  want %q", i, got, want[i])
		}
	}
}

// TestMarkedDialControl_SetsMark: a dialer using MarkedDialControl must
// carry DNSProxyFWMark, or the stub DNAT would loop cargowall's own stub
// peeks (cacheResolver) back into the proxy. Root-only: SO_MARK needs
// CAP_NET_ADMIN, and the sudo'd pkg/network test pass in CI provides it.
func TestMarkedDialControl_SetsMark(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SO_MARK requires CAP_NET_ADMIN; covered by the sudo test pass")
	}
	d := &net.Dialer{Control: MarkedDialControl}
	conn, err := d.Dial("udp", "127.0.0.1:53535")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	raw, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}
	var mark int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		mark, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("getsockopt SO_MARK: %v", sockErr)
	}
	if mark != DNSProxyFWMark {
		t.Fatalf("SO_MARK = %#x, want %#x", mark, DNSProxyFWMark)
	}
}

// TestFlushResolvedCache_Timeout: a wedged resolvectl is killed at the deadline
// and surfaced as an error rather than hanging startup.
func TestFlushResolvedCache_Timeout(t *testing.T) {
	installFakeResolvectl(t, "sleep 5")
	withResolvedRunning(t)
	prev := flushResolvedTimeout
	flushResolvedTimeout = 50 * time.Millisecond
	t.Cleanup(func() { flushResolvedTimeout = prev })

	done := make(chan error, 1)
	go func() { done <- FlushResolvedCache(context.Background(), discardLogger()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected a deadline-exceeded error naming the timeout, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FlushResolvedCache did not honor its timeout")
	}
}
