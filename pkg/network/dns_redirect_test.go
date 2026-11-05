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
	"slices"
	"testing"
	"time"
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

// TestContainerDNSRedirectRules: DNS arriving on docker0, over UDP and TCP,
// is sent to the bridge listener unless it is for docker0's own subnet or
// this host; DNS arriving on any br-* bridge is sent there when it is for
// the proxy's upstream, or for a public resolver other than this host.
func TestContainerDNSRedirectRules(t *testing.T) {
	notLocal := []string{"-m", "addrtype", "!", "--dst-type", "LOCAL"}
	dnat := []string{"-j", "DNAT", "--to-destination", "172.17.0.1:53"}
	private := []string{
		"-m", "iprange", "!", "--dst-range", "10.0.0.0-10.255.255.255",
		"-m", "iprange", "!", "--dst-range", "172.16.0.0-172.31.255.255",
		"-m", "iprange", "!", "--dst-range", "192.168.0.0-192.168.255.255",
	}
	rule := func(parts ...[]string) []string { return slices.Concat(parts...) }
	want := [][]string{
		rule([]string{"-t", "nat", "-i", "docker0", "-p", "udp", "--dport", "53", "!", "-d", "172.17.0.0/16"}, notLocal, dnat),
		rule([]string{"-t", "nat", "-i", "docker0", "-p", "tcp", "--dport", "53", "!", "-d", "172.17.0.0/16"}, notLocal, dnat),
		rule([]string{"-t", "nat", "-i", "br-+", "-p", "udp", "--dport", "53", "-d", "10.0.0.10"}, dnat),
		rule([]string{"-t", "nat", "-i", "br-+", "-p", "tcp", "--dport", "53", "-d", "10.0.0.10"}, dnat),
		rule([]string{"-t", "nat", "-i", "br-+", "-p", "udp", "--dport", "53"}, private, notLocal, dnat),
		rule([]string{"-t", "nat", "-i", "br-+", "-p", "tcp", "--dport", "53"}, private, notLocal, dnat),
	}
	c := ContainerDNS{
		Bridge:    &net.IPNet{IP: net.IPv4(172, 17, 0, 1).To4(), Mask: net.CIDRMask(16, 32)},
		Upstreams: []net.IP{net.IPv4(10, 0, 0, 10).To4()},
	}
	if got := containerDNSRedirectRules(c); !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("containerDNSRedirectRules = %q, want %q", got, want)
	}
}
