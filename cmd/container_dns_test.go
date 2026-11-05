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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeProxy answers WaitListening with err and records the address asked.
type fakeProxy struct {
	err   error
	asked []string
}

func (p *fakeProxy) WaitListening(_ context.Context, addr string) error {
	p.asked = append(p.asked, addr)
	return p.err
}

// TestRedirectContainerDNS_NoBridge: with no Docker bridge there is nothing
// to wait for and nothing installed.
func TestRedirectContainerDNS_NoBridge(t *testing.T) {
	proxy := &fakeProxy{}
	teardowns := &teardownList{}
	undo := redirectContainerDNS(context.Background(), proxy, "", "", teardowns, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.Nil(t, undo)
	require.Empty(t, proxy.asked)
	require.Empty(t, teardowns.fns)
}

// TestRedirectContainerDNS_ListenerNotHeld: when the proxy does not hold the
// bridge listener, no redirect is installed (and none is registered for
// teardown), so container DNS is never handed to whatever holds the address.
func TestRedirectContainerDNS_ListenerNotHeld(t *testing.T) {
	proxy := &fakeProxy{err: errors.New("address already in use")}
	teardowns := &teardownList{}
	undo := redirectContainerDNS(context.Background(), proxy, "172.17.0.1", "", teardowns, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.Nil(t, undo)
	require.Equal(t, []string{"172.17.0.1:53"}, proxy.asked, "the wait must name the address the proxy was asked to listen on")
	require.Empty(t, teardowns.fns)
}

// fakeIptables puts an iptables first on PATH that records its arguments,
// one call per line, in the returned file, and fails its failOn'th call
// (counting from 1; 0 never fails).
func fakeIptables(t *testing.T, failOn int) string {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %q
n=$(wc -l < %q)
[ "$n" -eq %d ] && exit 1
exit 0
`, calls, calls, failOn)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "iptables"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return calls
}

func readCalls(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// standInBridge makes docker0 172.17.0.1/16 for the test.
func standInBridge(t *testing.T) {
	t.Helper()
	prev := dockerBridgeNet
	dockerBridgeNet = func(ip string) (*net.IPNet, error) {
		return &net.IPNet{IP: net.ParseIP(ip).To4(), Mask: net.CIDRMask(16, 32)}, nil
	}
	t.Cleanup(func() { dockerBridgeNet = prev })
}

// TestRedirectContainerDNS_UndoCoversPartialInstall: the undo is registered
// before the rules go in, so when the install fails partway the rules it
// did add are still removed, by the returned undo and by the forced
// teardown alike.
func TestRedirectContainerDNS_UndoCoversPartialInstall(t *testing.T) {
	standInBridge(t)
	calls := fakeIptables(t, 2) // the second rule fails
	teardowns := &teardownList{}
	undo := redirectContainerDNS(context.Background(), &fakeProxy{}, "172.17.0.1", "10.0.0.10:53", teardowns,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NotNil(t, undo, "a failed install still needs its undo")
	require.Len(t, teardowns.fns, 1, "the undo must be registered for the forced teardown too")
	require.Len(t, readCalls(t, calls), 2, "the install stops at the failing rule")

	teardowns.forceAll()
	var deletes []string
	for _, call := range readCalls(t, calls) {
		if strings.HasPrefix(call, "-D PREROUTING ") {
			deletes = append(deletes, call)
		}
	}
	require.Len(t, deletes, 6, "the undo deletes every rule, the one that went in included")
	require.Contains(t, deletes[0], "-i docker0 -p udp --dport 53 ! -d 172.17.0.0/16")
	require.Contains(t, deletes[2], "-i br-+ -p udp --dport 53 -d 10.0.0.10 ")
}

// TestRedirectContainerDNS_Installs: with the listener held, the rules go in
// once, redirecting to the bridge listener and the upstream, and the undo
// takes them out.
func TestRedirectContainerDNS_Installs(t *testing.T) {
	standInBridge(t)
	calls := fakeIptables(t, 0)
	teardowns := &teardownList{}
	undo := redirectContainerDNS(context.Background(), &fakeProxy{}, "172.17.0.1", "10.0.0.10", teardowns,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NotNil(t, undo)
	installed := readCalls(t, calls)
	require.Len(t, installed, 6)
	for _, call := range installed {
		require.True(t, strings.HasPrefix(call, "-A PREROUTING -t nat "), call)
		require.True(t, strings.HasSuffix(call, "-j DNAT --to-destination 172.17.0.1:53"), call)
	}

	undo()
	undo() // once only, like every registered undo
	require.Len(t, readCalls(t, calls), 12, "six deletes after six adds")
}

// TestRedirectContainerDNS_ShutdownDuringWait: a shutdown signal while
// waiting for the listener installs nothing.
func TestRedirectContainerDNS_ShutdownDuringWait(t *testing.T) {
	calls := fakeIptables(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	teardowns := &teardownList{}
	undo := redirectContainerDNS(ctx, waitingProxy{}, "172.17.0.1", "10.0.0.10", teardowns,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.Nil(t, undo)
	require.Empty(t, teardowns.fns)
	require.Empty(t, readCalls(t, calls))
}

// waitingProxy never settles: its wait ends only with the context.
type waitingProxy struct{}

func (waitingProxy) WaitListening(ctx context.Context, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestUpstreamIPv4: only a non-loopback IPv4 upstream, with or without a
// port, is an address containers could ask.
func TestUpstreamIPv4(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.10:53":       "10.0.0.10",
		"168.63.129.16":      "168.63.129.16",
		"127.0.0.53:53":      "",
		"[2001:db8::1]:53":   "",
		"dns.example.com:53": "",
		"":                   "",
	} {
		got := upstreamIPv4(in)
		if want == "" {
			require.Empty(t, got, in)
			continue
		}
		require.Len(t, got, 1, in)
		require.Equal(t, want, got[0].String(), in)
	}
}
