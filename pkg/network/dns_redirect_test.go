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
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables/expr"
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

// TestMarkDNSProxySocket_SetsMark: a dialer using MarkDNSProxySocket must
// carry DNSProxyFWMark, or the stub DNAT would loop cargowall's own stub
// peeks (cacheResolver) back into the proxy. Root-only: SO_MARK needs
// CAP_NET_ADMIN, and the sudo'd pkg/network test pass in CI provides it.
func TestMarkDNSProxySocket_SetsMark(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SO_MARK requires CAP_NET_ADMIN; covered by the sudo test pass")
	}
	d := &net.Dialer{Control: MarkDNSProxySocket}
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

// TestInstallHint: under an enforcing policy an install error is the reason
// startup failed, so the errnos nf_tables answers with name what is missing.
func TestInstallHint(t *testing.T) {
	for errno, want := range map[unix.Errno]string{
		unix.EPERM:           "another process owns the table",
		unix.EPROTONOSUPPORT: "CONFIG_NETFILTER_NETLINK",
		unix.EOPNOTSUPP:      "CONFIG_NF_TABLES",
		unix.ENOENT:          "nft_chain_nat",
	} {
		if got := installHint(fmt.Errorf("netlink receive: %w", errno)); !strings.Contains(got, want) {
			t.Errorf("installHint(%v) = %q, want it to name %q", errno, got, want)
		}
	}
	if got := installHint(errors.New("other")); got != "" {
		t.Errorf("installHint(other) = %q, want none", got)
	}
}

// TestRedirectChains_Order pins each chain's rule order and targets: the
// mark returns come ahead of every DNAT, every DNAT sends to the proxy, the
// nat chains run ahead of dstnat, prerouting exists only with a bridge
// listener, and IPv6 rules exist only with ipv6.
func TestRedirectChains_Order(t *testing.T) {
	kinds := func(rules [][]expr.Any) (returns, dnats, drops int, order string) {
		for _, rule := range rules {
			switch last := rule[len(rule)-1].(type) {
			case *expr.Verdict:
				if last.Kind == expr.VerdictReturn {
					returns++
					order += "R"
				} else if last.Kind == expr.VerdictDrop {
					drops++
					order += "D"
				}
			case *expr.NAT:
				dnats++
				order += "N"
			}
		}
		return returns, dnats, drops, order
	}
	target := func(rule []expr.Any) net.IP { return net.IP(rule[len(rule)-3].(*expr.Immediate).Data) }

	chains := redirectChains(false, nil, nil)
	if len(chains) != 2 || chains[0].name != "output" || chains[1].name != "input" {
		t.Fatalf("without a bridge want output and input chains, got %+v", chains)
	}
	if returns, dnats, _, order := kinds(chains[0].rules); returns != 2 || dnats != 6 || order != "RRNNNNNN" {
		t.Errorf("output rules = %q, want the 2 mark returns ahead of the 6 DNATs", order)
	}
	if _, _, drops, order := kinds(chains[1].rules); drops != 2 || order != "DD" {
		t.Errorf("input rules = %q, want 2 drops", order)
	}
	if chains[0].priority != -101 || chains[1].priority != 0 {
		t.Errorf("priorities output %d input %d, want -101 (ahead of dstnat) and 0", chains[0].priority, chains[1].priority)
	}
	for _, rule := range chains[0].rules[2:] {
		if !target(rule).Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("an output DNAT does not send to the proxy at 127.0.0.1: %+v", rule[len(rule)-3])
		}
	}

	chains = redirectChains(true, nil, nil)
	if returns, dnats, _, order := kinds(chains[0].rules); returns != 2 || dnats != 8 || order != "RRNNNNNNNN" {
		t.Errorf("IPv6 output rules = %q, want the 2 mark returns ahead of 8 DNATs", order)
	}
	for _, rule := range chains[0].rules[8:] {
		if !target(rule).Equal(net.IPv6loopback) {
			t.Errorf("an IPv6 output DNAT does not send to the proxy at ::1: %+v", rule[len(rule)-3])
		}
	}
	if len(redirectChains(true, nil, nil)[1].rules) != 2 {
		t.Error("the input guard reads no address, so its 2 rules guard IPv6 as they are")
	}

	bridge := net.IPv4(172, 17, 0, 1).To4()
	bridge6 := net.ParseIP("fd00:17::1")
	chains = redirectChains(false, bridge, bridge6)
	if len(chains) != 3 || chains[2].name != "prerouting" || chains[2].priority != -101 {
		t.Fatalf("with a bridge want a prerouting chain at -101 third, got %+v", chains)
	}
	if _, dnats, _, _ := kinds(chains[2].rules); dnats != 4 {
		t.Errorf("prerouting has %d DNATs, want 4 (docker0 and br-*, UDP and TCP): no IPv6 without ipv6", dnats)
	}
	for _, rule := range chains[2].rules {
		if !target(rule).Equal(bridge) {
			t.Errorf("a prerouting DNAT does not send to the bridge listener: %+v", rule[len(rule)-3])
		}
	}
	chains = redirectChains(true, bridge, bridge6)
	if _, dnats, _, _ := kinds(chains[2].rules); dnats != 8 {
		t.Errorf("IPv6 prerouting has %d DNATs, want 8", dnats)
	}
	for _, rule := range chains[2].rules[4:] {
		if !target(rule).Equal(bridge6) {
			t.Errorf("an IPv6 prerouting DNAT does not send to the bridge's IPv6 listener: %+v", rule[len(rule)-3])
		}
	}
	if chains = redirectChains(true, nil, bridge6); len(chains) != 3 || len(chains[2].rules) != 4 {
		t.Errorf("an IPv6 bridge listener alone still gets its prerouting rules, got %+v", chains)
	}
}

// Every rule that reads an address or rewrites to one first matches the
// packet's family: in an inet table, an IPv4 offset read on an IPv6 packet
// compares bytes of its source address instead.
func TestRedirectChains_FamilyGated(t *testing.T) {
	for _, c := range redirectChains(true, net.IPv4(172, 17, 0, 1).To4(), net.ParseIP("fd00:17::1")) {
		for i, rule := range c.rules {
			var want byte
			for _, e := range rule {
				switch e := e.(type) {
				case *expr.Payload:
					if e.Base == expr.PayloadBaseNetworkHeader {
						want = unix.NFPROTO_IPV4
						if e.Len == net.IPv6len {
							want = unix.NFPROTO_IPV6
						}
					}
				case *expr.NAT:
					want = byte(e.Family)
				}
			}
			if want == 0 {
				continue
			}
			meta, ok := rule[0].(*expr.Meta)
			cmp, ok2 := rule[1].(*expr.Cmp)
			if !ok || !ok2 || meta.Key != expr.MetaKeyNFPROTO || len(cmp.Data) != 1 || cmp.Data[0] != want {
				t.Errorf("%s rule %d is not gated on family %d first: %+v", c.name, i, want, rule[:2])
			}
		}
	}
}
