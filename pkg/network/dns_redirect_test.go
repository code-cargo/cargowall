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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
// nat chains run ahead of dstnat, prerouting exists only with a container
// listener, and IPv6 rules exist only with ipv6. The container listeners'
// addresses are guarded elsewhere (guardChains), so input holds the sport-53
// guard alone.
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

	chains := redirectChains(false, containerListeners{})
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

	chains = redirectChains(true, containerListeners{})
	if returns, dnats, _, order := kinds(chains[0].rules); returns != 2 || dnats != 8 || order != "RRNNNNNNNN" {
		t.Errorf("IPv6 output rules = %q, want the 2 mark returns ahead of 8 DNATs", order)
	}
	for _, rule := range chains[0].rules[8:] {
		if !target(rule).Equal(net.IPv6loopback) {
			t.Errorf("an IPv6 output DNAT does not send to the proxy at ::1: %+v", rule[len(rule)-3])
		}
	}
	if len(chains[1].rules) != 2 {
		t.Error("the input guard reads no address, so its 2 rules guard IPv6 as they are")
	}

	both := containerListeners{v4: net.IP(ContainerDNSIPv4.AsSlice()), v6: net.IP(ContainerDNSIPv6.AsSlice())}
	chains = redirectChains(false, both)
	if len(chains) != 3 || chains[2].name != "prerouting" || chains[2].priority != -101 {
		t.Fatalf("with a container listener want prerouting at -101 third, and no other chain, got %+v", chains)
	}
	if _, dnats, drops, _ := kinds(chains[2].rules); dnats != 4 || drops != 0 {
		t.Errorf("prerouting has %d DNATs and %d drops, want 4 DNATs (docker0 and br-*, UDP and TCP) and no IPv6 "+
			"in an ip table", dnats, drops)
	}
	for _, rule := range chains[2].rules {
		if !target(rule).Equal(both.v4) {
			t.Errorf("a prerouting DNAT does not send to the IPv4 container listener: %+v", rule[len(rule)-3])
		}
	}
	if _, _, drops, order := kinds(chains[1].rules); drops != 2 || order != "DD" {
		t.Errorf("input rules = %q, want the 2 sport-53 guards alone", order)
	}

	chains = redirectChains(true, both)
	if _, _, drops, order := kinds(chains[2].rules); order != "NNNNNNNN" || drops != 0 {
		t.Errorf("IPv6 prerouting rules = %q, want 4 IPv4 DNATs, then 4 IPv6 ones, and no drop", order)
	}
	for i, rule := range chains[2].rules[4:] {
		if !target(rule).Equal(both.v6) {
			t.Errorf("IPv6 prerouting rule %d does not send to the IPv6 container listener: %+v", i, rule[len(rule)-3])
		}
	}
	if len(chains) != 3 || len(chains[1].rules) != 2 {
		t.Errorf("with both listeners want output, input with its 2 guards, and prerouting, got %+v", chains)
	}

	// A family whose listener the proxy does not hold gets no rule at all,
	// neither a DNAT nor a drop.
	chains = redirectChains(true, containerListeners{v6: both.v6})
	if _, dnats, drops, _ := kinds(chains[2].rules); dnats != 4 || drops != 0 {
		t.Errorf("with the IPv6 listener alone prerouting has %d DNATs and %d drops, want its 4 DNATs", dnats, drops)
	}
	if chains = redirectChains(false, containerListeners{v6: both.v6}); len(chains) != 2 {
		t.Errorf("an ip table has no IPv6 to redirect, so the IPv6 listener alone adds no chain, got %+v", chains)
	}
}

// A container DNS address's guard, in a table of its family: input drops a
// packet for it arriving on anything but lo or a docker bridge, forward
// drops any packet for it, and neither reads the family, which the table
// is.
func TestGuardChains(t *testing.T) {
	ifnames := func(rule []expr.Any) (names []string, ops []expr.CmpOp) {
		for i, e := range rule {
			if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyIIFNAME {
				cmp := rule[i+1].(*expr.Cmp)
				names = append(names, string(bytes.TrimRight(cmp.Data, "\x00")))
				ops = append(ops, cmp.Op)
			}
		}
		return names, ops
	}
	daddrOf := func(rule []expr.Any) (net.IP, uint32) {
		for i, e := range rule {
			if p, ok := e.(*expr.Payload); ok && p.Base == expr.PayloadBaseNetworkHeader {
				return net.IP(rule[i+1].(*expr.Cmp).Data), p.Offset
			}
		}
		return nil, 0
	}
	for _, c := range []struct {
		addr   netip.Addr
		offset uint32 // the destination's, in the family's header
	}{{ContainerDNSIPv4, 16}, {ContainerDNSIPv6, 24}} {
		chains := guardChains(c.addr)
		if len(chains) != 2 || chains[0].name != "input" || chains[0].hook != unix.NF_INET_LOCAL_IN ||
			chains[1].name != "forward" || chains[1].hook != unix.NF_INET_FORWARD {
			t.Fatalf("%s: want input and forward chains, got %+v", c.addr, chains)
		}
		want := net.IP(c.addr.AsSlice())
		for _, ch := range chains {
			if len(ch.rules) != 1 || ch.kind != "filter" {
				t.Fatalf("%s: %s wants one filter rule, got %+v", c.addr, ch.name, ch)
			}
			rule := ch.rules[0]
			if got, offset := daddrOf(rule); !got.Equal(want) || offset != c.offset {
				t.Errorf("%s: %s matches %s at %d, want %s at %d", c.addr, ch.name, got, offset, want, c.offset)
			}
			if v, ok := rule[len(rule)-1].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
				t.Errorf("%s: %s does not drop", c.addr, ch.name)
			}
			for _, e := range rule {
				if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyNFPROTO {
					t.Errorf("%s: %s matches nfproto, which its table's family settles", c.addr, ch.name)
				}
			}
		}
		names, ops := ifnames(chains[0].rules[0])
		if !slices.Equal(names, []string{"lo", "docker0", "br-"}) ||
			!slices.Equal(ops, []expr.CmpOp{expr.CmpOpNeq, expr.CmpOpNeq, expr.CmpOpNeq}) {
			t.Errorf("%s: input matches %v %v, want != lo, docker0, br-*", c.addr, names, ops)
		}
		if names, _ := ifnames(chains[1].rules[0]); len(names) != 0 {
			t.Errorf("%s: forward is limited to %v, want every interface", c.addr, names)
		}
	}
}

// With ipv6 the table is inet, and every rule that reads an address,
// rewrites to one, or acts on one family alone first matches the packet's
// family: there an IPv4 offset read on an IPv6 packet compares bytes of its
// source address instead. An ip table's packets are all IPv4, and its rules
// carry no such match.
func TestRedirectChains_FamilyGated(t *testing.T) {
	both := containerListeners{v4: net.IP(ContainerDNSIPv4.AsSlice()), v6: net.IP(ContainerDNSIPv6.AsSlice())}
	for _, c := range redirectChains(true, both) {
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
	for _, c := range redirectChains(false, both) {
		for i, rule := range c.rules {
			for _, e := range rule {
				if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyNFPROTO {
					t.Errorf("ip table %s rule %d matches nfproto, which is always IPv4 there", c.name, i)
				}
			}
		}
	}
}

// dnat writes an IPv4 address in its 4 bytes and family whatever form it is
// held in: net.ParseIP returns 16.
func TestDNAT_FamilyFromAddress(t *testing.T) {
	for _, c := range []struct {
		addr   net.IP
		family uint32
		len    int
	}{
		{net.ParseIP("172.17.0.1"), unix.NFPROTO_IPV4, net.IPv4len},
		{net.IPv4(127, 0, 0, 1).To4(), unix.NFPROTO_IPV4, net.IPv4len},
		{net.IPv6loopback, unix.NFPROTO_IPV6, net.IPv6len},
	} {
		exprs := dnat(c.addr, 53)
		if got := exprs[0].(*expr.Immediate).Data; len(got) != c.len {
			t.Errorf("dnat(%s) writes %d address bytes, want %d", c.addr, len(got), c.len)
		}
		if got := exprs[2].(*expr.NAT).Family; got != c.family {
			t.Errorf("dnat(%s) family %d, want %d", c.addr, got, c.family)
		}
	}
}
