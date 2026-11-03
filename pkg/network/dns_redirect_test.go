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

// A container DNS address's guard, in a table of its family: input drops
// what arrives for it on an uplink, admits it on docker0, br-* and any
// bridge, and drops it on anything else but lo; forward drops any packet for it; and neither reads
// the family, which the table is. The IPv4 address's arp table admits a
// request for it the same way.
func TestGuardChains(t *testing.T) {
	uplinks := []string{"eth0", "br0"}
	type ifmatch struct {
		key  expr.MetaKey
		op   expr.CmpOp
		name string
	}
	ifmatches := func(rule []expr.Any) (out []ifmatch) {
		for i, e := range rule {
			if m, ok := e.(*expr.Meta); ok && (m.Key == expr.MetaKeyIIFNAME || m.Key == metaKeyIIFKIND) {
				cmp := rule[i+1].(*expr.Cmp)
				out = append(out, ifmatch{m.Key, cmp.Op, string(bytes.TrimRight(cmp.Data, "\x00"))})
			}
		}
		return out
	}
	payload := func(rule []expr.Any, offset uint32) []byte {
		for i, e := range rule {
			if p, ok := e.(*expr.Payload); ok && p.Base == expr.PayloadBaseNetworkHeader && p.Offset == offset {
				return rule[i+1].(*expr.Cmp).Data
			}
		}
		return nil
	}
	lastVerdict := func(rule []expr.Any) expr.VerdictKind {
		if v, ok := rule[len(rule)-1].(*expr.Verdict); ok {
			return v.Kind
		}
		return -100
	}
	// admits checks rules against admitted's order: each uplink dropped,
	// docker0, br-* and any bridge accepted, then anything but lo dropped.
	admits := func(t *testing.T, what string, rules [][]expr.Any) {
		t.Helper()
		want := []struct {
			match   ifmatch
			verdict expr.VerdictKind
		}{
			{ifmatch{expr.MetaKeyIIFNAME, expr.CmpOpEq, "eth0"}, expr.VerdictDrop},
			{ifmatch{expr.MetaKeyIIFNAME, expr.CmpOpEq, "br0"}, expr.VerdictDrop},
			{ifmatch{expr.MetaKeyIIFNAME, expr.CmpOpEq, "docker0"}, expr.VerdictAccept},
			{ifmatch{expr.MetaKeyIIFNAME, expr.CmpOpEq, "br-"}, expr.VerdictAccept},
			{ifmatch{metaKeyIIFKIND, expr.CmpOpEq, "bridge"}, expr.VerdictAccept},
			{ifmatch{expr.MetaKeyIIFNAME, expr.CmpOpNeq, "lo"}, expr.VerdictDrop},
		}
		if len(rules) != len(want) {
			t.Fatalf("%s: %d rules, want %d", what, len(rules), len(want))
		}
		for i, w := range want {
			if got := ifmatches(rules[i]); len(got) != 1 || got[0] != w.match || lastVerdict(rules[i]) != w.verdict {
				t.Errorf("%s rule %d matches %+v with verdict %d, want %+v and %d", what, i, got,
					lastVerdict(rules[i]), w.match, w.verdict)
			}
		}
	}
	for _, c := range []struct {
		addr   netip.Addr
		offset uint32 // the destination's, in the family's header
	}{{ContainerDNSIPv4, 16}, {ContainerDNSIPv6, 24}} {
		chains := guardChains(c.addr, uplinks)
		if len(chains) != 2 || chains[0].name != "input" || chains[0].hook != unix.NF_INET_LOCAL_IN ||
			chains[1].name != "forward" || chains[1].hook != unix.NF_INET_FORWARD {
			t.Fatalf("%s: want input and forward chains, got %+v", c.addr, chains)
		}
		want := net.IP(c.addr.AsSlice())
		for _, ch := range chains {
			if ch.kind != "filter" {
				t.Errorf("%s: %s is a %s chain, want filter", c.addr, ch.name, ch.kind)
			}
			for i, rule := range ch.rules {
				if got := net.IP(payload(rule, c.offset)); !got.Equal(want) {
					t.Errorf("%s: %s rule %d matches %s, want %s", c.addr, ch.name, i, got, want)
				}
				for _, e := range rule {
					if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyNFPROTO {
						t.Errorf("%s: %s matches nfproto, which its table's family settles", c.addr, ch.name)
					}
				}
			}
		}
		admits(t, c.addr.String()+" input", chains[0].rules)
		if fwd := chains[1].rules; len(fwd) != 1 || len(ifmatches(fwd[0])) != 0 || lastVerdict(fwd[0]) != expr.VerdictDrop {
			t.Errorf("%s: forward wants one drop on every interface, got %+v", c.addr, fwd)
		}
	}

	arp := arpChains(ContainerDNSIPv4, uplinks)
	if len(arp) != 1 || arp[0].name != "input" || arp[0].hook != nfARPIn || arp[0].kind != "filter" {
		t.Fatalf("want one arp input filter chain, got %+v", arp)
	}
	for i, rule := range arp[0].rules {
		if got := payload(rule, 24); !net.IP(got).Equal(net.IP(ContainerDNSIPv4.AsSlice())) {
			t.Errorf("arp rule %d matches target %v, want %s", i, got, ContainerDNSIPv4)
		}
		if got := payload(rule, 6); !bytes.Equal(got, []byte{0, 1}) {
			t.Errorf("arp rule %d matches operation %v, want a request", i, got)
		}
		if got := payload(rule, 4); !bytes.Equal(got, []byte{6, 4}) {
			t.Errorf("arp rule %d matches hlen and plen %v, want Ethernet and IPv4", i, got)
		}
	}
	admits(t, "arp input", arp[0].rules)
}

// An uplink that is a Docker bridge, docker0 or br-*, is warned about once
// at startup, naming it: the guard drops its containers' DNS to the owned
// addresses. Other bridges, such as Proxmox's vmbr0, are not.
func TestOwnedAddrs_DockerBridgeUplinkWarned(t *testing.T) {
	for _, c := range []struct {
		uplinks []string
		warned  []string
	}{
		{uplinks: []string{"eth0", "vmbr0", "br0", "bond0"}},
		{uplinks: []string{"eth0", "docker0"}, warned: []string{"docker0"}},
		{uplinks: []string{"br-1a2b3c", "eno1", "br-ex"}, warned: []string{"br-1a2b3c", "br-ex"}},
	} {
		var buf bytes.Buffer
		NewOwnedAddrs(netip.Addr{}, c.uplinks, slog.New(slog.NewTextHandler(&buf, nil)))
		if got := strings.Count(buf.String(), "level=WARN"); got != len(c.warned) {
			t.Errorf("uplinks %v: %d warnings, want %d:\n%s", c.uplinks, got, len(c.warned), buf.String())
		}
		for _, name := range c.warned {
			if !strings.Contains(buf.String(), "bridge="+name) {
				t.Errorf("uplinks %v: no warning names %s:\n%s", c.uplinks, name, buf.String())
			}
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
