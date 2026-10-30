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
	"log/slog"
	"net"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// DNSProxyFWMark is the firewall mark applied to the DNS proxy's own upstream
// queries so that the redirect's return rules can exempt them from it.
const DNSProxyFWMark = 0xCA12

// MarkDNSProxySocket is a net Control function (Dialer.Control or
// ListenConfig.Control) that stamps DNSProxyFWMark on the socket, so its
// traffic matches the return exemptions in redirectChains instead of
// being DNAT'd back into the proxy. Every socket cargowall itself uses on
// the port-53 path — the proxy's upstream client, its listeners, and the
// startup stub peek — must carry the mark.
func MarkDNSProxySocket(_, _ string, c syscall.RawConn) error {
	var sErr error
	if err := c.Control(func(fd uintptr) {
		sErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, DNSProxyFWMark)
	}); err != nil {
		return err
	}
	return sErr
}

// RedirectTable names the nftables table (family ip) that holds the whole
// redirect. One table of cargowall's own, rather than rules spliced into
// the host's nat and filter tables, is what makes the redirect atomic: it
// is built in one transaction and deleted in one, so no packet meets half
// of it, and it never touches rules Docker or the host own. It needs only
// the kernel's nf_tables, not an iptables or nft binary, which container
// runner images such as ARC's do not carry.
const RedirectTable = "cargowall"

// bridgeDNATPriority puts the container redirect ahead of Docker's own
// PREROUTING DNAT for published ports, which sits at the standard dstnat
// priority (-100). The first NAT binding a flow gets is the one it keeps.
const bridgeDNATPriority = -101

// redirectChain is one base chain of the redirect table and its rules, in
// order.
type redirectChain struct {
	chain *nftables.Chain
	rules [][]expr.Any
}

// redirectChains is the redirect for traffic this netns originates, plus,
// with a docker bridge IP, for DNS that containers send through a docker
// bridge.
//
// output, the nat hook for locally generated packets:
//   - the DNS proxy's own sockets (DNSProxyFWMark: its upstream client, its
//     listeners, the startup stub peeks) return first, before any DNAT;
//   - the systemd-resolved stub is DNAT'd too: a stub-following client
//     otherwise reaches resolved, which re-queries upstream from its OWN
//     socket, laundering the querying process away from the sockdiag join
//     and serving warm cache hits the proxy never sees;
//   - every other DNS leaving for a non-loopback address goes to the proxy.
//     127.0.0.1, the proxy's listen address, is never DNAT'd.
//
// input, a filter hook: an inbound sport-53 packet off loopback must not
// CREATE a flow. A reply racing the conntrack flush would re-create it
// reversed, with a null NAT binding no later flush can see (design.md, "DNS
// redirect"). Replies on ESTABLISHED entries never match. Loopback is
// exempt: a reversed 127.x entry has loopback addresses on both sides, so it
// can only ever match loopback tuples and never capture a later external
// query, and dropping a stub or proxy reply mid-transaction would cost the
// client its full resolver timeout.
//
// prerouting, only with a bridge IP: DNS arriving on docker0 or a
// user-defined br-* bridge (which also matches bridges created later) goes
// to the proxy's container listener on that IP. That traffic is forwarded,
// not originated here, so the output chain never sees it: a container that
// names its own resolver (--dns, a hard-coded 8.8.8.8, a dockerd whose
// daemon.json cargowall cannot rewrite) would otherwise resolve around the
// proxy. DNAT keeps the source address, so the proxy still attributes the
// query by container IP.
func redirectChains(table *nftables.Table, bridgeIP net.IP) []redirectChain {
	proxy := net.IPv4(127, 0, 0, 1).To4()
	stub := net.IPv4(127, 0, 0, 53).To4()
	output := slices.Concat(
		udpAndTCP(func(proto []expr.Any) []expr.Any {
			return concat(proto, port(dstPort, 53), markIs(DNSProxyFWMark), verdict(expr.VerdictReturn))
		}),
		udpAndTCP(func(proto []expr.Any) []expr.Any {
			return concat(proto, daddr(expr.CmpOpEq, stub), port(dstPort, 53), dnat(proxy, 53))
		}),
		// One byte of the address is the /8: 127.0.0.0/8 is every address
		// whose first byte is 127.
		udpAndTCP(func(proto []expr.Any) []expr.Any {
			return concat(proto, port(dstPort, 53), daddr(expr.CmpOpNeq, []byte{127}), dnat(proxy, 53))
		}),
	)
	input := udpAndTCP(func(proto []expr.Any) []expr.Any {
		return concat(proto, iifname(expr.CmpOpNeq, "lo"), port(srcPort, 53), ctStateNew(), verdict(expr.VerdictDrop))
	})
	chains := []redirectChain{
		{chain: &nftables.Chain{
			Name: "output", Table: table, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest,
		}, rules: output},
		{chain: &nftables.Chain{
			Name: "input", Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter,
		}, rules: input},
	}
	if bridgeIP == nil {
		return chains
	}
	var prerouting [][]expr.Any
	for _, bridge := range [][]expr.Any{iifname(expr.CmpOpEq, "docker0"), iifnamePrefix("br-")} {
		prerouting = append(prerouting, udpAndTCP(func(proto []expr.Any) []expr.Any {
			return concat(bridge, proto, port(dstPort, 53), dnat(bridgeIP, 53))
		})...)
	}
	return append(chains, redirectChain{chain: &nftables.Chain{
		Name: "prerouting", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(bridgeDNATPriority),
	}, rules: prerouting})
}

// Expression helpers. A match loads into register 1 and compares it; dnat
// loads its address into register 1 and its port into register 2.

func concat(parts ...[]expr.Any) []expr.Any { return slices.Concat(parts...) }

// udpAndTCP is rule twice, given the UDP match and then the TCP one: DNS
// rides both.
func udpAndTCP(rule func(proto []expr.Any) []expr.Any) [][]expr.Any {
	return [][]expr.Any{rule(l4proto(unix.IPPROTO_UDP)), rule(l4proto(unix.IPPROTO_TCP))}
}

func l4proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// Offsets of the source and destination ports, which TCP and UDP place
// alike at the head of their headers.
const (
	srcPort = 0
	dstPort = 2
)

func port(offset uint32, p uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(p)},
	}
}

// daddr compares the leading len(addr) bytes of the IPv4 destination, which
// sits 16 bytes into the header, so a byte-aligned prefix is its own bytes.
func daddr(op expr.CmpOp, addr []byte) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: uint32(len(addr))},
		&expr.Cmp{Op: op, Register: 1, Data: addr},
	}
}

func markIs(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
	}
}

// iifname compares the whole interface name, NUL padding included, so
// "lo" does not also match "lo0".
func iifname(op expr.CmpOp, name string) []expr.Any {
	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, name)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: op, Register: 1, Data: padded},
	}
}

// iifnamePrefix compares only the prefix's bytes: nft's "br-*", iptables'
// "br-+".
func iifnamePrefix(prefix string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(prefix)},
	}
}

func ctStateNew() []expr.Any {
	zero := binaryutil.NativeEndian.PutUint32(0)
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW), Xor: zero,
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zero},
	}
}

func dnat(addr net.IP, p uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: addr},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(p)},
		&expr.NAT{
			Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4,
			RegAddrMin: 1, RegProtoMin: 2, Specified: true,
		},
	}
}

func verdict(kind expr.VerdictKind) []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: kind}}
}

// SetupDNSRedirect installs the redirect table (see redirectChains):
// outbound DNS (UDP+TCP port 53) goes to the local proxy at 127.0.0.1:53,
// except the proxy's own marked queries, and the input guard keeps flushed
// flows from being re-picked-up in reverse. A non-empty bridgeIP, where the
// proxy has a container listener, also redirects container DNS crossing a
// docker bridge.
//
// One transaction replaces any table a crashed earlier run left behind
// (add, delete, add: the first add makes the delete safe when there is
// none) and builds the new one, so a failure leaves the host as it was.
func SetupDNSRedirect(logger *slog.Logger, bridgeIP string) error {
	var bridge net.IP
	if bridgeIP != "" {
		if bridge = net.ParseIP(bridgeIP).To4(); bridge == nil {
			return fmt.Errorf("docker bridge IP %q is not an IPv4 address", bridgeIP)
		}
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: RedirectTable}
	conn.AddTable(table)
	conn.DelTable(table)
	conn.AddTable(table)
	for _, c := range redirectChains(table, bridge) {
		conn.AddChain(c.chain)
		for _, exprs := range c.rules {
			conn.AddRule(&nftables.Rule{Table: table, Chain: c.chain, Exprs: exprs})
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables: installing table ip %s: %w", RedirectTable, err)
	}
	logger.Info("DNS redirect installed", "nftables_table", "ip "+RedirectTable, "container_bridge_redirect", bridge != nil)

	// Purge DNS flow state predating the redirect — nat verdicts are
	// per-flow, so those flows would keep bypassing the proxy (see
	// FlushDNSConntrack). The input guard is already in place, so a reply in
	// flight across this flush cannot resurrect a deleted flow in reverse.
	if err := FlushDNSConntrack(logger); err != nil {
		logger.Warn("Failed to flush DNS conntrack entries; pre-existing DNS flows may bypass the proxy until they expire",
			"error", err)
	}
	return nil
}

// resolvedRuntimeDir exists only while systemd-resolved is running. Its
// presence is the signal that tells "resolved not in use" (a quiet skip) apart
// from "resolved running but the flush genuinely failed" (surfaced to the
// caller). A var so tests can point it at a controllable path.
var resolvedRuntimeDir = "/run/systemd/resolve"

// flushResolvedTimeout bounds the resolvectl call so a wedged systemd-resolved
// (or its D-Bus endpoint) cannot stall startup before the eBPF program
// attaches and the firewall begins enforcing. A var so tests can shorten it.
var flushResolvedTimeout = 5 * time.Second

// FlushResolvedCache clears systemd-resolved's DNS cache via
// `resolvectl flush-caches`. Client packets to the stub are DNAT'd to the
// proxy by the redirect (redirectChains), so the residual warm-cache exposure is lookups
// that reach resolved WITHOUT a client DNS packet — nss-resolve's
// D-Bus/varlink path — plus resolved's own upstream re-queries: a warm
// cache hit there is served invisibly, the proxy never sees the name, and
// the connection lands as an unallowed bare IP. Flushing forces those
// lookups upstream, through the redirect.
//
// Best-effort with two quiet skips (return nil, log at Debug): resolvectl not
// installed, or systemd-resolved not running — in both cases there is no stub
// cache to flush and the redirect alone suffices. Everything else is surfaced
// to the caller: a non-not-found lookup error (e.g. a non-executable resolvectl
// on PATH), a non-zero flush exit, or the bounded call timing out.
func FlushResolvedCache(ctx context.Context, logger *slog.Logger) error {
	path, err := exec.LookPath("resolvectl")
	if err != nil {
		// Only genuine not-installed is benign; a permission or other PATH
		// resolution failure is real and must not silently skip the flush.
		if errors.Is(err, exec.ErrNotFound) {
			logger.Debug("resolvectl not found; skipping systemd-resolved cache flush")
			return nil
		}
		return fmt.Errorf("locating resolvectl failed: %w", err)
	}

	// resolvectl can be installed on hosts that don't actually run
	// systemd-resolved (a different resolver is in use); its runtime dir is
	// absent there, so skip quietly rather than warn on every startup. Only a
	// genuine "not there" is benign — a stat failure such as EACCES/EIO is real
	// and surfaced, mirroring the LookPath classification above (otherwise a
	// host where resolved *is* running would be misreported as a correct skip).
	if _, err := os.Stat(resolvedRuntimeDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Debug("systemd-resolved not running; skipping cache flush", "probe", resolvedRuntimeDir)
			return nil
		}
		return fmt.Errorf("probing %s failed: %w", resolvedRuntimeDir, err)
	}

	flushCtx, cancel := context.WithTimeout(ctx, flushResolvedTimeout)
	defer cancel()
	flush := exec.CommandContext(flushCtx, path, "flush-caches")
	// WaitDelay bounds CombinedOutput's Wait after the deadline kills the
	// process: without it, Wait blocks until every inheritor of the stdout/
	// stderr pipes exits, so the timeout would rest on resolvectl never leaving
	// a lingering child holding them.
	flush.WaitDelay = time.Second
	if out, err := flush.CombinedOutput(); err != nil {
		// Name the deadline rather than surfacing a bare "signal: killed".
		if ctxErr := flushCtx.Err(); ctxErr != nil {
			return fmt.Errorf("resolvectl flush-caches timed out after %s: %w", flushResolvedTimeout, ctxErr)
		}
		return fmt.Errorf("resolvectl flush-caches failed: %w (output: %s)", err, out)
	}
	logger.Info("Flushed systemd-resolved DNS cache")
	return nil
}

// TeardownDNSRedirect deletes the redirect table, every chain of it in one
// transaction. A table that is not there means nothing was installed
// (teardown registers before a setup that may fail or never run): there is
// no flow state of ours to flush, so the host's DNS state is left alone.
func TeardownDNSRedirect(logger *slog.Logger) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: RedirectTable})
	if err := conn.Flush(); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("nftables: deleting table ip %s: %w", RedirectTable, err)
	}
	logger.Info("DNS redirect removed")

	// Purge flows still DNAT'd to the now-dead proxy, so client DNS recovers
	// immediately instead of at conntrack expiry (see FlushDNSConntrack).
	if err := FlushDNSConntrack(logger); err != nil {
		logger.Warn("Failed to flush DNS conntrack entries on teardown; client DNS may stall until entries expire",
			"error", err)
	}
	return nil
}
