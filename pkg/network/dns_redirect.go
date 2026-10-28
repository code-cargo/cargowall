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

	"golang.org/x/sys/unix"
)

// DNSProxyFWMark is the firewall mark applied to the DNS proxy's own upstream
// queries so that iptables RETURN rules can exempt them from redirection.
const DNSProxyFWMark = 0xCA12

// MarkDNSProxySocket is a net Control function (Dialer.Control or
// ListenConfig.Control) that stamps DNSProxyFWMark on the socket, so its
// traffic matches the RETURN exemptions in hostDNSRedirectRules instead of
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

// dnsProxyFWMarkStr is the hex string representation used in iptables rules.
var dnsProxyFWMarkStr = fmt.Sprintf("0x%X", DNSProxyFWMark)

// dnsRedirectRule is one iptables rule of the redirect: the chain it lives
// in plus its match/target arguments. An insert rule goes to the head of
// its chain instead of the tail.
type dnsRedirectRule struct {
	chain  string
	args   []string
	insert bool
}

// hostDNSRedirectRules are the redirect for traffic this netns originates.
// Order matters: RETURN rules for marked packets must come before DNAT
// rules, and teardown deletes in REVERSE so the exemptions outlive the
// DNAT they exempt from.
var hostDNSRedirectRules = []dnsRedirectRule{
	// Exempt the CargoWall DNS proxy's upstream queries (marked with DNSProxyFWMark)
	{chain: "OUTPUT", args: []string{"-t", "nat", "-p", "udp", "--dport", "53", "-m", "mark", "--mark", dnsProxyFWMarkStr, "-j", "RETURN"}},
	{chain: "OUTPUT", args: []string{"-t", "nat", "-p", "tcp", "--dport", "53", "-m", "mark", "--mark", dnsProxyFWMarkStr, "-j", "RETURN"}},
	// DNAT the systemd-resolved stub too: a stub-following client otherwise
	// reaches resolved, which re-queries upstream from its OWN socket —
	// laundering the querying process away from the sockdiag join and
	// serving warm cache hits the proxy never sees. Marked stub peeks are
	// exempted above; 127.0.0.1 (the proxy listen) stays un-DNATed.
	{chain: "OUTPUT", args: []string{"-t", "nat", "-p", "udp", "-d", "127.0.0.53", "--dport", "53", "-j", "DNAT", "--to-destination", "127.0.0.1:53"}},
	{chain: "OUTPUT", args: []string{"-t", "nat", "-p", "tcp", "-d", "127.0.0.53", "--dport", "53", "-j", "DNAT", "--to-destination", "127.0.0.1:53"}},
	// Redirect all other outbound DNS to the local proxy
	{chain: "OUTPUT", args: []string{"-t", "nat", "-p", "udp", "--dport", "53", "!", "-d", "127.0.0.0/8", "-j", "DNAT", "--to-destination", "127.0.0.1:53"}},
	{chain: "OUTPUT", args: []string{"-t", "nat", "-p", "tcp", "--dport", "53", "!", "-d", "127.0.0.0/8", "-j", "DNAT", "--to-destination", "127.0.0.1:53"}},
	// Reverse-direction guard: an inbound sport-53 packet must not CREATE a
	// flow — a reply racing the conntrack flush would re-create it reversed,
	// with a null NAT binding no later flush can see (design.md, "DNS
	// redirect"). Replies on ESTABLISHED entries never match. Loopback is
	// exempt: a reversed 127.x entry has loopback addresses on both sides,
	// so it can only ever match loopback tuples — it can never capture a
	// later external-resolver query, even now that stub-destined lo traffic
	// IS DNAT'd — and dropping a stub or proxy reply mid-transaction would
	// cost the client its full resolver timeout.
	{chain: "INPUT", args: []string{"-p", "udp", "!", "-i", "lo", "--sport", "53", "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"}},
	{chain: "INPUT", args: []string{"-p", "tcp", "!", "-i", "lo", "--sport", "53", "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"}},
}

// dnsRedirectRules is the full redirect. With a docker bridge IP it adds
// PREROUTING DNAT for DNS that containers send through a docker bridge,
// default (docker0) or user-defined (br-+, which also matches bridges
// created later), to the proxy's container listener on that IP. That
// traffic is forwarded, not originated here, so the OUTPUT rules never
// see it: a container that names its own resolver (--dns, a hard-coded
// 8.8.8.8, a dockerd whose daemon.json cargowall cannot rewrite) would
// otherwise resolve around the proxy. DNAT keeps the source address, so
// the proxy still attributes the query by container IP. The rules go to
// the head of PREROUTING, ahead of Docker's own DNAT for published ports.
func dnsRedirectRules(bridgeIP string) []dnsRedirectRule {
	if bridgeIP == "" {
		return hostDNSRedirectRules
	}
	to := net.JoinHostPort(bridgeIP, "53")
	rules := slices.Clone(hostDNSRedirectRules)
	for _, iface := range []string{"docker0", "br-+"} {
		for _, proto := range []string{"udp", "tcp"} {
			rules = append(rules, dnsRedirectRule{
				chain:  "PREROUTING",
				args:   []string{"-t", "nat", "-i", iface, "-p", proto, "--dport", "53", "-j", "DNAT", "--to-destination", to},
				insert: true,
			})
		}
	}
	return rules
}

// SetupDNSRedirect adds iptables DNAT rules to redirect all outbound DNS
// (UDP+TCP port 53) to the local proxy at 127.0.0.1:53, plus the INPUT
// guard that keeps flushed flows from being re-picked-up in reverse.
// Packets marked with DNSProxyFWMark (the DNS proxy's upstream queries) are exempted.
// A non-empty bridgeIP, where the proxy has a container listener, also
// redirects container DNS crossing a docker bridge (see dnsRedirectRules);
// teardown must be given the same bridgeIP.
func SetupDNSRedirect(logger *slog.Logger, bridgeIP string) error {
	for _, rule := range dnsRedirectRules(bridgeIP) {
		op := "-A"
		if rule.insert {
			op = "-I"
		}
		args := append([]string{op, rule.chain}, rule.args...)
		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %s %s %v failed: %w (output: %s)", op, rule.chain, rule.args, err, out)
		}
	}
	logger.Info("DNS redirect iptables rules installed", "container_bridge_redirect", bridgeIP != "")

	// Purge DNS flow state predating the rules — nat verdicts are per-flow,
	// so those flows would keep bypassing the proxy (see FlushDNSConntrack).
	// The INPUT guard above is already in place, so a reply in flight
	// across this flush cannot resurrect a deleted flow in reverse.
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
// proxy by hostDNSRedirectRules, so the residual warm-cache exposure is lookups
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

// TeardownDNSRedirect removes the iptables rules added by SetupDNSRedirect,
// in reverse install order so the mark RETURN exemptions outlive the DNAT
// rules they exempt the proxy's own upstream queries from — deleting in
// install order would leave a two-exec window where the proxy's queries
// DNAT back onto itself.
func TeardownDNSRedirect(logger *slog.Logger, bridgeIP string) error {
	var lastErr error
	removed := 0
	rules := dnsRedirectRules(bridgeIP)
	for i := len(rules) - 1; i >= 0; i-- {
		rule := rules[i]
		args := append([]string{"-D", rule.chain}, rule.args...)
		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			lastErr = fmt.Errorf("iptables -D %s %v failed: %w (output: %s)", rule.chain, rule.args, err, out)
			logger.Warn("Failed to remove DNS redirect rule", "chain", rule.chain, "rule", rule.args, "error", err)
		} else {
			removed++
		}
	}
	if removed == 0 {
		// Every -D failed: nothing was ever installed (teardown registers
		// before a setup that may fail or never run). No redirect means no
		// flow state of ours to flush — leave the host's DNS state alone.
		return lastErr
	}
	if lastErr == nil {
		logger.Info("DNS redirect iptables rules removed")
	}

	// Rules were installed (even if some -D calls failed), so purge flows
	// still DNAT'd to the now-dead proxy — client DNS recovers immediately
	// instead of at conntrack expiry (see FlushDNSConntrack).
	if err := FlushDNSConntrack(logger); err != nil {
		logger.Warn("Failed to flush DNS conntrack entries on teardown; client DNS may stall until entries expire",
			"error", err)
	}
	return lastErr
}
