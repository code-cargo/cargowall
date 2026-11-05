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
	"time"
)

// DNSProxyFWMark is the firewall mark applied to the DNS proxy's own upstream
// queries so that iptables RETURN rules can exempt them from redirection.
const DNSProxyFWMark = 0xCA12

// dnsProxyFWMarkStr is the hex string representation used in iptables rules.
var dnsProxyFWMarkStr = fmt.Sprintf("0x%X", DNSProxyFWMark)

// dnsRedirectRules defines the iptables rules for DNS redirection.
// Each rule is a slice of arguments to pass to iptables.
// Order matters: RETURN rules for marked packets must come before DNAT rules.
var dnsRedirectRules = [][]string{
	// Exempt the CargoWall DNS proxy's upstream queries (marked with DNSProxyFWMark)
	{"-t", "nat", "-p", "udp", "--dport", "53", "-m", "mark", "--mark", dnsProxyFWMarkStr, "-j", "RETURN"},
	{"-t", "nat", "-p", "tcp", "--dport", "53", "-m", "mark", "--mark", dnsProxyFWMarkStr, "-j", "RETURN"},
	// Redirect all other outbound DNS to the local proxy
	{"-t", "nat", "-p", "udp", "--dport", "53", "!", "-d", "127.0.0.0/8", "-j", "DNAT", "--to-destination", "127.0.0.1:53"},
	{"-t", "nat", "-p", "tcp", "--dport", "53", "!", "-d", "127.0.0.0/8", "-j", "DNAT", "--to-destination", "127.0.0.1:53"},
}

// privateDstExclusions are iptables matches excluding the RFC 1918 ranges,
// which every Docker bridge network lives in, as destinations.
var privateDstExclusions = []string{
	"-m", "iprange", "!", "--dst-range", "10.0.0.0-10.255.255.255",
	"-m", "iprange", "!", "--dst-range", "172.16.0.0-172.31.255.255",
	"-m", "iprange", "!", "--dst-range", "192.168.0.0-192.168.255.255",
}

// notLocalDst excludes this host's own addresses as destinations. DNS for
// one of them is the host's to answer: Docker's DNAT for a port published
// on 53 sits in this chain too, and a docker restart can move it behind
// these rules.
var notLocalDst = []string{"-m", "addrtype", "!", "--dst-type", "LOCAL"}

// ContainerDNS is what the container DNS redirect is built from.
type ContainerDNS struct {
	// Bridge is docker0's address, where the proxy's container listener
	// is bound on port 53, with docker0's prefix.
	Bridge *net.IPNet
	// Upstreams are the resolvers the proxy forwards to. DNS a container
	// on a br-* bridge sends one of them is redirected even when it is a
	// private address: a pod's cluster DNS, which Docker's embedded
	// resolver forwards to from the container's own namespace.
	Upstreams []net.IP
}

// containerDNSRedirectRules are the nat PREROUTING rules that send DNS
// arriving on docker0 or a user-defined br-* bridge to the proxy's listener
// on docker0's address, port 53.
//
// Container DNS is forwarded, not originated here, so the OUTPUT rules never
// see it. A container that names its own resolver therefore resolves around
// the proxy: one started with --dns, one given Docker's 8.8.8.8 fallback
// because the host lists only a loopback resolver, or any container of a
// docker-in-docker daemon whose daemon.json cargowall cannot rewrite. The
// addresses such a container resolves are never allowed, so its connections
// are blocked as bare IPs. DNAT keeps the container's source address, and
// the answer leaves the listener rewritten back to the resolver the
// container asked, so the container sees an ordinary reply.
//
// DNS between containers on one bridge must be left alone: a compose
// service or a kind node may run a DNS server. Where br_netfilter is loaded
// (every Kubernetes node, so every ARC pod) bridged frames pass these rules
// too, and nothing here tells a bridged frame from a routed one. So the
// destination decides. On docker0, whose subnet is known, only that subnet
// is exempt; its gateway is the listener itself. A br-* bridge may be
// created after the rules are installed, so every RFC 1918 destination is
// exempt there except the proxy's own upstreams: DNS for those, and for
// public resolvers, is redirected. br-+ also matches bridges that are not
// Docker's (br-ex, br-int); the same exemptions apply to them.
func containerDNSRedirectRules(c ContainerDNS) [][]string {
	listener := net.JoinHostPort(c.Bridge.IP.String(), "53")
	subnet := (&net.IPNet{IP: c.Bridge.IP.Mask(c.Bridge.Mask), Mask: c.Bridge.Mask}).String()
	dnat := []string{"-j", "DNAT", "--to-destination", listener}
	var rules [][]string
	for _, proto := range []string{"udp", "tcp"} {
		rule := []string{"-t", "nat", "-i", "docker0", "-p", proto, "--dport", "53", "!", "-d", subnet}
		rule = append(rule, notLocalDst...)
		rules = append(rules, append(rule, dnat...))
	}
	for _, up := range c.Upstreams {
		for _, proto := range []string{"udp", "tcp"} {
			rules = append(rules, append([]string{
				"-t", "nat", "-i", "br-+", "-p", proto, "--dport", "53", "-d", up.String(),
			}, dnat...))
		}
	}
	for _, proto := range []string{"udp", "tcp"} {
		rule := []string{"-t", "nat", "-i", "br-+", "-p", proto, "--dport", "53"}
		rule = append(rule, privateDstExclusions...)
		rule = append(rule, notLocalDst...)
		rules = append(rules, append(rule, dnat...))
	}
	return rules
}

// SetupDNSRedirect adds iptables DNAT rules to redirect all outbound DNS
// (UDP+TCP port 53) to the local proxy at 127.0.0.1:53.
// Packets marked with DNSProxyFWMark (the DNS proxy's upstream queries) are exempted.
func SetupDNSRedirect(logger *slog.Logger) error {
	if err := appendRules("OUTPUT", dnsRedirectRules); err != nil {
		return err
	}
	logger.Info("DNS redirect iptables rules installed")
	return nil
}

// SetupContainerDNSRedirect adds the iptables DNAT rules that send DNS from
// containers on docker0 and br-* bridges to the proxy's listener on
// docker0's address, port 53. The caller must already hold that listener:
// the DNAT hands container DNS to whatever is bound there. Like the host
// redirect, it leaves conntrack alone, so a flow already open when the rules
// go in, or still open when they come out, keeps the NAT it began with.
func SetupContainerDNSRedirect(c ContainerDNS, logger *slog.Logger) error {
	if err := appendRules("PREROUTING", containerDNSRedirectRules(c)); err != nil {
		return err
	}
	logger.Info("Container DNS redirect iptables rules installed",
		"listener", net.JoinHostPort(c.Bridge.IP.String(), "53"), "docker0", c.Bridge.String(), "upstreams", c.Upstreams)
	return nil
}

// appendRules appends each rule to chain, stopping at the first failure.
// Rules already added stay in place; the caller's teardown removes them.
func appendRules(chain string, rules [][]string) error {
	for _, rule := range rules {
		args := append([]string{"-A", chain}, rule...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables -A %s %v failed: %w (output: %s)", chain, rule, err, out)
		}
	}
	return nil
}

// deleteRules deletes each rule from chain, continuing past failures (a rule
// that was never added is one), and returns the last failure.
func deleteRules(chain string, rules [][]string, logger *slog.Logger) error {
	var lastErr error
	for _, rule := range rules {
		args := append([]string{"-D", chain}, rule...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			lastErr = fmt.Errorf("iptables -D %s %v failed: %w (output: %s)", chain, rule, err, out)
			logger.Warn("Failed to remove DNS redirect rule", "chain", chain, "rule", rule, "error", err)
		}
	}
	return lastErr
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
// `resolvectl flush-caches`. Once the DNS redirect is installed, flushing
// forces every subsequent lookup — including from processes that warmed the
// 127.0.0.53 stub cache before cargowall attached — to miss the stub and go
// upstream, where the redirect routes it through the proxy. That is where
// suffix/wildcard rules match, resolved IPs get firewall-allowed, and
// hostname attribution is retained; a warm stub cache hit never travels
// upstream, so the proxy never sees the name and the connection lands as an
// unattributed bare IP (deny-by-default).
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

// TeardownDNSRedirect removes the iptables DNAT rules added by SetupDNSRedirect.
func TeardownDNSRedirect(logger *slog.Logger) error {
	err := deleteRules("OUTPUT", dnsRedirectRules, logger)
	if err == nil {
		logger.Info("DNS redirect iptables rules removed")
	}
	return err
}

// TeardownContainerDNSRedirect removes the iptables DNAT rules added by
// SetupContainerDNSRedirect from the same c.
func TeardownContainerDNSRedirect(c ContainerDNS, logger *slog.Logger) error {
	err := deleteRules("PREROUTING", containerDNSRedirectRules(c), logger)
	if err == nil {
		logger.Info("Container DNS redirect iptables rules removed")
	}
	return err
}
