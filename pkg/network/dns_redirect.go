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
	"fmt"
	"log/slog"
	"os/exec"
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

// SetupDNSRedirect adds iptables DNAT rules to redirect all outbound DNS
// (UDP+TCP port 53) to the local proxy at 127.0.0.1:53.
// Packets marked with DNSProxyFWMark (the DNS proxy's upstream queries) are exempted.
func SetupDNSRedirect(logger *slog.Logger) error {
	for _, rule := range dnsRedirectRules {
		args := append([]string{"-A", "OUTPUT"}, rule...)
		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables -A OUTPUT %v failed: %w (output: %s)", rule, err, out)
		}
	}
	logger.Info("DNS redirect iptables rules installed")
	return nil
}

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
// Best-effort: on hosts without systemd-resolved there is no stub cache to
// flush and the redirect alone suffices, so a missing resolvectl is not an
// error. A genuine flush failure is returned for the caller to log.
func FlushResolvedCache(logger *slog.Logger) error {
	path, err := exec.LookPath("resolvectl")
	if err != nil {
		logger.Debug("resolvectl not found; skipping systemd-resolved cache flush")
		return nil
	}
	if out, err := exec.Command(path, "flush-caches").CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl flush-caches failed: %w (output: %s)", err, out)
	}
	logger.Info("Flushed systemd-resolved DNS cache")
	return nil
}

// TeardownDNSRedirect removes the iptables DNAT rules added by SetupDNSRedirect.
func TeardownDNSRedirect(logger *slog.Logger) error {
	var lastErr error
	for _, rule := range dnsRedirectRules {
		args := append([]string{"-D", "OUTPUT"}, rule...)
		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			lastErr = fmt.Errorf("iptables -D OUTPUT %v failed: %w (output: %s)", rule, err, out)
			logger.Warn("Failed to remove DNS redirect rule", "rule", rule, "error", err)
		}
	}
	if lastErr == nil {
		logger.Info("DNS redirect iptables rules removed")
	}
	return lastErr
}
