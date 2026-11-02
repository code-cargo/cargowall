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
	"fmt"
	"log/slog"
	"net"

	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/network"
)

// dnsRedirect owns --dns-redirect: the redirect that sends every resolver
// this netns and its docker bridges use through the proxy. It is the only
// thing that does: without it the proxy sees just the clients that pick it
// by choice, and any other resolver's answers never reach the firewall.
// Under an enforcing policy the job's allowed hostnames are then blocked on
// their bare IPs, which reads as a policy gap and pushes the operator to
// allow CDN addresses instead of fixing the capture. So a redirect that does
// not come up is a lost posture, and what that costs depends on the
// policy's mode, which is known only after the policy loads: by then the
// redirect must already be up, so setup records the failure and settle
// reports it. A redirect that covers IPv4 but not the IPv6 the host has is
// a loss too: IPv6 DNS then goes around the proxy the same way.
type dnsRedirect struct {
	active bool  // the redirect is in place, for IPv4 at least
	err    error // why it is not, or not for IPv6; nil when it is whole
}

// ipv6Coverage decides whether the redirect covers IPv6 and, when it does,
// adds the proxy's listener at network.ProxyAddrIPv6 that IPv6 DNS is sent
// to. Called before the proxy starts, so that listener failing to bind
// fails startup with it. gap is why the host's IPv6 DNS will go around the
// proxy instead, "" when it will not.
func ipv6Coverage(cmd *StartCmd, dnsServer *dns.Server) (ipv6 bool, gap string) {
	if !cmd.DNSRedirect {
		return false, ""
	}
	ipv6, gap = decideIPv6(network.LoopbackIPv6(), network.HostIPv6, probeListen)
	if ipv6 {
		dnsServer.AddRedirectListenAddr(network.ProxyAddrIPv6)
	}
	return ipv6, gap
}

// decideIPv6 is ipv6Coverage's rule. IPv6 is covered when loopback has ::1
// for the proxy and nothing else holds the port. When it cannot be, that is
// a gap only on a host with IPv6 for DNS to leave by; one without has
// nothing to cover. The port is probed rather than left to the proxy's
// bind, whose failure would end startup in every mode, where an uncovered
// IPv6 is a posture an auditing policy only records.
func decideIPv6(loopback bool, hostIPv6 func() bool, probe func(addr string) error) (bool, string) {
	if !loopback {
		if hostIPv6() {
			return false, "loopback has no IPv6 address for the proxy to listen on"
		}
		return false, ""
	}
	if err := probe(network.ProxyAddrIPv6); err != nil {
		if hostIPv6() {
			return false, fmt.Sprintf("the proxy cannot listen on %s: %v", network.ProxyAddrIPv6, err)
		}
		return false, ""
	}
	return true, ""
}

// probeListen binds addr over UDP and TCP and lets go, to learn whether the
// proxy can hold it.
func probeListen(addr string) error {
	pc, err := net.ListenPacket("udp6", addr)
	if err != nil {
		return err
	}
	_ = pc.Close()
	l, err := net.Listen("tcp6", addr)
	if err != nil {
		return err
	}
	return l.Close()
}

// startDNSRedirect installs the redirect for the proxy, and for its
// container listener on the docker bridge when there is one. gap is why
// IPv6 is not covered (see ipv6Coverage), which the kernel refusing an inet
// table can also be. The returned undo
// removes it; the caller defers it. It is registered before the install,
// like every host mutation's: a forced shutdown landing mid-install waits
// for it, then removes the table, which an unowned one needs, and flushes
// the flows DNAT'd to the proxy meanwhile, which even an owned one dying
// with the process does not do.
func startDNSRedirect(spec network.RedirectSpec, gap string, teardowns *teardownList,
	logger *slog.Logger,
) (*dnsRedirect, func()) {
	redirect := network.NewDNSRedirect(logger)
	undo := teardowns.add(func() {
		// An Error, not a Warn: what it can leave behind is the host's DNS
		// redirected to a proxy that has stopped.
		if err := redirect.Teardown(); err != nil {
			logger.Error("Failed to tear down DNS redirect", "error", err)
		}
	})
	if err := redirect.Install(spec); err != nil {
		return notInstalled(err, logger), undo
	}
	if why := redirect.IPv6Refused(); why != nil && network.HostIPv6() {
		gap = "the kernel took no inet table: " + why.Error()
	}
	if gap != "" {
		err := fmt.Errorf("IPv6 DNS is not redirected: %s", gap)
		logger.Info("DNS redirect covers IPv4 only; the policy's mode decides what that costs once it loads", "error", err)
		return &dnsRedirect{active: true, err: err}, undo
	}
	return &dnsRedirect{active: true}, undo
}

// notInstalled records a redirect that did not come up, and says so in the
// log where it happened. The posture line follows once the policy's mode
// decides what the loss costs; logging only then would leave it out of a
// startup that ends before, and out of order with the proxy's start.
func notInstalled(err error, logger *slog.Logger) *dnsRedirect {
	logger.Info("DNS redirect not installed; the policy's mode decides what that costs once it loads", "error", err)
	return &dnsRedirect{err: err}
}

// isActive reports whether the redirect is in place, for IPv4 at least.
// Nil-safe: nil is the redirect not requested.
func (r *dnsRedirect) isActive() bool { return r != nil && r.active }

// settle hands a failed setup to the ledger, which owns the log line and
// decides whether startup fails; one in place for IPv4 alone is recorded as
// that. Nil-safe.
func (r *dnsRedirect) settle(postures *postureLedger) error {
	if r == nil || r.err == nil {
		return nil
	}
	if r.active {
		return postures.loseTo(postureDNSRedirect, dnsRedirectIPv4, postures.errReason(r.err))
	}
	return postures.lose(postureDNSRedirect, postures.errReason(r.err))
}
