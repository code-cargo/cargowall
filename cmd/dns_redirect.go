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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"golang.org/x/sys/unix"

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
// a loss too: IPv6 DNS then goes around the proxy the same way. So is one
// that leaves container DNS alone for want of the proxy's listener on the
// docker bridge: containers then resolve around the proxy.
type dnsRedirect struct {
	active bool  // the redirect is in place, for the host's IPv4 at least
	err    error // why it is not, or not whole; nil when it is whole
	// applied is what a redirect in place but not whole covers, as the
	// posture record spells it: dnsRedirectIPv4, dnsRedirectHost or
	// dnsRedirectHostIPv4.
	applied string
}

// addIPv6Listener adds the proxy's listener at network.ProxyAddrIPv6, the
// one the redirect sends IPv6 DNS to: whether it binds decides whether the
// redirect covers IPv6 (startDNSRedirect). Called before the proxy starts.
func addIPv6Listener(cmd *StartCmd, dnsServer *dns.Server) {
	if cmd.DNSRedirect {
		dnsServer.AddListenAddr(network.ProxyAddrIPv6)
	}
}

// ipv6Gap is why IPv6 DNS will go around the proxy, "" when it will not.
// IPv6 is covered when the proxy holds its IPv6 listener (bindErr nil) and
// the kernel took the inet table (refused nil). Another process holding the
// port is a gap wherever it happens: it is a resolver any client can ask at
// ::1, around the proxy, as resolved's stub would be were the IPv4 rules not
// to send it on. Anything else is a gap only on a host with IPv6 for DNS to
// leave by; one without has nothing to cover. An uncovered IPv6 is a lost
// posture rather than a failed start, which an auditing policy only records.
func ipv6Gap(bindErr, refused error, hostIPv6 func() bool) string {
	switch {
	case bindErr == nil && refused == nil:
		return ""
	case errors.Is(bindErr, unix.EADDRINUSE):
		return listenGap(network.ProxyAddrIPv6, bindErr) + ", a resolver clients can ask around the proxy"
	case !hostIPv6():
		return ""
	case bindErr == nil:
		return "the kernel took no inet table: " + refused.Error()
	case errors.Is(bindErr, unix.EADDRNOTAVAIL), errors.Is(bindErr, unix.EAFNOSUPPORT):
		return "loopback has no IPv6 address for the proxy to listen on"
	default:
		return listenGap(network.ProxyAddrIPv6, bindErr)
	}
}

// bridgeGap is why container DNS will not reach the proxy, "" when it will:
// bindErr is why the proxy does not hold its listener on the docker bridge,
// and the redirect then leaves container DNS alone (redirectSpec).
func bridgeGap(containerDNS *dockerDNS, bindErr error) string {
	if bindErr == nil {
		return ""
	}
	return listenGap(containerDNS.listenAddr(), bindErr)
}

// listenGap is why the proxy does not hold its listener at addr, as a
// posture reason puts it: another process holds the address, or the bind
// failed for a cause of its own. The reason names the address once: the
// error listenBoth returns names it again (udp4: listen udp4 <addr>: bind:
// ...), so of that only the protocol and the cause are kept.
func listenGap(addr string, err error) string {
	var op *net.OpError
	switch {
	case errors.Is(err, unix.EADDRINUSE):
		return "another process holds " + addr
	case errors.As(err, &op):
		return fmt.Sprintf("the proxy cannot listen on %s: %s %v", addr, op.Net, op.Err)
	default:
		return fmt.Sprintf("the proxy cannot listen on %s: %v", addr, err)
	}
}

// redirectSpec is the redirect for the listeners the proxy holds once it is
// ready: IPv6 DNS goes to its IPv6 listener only when that is bound
// (ipv6BindErr nil), and container DNS to its docker bridge listener at
// bridgeIP only when that one is (bridgeBindErr nil). Otherwise the bridge
// gets no rule at all: a DNAT would hand container DNS to whatever holds the
// address, and a drop would block DNS under an auditing policy, which
// promises to block nothing, while under an enforcing one the loss already
// refuses startup.
func redirectSpec(ipv6BindErr error, bridgeIP string, bridgeBindErr error) network.RedirectSpec {
	spec := network.RedirectSpec{IPv6: ipv6BindErr == nil}
	if bridgeBindErr == nil {
		spec.BridgeIP = bridgeIP
	}
	return spec
}

// startDNSRedirect installs the redirect for the proxy, and for its
// container listener on the docker bridge when there is one, once the proxy
// has bound its listeners (redirectSpec), and what that leaves uncovered is
// ipv6Gap's and bridgeGap's to say. The returned undo
// removes it; the caller defers it. It is registered before the install,
// like every host mutation's: a forced shutdown landing mid-install waits
// for it, then removes the table, which an unowned one needs, and flushes
// the flows DNAT'd to the proxy meanwhile, which even an owned one dying
// with the process does not do.
func startDNSRedirect(dnsServer *dns.Server, containerDNS *dockerDNS, teardowns *teardownList,
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
	bindErr := dnsServer.BindError(network.ProxyAddrIPv6)
	bridgeErr := containerDNS.listenerErr()
	if err := redirect.Install(redirectSpec(bindErr, containerDNS.bridge(), bridgeErr)); err != nil {
		return notInstalled(err, logger), undo
	}
	return installed(ipv6Gap(bindErr, redirect.IPv6Refused(), network.HostIPv6), bridgeGap(containerDNS, bridgeErr),
		logger), undo
}

// installed records a redirect in place, whole unless it has a gap: ipv6
// when IPv6 DNS goes around the proxy, bridge when container DNS does, for
// want of the bridge listener, "" for none. One with a gap is recorded at
// what it still covers, with every gap's reason, and says so in the log
// where it happened, as notInstalled does.
func installed(ipv6, bridge string, logger *slog.Logger) *dnsRedirect {
	r := &dnsRedirect{active: true}
	switch {
	case ipv6 != "" && bridge != "":
		r.applied = dnsRedirectHostIPv4
	case ipv6 != "":
		r.applied = dnsRedirectIPv4
	case bridge != "":
		r.applied = dnsRedirectHost
	default:
		return r
	}
	// The bridge's reason goes first: it is short, while IPv6's can carry a
	// kernel refusal and its hint, and the record keeps only the first
	// maxPostureReasonBytes, so in this order both causes survive.
	var gaps []string
	if bridge != "" {
		gaps = append(gaps, "container DNS is not redirected: "+bridge)
	}
	if ipv6 != "" {
		gaps = append(gaps, "IPv6 DNS is not redirected: "+ipv6)
	}
	r.err = errors.New(strings.Join(gaps, "; "))
	logger.Info("DNS redirect not whole; the policy's mode decides what that costs once it loads",
		"covers", r.applied, "error", r.err)
	return r
}

// notInstalled records a redirect that did not come up, and says so in the
// log where it happened. The posture line follows once the policy's mode
// decides what the loss costs; logging only then would leave it out of a
// startup that ends before, and out of order with the proxy's start.
func notInstalled(err error, logger *slog.Logger) *dnsRedirect {
	logger.Info("DNS redirect not installed; the policy's mode decides what that costs once it loads", "error", err)
	return &dnsRedirect{err: err}
}

// isActive reports whether the redirect is in place, for the host's IPv4 at
// least. Nil-safe: nil is the redirect not requested.
func (r *dnsRedirect) isActive() bool { return r != nil && r.active }

// settle hands a failed setup to the ledger, which owns the log line and
// decides whether startup fails; one in place but not whole is recorded at
// what it covers. Nil-safe.
func (r *dnsRedirect) settle(postures *postureLedger) error {
	if r == nil || r.err == nil {
		return nil
	}
	if r.active {
		return postures.loseTo(postureDNSRedirect, r.applied, postures.errReason(r.err))
	}
	return postures.lose(postureDNSRedirect, postures.errReason(r.err))
}
