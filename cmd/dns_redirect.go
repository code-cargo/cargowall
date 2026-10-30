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

	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
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
// reports it.
type dnsRedirect struct {
	err error // why setup failed; nil when the redirect is in place
}

// startDNSRedirect installs the redirect for the proxy, and for its
// container listener at bridgeIP when there is one. kernel is the uname
// release: the redirect's owned table needs 5.12, above the 5.8 the rest of
// cargowall needs, and an older kernel would refuse the table's flags with
// a bare EINVAL, so it is refused here by name instead. The returned undo
// removes it; the caller defers it. It is registered before the install,
// like every host mutation's: the kernel deletes the table with its owning
// socket however the process ends, but a forced shutdown landing
// mid-install still owes the flush of the flows DNAT'd to the proxy
// meanwhile, and its teardown waits for the install to finish.
func startDNSRedirect(bridgeIP, kernel string, teardowns *teardownList, logger *slog.Logger) (*dnsRedirect, func()) {
	switch ok, err := cargowallEbpf.KernelAtLeast(kernel, 5, 12); {
	case err != nil:
		return notInstalled(fmt.Errorf("the redirect's owned nftables table needs kernel 5.12: %w", err), logger), func() {}
	case !ok:
		return notInstalled(fmt.Errorf("kernel %s is older than 5.12, which the redirect's owned nftables table needs", kernel), logger), func() {}
	}
	redirect := network.NewDNSRedirect(logger)
	undo := teardowns.add(func() {
		if err := redirect.Teardown(); err != nil {
			logger.Warn("Failed to tear down DNS redirect", "error", err)
		}
	})
	if err := redirect.Install(bridgeIP); err != nil {
		return notInstalled(err, logger), undo
	}
	return &dnsRedirect{}, undo
}

// notInstalled records a redirect that did not come up, and says so in the
// log where it happened. The posture line follows once the policy's mode
// decides what the loss costs; logging only then would leave it out of a
// startup that ends before, and out of order with the proxy's start.
func notInstalled(err error, logger *slog.Logger) *dnsRedirect {
	logger.Info("DNS redirect not installed; the policy's mode decides what that costs once it loads", "error", err)
	return &dnsRedirect{err: err}
}

// isActive reports whether the redirect is in place. Nil-safe: nil is the
// redirect not requested.
func (r *dnsRedirect) isActive() bool { return r != nil && r.err == nil }

// settle hands a failed setup to the ledger, which owns the log line and
// decides whether startup fails. Nil-safe.
func (r *dnsRedirect) settle(postures *postureLedger) error {
	if r == nil || r.err == nil {
		return nil
	}
	return postures.lose(postureDNSRedirect, postures.errReason(r.err))
}
