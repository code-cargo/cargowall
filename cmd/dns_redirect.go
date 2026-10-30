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
	"log/slog"

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
	installed *network.DNSRedirect
	err       error // why setup failed
}

// startDNSRedirect installs the redirect for the proxy, and for its
// container listener at bridgeIP when there is one. The returned undo
// removes it; the caller defers it. Unlike the other host mutations it is
// registered after setup: the kernel deletes the table with its owning
// socket however the process ends, so a signal landing mid-setup leaves
// nothing behind.
func startDNSRedirect(bridgeIP string, teardowns *teardownList, logger *slog.Logger) (*dnsRedirect, func()) {
	installed, err := network.SetupDNSRedirect(logger, bridgeIP)
	if err != nil {
		return &dnsRedirect{err: err}, func() {}
	}
	undo := teardowns.add(func() {
		if err := installed.Teardown(); err != nil {
			logger.Warn("Failed to tear down DNS redirect", "error", err)
		}
	})
	return &dnsRedirect{installed: installed}, undo
}

// isActive reports whether the redirect is in place. Nil-safe: nil is the
// redirect not requested.
func (r *dnsRedirect) isActive() bool { return r != nil && r.installed != nil }

// settle hands a failed setup to the ledger, which owns the log line and
// decides whether startup fails. Nil-safe.
func (r *dnsRedirect) settle(postures *postureLedger) error {
	if r == nil || r.err == nil {
		return nil
	}
	return postures.lose(postureDNSRedirect, postures.errReason(r.err))
}
