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

// dnsRedirect owns --dns-redirect-iptables: the redirect that sends every
// resolver this netns and its docker bridges use through the proxy. It is
// the only thing that does: without it the proxy sees just the clients that
// pick it by choice, and any other resolver's answers never reach the
// firewall. Under an enforcing policy the job's allowed hostnames are then
// blocked on their bare IPs, which reads as a policy gap and pushes the
// operator to allow CDN addresses instead of fixing the capture. So a
// redirect that does not come up is a lost posture, and what that costs
// depends on the policy's mode, which is known only after the policy loads:
// by then the redirect must already be up, so setup records the failure and
// settle reports it.
type dnsRedirect struct {
	active bool
	err    error // why setup failed
}

// startDNSRedirect installs the redirect for the proxy, and for its
// container listener at bridgeIP when there is one. The returned undo
// removes it; the caller defers it. It is registered before setup so a
// signal landing mid-setup still has one, and removing a redirect that was
// never installed is a quiet no-op. After a failed setup the undo still
// runs, for a table a crashed earlier run left, but its failure is the
// setup's failure again and settle already reports that.
func startDNSRedirect(bridgeIP string, teardowns *teardownList, logger *slog.Logger) (*dnsRedirect, func()) {
	r := &dnsRedirect{}
	undo := teardowns.add(func() {
		err := network.TeardownDNSRedirect(logger)
		switch {
		case err == nil:
		case r.err != nil:
			logger.Debug("DNS redirect teardown after a failed setup", "error", err)
		default:
			logger.Warn("Failed to tear down DNS redirect", "error", err)
		}
	})
	if err := network.SetupDNSRedirect(logger, bridgeIP); err != nil {
		r.err = err
		return r, undo
	}
	r.active = true
	return r, undo
}

// isActive reports whether the redirect is in place. Nil-safe: nil is the
// redirect not requested.
func (r *dnsRedirect) isActive() bool { return r != nil && r.active }

// settle hands a failed setup to the ledger, which owns the log line and
// decides whether startup fails. Nil-safe.
func (r *dnsRedirect) settle(postures *postureLedger) error {
	if r == nil || r.err == nil {
		return nil
	}
	return postures.lose(postureDNSRedirect, postures.errReason(r.err))
}
