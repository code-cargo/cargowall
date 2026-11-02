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
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/network"
)

// IPv6 is covered when the proxy holds its IPv6 listener and the kernel took
// the inet table. Another process holding the port is a gap wherever it is:
// a resolver anyone can ask at ::1. Anything else is a gap only where the
// host has IPv6 for DNS to leave by, and the reason says which it is.
func TestIPv6Gap(t *testing.T) {
	refused := errors.New("nftables: installing table inet cargowall: address family not supported")
	for _, c := range []struct {
		name             string
		bindErr, refused error
		hostIPv6         bool
		gap              string
	}{
		{name: "covered", hostIPv6: true},
		{name: "covered, no other IPv6"},
		{
			name: "no ::1, host IPv6", bindErr: fmt.Errorf("udp6: %w", unix.EADDRNOTAVAIL), hostIPv6: true,
			gap: "loopback has no IPv6 address",
		},
		{name: "no IPv6 at all", bindErr: fmt.Errorf("udp6: %w", unix.EAFNOSUPPORT)},
		{
			name: "port held, host IPv6", bindErr: fmt.Errorf("tcp6: %w", unix.EADDRINUSE), hostIPv6: true,
			gap: "another process holds [::1]:53",
		},
		{
			name: "port held, no other IPv6", bindErr: fmt.Errorf("udp6: %w", unix.EADDRINUSE),
			gap: "another process holds [::1]:53",
		},
		{
			name: "cannot bind, host IPv6", bindErr: fmt.Errorf("udp6: %w", unix.EACCES), hostIPv6: true,
			gap: "the proxy cannot listen on [::1]:53: udp6: permission denied",
		},
		{name: "inet refused, host IPv6", refused: refused, hostIPv6: true, gap: "the kernel took no inet table"},
		{name: "inet refused, no other IPv6", refused: refused},
	} {
		t.Run(c.name, func(t *testing.T) {
			gap := ipv6Gap(c.bindErr, c.refused, func() bool { return c.hostIPv6 })
			if c.gap == "" {
				assert.Empty(t, gap)
			} else {
				assert.Contains(t, gap, c.gap)
			}
		})
	}
}

// Container DNS reaches the proxy when the proxy holds its listener on the
// docker bridge, and the reason it does not names the address and why.
// Without a bridge, or with the feature off, there is nothing to reach, and
// the proxy is not asked.
func TestBridgeGap(t *testing.T) {
	for _, c := range []struct {
		name string
		d    *dockerDNS
		gap  string
	}{
		{name: "bound", d: &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{}}},
		{name: "no bridge", d: &dockerDNS{proxy: bindErrs{":53": unix.EADDRINUSE}}},
		{name: "interception off"},
		{
			name: "port held",
			d:    &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{"172.17.0.1:53": fmt.Errorf("tcp4: %w", unix.EADDRINUSE)}},
			gap:  "another process holds 172.17.0.1:53",
		},
		{
			name: "address gone",
			d:    &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{"172.17.0.1:53": fmt.Errorf("udp4: %w", unix.EADDRNOTAVAIL)}},
			gap:  "the proxy cannot listen on 172.17.0.1:53: udp4: cannot assign requested address",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.gap, bridgeGap(c.d))
		})
	}
}

// The redirect sends container DNS to the bridge listener only once the
// proxy holds it, and drops it at the bridge when not; IPv6 DNS likewise
// goes to the IPv6 listener only once that is held. No bridge, or the
// feature off, is no bridge chain, and nothing to drop, whatever the proxy
// says of an address it was never given.
func TestRedirectSpec(t *testing.T) {
	held := fmt.Errorf("udp4: %w", unix.EADDRINUSE)
	bound := &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{}}
	unbound := &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{"172.17.0.1:53": held}}
	for _, c := range []struct {
		name    string
		ipv6Err error
		d       *dockerDNS
		want    network.RedirectSpec
	}{
		{"whole", nil, bound, network.RedirectSpec{IPv6: true, BridgeIP: "172.17.0.1"}},
		{"bridge listener unbound", nil, unbound, network.RedirectSpec{IPv6: true, BridgeIP: "172.17.0.1", DropBridgeDNS: true}},
		{"IPv6 listener unbound", held, bound, network.RedirectSpec{BridgeIP: "172.17.0.1"}},
		{"neither bound", held, unbound, network.RedirectSpec{BridgeIP: "172.17.0.1", DropBridgeDNS: true}},
		{"no bridge", nil, &dockerDNS{proxy: bindErrs{":53": held}}, network.RedirectSpec{IPv6: true}},
		{"interception off", nil, nil, network.RedirectSpec{IPv6: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, redirectSpec(c.ipv6Err, c.d))
		})
	}
}

// A redirect in place but not whole is active, so the resolved cache flush
// it gates still runs, and is a lost posture: fatal under an enforcing
// policy, recorded under an auditing one. It is recorded at what it still
// covers, with every gap's reason: ipv4 when IPv6 DNS goes around the
// proxy, host when container DNS is dropped at the bridge, host-ipv4 for
// both.
func TestDNSRedirect_PartialIsALoss(t *testing.T) {
	const (
		ipv6   = "loopback has no IPv6 address for the proxy to listen on"
		bridge = "another process holds 172.17.0.1:53"
	)
	ipv6Reason := "IPv6 DNS is not redirected: " + ipv6
	bridgeReason := "container DNS is dropped, not redirected: " + bridge
	logger := slog.New(slog.DiscardHandler)
	for _, c := range []struct {
		name, ipv6, bridge, applied string
		reasons                     []string
	}{
		{"IPv6 gap", ipv6, "", "ipv4", []string{ipv6Reason}},
		{"bridge gap", "", bridge, "host", []string{bridgeReason}},
		{"both", ipv6, bridge, "host-ipv4", []string{ipv6Reason, bridgeReason}},
	} {
		t.Run(c.name, func(t *testing.T) {
			partial := installed(c.ipv6, c.bridge, logger)
			assert.True(t, partial.isActive())
			for _, enforcing := range []bool{true, false} {
				redirectStateFiles(t)
				var buf bytes.Buffer
				cmd := &StartCmd{DNSRedirect: true}
				p := newPostures(cmd, "6.6.141", enforcing, slog.New(slog.NewTextHandler(&buf, nil)))
				err := partial.settle(p)
				if enforcing {
					require.ErrorContains(t, err, "--dns-redirect=true requested but applied only as "+c.applied+": ")
					assert.Equal(t, postureDNSRedirect, cmd.refusedPosture)
				} else {
					require.NoError(t, err)
					assert.Contains(t, buf.String(), "level=WARN")
				}
				line := p.lines()[0]
				assert.Equal(t, c.applied, line.Applied, "the summary must show what the redirect still covers, not none")
				for _, reason := range c.reasons {
					assert.Contains(t, line.Reason, reason)
				}
			}
		})
	}
	assert.False(t, (&dnsRedirect{err: errors.New("x")}).isActive(), "a redirect that failed outright is not active")
	whole := installed("", "", logger)
	assert.True(t, whole.isActive())
	assert.NoError(t, whole.settle(nil), "a whole redirect has nothing to report")
}
