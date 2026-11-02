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

// A redirect in place for IPv4 but not for the host's IPv6 is active, so the
// resolved cache flush it gates still runs, and is a lost posture: fatal
// under an enforcing policy, recorded under an auditing one.
func TestDNSRedirect_IPv4OnlyIsALoss(t *testing.T) {
	partial := &dnsRedirect{active: true, err: errors.New("IPv6 DNS is not redirected: loopback has no IPv6 address")}
	assert.True(t, partial.isActive())
	assert.False(t, (&dnsRedirect{err: errors.New("x")}).isActive(), "a redirect that failed outright is not active")

	for _, enforcing := range []bool{true, false} {
		redirectStateFiles(t)
		var buf bytes.Buffer
		cmd := &StartCmd{DNSRedirect: true}
		p := newPostures(cmd, "6.6.141", enforcing, slog.New(slog.NewTextHandler(&buf, nil)))
		err := partial.settle(p)
		if enforcing {
			require.ErrorContains(t, err, "--dns-redirect=true requested but applied only as ipv4: IPv6 DNS is not redirected")
			assert.Equal(t, postureDNSRedirect, cmd.refusedPosture)
		} else {
			require.NoError(t, err)
			assert.Contains(t, buf.String(), "level=WARN")
		}
		line := p.lines()[0]
		assert.Equal(t, "ipv4", line.Applied, "the summary must show the IPv4 redirect in place, not none")
		assert.Contains(t, line.Reason, "IPv6 DNS is not redirected")
	}
	assert.NoError(t, (&dnsRedirect{active: true}).settle(nil), "a whole redirect has nothing to report")
}
