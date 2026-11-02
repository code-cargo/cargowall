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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IPv6 is covered when loopback has ::1 and the proxy's port is free. When
// it cannot be, that is a gap only where the host has IPv6 for DNS to leave
// by; and the port is probed only when there is a loopback to probe.
func TestDecideIPv6(t *testing.T) {
	inUse := errors.New("address already in use")
	for _, c := range []struct {
		name               string
		loopback, hostIPv6 bool
		probe              error
		cover              bool
		gap                string
	}{
		{name: "covered", loopback: true, hostIPv6: true, cover: true},
		{name: "covered, no other IPv6", loopback: true, cover: true},
		{name: "no ::1, host IPv6", hostIPv6: true, gap: "loopback has no IPv6 address"},
		{name: "no IPv6 at all"},
		{name: "port held, host IPv6", loopback: true, hostIPv6: true, probe: inUse, gap: "address already in use"},
		{name: "port held, no other IPv6", loopback: true, probe: inUse},
	} {
		t.Run(c.name, func(t *testing.T) {
			probed := false
			cover, gap := decideIPv6(c.loopback, func() bool { return c.hostIPv6 }, func(addr string) error {
				probed = true
				assert.Equal(t, "[::1]:53", addr)
				return c.probe
			})
			assert.Equal(t, c.cover, cover)
			if c.gap == "" {
				assert.Empty(t, gap)
			} else {
				assert.Contains(t, gap, c.gap)
			}
			assert.Equal(t, c.loopback, probed, "the port is probed exactly when loopback has ::1")
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
			require.ErrorContains(t, err, "IPv6 DNS is not redirected")
			assert.Equal(t, postureDNSRedirect, cmd.refusedPosture)
		} else {
			require.NoError(t, err)
			assert.Contains(t, p.lines()[0].Reason, "IPv6 DNS is not redirected")
		}
	}
	assert.NoError(t, (&dnsRedirect{active: true}).settle(nil), "a whole redirect has nothing to report")
}
