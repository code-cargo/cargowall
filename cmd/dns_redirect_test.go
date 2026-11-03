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
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/podenv"
)

// listenErr is a bind failure as the proxy reports it (dns.Server's
// listenBoth): the protocol, then net's own error, which names the address
// again.
func listenErr(proto, addr string, errno unix.Errno) error {
	ap := netip.MustParseAddrPort(addr)
	var a net.Addr = net.UDPAddrFromAddrPort(ap)
	if strings.HasPrefix(proto, "tcp") {
		a = net.TCPAddrFromAddrPort(ap)
	}
	return fmt.Errorf("%s: %w", proto, &net.OpError{Op: "listen", Net: proto, Addr: a, Err: os.NewSyscallError("bind", errno)})
}

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
			name: "no ::1, host IPv6", bindErr: listenErr("udp6", "[::1]:53", unix.EADDRNOTAVAIL), hostIPv6: true,
			gap: "loopback has no IPv6 address",
		},
		{name: "no IPv6 at all", bindErr: listenErr("udp6", "[::1]:53", unix.EAFNOSUPPORT)},
		{
			name: "port held, host IPv6", bindErr: listenErr("tcp6", "[::1]:53", unix.EADDRINUSE), hostIPv6: true,
			gap: "another process holds [::1]:53, a resolver clients can ask around the proxy",
		},
		{
			name: "port held, no other IPv6", bindErr: listenErr("udp6", "[::1]:53", unix.EADDRINUSE),
			gap: "another process holds [::1]:53",
		},
		{
			name: "cannot bind, host IPv6", bindErr: listenErr("udp6", "[::1]:53", unix.EACCES), hostIPv6: true,
			gap: "the proxy cannot listen on [::1]:53: udp6 bind: permission denied",
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

// Container DNS reaches the proxy when the proxy holds its container
// listener of its family. The reason one does not names its address once,
// and why: another process's bind, net's own error with the address it
// repeats left out, or the refusal of the address itself
// (network.OwnedAddrs). The IPv6 listener counts only where the redirect
// covers IPv6; with the feature off there is nothing to reach.
func TestContainerGap(t *testing.T) {
	held := listenErr("udp4", "169.254.0.53:53", unix.EADDRINUSE)
	gone := listenErr("udp4", "169.254.0.53:53", unix.EADDRNOTAVAIL)
	routed := errors.New("it is routed through tun0 by fd97:d1fb:f215::/48")
	for _, c := range []struct {
		name string
		errs bindErrs
		ipv6 bool
		gap  string
	}{
		{name: "both bound", errs: bindErrs{}, ipv6: true},
		{name: "IPv4 port held", errs: bindErrs{listen4: held}, gap: "another process holds 169.254.0.53:53"},
		{
			name: "IPv4 address gone", errs: bindErrs{listen4: gone},
			gap: "the proxy cannot listen on 169.254.0.53:53: udp4 bind: cannot assign requested address",
		},
		{
			name: "IPv4 refused", errs: bindErrs{listen4: errRefused4},
			gap: "the proxy cannot listen on 169.254.0.53:53: it is already assigned to eth0",
		},
		{
			name: "IPv6 refused, IPv6 covered", errs: bindErrs{listen6: routed}, ipv6: true,
			gap: "the proxy cannot listen on [fd97:d1fb:f215::53]:53: it is routed through tun0 by fd97:d1fb:f215::/48",
		},
		{name: "IPv6 refused, IPv6 not covered", errs: bindErrs{listen6: routed}},
		{
			name: "both refused", errs: bindErrs{listen4: errRefused4, listen6: routed}, ipv6: true,
			gap: "the proxy cannot listen on 169.254.0.53:53: it is already assigned to eth0; " +
				"the proxy cannot listen on [fd97:d1fb:f215::53]:53: it is routed through tun0 by fd97:d1fb:f215::/48",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.gap, containerGap(&dockerDNS{proxy: c.errs}, c.ipv6))
		})
	}
	assert.Empty(t, containerGap(nil, true))
}

// A redirect in place but not whole is active, so the resolved cache flush
// it gates still runs, and is a lost posture: fatal under an enforcing
// policy, recorded under an auditing one. It is recorded at what it still
// covers, with every gap's reason: ipv4 when IPv6 DNS goes around the
// proxy, host when container DNS does, for want of a container listener,
// host-ipv4 for both.
func TestDNSRedirect_PartialIsALoss(t *testing.T) {
	const (
		ipv6      = "loopback has no IPv6 address for the proxy to listen on"
		container = "another process holds 169.254.0.53:53"
	)
	ipv6Reason := "IPv6 DNS is not redirected: " + ipv6
	containerReason := "container DNS is not redirected: " + container
	logger := slog.New(slog.DiscardHandler)
	for _, c := range []struct {
		name, ipv6, container, applied string
		reason                         string
	}{
		{"IPv6 gap", ipv6, "", "ipv4", ipv6Reason},
		{"container gap", "", container, "host", containerReason},
		{"both", ipv6, container, "host-ipv4", containerReason + "; " + ipv6Reason},
	} {
		t.Run(c.name, func(t *testing.T) {
			partial := installed(c.ipv6, c.container, logger)
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
				assert.Equal(t, c.reason, line.Reason)
			}
		})
	}
	assert.False(t, (&dnsRedirect{err: errors.New("x")}).isActive(), "a redirect that failed outright is not active")
	whole := installed("", "", logger)
	assert.True(t, whole.isActive())
	assert.NoError(t, whole.settle(nil), "a whole redirect has nothing to report")
}

// A container listener the proxy could not bind costs the dns-redirect
// posture only where Docker could be present. With no socket and no bridge
// there is no container whose DNS could go around the proxy, so neither
// family's refusal is a loss, under an enforcing policy or an auditing one.
// A daemon still to come up, one up, bridges with no socket, and bridges
// that could not be listed all still lose it to host: fatal under an
// enforcing policy, recorded under an auditing one.
func TestDNSRedirect_ContainerGapNeedsDocker(t *testing.T) {
	routed6 := errors.New("it is routed through tun0 by fd97:d1fb:f215::/48")
	for _, c := range []struct {
		name    string
		dockerd podenv.Dockerd
		lost    bool
	}{
		{name: "none", dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent}},
		{name: "pending", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal}, lost: true},
		{name: "up", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: []string{"docker0"}, Answers: true}, lost: true},
		{name: "up, no bridge", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Answers: true}, lost: true},
		{name: "unreachable", dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent, Bridges: []string{"docker0"}}, lost: true},
		{
			name: "bridges not listed", lost: true,
			dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent, BridgesErr: errors.New("netlink: permission denied")},
		},
	} {
		for _, refused := range []struct {
			family string
			errs   bindErrs
		}{
			{"IPv4", bindErrs{listen4: errRefused4}},
			{"IPv6", bindErrs{listen6: routed6}},
		} {
			for _, enforcing := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/enforcing=%v", c.name, refused.family, enforcing), func(t *testing.T) {
					d := &dockerDNS{dockerd: c.dockerd, proxy: refused.errs}
					ipv6, container := redirectGaps(nil, nil, func() bool { return true }, d)
					assert.Empty(t, ipv6)
					r := installed(ipv6, container, slog.New(slog.DiscardHandler))
					redirectStateFiles(t)
					cmd := &StartCmd{DNSRedirect: true}
					p := newPostures(cmd, "6.6.141", enforcing, slog.New(slog.DiscardHandler))
					err := r.settle(p)
					line := p.lines()[0]
					if !c.lost {
						require.NoError(t, err)
						assert.False(t, line.degraded(), "no Docker, so no container DNS to cover: %+v", line)
						assert.Empty(t, cmd.refusedPosture)
						return
					}
					if enforcing {
						require.ErrorContains(t, err, "--dns-redirect=true requested but applied only as host: ")
						assert.Equal(t, postureDNSRedirect, cmd.refusedPosture)
					} else {
						require.NoError(t, err)
					}
					assert.Equal(t, dnsRedirectHost, line.Applied)
					assert.Contains(t, line.Reason, "container DNS is not redirected: ")
				})
			}
		}
	}
}

// IPv6 is covered, and the IPv6 container listener's gap counts with it,
// only where the proxy holds [::1]:53 and the kernel took the inet table:
// otherwise the IPv6 gap speaks for the host and its containers alike.
func TestRedirectGaps(t *testing.T) {
	d := &dockerDNS{proxy: bindErrs{listen6: errors.New("it is routed through tun0 by fd97:d1fb:f215::/48")}}
	held := listenErr("udp6", "[::1]:53", unix.EADDRINUSE)
	refused := errors.New("nftables: installing table inet cargowall: netlink receive: address family not supported")
	for _, c := range []struct {
		name                  string
		bindErr, refused      error
		ipv6Gap, containerGap bool
	}{
		{name: "IPv6 covered", containerGap: true},
		{name: "[::1]:53 held", bindErr: held, ipv6Gap: true},
		{name: "inet refused", refused: refused, ipv6Gap: true},
	} {
		ipv6, container := redirectGaps(c.bindErr, c.refused, func() bool { return true }, d)
		assert.Equal(t, c.ipv6Gap, ipv6 != "", "%s: the IPv6 gap", c.name)
		assert.Equal(t, c.containerGap, container != "", "%s: the IPv6 container listener's gap", c.name)
	}
}

// The record keeps a lost dns-redirect's reasons whole at their longest,
// within maxPostureReasonBytes. One case is the kernel refusing the inet
// table, with its hint, beside the IPv4 container listener's address
// refused for a route through an interface whose name is as long as one
// gets. The other is both container listeners refused that way, with IPv6
// covered: were it not, the IPv6 listener would not count.
func TestDNSRedirect_GapsKeptWhole(t *testing.T) {
	refused := errors.New("nftables: installing table inet cargowall: netlink receive: address family not supported " +
		"by protocol (the kernel may lack inet tables or IPv6 nat: CONFIG_NF_TABLES_INET, or nf_nat for IPv6)")
	routed4 := errors.New("it is routed through a-15-char-link by 169.254.0.0/17")
	routed6 := errors.New("it is routed through a-15-char-link by fd97:d1fb:f215::/48")
	for _, c := range []struct {
		name    string
		refused error
		errs    bindErrs
		applied string
	}{
		{name: "inet refused", refused: refused, errs: bindErrs{listen4: routed4}, applied: "host-ipv4"},
		{name: "both refused", errs: bindErrs{listen4: routed4, listen6: routed6}, applied: "host"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ipv6, container := redirectGaps(nil, c.refused, func() bool { return true }, &dockerDNS{proxy: c.errs})
			r := installed(ipv6, container, slog.New(slog.DiscardHandler))
			redirectStateFiles(t)
			p := newPostures(&StartCmd{DNSRedirect: true}, "6.6.141", false, slog.New(slog.DiscardHandler))
			require.NoError(t, r.settle(p))
			line := p.lines()[0]
			assert.Equal(t, c.applied, line.Applied)
			assert.Equal(t, r.err.Error(), line.Reason, "the reasons must fit whole")
		})
	}
}
