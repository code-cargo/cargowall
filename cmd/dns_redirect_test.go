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

	"github.com/code-cargo/cargowall/pkg/network"
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

// Container DNS reaches the proxy when the proxy holds its listener on the
// docker bridge. The reason it does not names the address once, and why:
// the bind error repeats the address, and only its protocol and cause are
// kept.
func TestBridgeGap(t *testing.T) {
	d := &dockerDNS{bridgeIP: "172.17.0.1"}
	for _, c := range []struct {
		name string
		err  error
		gap  string
	}{
		{name: "bound"},
		{name: "port held", err: listenErr("tcp4", "172.17.0.1:53", unix.EADDRINUSE), gap: "another process holds 172.17.0.1:53"},
		{
			name: "address gone", err: listenErr("udp4", "172.17.0.1:53", unix.EADDRNOTAVAIL),
			gap: "the proxy cannot listen on 172.17.0.1:53: udp4 bind: cannot assign requested address",
		},
		{
			name: "not a net error", err: fmt.Errorf("udp4: %w", unix.EACCES),
			gap: "the proxy cannot listen on 172.17.0.1:53: udp4: permission denied",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.gap, bridgeGap(d, c.err))
		})
	}
}

// The redirect sends container DNS to the bridge listener only once the
// proxy holds it, and otherwise leaves the bridge without a rule, neither
// DNAT nor drop; IPv6 DNS likewise goes to the IPv6 listener only once that
// is held. No bridge is no bridge rule.
func TestRedirectSpec(t *testing.T) {
	held := listenErr("udp4", "172.17.0.1:53", unix.EADDRINUSE)
	held6 := listenErr("udp6", "[::1]:53", unix.EADDRINUSE)
	for _, c := range []struct {
		name               string
		ipv6Err, bridgeErr error
		bridgeIP           string
		want               network.RedirectSpec
	}{
		{"whole", nil, nil, "172.17.0.1", network.RedirectSpec{IPv6: true, BridgeIP: "172.17.0.1"}},
		{"bridge listener unbound", nil, held, "172.17.0.1", network.RedirectSpec{IPv6: true}},
		{"IPv6 listener unbound", held6, nil, "172.17.0.1", network.RedirectSpec{BridgeIP: "172.17.0.1"}},
		{"neither bound", held6, held, "172.17.0.1", network.RedirectSpec{}},
		{"no bridge", nil, nil, "", network.RedirectSpec{IPv6: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, redirectSpec(c.ipv6Err, c.bridgeIP, c.bridgeErr))
		})
	}
}

// A redirect in place but not whole is active, so the resolved cache flush
// it gates still runs, and is a lost posture: fatal under an enforcing
// policy, recorded under an auditing one. It is recorded at what it still
// covers, with every gap's reason: ipv4 when IPv6 DNS goes around the
// proxy, host when container DNS does, for want of the bridge listener,
// host-ipv4 for both.
func TestDNSRedirect_PartialIsALoss(t *testing.T) {
	const (
		ipv6   = "loopback has no IPv6 address for the proxy to listen on"
		bridge = "another process holds 172.17.0.1:53"
	)
	ipv6Reason := "IPv6 DNS is not redirected: " + ipv6
	bridgeReason := "container DNS is not redirected: " + bridge
	logger := slog.New(slog.DiscardHandler)
	for _, c := range []struct {
		name, ipv6, bridge, applied string
		reason                      string
	}{
		{"IPv6 gap", ipv6, "", "ipv4", ipv6Reason},
		{"bridge gap", "", bridge, "host", bridgeReason},
		{"both", ipv6, bridge, "host-ipv4", bridgeReason + "; " + ipv6Reason},
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
				assert.Equal(t, c.reason, line.Reason)
			}
		})
	}
	assert.False(t, (&dnsRedirect{err: errors.New("x")}).isActive(), "a redirect that failed outright is not active")
	whole := installed("", "", logger)
	assert.True(t, whole.isActive())
	assert.NoError(t, whole.settle(nil), "a whole redirect has nothing to report")
}

// The record keeps only the first maxPostureReasonBytes of a reason, and
// both gaps' causes survive it at their longest: the kernel refusing the
// inet table, with its hint, and the longest bridge address the bind cannot
// assign.
func TestDNSRedirect_BothGapsKeepTheirCauses(t *testing.T) {
	refused := errors.New("nftables: installing table inet cargowall: netlink receive: address family not supported " +
		"by protocol (the kernel may lack inet tables or IPv6 nat: CONFIG_NF_TABLES_INET, or nf_nat for IPv6)")
	d := &dockerDNS{bridgeIP: "255.255.255.255"}
	r := installed(ipv6Gap(nil, refused, func() bool { return true }),
		bridgeGap(d, listenErr("udp4", d.listenAddr(), unix.EADDRNOTAVAIL)), slog.New(slog.DiscardHandler))
	require.Greater(t, len(r.err.Error()), maxPostureReasonBytes, "the worst case must be one the record cuts")

	redirectStateFiles(t)
	p := newPostures(&StartCmd{DNSRedirect: true}, "6.6.141", false, slog.New(slog.DiscardHandler))
	require.NoError(t, r.settle(p))
	line := p.lines()[0]
	assert.Equal(t, "host-ipv4", line.Applied)
	assert.Contains(t, line.Reason, "cannot assign requested address")
	assert.Contains(t, line.Reason, "address family not supported by protocol")
}
