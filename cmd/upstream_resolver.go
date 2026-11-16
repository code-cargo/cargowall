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
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/network"
)

// newUpstreamReverseResolver resolves straight to the DNS upstream, marking
// its socket (DNSProxyFWMark) so the redirect exempts it and it bypasses the
// proxy. cargowall's own reverse and confirming lookups use it, the lazy
// ones on denials and the startup round over existing connections: the
// proxy's filter answers a reverse lookup only for an address the run
// allows, and would refuse them, as would systemd-resolved's stub, whose
// own upstream query the redirect sends through the proxy.
func newUpstreamReverseResolver(upstream string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, proto, _ string) (net.Conn, error) {
			d := &net.Dialer{
				Control: func(_, _ string, c syscall.RawConn) error {
					var sErr error
					if err := c.Control(func(fd uintptr) {
						sErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_MARK, network.DNSProxyFWMark)
					}); err != nil {
						return err
					}
					return sErr
				},
			}
			return d.DialContext(ctx, proto, upstream)
		},
	}
}
