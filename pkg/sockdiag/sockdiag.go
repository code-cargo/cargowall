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

// Package sockdiag sends NETLINK_SOCK_DIAG requests: pkg/steps reads a
// client's socket cookie from the inet socket tables with it, and podenv
// reads the other end of a unix socket's connection.
package sockdiag

import (
	"fmt"
	"os"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Request sends one SOCK_DIAG_BY_FAMILY request with body req, a dump of a
// table when dump is set, from the network namespace netns names (a
// /proc/<pid>/ns/net, or "" for ours), and returns the replies, within
// timeout. Execute aggregates a multipart dump and surfaces NLMSG_ERROR,
// so an error means the request failed, not that nothing matched: netlink
// unavailable (a kernel without the family's diag module), the namespace
// not entered, or the deadline passed.
func Request(netns string, req []byte, dump bool, timeout time.Duration) ([]netlink.Message, error) {
	cfg := &netlink.Config{}
	if netns != "" {
		f, err := os.Open(netns)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		cfg.NetNS = int(f.Fd())
	}
	conn, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial sock_diag netlink: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set netlink deadline: %w", err)
	}
	flags := netlink.Request
	if dump {
		flags |= netlink.Dump
	}
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.SOCK_DIAG_BY_FAMILY), Flags: flags},
		Data:   req,
	})
	if err != nil {
		return nil, err
	}
	return msgs, nil
}
