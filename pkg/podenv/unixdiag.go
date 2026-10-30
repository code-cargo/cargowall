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

package podenv

// Who holds the other end of a unix socket connection: unix_diag
// (NETLINK_SOCK_DIAG, AF_UNIX) gives a connected socket's peer by inode,
// and a process's descriptors name the sockets it holds by inode too.
// SO_PEERCRED gives only the pid that made the listener, which a service
// manager may have made and handed to the daemon it activated.

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/sockdiag"
)

// struct unix_diag_req and struct unix_diag_msg, and the attributes asked
// for, from linux/unix_diag.h.
const (
	sizeofUnixDiagReq = 24
	sizeofUnixDiagMsg = 16
	udiagShowName     = 0x01 // UDIAG_SHOW_NAME
	udiagShowPeer     = 0x04 // UDIAG_SHOW_PEER
	unixDiagName      = 0    // UNIX_DIAG_NAME
	unixDiagPeer      = 2    // UNIX_DIAG_PEER
	unixDiagShutdown  = 6    // UNIX_DIAG_SHUTDOWN, always given
	// tcpEstablished is a connected unix socket's state (TCP_ESTABLISHED).
	tcpEstablished = 1
	// shutdownBoth is sk_shutdown once both directions are shut: so the
	// peer leaves it when it closes.
	shutdownBoth = 3
)

// unixSock is one socket unix_diag reports.
type unixSock struct {
	ino uint64
	// peer is the socket at the other end of its connection, 0 for none.
	peer   uint64
	stream bool
	// named is bound to an address, as a listener is, and every
	// connection it accepts, which carries the listener's.
	named bool
	// closed: both directions are shut, as the peer leaves them when it
	// closes its end.
	closed bool
}

// unixDiag asks unix_diag about the unix sockets of a network namespace,
// the one netns names (a /proc/<pid>/ns/net), or ours for "": the socket
// whose inode is ino, or, for 0, every connected one.
func unixDiag(netns string, ino uint64) ([]unixSock, error) {
	if ino > math.MaxUint32 {
		return nil, fmt.Errorf("socket inode %d is past unix_diag's 32 bits", ino)
	}
	req := make([]byte, sizeofUnixDiagReq)
	req[0] = unix.AF_UNIX
	if ino == 0 {
		binary.NativeEndian.PutUint32(req[4:8], 1<<tcpEstablished)
	} else {
		binary.NativeEndian.PutUint32(req[8:12], uint32(ino))
	}
	binary.NativeEndian.PutUint32(req[12:16], udiagShowName|udiagShowPeer)
	// No cookie to check: INET_DIAG_NOCOOKIE in both halves.
	binary.NativeEndian.PutUint32(req[16:20], math.MaxUint32)
	binary.NativeEndian.PutUint32(req[20:24], math.MaxUint32)
	msgs, err := sockdiag.Request(netns, req, ino == 0, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("unix_diag: %w", err)
	}
	socks := make([]unixSock, 0, len(msgs))
	for _, m := range msgs {
		if len(m.Data) < sizeofUnixDiagMsg {
			continue
		}
		s := unixSock{stream: m.Data[1] == unix.SOCK_STREAM, ino: uint64(binary.NativeEndian.Uint32(m.Data[4:8]))}
		ad, err := netlink.NewAttributeDecoder(m.Data[sizeofUnixDiagMsg:])
		if err != nil {
			return nil, fmt.Errorf("unix_diag: %w", err)
		}
		for ad.Next() {
			switch ad.Type() {
			case unixDiagName:
				s.named = len(ad.Bytes()) > 0
			case unixDiagPeer:
				s.peer = uint64(ad.Uint32())
			case unixDiagShutdown:
				s.closed = ad.Uint8() == shutdownBoth
			}
		}
		if err := ad.Err(); err != nil {
			return nil, fmt.Errorf("unix_diag: %w", err)
		}
		socks = append(socks, s)
	}
	return socks, nil
}

// connPeer is the inode of the socket at the other end of conn, which
// for a connection to a listener is the one it accepted it as.
func connPeer(conn *net.UnixConn) (uint64, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var st unix.Stat_t
	var statErr error
	if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &st) }); err != nil {
		return 0, err
	}
	if statErr != nil {
		return 0, statErr
	}
	socks, err := unixDiag("", st.Ino)
	if err != nil {
		return 0, err
	}
	if len(socks) != 1 || socks[0].peer == 0 {
		return 0, fmt.Errorf("unix_diag shows no peer for socket %d", st.Ino)
	}
	return socks[0].peer, nil
}
