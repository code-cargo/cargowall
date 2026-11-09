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

package bpf

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// The tests below reuse one socket for a second connection to the same
// destination, which keeps its cookie and so its L7 flow key: each
// connection must still be adjudicated on its own.
// TestOriginL7RealSocketReconnectReadjudicated: a socket whose connection was
// ALLOWED, then disconnected (connect with AF_UNSPEC) and connected again to
// the same destination, keeps its cookie and so its flow key. The new
// connection's SYN must park the flow NEED_HELLO, so its own ClientHello is
// adjudicated rather than riding the old connection's verdict.
func TestOriginL7RealSocketReconnectReadjudicated(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeEnforce, 443, L7ScopeTLS)
	got := acceptReads(t, h.ln)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	peer := &unix.SockaddrInet4{Port: int(h.port)}
	copy(peer.Addr[:], h.hostIP.To4())
	require.NoError(t, unix.Connect(fd, peer))
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)

	hello := snitest.BuildClientHello("allowed.example")
	_, err = unix.Write(fd, hello)
	require.NoError(t, err)
	key := readL7SampleFor(t, h.rd, cookie).FlowKey()
	require.NoError(t, h.objs.MapL7Flow.Put(key, OriginBpfL7FlowVal{State: l7StateAllowed}),
		"the oracle's ALLOWED verdict")
	requireReceived(t, got, hello, "the allowed hello, delivered by its retransmit")

	// connect(2) with an AF_UNSPEC address disconnects a TCP socket.
	var unspec [unix.SizeofSockaddrInet4]byte
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&unspec[0])), uintptr(len(unspec)))
	require.Zero(t, errno, "disconnect")
	require.NoError(t, unix.Connect(fd, peer))

	var fv OriginBpfL7FlowVal
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StateNeedHello), fv.State, "the new connection's SYN must park NEED_HELLO")

	other := snitest.BuildClientHello("other.example")
	_, err = unix.Write(fd, other)
	require.NoError(t, err)
	ev := readL7SampleFor(t, h.rd, cookie)
	require.Zero(t, ev.Flags&l7PuntFlagRefused, "the new hello is punted for adjudication")
	require.Equal(t, other, append([]byte(nil), ev.Payload[:ev.PayloadLen]...))
	select {
	case b := <-got:
		t.Fatalf("the new connection's hello was delivered before any verdict: %d bytes", len(b))
	case <-time.After(500 * time.Millisecond):
	}
}

// TestOriginL7RealSocketReconnectFastOpenReadjudicated is the same for a
// reconnect whose SYN carries the new ClientHello (TCP Fast Open): the SYN's
// data is the new connection's first flight, adjudicated on its own.
func TestOriginL7RealSocketReconnectFastOpenReadjudicated(t *testing.T) {
	h := newL7FastOpenHarness(t, l7ModeEnforce)
	got := acceptReads(t, h.ln)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	peer := &unix.SockaddrInet4{Port: int(h.port)}
	copy(peer.Addr[:], h.hostIP.To4())
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)

	// The first connection asks for a Fast Open cookie; its hello follows the
	// handshake and is ALLOWED.
	hello := snitest.BuildClientHello("allowed.example")
	require.NoError(t, unix.Sendto(fd, hello, unix.MSG_FASTOPEN, peer))
	key := readL7SampleFor(t, h.rd, cookie).FlowKey()
	require.NoError(t, h.objs.MapL7Flow.Put(key, OriginBpfL7FlowVal{State: l7StateAllowed}),
		"the oracle's ALLOWED verdict")
	requireReceived(t, got, hello, "the allowed hello, delivered by its retransmit")
	info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	require.NoError(t, err)
	const tcpiOptSynData = 0x20 // TCPI_OPT_SYN_DATA, linux/tcp.h
	if info.Options&tcpiOptSynData != 0 {
		t.Skip("the first connection already carried data in its SYN; no cookie exchange to rely on")
	}

	// The first connection's own punts (its hello's, before the verdict)
	// may still sit in the ring.
	drainL7SamplesFor(t, h.rd, cookie, 300*time.Millisecond)

	var unspec [unix.SizeofSockaddrInet4]byte
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&unspec[0])), uintptr(len(unspec)))
	require.Zero(t, errno, "disconnect")

	// With the cookie cached, the reconnect's SYN carries the new hello.
	other := snitest.BuildClientHello("other.example")
	require.NoError(t, unix.Sendto(fd, other, unix.MSG_FASTOPEN, peer))
	ev := readL7SampleFor(t, h.rd, cookie)
	require.Zero(t, ev.Flags&l7PuntFlagRefused, "the SYN's hello is punted for adjudication")
	require.Equal(t, other, append([]byte(nil), ev.Payload[:ev.PayloadLen]...))
	select {
	case b := <-got:
		t.Fatalf("the reconnect's hello was delivered before any verdict: %d bytes", len(b))
	case <-time.After(500 * time.Millisecond):
	}
}

// drainL7SamplesFor discards the samples for cookie that reach the ring
// within d, logging each.
func drainL7SamplesFor(t *testing.T, rd *ringbuf.Reader, cookie uint64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(50 * time.Millisecond))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		require.NoError(t, err)
		ev, ok := L7EventFromBytes(rec.RawSample)
		require.True(t, ok)
		if ev.Cookie == cookie {
			t.Logf("drained a sample: flags %#x, seq %d, %d bytes", ev.Flags, ev.Seq, ev.PayloadLen)
		}
	}
}

// newL7FastOpenHarness is the real-socket harness with TCP Fast Open turned on
// for client and server, restored when the test ends.
func newL7FastOpenHarness(t *testing.T, l7mode uint8) *l7RealSocketHarness {
	t.Helper()
	const sysctl = "/proc/sys/net/ipv4/tcp_fastopen"
	old, err := os.ReadFile(sysctl)
	if err != nil {
		t.Skipf("no %s: %v", sysctl, err)
	}
	require.NoError(t, os.WriteFile(sysctl, []byte("3"), 0o644), "enable Fast Open for client and server")
	t.Cleanup(func() { _ = os.WriteFile(sysctl, old, 0o644) })

	h := newL7RealSocketHarness(t, l7mode, 443, L7ScopeTLS)
	raw, err := h.ln.(*net.TCPListener).SyscallConn()
	require.NoError(t, err)
	require.NoError(t, raw.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 16)
	}))
	require.NoError(t, err)
	return h
}
