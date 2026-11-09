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
)

// The real-socket tests below open their connection with L7 off, so it has no
// flow entry when L7 turns on: the shape of a connection that predates attach.

const (
	statGateNoState  = 8
	statContinuation = 10
)

// bytesAcked reads the socket's tcpi_bytes_acked, which counts the SYN's byte.
func bytesAcked(t *testing.T, conn *net.TCPConn) uint64 {
	t.Helper()
	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	var info *unix.TCPInfo
	require.NoError(t, raw.Control(func(fd uintptr) {
		info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}))
	require.NoError(t, err)
	return info.Bytes_acked
}

// setL7Mode switches L7 on (or off) under a live connection.
func (h *l7RealSocketHarness) setL7Mode(t *testing.T, mode uint8) {
	t.Helper()
	require.NoError(t, h.objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), mode))
}

// requireNoL7SampleFor fails if a sample for cookie reaches the ring within d.
// Samples for other sockets are skipped: the harness hooks the root cgroup.
func requireNoL7SampleFor(t *testing.T, rd *ringbuf.Reader, cookie uint64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		require.NoError(t, err)
		ev, ok := L7EventFromBytes(rec.RawSample)
		require.True(t, ok)
		require.NotEqual(t, cookie, ev.Cookie, "no sample expected for the test socket (flags %#x)", ev.Flags)
	}
}

// acceptReads serves every connection on ln, sending what each read returns
// and acknowledging each connection's first read with one byte.
func acceptReads(t *testing.T, ln net.Listener) <-chan []byte {
	t.Helper()
	got := make(chan []byte, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for first := true; ; first = false {
					_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
					n, err := c.Read(buf)
					if n > 0 {
						got <- append([]byte(nil), buf[:n]...)
						if first {
							_, _ = c.Write([]byte{1})
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return got
}

func requireReceived(t *testing.T, got <-chan []byte, want []byte, why string) {
	t.Helper()
	var all []byte
	deadline := time.After(5 * time.Second)
	for len(all) < len(want) {
		select {
		case b := <-got:
			all = append(all, b...)
		case <-deadline:
			t.Fatalf("%s: the server got %d of %d bytes within 5s", why, len(all), len(want))
		}
	}
	require.Equal(t, want, all, why)
}

// TestOriginL7RealSocketContinuationRides: a TLS connection opened before L7
// turned on, which has had data acknowledged, keeps working under enforce
// when a segment starts mid-record. Judged by its first byte, that segment
// and every retransmit of it would be dropped and the connection would hang.
// Every segment of it rides, with no flow entry written and no refusal
// record.
func TestOriginL7RealSocketContinuationRides(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeOff, 443, L7ScopeTLS)
	got := acceptReads(t, h.ln)
	conn, cookie, key := h.dial(t)

	warm := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	_, err := conn.Write(warm)
	require.NoError(t, err)
	requireReceived(t, got, warm, "the warm-up record")
	require.Equal(t, []byte{1}, readFull(conn, 1), "the server's acknowledgment")
	require.Greater(t, bytesAcked(t, conn), uint64(1), "the warm-up must have been acknowledged")

	var fv OriginBpfL7FlowVal
	require.Error(t, h.objs.MapL7Flow.Lookup(key, &fv), "with L7 off the connection has no entry")

	h.setL7Mode(t, l7ModeEnforce)
	beforeRide := l7StatSum(t, h.objs, statContinuation)
	beforeNoState := l7StatSum(t, h.objs, statGateNoState)

	// The middle of a record: an arbitrary first byte, not a record header.
	mid := []byte("ciphertext from the middle of a record")
	_, err = conn.Write(mid)
	require.NoError(t, err)
	requireReceived(t, got, mid, "a mid-record segment of a connection L7 never saw open")
	require.Greater(t, l7StatSum(t, h.objs, statContinuation), beforeRide, "the segment rode as a continuation")

	// So does every later segment, even one that is not TLS at all.
	next := []byte("SSH-2.0-OpenSSH_9.7\r\n")
	_, err = conn.Write(next)
	require.NoError(t, err)
	requireReceived(t, got, next, "a later segment of the same connection")
	require.Error(t, h.objs.MapL7Flow.Lookup(key, &fv), "riding writes no flow entry")
	require.Equal(t, beforeNoState, l7StatSum(t, h.objs, statGateNoState), "nothing was refused")
	requireNoL7SampleFor(t, h.rd, cookie, 300*time.Millisecond)
}

// TestOriginL7RealSocketNoStateRefusalRecordedOnce: on a connection with no
// entry whose socket has had no data acknowledged (opened just before L7
// turned on), bytes that are not TLS are refused as before, and now leave a
// record carrying the NO_STATE flag, once per flow per interval, so their
// retransmits don't each add one. Under observe they pass, recorded the same
// way with the OBSERVE flag.
func TestOriginL7RealSocketNoStateRefusalRecordedOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    uint8
		deliver bool
	}{
		{"enforce", l7ModeEnforce, false},
		{"observe", l7ModeObserve, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newL7RealSocketHarness(t, l7ModeOff, 443, L7ScopeTLS)
			got := acceptReads(t, h.ln)
			conn, cookie, key := h.dial(t)
			require.LessOrEqual(t, bytesAcked(t, conn), uint64(1), "no data acknowledged yet")

			h.setL7Mode(t, tc.mode)
			beforeNoState := l7StatSum(t, h.objs, statGateNoState)

			banner := []byte("SSH-2.0-OpenSSH_9.7\r\n")
			_, err := conn.Write(banner)
			require.NoError(t, err)

			ev := readL7SampleFor(t, h.rd, cookie)
			require.NotZero(t, ev.Flags&l7PuntFlagRefused, "a no-state refusal must emit a refusal record")
			require.NotZero(t, ev.Flags&l7PuntFlagNoState, "the record must say the flow had no entry")
			require.Equal(t, key, ev.FlowKey())
			require.Equal(t, banner, append([]byte(nil), ev.Payload[:ev.PayloadLen]...),
				"the snippet must be the refused bytes")

			var fv OriginBpfL7FlowVal
			require.Error(t, h.objs.MapL7Flow.Lookup(key, &fv), "a refusal writes no flow state")

			if tc.deliver {
				require.NotZero(t, ev.Flags&l7PuntFlagObserve, "observe posture on the record")
				requireReceived(t, got, banner, "observe passes the refused bytes")
				return
			}
			require.Zero(t, ev.Flags&l7PuntFlagObserve, "enforce posture on the record")

			// The drop's retransmits are refused too, without a second record.
			requireNoL7SampleFor(t, h.rd, cookie, 1500*time.Millisecond)
			require.GreaterOrEqual(t, l7StatSum(t, h.objs, statGateNoState), beforeNoState+2,
				"the retransmits must have been refused as well")
			select {
			case b := <-got:
				t.Fatalf("enforce delivered %q", b)
			default:
			}
		})
	}
}

// TestOriginL7RealSocketHTTPContinuationAdjudicated: riding is for TLS. A
// plaintext HTTP connection L7 never saw open still has a new request line
// adjudicated by its Host, so it is punted, not set RIDING.
func TestOriginL7RealSocketHTTPContinuationAdjudicated(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeOff, 80, L7ScopeHTTP)
	got := acceptReads(t, h.ln)
	conn, cookie, key := h.dial(t)

	warm := []byte("GET / HTTP/1.1\r\nHost: warm.example\r\n\r\n")
	_, err := conn.Write(warm)
	require.NoError(t, err)
	requireReceived(t, got, warm, "the warm-up request")
	require.Equal(t, []byte{1}, readFull(conn, 1), "the server's acknowledgment")
	require.Greater(t, bytesAcked(t, conn), uint64(1))

	h.setL7Mode(t, l7ModeEnforce)
	_, err = conn.Write([]byte("GET /next HTTP/1.1\r\nHost: next.example\r\n\r\n"))
	require.NoError(t, err)

	ev := readL7SampleFor(t, h.rd, cookie)
	require.Zero(t, ev.Flags&l7PuntFlagRefused, "a request line is punted for its Host, not refused")
	require.NotZero(t, ev.Flags&l7PuntFlagNoState, "the punt must say the flow had no entry")
	var fv OriginBpfL7FlowVal
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State, "an HTTP request line on it is adjudicated")
}

// TestOriginL7RealSocketReconnectStartsOver: a socket that has had data
// acknowledged, then disconnects (connect with AF_UNSPEC) and connects again
// while L7 is off, keeps its cookie but not its acknowledged bytes. Its first
// flight on the new connection is judged by its first byte, not let through
// as a continuation of the old one.
func TestOriginL7RealSocketReconnectStartsOver(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeOff, 443, L7ScopeTLS)
	got := acceptReads(t, h.ln)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	peer := &unix.SockaddrInet4{Port: int(h.port)}
	copy(peer.Addr[:], h.hostIP.To4())
	require.NoError(t, unix.Connect(fd, peer))
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)
	acked := func() uint64 {
		info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
		require.NoError(t, err)
		return info.Bytes_acked
	}

	warm := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	_, err = unix.Write(fd, warm)
	require.NoError(t, err)
	requireReceived(t, got, warm, "the warm-up record")
	ack := make([]byte, 1)
	_, err = unix.Read(fd, ack)
	require.NoError(t, err)
	require.Greater(t, acked(), uint64(1), "the warm-up must have been acknowledged")

	// connect(2) with an AF_UNSPEC address disconnects a TCP socket.
	var unspec [unix.SizeofSockaddrInet4]byte
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&unspec[0])), uintptr(len(unspec)))
	require.Zero(t, errno, "disconnect")
	require.LessOrEqual(t, acked(), uint64(1), "a disconnect clears the acknowledged bytes")
	require.NoError(t, unix.Connect(fd, peer))
	again, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)
	require.Equal(t, cookie, again, "test premise: the reconnected socket keeps its cookie")

	h.setL7Mode(t, l7ModeEnforce)
	banner := []byte("SSH-2.0-OpenSSH_9.7\r\n")
	_, err = unix.Write(fd, banner)
	require.NoError(t, err)
	ev := readL7SampleFor(t, h.rd, cookie)
	require.NotZero(t, ev.Flags&l7PuntFlagRefused, "the new connection's first flight is refused, not ridden")
	require.NotZero(t, ev.Flags&l7PuntFlagNoState)
	select {
	case b := <-got:
		t.Fatalf("enforce delivered %q", b)
	case <-time.After(500 * time.Millisecond):
	}
}
