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
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// readL7SampleFor drains punt samples until one for the given socket cookie
// arrives — the root-cgroup attachment observes every flow on the host, so
// unrelated samples are skipped, exactly as TestOriginRealSocket scans origin
// records. It POLLS on a short deadline instead of one long blocking Read:
// the kernel's adaptive ringbuf notification is best-effort, and a lone
// commit's missed wakeup would otherwise stall a blocking read for its whole
// deadline even though the sample is sitting in the ring (Read drains pending
// samples after a deadline tick).
func readL7SampleFor(t *testing.T, rd *ringbuf.Reader, cookie uint64) *L7Event {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		require.NoError(t, err, "reading punt samples")
		ev, ok := L7EventFromBytes(rec.RawSample)
		require.True(t, ok)
		if ev.Cookie == cookie {
			return ev
		}
	}
	t.Fatal("no punt sample for the test socket within 10s")
	return nil
}

// l7RealSocketHarness is the shared rig for the real-socket L7 tests: the
// origin collection attached at the real root cgroup, a listener owning
// hostIP:port (the scope bits are port-specific — TLS means TCP/443, HTTP
// TCP/80 — so the listener must own the real port), and a punt-ring reader.
// Origin mode stays observe and only this one destination is ever L7-scoped,
// so the root-cgroup attachment cannot affect host traffic beyond our own
// test flows.
type l7RealSocketHarness struct {
	objs   *OriginBpfObjects
	hostIP net.IP
	port   uint16
	ln     net.Listener
	rd     *ringbuf.Reader
}

func newL7RealSocketHarness(t *testing.T, l7mode uint8, port uint16, scope uint8) *l7RealSocketHarness {
	t.Helper()
	objs := loadOriginObjects(t)
	setOriginMode(t, objs, originModeObserve)
	require.NoError(t, objs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), l7mode))

	// The host's own address: rides lo (which stays uncarved — the lo
	// carve-out config is off, as in every PROG_TEST_RUN test) and never
	// leaves the machine.
	hostIP := hostOwnIPv4(t)
	require.NoError(t, objs.MapL7Scope.Put(binary.NativeEndian.Uint32(hostIP), scope))

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgOriginEgress,
	})
	if err != nil {
		t.Skipf("cannot attach cgroup_skb/egress at root cgroup: %v", err)
	}
	t.Cleanup(func() { lnk.Close() })

	ln, err := net.Listen("tcp4", net.JoinHostPort(hostIP.String(), strconv.Itoa(int(port))))
	if err != nil {
		t.Skipf("cannot listen on %s:%d: %v", hostIP, port, err)
	}
	t.Cleanup(func() { ln.Close() })

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	return &l7RealSocketHarness{objs: objs, hostIP: hostIP, port: port, ln: ln, rd: rd}
}

// dial opens a client connection and returns it with its SO_COOKIE and the
// map_l7_flow key the kernel derives for it (mirrors l7_flow_key_init: v4
// destination as a host-order u32 in the low bytes).
func (h *l7RealSocketHarness) dial(t *testing.T) (*net.TCPConn, uint64, OriginBpfL7FlowKey) {
	t.Helper()
	conn, err := net.Dial("tcp4", h.ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	var cookie uint64
	raw, err := conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	require.NoError(t, raw.Control(func(fd uintptr) {
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}))
	require.NoError(t, err)
	require.NotZero(t, cookie)

	var key OriginBpfL7FlowKey
	key.Cookie = cookie
	binary.NativeEndian.PutUint32(key.Dst[0:4], binary.BigEndian.Uint32(h.hostIP))
	key.DstPort = h.port
	key.IpProto = 6
	key.IpVersion = 4
	return conn.(*net.TCPConn), cookie, key
}

// readFull reads exactly n bytes from c (or returns what arrived at error).
func readFull(c net.Conn, n int) []byte {
	buf := make([]byte, 0, n)
	tmp := make([]byte, 4096)
	for len(buf) < n {
		r, err := c.Read(tmp)
		buf = append(buf, tmp[:r]...)
		if err != nil {
			break
		}
	}
	return buf
}

// TestOriginL7RealSocketWriteback closes the stable-cookie gap PROG_TEST_RUN
// cannot cover (every Test() call mints a fresh dummy-socket cookie): one real
// socket walks SYN → NEED_HELLO → punted ClientHello → PENDING, then an
// ALLOWED verdict written back on the punted flow's exact key — what the
// oracle does — must let the client's own TCP retransmit machinery deliver
// the hello. This is the end-to-end proof that the writeback admits the
// retransmit of the very flow that punted, under L7 ENFORCE.
func TestOriginL7RealSocketWriteback(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeEnforce, 443, L7ScopeTLS)
	hello := snitest.BuildClientHello("auth.docker.io")

	received := make(chan []byte, 1)
	go func() {
		c, err := h.ln.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		received <- readFull(c, len(hello))
	}()

	conn, cookie, key := h.dial(t)

	// The real SYN parked the flow in NEED_HELLO under the socket's own
	// cookie — the same-flow proof the single-shot tests cannot make.
	var fv OriginBpfL7FlowVal
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv),
		"the connect()'s SYN must have created this socket's flow entry")
	require.Equal(t, uint8(l7StateNeedHello), fv.State, "a SYN must park NEED_HELLO")

	// The hello: punted and dropped, PENDING. NO_STATE must be absent — the
	// SYN's entry was found, on the same flow.
	_, err := conn.Write(hello)
	require.NoError(t, err)
	ev := readL7SampleFor(t, h.rd, cookie)
	require.Zero(t, ev.Flags&l7PuntFlagNoState, "the SYN's NEED_HELLO entry existed")
	require.Zero(t, ev.Flags&l7PuntFlagObserve, "L7 enforce posture")
	require.Equal(t, key, ev.FlowKey(), "the sample must map back to this socket's flow key")
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State, "the punted flow must park PENDING")
	require.GreaterOrEqual(t, fv.Punts, uint8(1), "the punt must consume budget")

	// Nothing was delivered while PENDING: the server has the connection but
	// no payload (the segment was dropped at egress).
	select {
	case got := <-received:
		t.Fatalf("bytes were delivered before any verdict: %d", len(got))
	case <-time.After(300 * time.Millisecond):
	}

	// The writeback the oracle performs, on this flow's exact key. The
	// client's own retransmit machinery must then deliver the hello.
	require.NoError(t, h.objs.MapL7Flow.Put(key, OriginBpfL7FlowVal{State: l7StateAllowed}))
	select {
	case got := <-received:
		require.Equal(t, hello, got, "the full hello must reach the server after the ALLOWED writeback")
	case <-time.After(20 * time.Second):
		t.Fatal("retransmit was not admitted after the ALLOWED writeback")
	}
}

// TestOriginL7RealSocketSplitHello drives the R5 regression shape on one real
// socket: a ClientHello split across two segments, where the second half
// starts mid-record — bytes the identity gate refuses drop-without-punt on a
// stateless flow (TestOriginL7FlowStateMachine) — and MUST be punted here
// because the flow is PENDING and PENDING skips the gate. L7 runs in OBSERVE
// so the first half is delivered and ACKed before the second is written: under
// enforce the un-ACKed halves merge in the client's retransmit queue
// (tcp_retrans_collapse) and the pure mid-record segment never reappears,
// while the punt/dedup/state machinery is mode-independent — only the drop
// posture differs, and enforce's is covered by TestOriginL7RealSocketWriteback.
func TestOriginL7RealSocketSplitHello(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeObserve, 443, L7ScopeTLS)
	hello := snitest.BuildClientHello("auth.docker.io")
	mid := len(hello) / 2

	gotFirst := make(chan []byte, 1)
	gotRest := make(chan []byte, 1)
	go func() {
		c, err := h.ln.Accept()
		if err != nil {
			gotFirst <- nil
			gotRest <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		gotFirst <- readFull(c, mid)
		gotRest <- readFull(c, len(hello)-mid)
	}()

	conn, cookie, key := h.dial(t)

	var fv OriginBpfL7FlowVal
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv),
		"the connect()'s SYN must have created this socket's flow entry")
	require.Equal(t, uint8(l7StateNeedHello), fv.State, "a SYN must park NEED_HELLO")

	// First half: an unfinished hello prefix — punted (OBSERVE posture, so the
	// segment is also delivered), and the flow parks PENDING.
	_, err := conn.Write(hello[:mid])
	require.NoError(t, err)
	ev1 := readL7SampleFor(t, h.rd, cookie)
	require.Zero(t, ev1.Flags&l7PuntFlagNoState, "the SYN's NEED_HELLO entry existed")
	require.NotZero(t, ev1.Flags&l7PuntFlagObserve, "observe posture must be stamped")
	require.Equal(t, uint16(mid), ev1.PayloadLen)
	require.Equal(t, key, ev1.FlowKey(), "the sample must map back to this socket's flow key")
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State, "the punted flow must park PENDING")

	// Wait until the server has the first half — its ACK guarantees the second
	// write becomes its OWN segment rather than joining a retransmit.
	require.Equal(t, hello[:mid], <-gotFirst, "observe must deliver the first half")

	// Second half: mid-record bytes on the SAME, PENDING flow. The identity
	// gate must be skipped and the segment punted — the handoff the oracle's
	// reassembly depends on. Its sequence pins it as the continuation.
	_, err = conn.Write(hello[mid:])
	require.NoError(t, err)
	ev2 := readL7SampleFor(t, h.rd, cookie)
	require.Equal(t, ev1.Seq+uint32(mid), ev2.Seq, "the punt must be the continuation segment")
	require.Equal(t, uint16(len(hello)-mid), ev2.PayloadLen)
	require.Equal(t, hello[mid:], append([]byte(nil), ev2.Payload[:ev2.PayloadLen]...),
		"the mid-record bytes must be punted verbatim, not dropped unpunted")
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State, "still PENDING — no verdict was written")
	require.GreaterOrEqual(t, fv.Punts, uint8(2), "both halves must have consumed punt budget")

	require.Equal(t, hello[mid:], <-gotRest, "observe must deliver the second half")
}

// TestOriginL7RealSocketHTTPPrefix pins the NEED_HELLO arm of the HTTP
// request-line classifier on a real flow: a first flight that is a method
// token or a proper prefix of one ("GET /he", 7 bytes) must punt and park
// PENDING — a classifier miss on a NEED_HELLO flow is a drop with no punt
// and no audit record, unreachable by the assembler. The continuation then
// rides the PENDING gate-skip exactly as the split TLS hello does. Observe
// mode for the same reason as
// TestOriginL7RealSocketSplitHello: the first segment must be delivered and
// ACKed so the continuation is its own segment rather than a collapsed
// retransmit.
func TestOriginL7RealSocketHTTPPrefix(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeObserve, 80, L7ScopeHTTP)
	req := []byte("GET /hello HTTP/1.1\r\nHost: registry.example\r\n\r\n")
	const prefix = 7 // "GET /he" — a request line cut mid-target

	gotFirst := make(chan []byte, 1)
	gotRest := make(chan []byte, 1)
	go func() {
		c, err := h.ln.Accept()
		if err != nil {
			gotFirst <- nil
			gotRest <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		gotFirst <- readFull(c, prefix)
		gotRest <- readFull(c, len(req)-prefix)
	}()

	conn, cookie, key := h.dial(t)

	var fv OriginBpfL7FlowVal
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv),
		"the connect()'s SYN must have created this socket's flow entry")
	require.Equal(t, uint8(l7StateNeedHello), fv.State, "a SYN must park NEED_HELLO")

	// The short first flight: a request-line prefix on the NEED_HELLO flow
	// must OPEN adjudication — punt with the bytes verbatim, park PENDING.
	_, err := conn.Write(req[:prefix])
	require.NoError(t, err)
	ev1 := readL7SampleFor(t, h.rd, cookie)
	require.Zero(t, ev1.Flags&l7PuntFlagNoState, "the SYN's NEED_HELLO entry existed")
	require.Equal(t, uint16(prefix), ev1.PayloadLen)
	require.Equal(t, req[:prefix], append([]byte(nil), ev1.Payload[:ev1.PayloadLen]...))
	require.Equal(t, key, ev1.FlowKey(), "the sample must map back to this socket's flow key")
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State,
		"a NEED_HELLO request-line prefix must punt and park PENDING, not fail closed unpunted")

	require.Equal(t, req[:prefix], <-gotFirst, "observe must deliver the prefix")

	// The continuation on the now-PENDING flow: gate skipped, punted.
	_, err = conn.Write(req[prefix:])
	require.NoError(t, err)
	ev2 := readL7SampleFor(t, h.rd, cookie)
	require.Equal(t, ev1.Seq+uint32(prefix), ev2.Seq, "the punt must be the continuation segment")
	require.Equal(t, uint16(len(req)-prefix), ev2.PayloadLen)
	require.Equal(t, req[prefix:], append([]byte(nil), ev2.Payload[:ev2.PayloadLen]...),
		"the continuation must be punted verbatim for reassembly")
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State, "still PENDING — no verdict was written")

	require.Equal(t, req[prefix:], <-gotRest, "observe must deliver the continuation")
}

// TestOriginL7RealSocketFreshRefusalRecorded proves the FRESH identity-gate
// refusal path that PROG_TEST_RUN cannot (its per-call cookie can't carry a
// SYN's NEED_HELLO into the data segment): one real socket sends non-TLS bytes
// on a scoped 443 after its SYN parked NEED_HELLO, and the refusal must emit an
// L7_PUNT_F_REFUSED audit record (the counter-only refusal's missing trace)
// carrying the refused snippet and mapping back to this socket's flow key.
// Enforce, so the drop posture is stamped.
func TestOriginL7RealSocketFreshRefusalRecorded(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeEnforce, 443, L7ScopeTLS)
	banner := []byte("SSH-2.0-OpenSSH_9.7\r\n")

	go func() {
		c, err := h.ln.Accept()
		if err == nil {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_ = readFull(c, len(banner)) // never delivered under enforce; drain if it is
		}
	}()

	conn, cookie, key := h.dial(t)

	var fv OriginBpfL7FlowVal
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv), "the SYN must create the flow entry")
	require.Equal(t, uint8(l7StateNeedHello), fv.State, "a SYN must park NEED_HELLO")

	_, err := conn.Write(banner)
	require.NoError(t, err)

	ev := readL7SampleFor(t, h.rd, cookie)
	require.NotZero(t, ev.Flags&l7PuntFlagRefused, "a fresh non-TLS first flight must emit a refusal record")
	require.Zero(t, ev.Flags&l7PuntFlagObserve, "enforce posture on the refusal record")
	require.Equal(t, key, ev.FlowKey(), "the refusal record must map back to this socket's flow key")
	require.LessOrEqual(t, int(ev.PayloadLen), 64, "a refusal carries only a snippet")
	require.Equal(t, banner[:int(ev.PayloadLen)], append([]byte(nil), ev.Payload[:ev.PayloadLen]...),
		"the refusal snippet must be the refused bytes verbatim")

	// A refusal opens no adjudication cycle: the flow stays NEED_HELLO, not
	// PENDING (nothing was punted for a verdict).
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StateNeedHello), fv.State, "a refusal must not park the flow PENDING")
}

// quicInitialDatagram builds a minimal Initial-shaped long header of the
// given version with the given Destination CID — enough for the kernel's
// type/version/DCID walk; the payload past the CIDs is filler (the oracle,
// not exercised here, would reject it). The type bits are version-correct:
// Initial is long-header type 00 for v1/draft-29 and 01 for v2.
func quicInitialDatagram(version uint32, dcid []byte) []byte {
	b0 := byte(0xc0)
	if version == 0x6b3343cf {
		b0 = 0xd0 // v2: Initial = type 01
	}
	pkt := []byte{
		b0,
		byte(version >> 24), byte(version >> 16), byte(version >> 8), byte(version),
		byte(len(dcid)),
	}
	pkt = append(pkt, dcid...)
	pkt = append(pkt, 0x00)       // scid length
	pkt = append(pkt, 0x00)       // token length
	pkt = append(pkt, 0x40, 0x20) // Length varint
	return append(pkt, make([]byte, 32)...)
}

// TestOriginL7RealSocketHTTPConnectionPinned drives the per-CONNECTION HTTP
// model end-to-end under ENFORCE: request 1 is dropped pending, the verdict
// lands, its own retransmit delivers — and request 2 on the kept-alive
// connection RIDES that verdict with no further punt (the keep-alive Host
// change is a documented residual; see design.md).
func TestOriginL7RealSocketHTTPConnectionPinned(t *testing.T) {
	h := newL7RealSocketHarness(t, l7ModeEnforce, 80, L7ScopeHTTP)
	req1 := []byte("GET /one HTTP/1.1\r\nHost: first.example\r\n\r\n")
	req2 := []byte("GET /two HTTP/1.1\r\nHost: second.example\r\n\r\n")

	gotFirst := make(chan []byte, 1)
	gotSecond := make(chan []byte, 1)
	go func() {
		c, err := h.ln.Accept()
		if err != nil {
			gotFirst <- nil
			gotSecond <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		gotFirst <- readFull(c, len(req1))
		gotSecond <- readFull(c, len(req2))
	}()

	conn, cookie, key := h.dial(t)

	// Request 1: dropped pending, punted on the same flow (SYN was seen).
	_, err := conn.Write(req1)
	require.NoError(t, err)
	ev1 := readL7SampleFor(t, h.rd, cookie)
	require.Zero(t, ev1.Flags&l7PuntFlagNoState)
	require.Equal(t, req1, append([]byte(nil), ev1.Payload[:ev1.PayloadLen]...))

	// The oracle's verdict (State only — a TCP verdict carries no DCID, and
	// last_punt_seq is the kernel's PENDING dedup field, unread on a terminal
	// state); request 1's retransmit must now be DELIVERED.
	require.NoError(t, h.objs.MapL7Flow.Put(key, OriginBpfL7FlowVal{State: l7StateAllowed}))
	require.Equal(t, req1, <-gotFirst,
		"the adjudicated request's retransmit must be admitted")

	// Request 2 rides the connection's verdict: delivered, and NO new punt.
	_, err = conn.Write(req2)
	require.NoError(t, err)
	require.Equal(t, req2, <-gotSecond,
		"a later request on the kept-alive connection rides the verdict")
	requireNoL7Sample(t, h.rd)
	var fv OriginBpfL7FlowVal
	require.NoError(t, h.objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StateAllowed), fv.State, "the verdict is undisturbed")
}

// TestOriginL7RealSocketQUICIdentity drives the QUIC connection-attempt
// identity on one real UDP socket, across ALL supported versions and BOTH
// terminal verdicts. The flow key cannot tell two QUIC connections on the
// same socket apart, so a verdict admits (or denies) ONE exact Initial DCID:
// that attempt's Initials ride the verdict, while an Initial with a
// DIFFERENT DCID — a second connection to the same shared edge — re-enters
// adjudication (REPIN) and must present its own SNI, from ALLOWED and DENIED
// alike. The identity is the exact DCID compared byte-for-byte (design.md: why
// not a hash). Each version (v1, draft-29, v2) must be recognized as an
// Initial, or its DCID would read as absent (dcid_len 0) and the datagram would
// ride the prior verdict instead of re-pinning — so re-pinning across all three
// pins the version+type table end-to-end. Observe mode: delivery does not gate
// the punt/no-punt pattern under test.
func TestOriginL7RealSocketQUICIdentity(t *testing.T) {
	objs := loadOriginObjects(t)
	setOriginMode(t, objs, originModeObserve)
	require.NoError(t, objs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeObserve)))

	hostIP := hostOwnIPv4(t)
	require.NoError(t, objs.MapL7Scope.Put(binary.NativeEndian.Uint32(hostIP), uint8(L7ScopeQUIC)))

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgOriginEgress,
	})
	if err != nil {
		t.Skipf("cannot attach cgroup_skb/egress at root cgroup: %v", err)
	}
	t.Cleanup(func() { lnk.Close() })

	// A bound peer so the datagrams have somewhere to land.
	pc, err := net.ListenPacket("udp4", net.JoinHostPort(hostIP.String(), "443"))
	if err != nil {
		t.Skipf("cannot listen on udp %s:443: %v", hostIP, err)
	}
	t.Cleanup(func() { pc.Close() })

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	conn, err := net.Dial("udp4", pc.LocalAddr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	var cookie uint64
	raw, err := conn.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)
	require.NoError(t, raw.Control(func(fd uintptr) {
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}))
	require.NoError(t, err)

	var key OriginBpfL7FlowKey
	key.Cookie = cookie
	binary.NativeEndian.PutUint32(key.Dst[0:4], binary.BigEndian.Uint32(hostIP))
	key.DstPort = 443
	key.IpProto = 17
	key.IpVersion = 4

	// allow writes the oracle's ALLOWED verdict, admitting the exact DCID.
	allow := func(dcid []byte) {
		t.Helper()
		var v OriginBpfL7FlowVal
		v.State = l7StateAllowed
		v.DcidLen = uint8(len(dcid))
		copy(v.Dcid[:], dcid)
		require.NoError(t, objs.MapL7Flow.Put(key, v))
	}

	dcid1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Connection 1's Initial (v1): punted (no state, UDP has no SYN). The
	// sample carries the kernel-extracted DCID (the oracle stamps it into the
	// verdict without re-parsing), and the PENDING entry records it as the
	// cycle's identity.
	_, err = conn.Write(quicInitialDatagram(0x00000001, dcid1))
	require.NoError(t, err)
	ev := readL7SampleFor(t, rd, cookie)
	require.NotZero(t, ev.Flags&l7PuntFlagQUIC)
	require.Equal(t, dcid1, ev.Dcid[:ev.DcidLen], "the punt sample must carry the Initial's DCID")
	var fv OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State)
	require.Equal(t, dcid1, fv.Dcid[:fv.DcidLen], "the punt must stamp the cycle's identity")
	puntsBefore := fv.Punts

	// A non-Initial long header (0-RTT type bits) on the PENDING flow: no
	// identity — it must neither punt nor spend the cycle's budget.
	zeroRTT := append([]byte{0xd0, 0x00, 0x00, 0x00, 0x01, 0x08, 9, 9, 9, 9, 9, 9, 9, 9, 0x00}, make([]byte, 32)...)
	_, err = conn.Write(zeroRTT)
	require.NoError(t, err)
	requireNoL7Sample(t, rd)
	require.NoError(t, objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State)
	require.Equal(t, puntsBefore, fv.Punts, "a non-identity datagram must not spend punt budget")

	allow(dcid1)

	// A retransmit of connection 1's Initial: exact-DCID match — passes, NO
	// punt, verdict undisturbed.
	_, err = conn.Write(quicInitialDatagram(0x00000001, dcid1))
	require.NoError(t, err)
	requireNoL7Sample(t, rd)
	require.NoError(t, objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StateAllowed), fv.State, "an exact-DCID retransmit must not disturb the verdict")

	// New connections on the same socket, one per supported version, each with
	// a distinct DCID: each must re-enter adjudication (REPIN). A version the
	// kernel failed to recognize as an Initial would read dcid_len 0 and RIDE
	// the prior verdict — so a passing REPIN here pins v1/draft-29/v2
	// version+type recognition.
	for i, tc := range []struct {
		name    string
		version uint32
	}{
		{"draft-29", 0xff00001d},
		{"v2", 0x6b3343cf},
		{"v1", 0x00000001},
	} {
		dcid := []byte{byte(0x20 + i), 2, 3, 4, 5, 6, 7, 8}
		_, err = conn.Write(quicInitialDatagram(tc.version, dcid))
		require.NoError(t, err)
		ev = readL7SampleFor(t, rd, cookie)
		require.NotZero(t, ev.Flags&l7PuntFlagRepin, "%s: a new DCID must re-pin", tc.name)
		require.NoError(t, objs.MapL7Flow.Lookup(key, &fv))
		require.Equal(t, uint8(l7StatePending), fv.State, "%s: awaits its own verdict", tc.name)
		allow(dcid) // admit it so the next iteration starts from ALLOWED
	}

	// The DENIED half of the identity: a deny is scoped to ONE attempt, not
	// the socket. Deny an attempt, then prove its own Initial stays denied
	// with no punt while a NEW DCID re-enters adjudication — without this,
	// one denied attempt would fail-close every later QUIC connection on the
	// connected socket until LRU eviction (the entry has no TTL).
	dcidDenied := []byte{0x40, 2, 3, 4, 5, 6, 7, 8}
	_, err = conn.Write(quicInitialDatagram(0x00000001, dcidDenied))
	require.NoError(t, err)
	ev = readL7SampleFor(t, rd, cookie)
	require.NotZero(t, ev.Flags&l7PuntFlagRepin)
	var dv OriginBpfL7FlowVal
	dv.State = l7StateDenied
	dv.DcidLen = uint8(copy(dv.Dcid[:], dcidDenied))
	require.NoError(t, objs.MapL7Flow.Put(key, dv))

	// The denied attempt's own Initial: matches the pinned DCID — stays
	// denied, no punt, verdict undisturbed.
	_, err = conn.Write(quicInitialDatagram(0x00000001, dcidDenied))
	require.NoError(t, err)
	requireNoL7Sample(t, rd)
	require.NoError(t, objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StateDenied), fv.State, "the denied attempt's Initial must not disturb the deny")

	// A NEW connection attempt after the deny: must re-pin and go PENDING,
	// not inherit the dead attempt's sentence.
	dcidNext := []byte{0x41, 2, 3, 4, 5, 6, 7, 8}
	_, err = conn.Write(quicInitialDatagram(0x00000001, dcidNext))
	require.NoError(t, err)
	ev = readL7SampleFor(t, rd, cookie)
	require.NotZero(t, ev.Flags&l7PuntFlagRepin, "a new DCID on a DENIED flow must re-pin")
	require.Equal(t, dcidNext, ev.Dcid[:ev.DcidLen])
	require.NoError(t, objs.MapL7Flow.Lookup(key, &fv))
	require.Equal(t, uint8(l7StatePending), fv.State, "the new attempt awaits its own verdict")
	require.Equal(t, dcidNext, fv.Dcid[:fv.DcidLen], "the cycle identity moves to the new attempt")
}

// TestOriginL7RealSocketQUICGSOHiddenInitial drives the UDP_SEGMENT shape that
// PROG_TEST_RUN cannot reach, and that every other test in this file misses
// because they send one datagram per write.
//
// cgroup_skb/egress runs in ip_finish_output, BEFORE ip_finish_output_gso
// splits the send — so a GSO batch arrives as ONE skb holding several
// datagrams that the stack emits independently a moment later. The coalesced
// walk models a single datagram, and a short header legitimately ends one, so
// a batch whose FIRST segment is a short header stopped the walk with no
// Initial and no uncertainty: the identity gate read it as established 1-RTT
// traffic and passed the whole batch, hidden Initial and all. That is an
// unprivileged SNI bypass — the exact thing this layer exists to stop.
func TestOriginL7RealSocketQUICGSOHiddenInitial(t *testing.T) {
	objs := loadOriginObjects(t)
	// Origin stays in OBSERVE while L7 enforces, as newL7RealSocketHarness
	// does: the L4 verdict then passes everything and any drop below is
	// unambiguously L7's.
	setOriginMode(t, objs, originModeObserve)
	require.NoError(t, objs.MapAuditMode.Put(uint32(0), uint8(0)))
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))

	hostIP := hostOwnIPv4(t)
	require.NoError(t, objs.MapL7Scope.Put(binary.NativeEndian.Uint32(hostIP), uint8(L7ScopeQUIC)))

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgOriginEgress,
	})
	if err != nil {
		t.Skipf("cannot attach cgroup_skb/egress at root cgroup: %v", err)
	}
	t.Cleanup(func() { lnk.Close() })

	pc, err := net.ListenPacket("udp4", net.JoinHostPort(hostIP.String(), "443"))
	if err != nil {
		t.Skipf("cannot listen on udp %s:443: %v", hostIP, err)
	}
	t.Cleanup(func() { pc.Close() })

	const segSize = 256
	send := func(t *testing.T, gso bool, payload []byte) error {
		t.Helper()
		conn, err := net.Dial("udp4", pc.LocalAddr().String())
		require.NoError(t, err)
		defer conn.Close()
		if gso {
			raw, err := conn.(*net.UDPConn).SyscallConn()
			require.NoError(t, err)
			var serr error
			require.NoError(t, raw.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, segSize)
			}))
			if serr != nil {
				t.Skipf("UDP_SEGMENT unsupported here: %v", serr)
			}
		}
		_, werr := conn.Write(payload)
		return werr
	}

	// A short-header datagram: no first-flight identity, so with no flow state
	// it rides as established traffic. This is the posture the hidden-Initial
	// batch abuses, and the control proving the fix does not simply refuse
	// every short header.
	shortHdr := make([]byte, segSize)
	shortHdr[0] = 0x40 // fixed bit set, long-header bit CLEAR

	t.Run("plain short header rides", func(t *testing.T) {
		require.NoError(t, send(t, false, shortHdr))
	})

	// Bulk 1-RTT traffic is GSO'd constantly; every segment is a short header
	// and none of it may be refused.
	t.Run("all-short-header batch rides", func(t *testing.T) {
		batch := append(append([]byte{}, shortHdr...), shortHdr...)
		require.NoError(t, send(t, true, batch))
	})

	// The bypass: segment 0 stops the walk, segment 1 carries an Initial whose
	// SNI was never adjudicated. Must fail closed.
	t.Run("initial hidden behind a short header is refused", func(t *testing.T) {
		initial := quicInitialDatagram(0x00000001, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		require.LessOrEqual(t, len(initial), segSize, "the Initial must fit one segment")
		batch := append(append([]byte{}, shortHdr...), initial...)
		err := send(t, true, batch)
		require.Error(t, err, "a GSO batch hiding a QUIC Initial behind a short header must be dropped")
		require.ErrorIs(t, err, unix.EPERM)
	})
}
