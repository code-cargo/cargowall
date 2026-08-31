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

package sni

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// RFC 9001 Appendix A.1/A.2: the client Initial test vector. dcid is the
// Destination Connection ID the keys derive from; the packet is the complete
// protected client Initial datagram (padded to 1200 bytes).
const (
	rfc9001DCID   = "8394c8f03e515708"
	rfc9001KeyHex = "1f369613dd76d5467730efcbe3b1a22d"
	rfc9001IVHex  = "fa044b2f42a3fd3b46fb255c"
	rfc9001HPHex  = "9f50449e04a0e810283a1e9933adedd2"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestDeriveInitialKeys_RFC9001Vector pins the HKDF key schedule (Extract with
// the v1 salt, "client in", then quic key/iv/hp) to the RFC's published values.
func TestDeriveInitialKeys_RFC9001Vector(t *testing.T) {
	dcid := unhex(t, rfc9001DCID)
	key, iv, hp := deriveInitialKeys(dcid, initialVersions[0x00000001])
	if got := hex.EncodeToString(key); got != rfc9001KeyHex {
		t.Errorf("key = %s, want %s", got, rfc9001KeyHex)
	}
	if got := hex.EncodeToString(iv); got != rfc9001IVHex {
		t.Errorf("iv = %s, want %s", got, rfc9001IVHex)
	}
	if got := hex.EncodeToString(hp); got != rfc9001HPHex {
		t.Errorf("hp = %s, want %s", got, rfc9001HPHex)
	}
}

// TestDecodeInitialCrypto_RFC9001Packet decrypts the RFC's protected client
// Initial and checks that the CRYPTO frame it carries is the ClientHello the
// RFC documents (which has SNI "example.com").
func TestDecodeInitialCrypto_RFC9001Packet(t *testing.T) {
	pkt := snitest.RFC9001ClientInitial()
	chunks, err := DecodeInitialCrypto(pkt)
	if err != nil {
		t.Fatalf("DecodeInitialCrypto: %v", err)
	}
	if len(chunks) == 0 {
		t.Fatal("no CRYPTO chunks recovered")
	}
	var asm Assembler
	for _, c := range chunks {
		if err := asm.Add(c.Offset, c.Data); err != nil {
			t.Fatalf("assemble: %v", err)
		}
	}
	h, err := ParseQUICClientHello(asm.Bytes())
	if err != nil {
		t.Fatalf("ParseQUICClientHello: %v", err)
	}
	if h.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", h.ServerName)
	}
	if h.Protocol != ProtoQUIC {
		t.Errorf("Protocol = %v, want quic", h.Protocol)
	}
}

func TestDecodeInitialCrypto_UnknownVersion(t *testing.T) {
	pkt := snitest.RFC9001ClientInitial()
	// Stamp an unregistered version number.
	pkt[1], pkt[2], pkt[3], pkt[4] = 0x0a, 0x0a, 0x0a, 0x0a
	if _, err := DecodeInitialCrypto(pkt); !errors.Is(err, ErrQUICVersion) {
		t.Errorf("err = %v, want ErrQUICVersion", err)
	}
}

func TestDecodeInitialCrypto_NotQUIC(t *testing.T) {
	// A short-header (or plain non-QUIC) datagram: high bit clear.
	if _, err := DecodeInitialCrypto([]byte{0x40, 0x01, 0x02, 0x03}); !errors.Is(err, ErrNotQUIC) {
		t.Errorf("err = %v, want ErrNotQUIC", err)
	}
}

// A truncated datagram must be ErrMalformed, NOT ErrIncomplete: a datagram is
// atomic, so "incomplete" would tell the oracle to wait for bytes that can
// never arrive — parking the flow until the punt budget black-holes it.
func TestDecodeInitialCrypto_Truncated(t *testing.T) {
	pkt := snitest.RFC9001ClientInitial()
	if _, err := DecodeInitialCrypto(pkt[:40]); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed (terminal)", err)
	}
}

// A structurally complete header whose Length field claims more bytes than
// the datagram holds is the crafted park-the-flow attack shape: it must also
// be terminal ErrMalformed.
func TestDecodeInitialCrypto_LengthOverrunIsMalformed(t *testing.T) {
	pkt := []byte{
		0xc0,                   // long header, fixed bit, type Initial (v1)
		0x00, 0x00, 0x00, 0x01, // version 1
		0x08, 1, 2, 3, 4, 5, 6, 7, 8, // dcid len + dcid
		0x00,       // scid len 0
		0x00,       // token length 0
		0x7f, 0xff, // Length = 16383, far beyond the datagram
	}
	if _, err := DecodeInitialCrypto(pkt); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed (terminal)", err)
	}
}

func TestDecodeInitialCrypto_TamperedFailsAEAD(t *testing.T) {
	pkt := snitest.RFC9001ClientInitial()
	pkt[len(pkt)-1] ^= 0xff // corrupt the AEAD tag region
	if _, err := DecodeInitialCrypto(pkt); err == nil {
		t.Error("tampered packet decrypted successfully; want an error")
	}
}

func TestReadVarint(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		n    int
	}{
		{"00", 0, 1},
		{"3f", 63, 1},
		{"4040", 64, 2},
		{"7bbd", 15293, 2},
		{"9d7f3e7d", 494878333, 4},
		{"c2197c5eff14e88c", 151288809941952652, 8},
	}
	for _, tc := range tests {
		b, err := hex.DecodeString(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		got, n := readVarint(b, 0)
		if got != tc.want || n != tc.n {
			t.Errorf("readVarint(%s) = (%d,%d), want (%d,%d)", tc.in, got, n, tc.want, tc.n)
		}
	}
	if _, n := readVarint([]byte{0xc0, 0x00}, 0); n != 0 {
		t.Error("truncated 8-byte varint should return n=0")
	}
}

// Regression (found by FuzzDecodeInitialCrypto): a QUIC Initial whose Length
// field is smaller than the packet number it must cover once inverted the
// ciphertext slice and panicked. A single crafted UDP datagram would have
// crashed the daemon, so this must be a clean ErrMalformed.
func TestDecodeInitialCrypto_LengthUnderflowNoPanic(t *testing.T) {
	pkt := []byte("\xc0\x00\x00\x00\x01\x00\x00\x00\x00")
	pkt = append(pkt, []byte("00000000000000000000")...)
	if _, err := DecodeInitialCrypto(pkt); err == nil {
		t.Error("expected an error for a Length that cannot cover the packet number")
	}
}

// Regression (code review): a datagram with a valid v1 Initial followed by a
// coalesced packet of unknown version must still yield the first Initial's
// CRYPTO, not discard it over the trailing packet.
func TestDecodeInitialCrypto_TrailingUnknownVersionKeepsInitial(t *testing.T) {
	pkt := snitest.RFC9001ClientInitial()
	// Append a long-header packet with an unregistered version.
	trailer := []byte{0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 0x00, 0x00}
	chunks, err := DecodeInitialCrypto(append(append([]byte{}, pkt...), trailer...))
	if err != nil {
		t.Fatalf("DecodeInitialCrypto: %v", err)
	}
	if len(chunks) == 0 {
		t.Fatal("valid Initial's CRYPTO was discarded over a trailing unknown-version packet")
	}
	var asm Assembler
	for _, c := range chunks {
		if err := asm.Add(c.Offset, c.Data); err != nil {
			t.Fatal(err)
		}
	}
	h, err := ParseQUICClientHello(asm.Bytes())
	if err != nil || h.ServerName != "example.com" {
		t.Errorf("recovered %q / %v, want example.com", h.ServerName, err)
	}
}

// TestDecodeInitialCrypto_LeadingNonInitialSkipped: an attacker can coalesce a
// 0-RTT/Handshake long header BEFORE the Initial to push the SNI past a
// first-packet check. DecodeInitialCrypto must walk past that leading packet
// (skipping it by its Length) and still recover the Initial's ClientHello.
func TestDecodeInitialCrypto_LeadingNonInitialSkipped(t *testing.T) {
	// A minimal v1 0-RTT packet (long header, fixed bit, type 0b01), dcid/scid
	// length 0, a 1-byte Length varint and that many filler bytes.
	zeroRTT := []byte{0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0, 0, 0, 0}
	datagram := append(append([]byte{}, zeroRTT...), snitest.RFC9001ClientInitial()...)

	chunks, err := DecodeInitialCrypto(datagram)
	if err != nil {
		t.Fatalf("DecodeInitialCrypto: %v (the leading 0-RTT must be skipped)", err)
	}
	var asm Assembler
	for _, c := range chunks {
		if err := asm.Add(c.Offset, c.Data); err != nil {
			t.Fatal(err)
		}
	}
	h, err := ParseQUICClientHello(asm.Bytes())
	if err != nil || h.ServerName != "example.com" {
		t.Errorf("recovered %q / %v, want example.com", h.ServerName, err)
	}
}

// TestDecodeInitialCrypto_LeadingUnknownVersionFailsClosed: a leading long
// header whose version is unknown cannot be sized, so the walk cannot reach an
// Initial behind it. Rather than silently skip it (which would let an
// [unknown-version][Initial] datagram bypass the SNI check), the decoder fails
// closed with the unknown-version error, which the oracle maps to a deny.
func TestDecodeInitialCrypto_LeadingUnknownVersionFailsClosed(t *testing.T) {
	unknown := []byte{0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 0x00, 0x00, 0x04, 0, 0, 0, 0}
	datagram := append(append([]byte{}, unknown...), snitest.RFC9001ClientInitial()...)
	if _, err := DecodeInitialCrypto(datagram); !errors.Is(err, ErrQUICVersion) {
		t.Errorf("err = %v, want ErrQUICVersion (an unknown-version prefix must fail closed)", err)
	}
}

// TestParseFramesForCrypto covers frame skipping — PADDING, PING, and ACK
// (including the ECN variant) — so a CRYPTO frame that follows them is still
// found. skipACK is otherwise unexercised by the RFC packet (which is PADDING +
// CRYPTO only).
func TestParseFramesForCrypto(t *testing.T) {
	crypto := func(off uint64, data []byte) []byte {
		// type 0x06, offset varint, length varint, data (all small → 1-byte varints)
		return append([]byte{0x06, byte(off), byte(len(data))}, data...)
	}

	tests := []struct {
		name    string
		frames  []byte
		wantLen int
		wantOff uint64
	}{
		{"padding then crypto", append([]byte{0x00, 0x00, 0x00}, crypto(0, []byte("abc"))...), 3, 0},
		{"ping then crypto", append([]byte{0x01}, crypto(0, []byte("hi"))...), 2, 0},
		{
			name:    "ack then crypto",
			frames:  append([]byte{0x02, 0x00, 0x00, 0x00, 0x00}, crypto(5, []byte("xyz"))...),
			wantLen: 3, wantOff: 5,
		},
		{
			name: "ack-with-ranges-and-ecn then crypto",
			// type 0x03: largest=5, delay=0, range_count=1, first_range=0,
			// then 1 (gap,len) pair = (0,0), then 3 ECN counts (0,0,0).
			frames:  append([]byte{0x03, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, crypto(0, []byte("ok"))...),
			wantLen: 2, wantOff: 0,
		},
		{"unknown frame stops scan", []byte{0x30, 0x01, 0x02}, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chunks := parseFramesForCrypto(tc.frames)
			if tc.wantLen == 0 {
				if len(chunks) != 0 {
					t.Fatalf("got %d chunks, want 0", len(chunks))
				}
				return
			}
			if len(chunks) != 1 {
				t.Fatalf("got %d chunks, want 1", len(chunks))
			}
			if chunks[0].Offset != tc.wantOff || len(chunks[0].Data) != tc.wantLen {
				t.Errorf("chunk = {off:%d len:%d}, want {off:%d len:%d}",
					chunks[0].Offset, len(chunks[0].Data), tc.wantOff, tc.wantLen)
			}
		})
	}
}

// TestProtocolString covers the trivial String() method.
func TestProtocolString(t *testing.T) {
	cases := map[Protocol]string{ProtoTLS: "tls", ProtoHTTP: "http", ProtoQUIC: "quic", ProtoUnknown: "unknown"}
	for p, want := range cases {
		if p.String() != want {
			t.Errorf("Protocol(%d).String() = %q, want %q", p, p.String(), want)
		}
	}
}

// TestDecodeInitialCrypto_CoalescedWalkIsBounded: the walk must stop where the
// kernel's does. Its only structural bound was that the offset strictly
// increases, so a buffer of minimal long headers drove one key derivation
// (HKDF + three expandLabel calls + aes.NewCipher) per 12 bytes — pure CPU
// burned on the oracle goroutine under its mutex, stalling every other flow's
// adjudication while a punted datagram it would never admit anyway was chewed
// through. Past MaxCoalescedPackets the kernel refuses the datagram, so nothing
// beyond it was ever punted.
func TestDecodeInitialCrypto_CoalescedWalkIsBounded(t *testing.T) {
	// A minimal skippable v1 0-RTT: 12 bytes, so an unbounded walk would run
	// ~1300 iterations over this buffer.
	zeroRTT := []byte{0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0, 0, 0, 0}
	var datagram []byte
	for i := 0; i < 16*1024/len(zeroRTT); i++ {
		datagram = append(datagram, zeroRTT...)
	}

	// No Initial is reachable, so this fails closed either way — the point is
	// that it returns after a bounded number of packets.
	if _, err := DecodeInitialCrypto(datagram); !errors.Is(err, ErrNotQUIC) {
		t.Errorf("err = %v, want ErrNotQUIC", err)
	}

	// An Initial buried past the cap is NOT recovered: the kernel refused that
	// datagram, so recovering it here would decode a shape the datapath never
	// punts and would disagree with the walk it mirrors.
	var buried []byte
	for i := 0; i < MaxCoalescedPackets; i++ {
		buried = append(buried, zeroRTT...)
	}
	buried = append(buried, snitest.RFC9001ClientInitial()...)
	if _, err := DecodeInitialCrypto(buried); err == nil {
		t.Error("an Initial past the coalesced cap must not be decoded")
	}

	// One packet inside the cap, it still is.
	var reachable []byte
	for i := 0; i < MaxCoalescedPackets-1; i++ {
		reachable = append(reachable, zeroRTT...)
	}
	reachable = append(reachable, snitest.RFC9001ClientInitial()...)
	if _, err := DecodeInitialCrypto(reachable); err != nil {
		t.Errorf("an Initial inside the cap must still decode: %v", err)
	}
}

// TestDecodeInitialCrypto_OversizeDCIDRejected: RFC 9000 §17.2 caps a
// connection ID at 20 bytes. skipLongHeader enforces it and so does the kernel
// classifier (l7_quic_one refuses dlen > 20) — decodeOneInitial did not, so
// the two halves of the same walk disagreed on which packets are well formed
// and this one would derive Initial keys from a value no conformant peer can
// send.
func TestDecodeInitialCrypto_OversizeDCIDRejected(t *testing.T) {
	pkt := append([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 200}, make([]byte, 220)...)
	if _, err := DecodeInitialCrypto(pkt); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed for a 200-byte DCID", err)
	}
}
