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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// ErrQUICVersion signals a QUIC Initial whose version is not in initialVersions,
// so its protection keys cannot be derived. The oracle maps it to
// L7QUICVersion and fails closed — an unknown version is denied until the
// table is extended, and clients fall back to TCP.
var ErrQUICVersion = errors.New("sni: unknown QUIC version")

// ErrNotQUIC signals a UDP payload that is not a QUIC long-header Initial.
var ErrNotQUIC = errors.New("sni: not a QUIC Initial")

// gcmTagSize is the AES-GCM authentication tag length every QUIC packet
// carries, and so the minimum ciphertext a well-formed packet can hold.
const gcmTagSize = 16

// maxConnIDLen is RFC 9000 §17.2's connection ID cap, part of the walk
// contract at skipLongHeader.
const maxConnIDLen = 20

// MaxCoalescedPackets bounds DecodeInitialCrypto's walk over one punted
// datagram. Exported so the kernel's cap can be pinned equal by test
// (TestKernelCoalescedCapMatchesParser), the way InitialVersions pins the
// version table: the kernel refuses whatever it could not reach within
// L7_QUIC_MAX_COALESCED, so a datagram this walk would keep reading past that
// is one the datapath never punted. The kernel's cap is set by verifier budget
// (see bpf/sni_quic.h); this side just has to agree with it.
const MaxCoalescedPackets = 4

// CryptoChunk is one CRYPTO frame's contribution to the TLS handshake stream:
// its byte offset within that stream and the bytes themselves. A large
// ClientHello (post-quantum key shares) spans several chunks across one or more
// Initial packets; the caller reassembles them by offset.
type CryptoChunk struct {
	Offset uint64
	Data   []byte
}

// quicVersion describes how to derive Initial keys for one QUIC version: its
// key-derivation salt, the packet-protection labels (which gained a "quicv2 "
// prefix in RFC 9369), and the long-header type bits that mark an Initial and
// a Retry. THE one per-version packet-type table: decodeOneInitial and
// skipLongHeader both read it, and the kernel's copy (l7_quic_one in
// bpf/sni_quic.h) is pinned equal by test — v2 rotated the bits once already, and
// a future version will again.
type quicVersion struct {
	salt        []byte
	keyLabel    string
	ivLabel     string
	hpLabel     string
	initialType byte // long-header packet-type bits identifying an Initial
	retryType   byte // ...and a Retry, which carries no Length and cannot be skipped
}

// initialVersions is the supported QUIC version table. The "client in" /
// "server in" secret labels are identical across versions; only the salt and
// the key/iv/hp labels differ.
var initialVersions = map[uint32]quicVersion{
	// QUIC v1 (RFC 9000 / 9001): Initial 00, 0-RTT 01, Handshake 10, Retry 11.
	0x00000001: {
		salt:        hexBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
		keyLabel:    "quic key",
		ivLabel:     "quic iv",
		hpLabel:     "quic hp",
		initialType: 0b00,
		retryType:   0b11,
	},
	// QUIC v2 (RFC 9369): different salt, "quicv2 " labels, remapped types
	// (Initial 01, 0-RTT 10, Handshake 11, Retry 00).
	0x6b3343cf: {
		salt:        hexBytes("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
		keyLabel:    "quicv2 key",
		ivLabel:     "quicv2 iv",
		hpLabel:     "quicv2 hp",
		initialType: 0b01,
		retryType:   0b00,
	},
	// draft-29: still widely emitted by older stacks; v1 labels and type
	// bits, its own salt.
	0xff00001d: {
		salt:        hexBytes("afbfec289993d24c9e9786f19c6111e04390a899"),
		keyLabel:    "quic key",
		ivLabel:     "quic iv",
		hpLabel:     "quic hp",
		initialType: 0b00,
		retryType:   0b11,
	},
}

// InitialVersions returns the QUIC versions this decryptor supports.
// Exported so the kernel's Initial classifier (l7_quic_one in bpf/sni_quic.h) can
// be pinned equal by test: a version userspace decrypts but
// the kernel's table misses would yield no connection-attempt identity, so a
// second connection in that version on one UDP socket would ride the first's
// verdict with its SNI never parsed.
func InitialVersions() []uint32 {
	out := make([]uint32, 0, len(initialVersions))
	for v := range initialVersions {
		out = append(out, v)
	}
	return out
}

// InitialTypeBits returns the long-header packet-type bits that mark an
// Initial and a Retry for a supported version, ok=false for an unknown one.
// Exported for the kernel pin test (the version table alone cannot catch a
// version present with the WRONG bits) and for the oracle's refusal
// classifier, which asks only "is this version one we decrypt".
func InitialTypeBits(version uint32) (initialType, retryType byte, ok bool) {
	v, known := initialVersions[version]
	if !known {
		return 0, 0, false
	}
	return v.initialType, v.retryType, true
}

// DecodeInitialCrypto decrypts every QUIC Initial packet coalesced in a single
// UDP datagram and returns the CRYPTO-frame chunks they carry, in packet order.
// It performs the full RFC 9001 client-Initial unprotection: derive keys from
// the Destination Connection ID, remove header protection, and AEAD-decrypt.
//
// The kernel does none of this — it walks the coalesced long headers to the
// Initial and punts the datagram here. This function walks too: a leading
// 0-RTT/Handshake packet (which an attacker can coalesce before the Initial to
// hide the SNI) is skipped by its Length to reach the Initial. Returns
// ErrNotQUIC when the datagram holds NO Initial (every packet was a short
// header or a skippable non-Initial) — established/evicted traffic to ride,
// not deny — ErrQUICVersion for an unknown-version Initial (fail closed), and
// ErrMalformed on structural corruption, AEAD failure, or a datagram truncated
// below its declared length — a UDP datagram is atomic and can never grow, so
// truncation within it is terminal, never "reassemble and retry". This
// function never returns ErrIncomplete; that error belongs to the
// CRYPTO-stream level above (a ClientHello spanning several Initial packets).
func DecodeInitialCrypto(datagram []byte) ([]CryptoChunk, error) {
	var chunks []CryptoChunk
	var firstDCID []byte
	off := 0
	sawInitial := false
	for i := 0; off < len(datagram); i++ {
		if i >= MaxCoalescedPackets {
			// The kernel walk stops here too, and refuses what it could not
			// reach — so past this point the datagram was never punted and
			// anything this loop found is drift. Bounding it also prices the
			// walk: without a cap a 16KB buffer of minimal 7-byte long headers
			// drives ~2000 key derivations (HKDF + three expandLabel calls +
			// aes.NewCipher each), all on the oracle goroutine under l.mu,
			// stalling every other flow's adjudication.
			break
		}
		b0 := datagram[off]
		// A short header or a padding/non-long byte ends the useful part of the
		// datagram. Anything after the Initial we don't need.
		if b0&0x80 == 0 {
			break
		}
		next, dcid, cs, err := decodeOneInitial(datagram, off)
		if err == nil {
			if sawInitial && !bytes.Equal(firstDCID, dcid) {
				// Two decodable Initials under DIFFERENT DCIDs are two
				// connection attempts in one datagram — the kernel walk
				// refuses that shape before ever punting it (bpf/sni_quic.h), so
				// here it is drift, and mixing the attempts' CRYPTO into one
				// assembler would adjudicate neither. Fail closed.
				return nil, ErrMalformed
			}
			sawInitial = true
			firstDCID = dcid
			chunks = append(chunks, cs...)
			if next <= off {
				break
			}
			off = next
			continue
		}
		if sawInitial {
			// A trailing coalesced packet we can't decode — a Handshake/0-RTT
			// packet, one whose version we don't recognize, or one cut short by
			// the kernel's punt window (a GSO super-datagram sampled at
			// L7_PUNT_PAYLOAD). Once we already hold a valid Initial's CRYPTO,
			// stop and keep it rather than discarding a decodable ClientHello
			// over a later packet: the kept chunks are AEAD-authenticated, so
			// trailing bytes cannot have altered them.
			break
		}
		// A LEADING packet that is not a decodable Initial. It may be a
		// 0-RTT/Handshake long header an attacker coalesced BEFORE the Initial
		// to push the SNI past a first-packet check (the kernel walks past it
		// too; see bpf/sni_quic.h). Skip it by its Length to reach a later
		// coalesced Initial; if it cannot be skipped (Retry, unknown version,
		// truncation), give up with the original error.
		skip, ok := skipLongHeader(datagram, off)
		if !ok || skip <= off {
			return nil, err
		}
		off = skip
	}
	if !sawInitial {
		return nil, ErrNotQUIC
	}
	return chunks, nil
}

// skipLongHeader returns the offset of the coalesced packet following the
// non-Initial long-header packet at off, or ok=false when it cannot be sized.
//
// THE skippable-long-header contract, implemented twice — here and by
// l7_quic_one in bpf/sni_quic.h — and pinned equal by
// bpf.TestOriginL7QUICWalkContract, which feeds one datagram to both:
//   - DCID and SCID are capped at maxConnIDLen; a longer one is unskippable.
//   - Retry is unskippable: it carries no Length field.
//   - 0-RTT and Handshake are skipped by their Length varint.
//   - an unknown version cannot be sized at all.
//   - one datagram carries one connection ID (RFC 9000 §12.2); mixed IDs are
//     refused — by the kernel across every long header, here only across
//     decodable Initials, which is why the kernel refusal is load-bearing.
//
// Initials are decoded by decodeOneInitial, not skipped here.
func skipLongHeader(d []byte, off int) (int, bool) {
	if len(d)-off < 6 { // byte0 + version(4) + dcidlen(1)
		return 0, false
	}
	b0 := d[off]
	version := binary.BigEndian.Uint32(d[off+1 : off+5])
	ver, known := initialVersions[version]
	if !known {
		return 0, false // unknown version: cannot size the packet
	}
	// Retry has no Length field.
	if (b0>>4)&0b11 == ver.retryType {
		return 0, false
	}
	p := off + 5
	dcidLen := int(d[p])
	if dcidLen > maxConnIDLen {
		return 0, false
	}
	p++
	p += dcidLen
	if p >= len(d) {
		return 0, false
	}
	scidLen := int(d[p])
	if scidLen > maxConnIDLen {
		return 0, false
	}
	p++
	p += scidLen
	if p > len(d) {
		return 0, false
	}
	// An Initial would carry a Token before Length, but Initials are decoded
	// elsewhere; a 0-RTT/Handshake goes straight to the Length varint.
	if (b0>>4)&0b11 == ver.initialType {
		return 0, false
	}
	length, n := readVarint(d, p)
	if n == 0 {
		return 0, false
	}
	p += n
	if length > uint64(len(d)) || uint64(p)+length > uint64(len(d)) {
		return 0, false
	}
	next := p + int(length)
	if next <= off {
		return 0, false
	}
	return next, true
}

// decodeOneInitial unprotects the single QUIC packet starting at off. It
// returns the offset of the next coalesced packet, the packet's Destination
// Connection ID field (the caller compares it across coalesced packets), and
// the CRYPTO chunks recovered.
//
// Every "field overruns the received bytes" case here is ErrMalformed, not
// ErrIncomplete: the datagram is atomic, so no retransmit can ever complete it
// — mapping truncation to ErrIncomplete would park the flow as needs-more
// forever (each re-sent copy re-punts, re-returns incomplete, and the punt
// budget black-holes the flow with no audit record).
func decodeOneInitial(d []byte, off int) (int, []byte, []CryptoChunk, error) {
	start := off
	if len(d)-off < 7 { // byte0 + version(4) + dcidlen(1) + at least scidlen
		return 0, nil, nil, ErrMalformed
	}
	b0 := d[off]
	off++
	version := binary.BigEndian.Uint32(d[off : off+4])
	off += 4

	ver, known := initialVersions[version]
	if !known {
		return 0, nil, nil, ErrQUICVersion
	}
	// Long-header packet type lives in bits 5-4 of the first byte.
	if (b0>>4)&0b11 != ver.initialType || b0&0x40 == 0 {
		return 0, nil, nil, ErrNotQUIC
	}

	dcidLen := int(d[off])
	off++
	// RFC 9000 §17.2 caps a connection ID at maxConnIDLen. skipLongHeader
	// enforces it and so does the kernel classifier (l7_quic_one refuses
	// dlen > 20), so accepting a longer one here would make the two halves of
	// the same walk disagree — exactly the kernel/userspace drift the pin
	// tests exist to catch — and derive Initial keys from a value no
	// conformant peer can send.
	if dcidLen > maxConnIDLen {
		return 0, nil, nil, ErrMalformed
	}
	if off+dcidLen > len(d) {
		return 0, nil, nil, ErrMalformed
	}
	dcid := d[off : off+dcidLen]
	off += dcidLen
	if off >= len(d) {
		return 0, nil, nil, ErrMalformed
	}
	scidLen := int(d[off])
	off++
	off += scidLen
	if off > len(d) {
		return 0, nil, nil, ErrMalformed
	}
	// Initial packets carry a Token before the Length field. Bound each varint
	// against the datagram before narrowing to int: a QUIC varint holds up to
	// 2^62, which would wrap a 32-bit int negative and slip past the length
	// checks. Comparing as uint64 keeps the conversions safe on any int width.
	tokenLen, n := readVarint(d, off)
	if n == 0 {
		return 0, nil, nil, ErrMalformed
	}
	if tokenLen > uint64(len(d)) {
		return 0, nil, nil, ErrMalformed
	}
	off += n + int(tokenLen)
	if off > len(d) {
		return 0, nil, nil, ErrMalformed
	}
	length, n := readVarint(d, off)
	if n == 0 {
		return 0, nil, nil, ErrMalformed
	}
	off += n
	pnOffset := off
	if length > uint64(len(d)) {
		return 0, nil, nil, ErrMalformed
	}
	end := pnOffset + int(length)
	if end > len(d) {
		return 0, nil, nil, ErrMalformed
	}

	key, iv, hp := deriveInitialKeys(dcid, ver)

	// Header protection: sample 16 bytes 4 into the (protected) packet number.
	sampleOff := pnOffset + 4
	if sampleOff+16 > len(d) {
		return 0, nil, nil, ErrMalformed
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return 0, nil, nil, ErrMalformed
	}
	var mask [16]byte
	block.Encrypt(mask[:], d[sampleOff:sampleOff+16])

	unB0 := b0 ^ (mask[0] & 0x0f) // long header masks the low 4 bits
	pnLen := int(unB0&0x03) + 1
	if pnOffset+pnLen > len(d) {
		return 0, nil, nil, ErrMalformed
	}
	// The Length field must cover the packet number plus at least the AEAD
	// tag. A shorter Length is not a truncated packet but a malformed one, and
	// without this check the ciphertext slice below inverts and panics.
	if end < pnOffset+pnLen+gcmTagSize {
		return 0, nil, nil, ErrMalformed
	}

	// Reconstruct header (AAD) and packet number from the unprotected bytes.
	header := make([]byte, pnOffset+pnLen-start)
	copy(header, d[start:pnOffset+pnLen])
	header[0] = unB0
	var pn uint64
	for i := 0; i < pnLen; i++ {
		p := d[pnOffset+i] ^ mask[1+i]
		header[pnOffset-start+i] = p
		pn = pn<<8 | uint64(p)
	}

	ciphertext := d[pnOffset+pnLen : end]
	aead, err := newAESGCM(key)
	if err != nil {
		return 0, nil, nil, ErrMalformed
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	// XOR the packet number into the right-hand side of the IV.
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return 0, nil, nil, ErrMalformed
	}
	return end, dcid, parseFramesForCrypto(plaintext), nil
}

// deriveInitialKeys performs the RFC 9001 client-Initial key schedule.
func deriveInitialKeys(dcid []byte, ver quicVersion) (key, iv, hp []byte) {
	initialSecret, _ := hkdf.Extract(sha256.New, dcid, ver.salt)
	clientSecret := expandLabel(initialSecret, "client in", 32)
	key = expandLabel(clientSecret, ver.keyLabel, 16)
	iv = expandLabel(clientSecret, ver.ivLabel, 12)
	hp = expandLabel(clientSecret, ver.hpLabel, 16)
	return key, iv, hp
}

// expandLabel is TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) over SHA-256.
func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context
	out, _ := hkdf.Expand(sha256.New, secret, string(info), length)
	return out
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// parseFramesForCrypto walks the decrypted Initial payload and returns the
// CRYPTO chunks. It understands the frame types a client Initial can hold
// (PADDING, PING, ACK, CRYPTO) and stops at the first type it cannot size,
// which is safe: the CRYPTO carrying the ClientHello comes early.
func parseFramesForCrypto(p []byte) []CryptoChunk {
	var out []CryptoChunk
	off := 0
	for off < len(p) {
		ftype, n := readVarint(p, off)
		if n == 0 {
			break
		}
		off += n
		switch ftype {
		case 0x00, 0x01: // PADDING, PING
			continue
		case 0x02, 0x03: // ACK (0x03 adds ECN counts)
			var ok bool
			off, ok = skipACK(p, off, ftype == 0x03)
			if !ok {
				return out
			}
		case 0x06: // CRYPTO
			offset, n1 := readVarint(p, off)
			off += n1
			clen, n2 := readVarint(p, off)
			off += n2
			// uint64 comparison so a huge clen cannot wrap int(clen) negative
			// and defeat the bound on a 32-bit build.
			if n1 == 0 || n2 == 0 || clen > uint64(len(p)) || uint64(off)+clen > uint64(len(p)) {
				return out
			}
			data := make([]byte, int(clen))
			copy(data, p[off:off+int(clen)])
			out = append(out, CryptoChunk{Offset: offset, Data: data})
			off += int(clen)
		default:
			return out // unknown frame type: cannot size, stop
		}
	}
	return out
}

func skipACK(p []byte, off int, ecn bool) (int, bool) {
	// largest_ack, ack_delay, ack_range_count, first_ack_range — only the
	// third is needed, so keep it rather than allocating for all four on a
	// path every punted Initial with an ACK frame walks.
	var rangeCount uint64
	for i := 0; i < 4; i++ {
		v, n := readVarint(p, off)
		if n == 0 {
			return off, false
		}
		off += n
		if i == 2 {
			rangeCount = v
		}
	}
	for i := uint64(0); i < rangeCount; i++ {
		for j := 0; j < 2; j++ { // gap, ack_range_length
			_, n := readVarint(p, off)
			if n == 0 {
				return off, false
			}
			off += n
		}
	}
	if ecn {
		for i := 0; i < 3; i++ { // ECT0, ECT1, ECN-CE
			_, n := readVarint(p, off)
			if n == 0 {
				return off, false
			}
			off += n
		}
	}
	return off, true
}

// readVarint decodes a QUIC variable-length integer (RFC 9000 §16). It returns
// the value and the number of bytes consumed, or n==0 on truncation.
func readVarint(b []byte, off int) (uint64, int) {
	if off >= len(b) {
		return 0, 0
	}
	prefix := b[off] >> 6
	length := 1 << prefix // 1, 2, 4, or 8 bytes
	if off+length > len(b) {
		return 0, 0
	}
	v := uint64(b[off] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[off+i])
	}
	return v, length
}

// hexBytes decodes a compile-time-constant hex string used for the QUIC
// version salts. The inputs are fixed literals from the RFCs, so a malformed
// one is a programming error and panics at init.
func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("sni: bad hex constant: " + s)
	}
	return b
}

// ParseQUICClientHello parses a ClientHello out of a reassembled QUIC CRYPTO
// stream. QUIC carries TLS handshake messages with no record layer, so the
// bytes go straight to the shared handshake parser.
func ParseQUICClientHello(cryptoStream []byte) (Hello, error) {
	return parseHandshakeStream(cryptoStream, ProtoQUIC)
}
