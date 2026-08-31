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

import "strings"

// TLS record content types and handshake message types we care about.
const (
	tlsRecordHandshake = 22 // content_type for handshake records
	tlsHandshakeHello  = 1  // handshake msg_type for ClientHello

	extServerName = 0x0000 // RFC 6066 server_name
	extECH        = 0xfe0d // RFC 9180 encrypted_client_hello
	sniHostName   = 0x00   // NameType host_name

	maxServerNameLen = 253 // a DNS name never exceeds this
	maxExtensions    = 128 // defensive cap on the extension walk
)

// ParseTLSClientHello recovers the SNI from a (possibly record-fragmented)
// buffer that begins at the first byte a client writes on a TLS connection.
//
// Returns (Hello, nil) on a fully-parsed ClientHello — including the legitimate
// no-SNI and ECH-only cases, where ServerName is "". Returns ErrIncomplete when
// buf is a valid prefix of a larger ClientHello (reassemble and retry), and
// ErrMalformed / ErrNotTLS when the bytes cannot be a client's first flight.
func ParseTLSClientHello(buf []byte) (Hello, error) {
	hs, err := coalesceRecords(buf)
	if err != nil {
		return Hello{Protocol: ProtoTLS}, err
	}
	return parseHandshakeStream(hs, ProtoTLS)
}

// coalesceRecords walks the TLS record layer and concatenates the payloads of
// the handshake records into a single handshake byte stream. A trailing partial
// record is not fatal — the caller may already hold the whole ClientHello. It
// validates only the record framing; handshake-message framing is
// parseHandshakeStream's job.
func coalesceRecords(buf []byte) ([]byte, error) {
	var hs []byte
	off := 0
	for off < len(buf) {
		if len(buf)-off < 5 { // record header: type(1) ver(2) len(2)
			break
		}
		ctype := buf[off]
		verMajor := buf[off+1]
		rlen := int(buf[off+3])<<8 | int(buf[off+4])
		// TLS 1.0-1.3 all carry record-layer major version 3. A first record
		// that is neither a handshake nor version-3 is not TLS; a later one
		// ENDS the handshake bytes rather than poisoning them, which is what
		// lets a 0-RTT flight ([ClientHello][early data]) parse. The SNI comes
		// only from the contiguous handshake records at offset 0.
		if ctype != tlsRecordHandshake || verMajor != 3 {
			if off == 0 {
				return nil, ErrNotTLS
			}
			break
		}
		payloadStart := off + 5
		avail := len(buf) - payloadStart
		if avail < rlen {
			hs = append(hs, buf[payloadStart:]...)
			break
		}
		hs = append(hs, buf[payloadStart:payloadStart+rlen]...)
		off = payloadStart + rlen
	}
	return hs, nil
}

// parseHandshakeStream frames and parses a ClientHello out of a raw TLS
// handshake byte stream — the record-coalesced bytes for TLS, or the
// CRYPTO-frame-reassembled bytes for QUIC (which carries handshake messages
// with no record layer). proto tags the returned Hello. A stream shorter than
// the message the handshake header promises is ErrIncomplete; a well-framed but
// internally-inconsistent message is ErrMalformed.
func parseHandshakeStream(hs []byte, proto Protocol) (Hello, error) {
	if len(hs) < 4 { // handshake header: msg_type(1) length(3)
		return Hello{Protocol: proto}, ErrIncomplete
	}
	if hs[0] != tlsHandshakeHello {
		return Hello{Protocol: proto}, ErrMalformed
	}
	total := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
	if len(hs) < total {
		return Hello{Protocol: proto}, ErrIncomplete
	}
	h, err := parseClientHelloBody(hs[4:total])
	if err != nil {
		// Never hand back a name we recovered from a hello we then failed to
		// parse: a caller that reads the name before the error would trust
		// attacker-chosen bytes from a message we rejected.
		return Hello{Protocol: proto}, err
	}
	h.Protocol = proto
	return h, nil
}

// parseClientHelloBody parses the ClientHello body (everything after the 4-byte
// handshake header). The body is a complete message, so any internal length
// that overruns it is malformed, never incomplete.
func parseClientHelloBody(body []byte) (Hello, error) {
	h := Hello{Protocol: ProtoTLS}
	c := cursor{b: body}

	c.skip(2)     // client_version
	c.skip(32)    // random
	c.skipVec8()  // session_id
	c.skipVec16() // cipher_suites
	c.skipVec8()  // compression_methods
	if c.bad {
		return h, ErrMalformed
	}
	if c.remaining() == 0 {
		return h, nil // no extensions block: a valid no-SNI hello
	}

	ext := c.readVec16()
	if c.bad {
		return h, ErrMalformed
	}
	if c.remaining() > 0 {
		// The vector must CONSUME the body. Undeclared trailing bytes are ones
		// a peer could read as further extensions, recovering a different name.
		return h, ErrMalformed
	}
	ec := cursor{b: ext}
	sawServerName := false
	for i := 0; i < maxExtensions && ec.remaining() > 0; i++ {
		etype := ec.readU16()
		edata := ec.readVec16()
		if ec.bad {
			return h, ErrMalformed
		}
		switch etype {
		case extECH:
			h.ECHPresent = true
		case extServerName:
			// Two names in one hello means the enforcer and the server may pin
			// different ones, so the ambiguity is refused rather than resolved
			// first- or last-wins.
			if sawServerName {
				return h, ErrMalformed
			}
			sawServerName = true
			name, ok := parseSNIExtension(edata)
			if !ok {
				return h, ErrMalformed
			}
			if name != "" {
				h.ServerName = name
			}
		}
	}
	if ec.remaining() > 0 {
		// The cap tripped with bytes unwalked: a server_name hidden past it is
		// the duplicate-name ambiguity through another door.
		return h, ErrMalformed
	}
	return h, nil
}

// parseSNIExtension pulls the single host_name entry out of a server_name
// extension. ok is false on structural corruption AND on a list with more
// than one entry: RFC 6066 §3 forbids two entries of the same name_type, the
// only defined type is host_name, and a multi-name hello is the same
// which-name-gets-enforced ambiguity as a duplicate extension (see the caller).
// A single entry of an unknown future name_type yields ("", true) — no
// identity recovered, the verdict layer fails it closed as no_name.
func parseSNIExtension(data []byte) (string, bool) {
	c := cursor{b: data}
	list := c.readVec16() // server_name_list
	if c.bad {
		return "", false
	}
	if c.remaining() > 0 {
		// The list must CONSUME the extension data. Trailing bytes after it
		// are an entry we never look at, and a peer that iterates the full
		// extension_data instead of the list length would select that name —
		// defeating the single-entry rule below through the outer length.
		return "", false
	}
	lc := cursor{b: list}
	result := ""
	seen := false
	for lc.remaining() > 0 {
		nameType := lc.readU8()
		name := lc.readVec16()
		if lc.bad {
			return "", false
		}
		if seen {
			return "", false // second list entry: ambiguous identity
		}
		seen = true
		if nameType == sniHostName {
			norm, ok := normalizeName(name)
			if !ok {
				return "", false
			}
			result = norm
		}
	}
	return result, true
}

// normalizeName lowercases and trailing-dot-strips a host name and rejects
// anything that is not a plausible DNS name: empty, over-long, bytes outside
// the LDH-plus-dot set, or an empty label (a leading dot, a trailing dot after
// the one we strip, or a "foo..bar" run). Empty labels are rejected because a
// hostname rule never contains them, so admitting "example.com.." as if it were
// "example.com" would be a name the matcher and the wire disagree on. A
// rejected name yields ok=false so the caller treats it as corruption.
func normalizeName(raw []byte) (string, bool) {
	if len(raw) == 0 || len(raw) > maxServerNameLen {
		return "", false
	}
	s := strings.ToLower(strings.TrimSuffix(string(raw), "."))
	if s == "" {
		return "", false
	}
	prevDot := true // a leading dot means an empty first label
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '-' || ch == '_'
		if !ok {
			return "", false
		}
		if ch == '.' {
			if prevDot { // empty label: leading dot or "foo..bar"
				return "", false
			}
			prevDot = true
		} else {
			prevDot = false
		}
	}
	if prevDot {
		// A dot still trailing after the one we stripped ("example.com..").
		// Without this the name keeps its dot and matches nothing: rules and
		// the per-IP binding store are both keyed dot-stripped, so it would
		// deny with name_mismatch and print the odd spelling into the audit
		// record, the OTLP server.address, and the allowlist suggestion.
		return "", false
	}
	return s, true
}
