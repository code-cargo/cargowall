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

// Package sni recovers the L7 destination identity — a TLS ClientHello's SNI,
// an HTTP/1.x Host header, or a QUIC Initial's SNI — from raw handshake bytes.
// It is a parse-only library: it turns bytes into a Hello (a name, or a
// well-defined error), and takes no policy decisions. Deciding what a recovered
// name means — matching it against rules, mapping a parse error onto an audit
// reason, adjudicating a flow — belongs to the oracle (pkg/origin's L7), not here.
//
// It is deliberately free of eBPF and config dependencies so the parsers and
// the QUIC Initial decryptor build and test on any host.
//
// The security contract every parser here obeys: a prefix of a well-formed
// handshake yields ErrIncomplete (the caller reassembles and retries), while
// anything structurally wrong yields ErrMalformed (the caller fails closed).
// Neither ever guesses a name from partial bytes, and an error never carries a
// recovered name — so a caller that reads the name before checking the error
// still cannot act on bytes from a message the parser rejected.
package sni

import "errors"

// Protocol distinguishes the three L7 identities the parsers handle.
type Protocol uint8

const (
	ProtoUnknown Protocol = iota
	ProtoTLS              // TLS ClientHello over TCP (typically :443)
	ProtoHTTP             // HTTP/1.x request over TCP (typically :80)
	ProtoQUIC             // QUIC Initial over UDP (typically :443)
)

func (p Protocol) String() string {
	switch p {
	case ProtoTLS:
		return "tls"
	case ProtoHTTP:
		return "http"
	case ProtoQUIC:
		return "quic"
	default:
		return "unknown"
	}
}

// Hello is the outcome of parsing a single handshake: the recovered name (if
// any), whether an ECH extension was present, and which protocol produced it.
// ServerName is lowercased and trailing-dot-stripped, ready for a rule match.
type Hello struct {
	Protocol   Protocol
	ServerName string // SNI (TLS/QUIC) or Host (HTTP); "" if none was present
	ECHPresent bool   // a TLS/QUIC ECH extension was seen
}

// HasName reports whether a usable cleartext destination name was recovered.
func (h Hello) HasName() bool { return h.ServerName != "" }

var (
	// ErrIncomplete signals that the bytes are a valid prefix of a larger
	// handshake: the caller should reassemble more and retry. It is never a
	// verdict on its own.
	ErrIncomplete = errors.New("sni: incomplete handshake")
	// ErrMalformed signals structurally invalid bytes: the caller fails closed.
	ErrMalformed = errors.New("sni: malformed handshake")
)

// ErrNotTLS signals the first bytes on a scoped TLS port are not a TLS
// handshake at all (e.g. SSH-over-443). The caller maps it to L7NotProtocol,
// distinct from a corrupt-but-TLS ErrMalformed.
var ErrNotTLS = errors.New("sni: not a TLS handshake")
