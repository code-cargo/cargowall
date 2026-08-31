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
	"errors"
	"strings"
)

// ErrNotHTTP signals bytes on a scoped cleartext port that are not an HTTP/1.x
// request. Like ErrNotTLS it is a distinct reason so telemetry can tell
// "someone tunneled a foreign protocol over :80" from "malformed HTTP".
var ErrNotHTTP = errors.New("sni: not an HTTP/1.x request")

// maxRequestHead bounds how much of a request head we scan for the Host
// header. A head whose terminator lies at or beyond it is malformed, exactly
// like one with no terminator at all — the bound governs what we will parse,
// not merely how long we will wait for CRLFCRLF to show up.
const maxRequestHead = 8 << 10

// httpMethods are the HTTP/1.x methods we accept as a request-line opener.
// An unrecognized token means this is not HTTP, which fails closed.
var httpMethods = []string{
	"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT",
	"OPTIONS", "TRACE", "PATCH",
}

// HTTPMethods returns the request-line method tokens this parser accepts.
// Exported so the kernel identity gate's token table (l7_http_request_line
// in bpf/sni.h) can be pinned equal by test — the two lists answer the same
// question in two places, and a divergence either silently fail-closes a
// legal first flight on a NEED_HELLO flow or passes a no-state request as
// established body traffic.
func HTTPMethods() []string {
	out := make([]string, len(httpMethods))
	copy(out, httpMethods)
	return out
}

// ParseHTTPRequestHost recovers the destination name from an HTTP/1.x request
// head, pinned on the Host header. This package's threat model is a shared-edge
// origin (Cloudflare/Akamai virtual-host on Host, exactly as TLS routes on
// SNI), so Host is authoritative — not the absolute-form request-target a
// forward proxy would route on. The target authority (absolute-form, or a
// CONNECT authority-form target) is consulted only as a fallback when no Host
// header is present, and a Host that disagrees with the target authority is
// rejected as a smuggling signature rather than resolved in either direction.
//
// Returns ErrIncomplete until the head is terminated by CRLFCRLF (or LFLF), so
// a request split across segments is reassembled rather than guessed at. A
// request with no name at all parses successfully with an empty ServerName —
// the oracle turns that into a deny, keeping policy out of the parser.
func ParseHTTPRequestHost(buf []byte) (Hello, error) {
	h := Hello{Protocol: ProtoHTTP}
	if len(buf) == 0 {
		return h, ErrIncomplete
	}
	if !looksLikeHTTP(buf) {
		return h, ErrNotHTTP
	}

	head, ok := requestHead(buf)
	if !ok {
		if len(buf) >= maxRequestHead {
			return h, ErrMalformed
		}
		return h, ErrIncomplete
	}

	lines := splitLines(head)
	if len(lines) == 0 {
		return h, ErrMalformed
	}

	// Request line: METHOD SP request-target SP HTTP/x.y
	parts := strings.Fields(lines[0])
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return h, ErrMalformed
	}
	method := parts[0]
	// The name the request-target itself names, if any: the authority of an
	// absolute-form target, or a CONNECT authority-form target.
	targetName, targetHasName, targetOK := targetAuthorityName(method, parts[1])
	if !targetOK {
		return h, ErrMalformed
	}

	hostName, sawHost, hostOK := hostHeaderName(lines[1:])
	if !hostOK {
		return h, ErrMalformed
	}

	switch {
	case sawHost && targetHasName:
		// Both name the destination: they must agree. A mismatch is a request
		// smuggling attempt (route on one, be filtered on the other).
		if hostName != targetName {
			return h, ErrMalformed
		}
		h.ServerName = hostName
	case sawHost:
		h.ServerName = hostName // may be "" for an IPv6-literal Host
	case targetHasName:
		h.ServerName = targetName // fallback: absolute-form / CONNECT, no Host
	}
	return h, nil
}

// hostHeaderName scans the header lines for the Host header. It returns the
// recovered name (possibly "" for an IPv6-literal Host), whether a Host header
// was seen at all, and ok=false on any structural problem: a malformed header
// line, an obs-fold continuation (a line starting with SP/HTAB — refused
// outright, since folding Host is a smuggling vector no real client needs), a
// duplicate Host, or an unparseable Host value.
func hostHeaderName(headerLines []string) (name string, sawHost, ok bool) {
	for _, line := range headerLines {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// obs-fold continuation: refuse the whole request rather than
			// unfold it (RFC 7230 §3.2.4 lets a firewall do exactly this).
			return "", false, false
		}
		fieldName, value, found := strings.Cut(line, ":")
		if !found {
			return "", false, false
		}
		if !strings.EqualFold(strings.TrimSpace(fieldName), "host") {
			continue
		}
		if sawHost {
			// Duplicate Host headers are a smuggling signature. Tracked with an
			// explicit flag, not a non-empty name: a first Host that is an IPv6
			// literal leaves name "" yet must still count as seen.
			return "", true, false
		}
		sawHost = true
		host, parsedOK := hostFromAuthority(strings.TrimSpace(value))
		if !parsedOK {
			return "", true, false
		}
		name = host
	}
	return name, sawHost, true
}

// targetAuthorityName extracts the name the request-target itself names, if
// any: the authority of an absolute-form target, or a CONNECT authority-form
// target (which is always authority-form per RFC 9110 §9.3.6). It returns the
// name, whether the target named anything, and ok=false only on a target that
// is structurally an authority but not parseable.
func targetAuthorityName(method, target string) (name string, hasName, ok bool) {
	var authority string
	if strings.EqualFold(method, "CONNECT") {
		authority = target
	} else {
		authority = absoluteFormAuthority(target)
	}
	if authority == "" {
		return "", false, true // origin-form target: names nothing
	}
	n, parsedOK := hostFromAuthority(authority)
	if !parsedOK {
		return "", true, false
	}
	return n, true, true
}

// looksLikeHTTP checks the first token against the known methods so a non-HTTP
// protocol on :80 is rejected as such rather than parsed as a malformed
// request.
func looksLikeHTTP(buf []byte) bool {
	limit := len(buf)
	if limit > 8 {
		limit = 8
	}
	prefix := string(buf[:limit])
	for _, m := range httpMethods {
		if strings.HasPrefix(prefix, m+" ") {
			return true
		}
		// We may hold only part of the request line — "GE", "GET", "GET" with
		// the space still in flight. Any prefix of "METHOD " keeps the request
		// eligible so the caller reassembles instead of failing closed on a
		// mid-method segment boundary.
		if len(prefix) <= len(m) && strings.HasPrefix(m+" ", prefix) {
			return true
		}
	}
	return false
}

// requestHead returns the head (up to but excluding the terminator) and whether
// a terminator was found.
func requestHead(buf []byte) ([]byte, bool) {
	// Scan at most maxRequestHead bytes. A terminator past that is not found,
	// so the caller refuses the request as malformed — the same answer it
	// gives a head with no terminator at all. Searching the whole buffer
	// instead let an oversized head through whenever it happened to terminate,
	// which is the case the bound exists to refuse.
	if len(buf) > maxRequestHead {
		buf = buf[:maxRequestHead]
	}
	if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
		return buf[:i], true
	}
	if i := bytes.Index(buf, []byte("\n\n")); i >= 0 {
		return buf[:i], true
	}
	return nil, false
}

func splitLines(head []byte) []string {
	s := strings.ReplaceAll(string(head), "\r\n", "\n")
	return strings.Split(s, "\n")
}

// absoluteFormAuthority extracts the authority from an absolute-form
// request-target (RFC 9112 §3.2.2, "GET http://host/path HTTP/1.1"). It returns
// "" for the ordinary origin-form target.
func absoluteFormAuthority(target string) string {
	lower := strings.ToLower(target)
	for _, scheme := range []string{"http://", "https://"} {
		if strings.HasPrefix(lower, scheme) {
			rest := target[len(scheme):]
			if i := strings.IndexAny(rest, "/?#"); i >= 0 {
				return rest[:i]
			}
			return rest
		}
	}
	return ""
}

// hostFromAuthority strips any userinfo and port from an authority and
// normalizes the host. IPv6 literals are unwrapped from their brackets.
func hostFromAuthority(authority string) (string, bool) {
	if authority == "" {
		return "", false
	}
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		authority = authority[i+1:]
	}
	if strings.HasPrefix(authority, "[") {
		end := strings.Index(authority, "]")
		if end < 0 {
			return "", false
		}
		// An IPv6 literal is a valid authority but never a name we can pin to
		// a hostname rule; report it as nameless so the oracle fails closed.
		return "", true
	}
	if i := strings.LastIndex(authority, ":"); i >= 0 {
		authority = authority[:i]
	}
	name, ok := normalizeName([]byte(authority))
	if !ok {
		return "", false
	}
	return name, true
}
