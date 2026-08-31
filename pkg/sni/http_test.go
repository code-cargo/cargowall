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
	"errors"
	"strings"
	"testing"
)

func TestParseHTTPRequestHost(t *testing.T) {
	tests := []struct {
		name string
		req  string
		want string
	}{
		{
			name: "ordinary GET",
			req:  "GET /v2/ HTTP/1.1\r\nHost: registry.example.com\r\nUser-Agent: curl/8\r\n\r\n",
			want: "registry.example.com",
		},
		{
			name: "host case and port stripped",
			req:  "GET / HTTP/1.1\r\nHost: OCSP.Sectigo.COM:80\r\n\r\n",
			want: "ocsp.sectigo.com",
		},
		{
			name: "header name case insensitive",
			req:  "POST /ocsp HTTP/1.1\r\nhOsT: ocsp.digicert.com\r\n\r\n",
			want: "ocsp.digicert.com",
		},
		{
			name: "Host is authoritative, agreeing absolute form ok",
			req:  "GET http://real.example.com/p HTTP/1.1\r\nHost: real.example.com\r\n\r\n",
			want: "real.example.com",
		},
		{
			name: "absolute form only as fallback when no Host",
			req:  "GET http://fallback.example.com/p HTTP/1.0\r\n\r\n",
			want: "fallback.example.com",
		},
		{
			name: "CONNECT authority-form target",
			req:  "CONNECT tunnel.example.com:443 HTTP/1.1\r\n\r\n",
			want: "tunnel.example.com",
		},
		{
			name: "LF-only terminator",
			req:  "GET / HTTP/1.1\nHost: lf.example.com\n\n",
			want: "lf.example.com",
		},
		{
			name: "trailing dot stripped",
			req:  "GET / HTTP/1.1\r\nHost: root.example.com.\r\n\r\n",
			want: "root.example.com",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParseHTTPRequestHost([]byte(tc.req))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h.ServerName != tc.want {
				t.Errorf("ServerName = %q, want %q", h.ServerName, tc.want)
			}
			if h.Protocol != ProtoHTTP {
				t.Errorf("Protocol = %v, want http", h.Protocol)
			}
		})
	}
}

func TestParseHTTPRequestHost_NoHost(t *testing.T) {
	// HTTP/1.0 without a Host header: parses fine, no name. The oracle denies.
	h, err := ParseHTTPRequestHost([]byte("GET / HTTP/1.0\r\n\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.HasName() {
		t.Errorf("HasName = true, want false")
	}
}

func TestParseHTTPRequestHost_Incomplete(t *testing.T) {
	full := "GET / HTTP/1.1\r\nHost: split.example.com\r\n\r\n"
	for n := 1; n < len(full)-1; n++ {
		h, err := ParseHTTPRequestHost([]byte(full[:n]))
		if !errors.Is(err, ErrIncomplete) {
			t.Fatalf("prefix %d (%q): err = %v, want ErrIncomplete", n, full[:n], err)
		}
		if h.HasName() {
			t.Fatalf("prefix %d: recovered a name from a partial head", n)
		}
	}
}

func TestParseHTTPRequestHost_DuplicateHostIsMalformed(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n"
	if _, err := ParseHTTPRequestHost([]byte(req)); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed (smuggling signature)", err)
	}
}

func TestParseHTTPRequestHost_NotHTTP(t *testing.T) {
	for _, s := range []string{
		"SSH-2.0-OpenSSH_9.6\r\n",
		"\x16\x03\x01\x00\x50", // a TLS record on :80
	} {
		if _, err := ParseHTTPRequestHost([]byte(s)); !errors.Is(err, ErrNotHTTP) {
			t.Errorf("%q: err = %v, want ErrNotHTTP", s, err)
		}
	}
}

func TestParseHTTPRequestHost_IPv6LiteralHasNoName(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: [2606:4700::1]:80\r\n\r\n"
	h, err := ParseHTTPRequestHost([]byte(req))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.HasName() {
		t.Errorf("ServerName = %q, want empty (an IP literal pins no hostname)", h.ServerName)
	}
}

func TestParseHTTPRequestHost_BadRequestLine(t *testing.T) {
	if _, err := ParseHTTPRequestHost([]byte("GET /only-two-fields\r\nHost: x.com\r\n\r\n")); !errors.Is(err, ErrMalformed) {
		t.Errorf("want ErrMalformed for a 2-field request line")
	}
}

// Regression (found by FuzzParseHTTPRequestHost): a request whose Host parses
// but whose later header line is malformed must yield no name alongside the
// error, so a caller cannot act on a name from a rejected request.
func TestParseHTTPRequestHost_ErrorNeverCarriesName(t *testing.T) {
	h, err := ParseHTTPRequestHost([]byte("GET 0 HTTP/\nHost:0\n00\n\n"))
	if err == nil {
		t.Fatal("expected an error for the malformed header line")
	}
	if h.HasName() {
		t.Errorf("ServerName = %q alongside error %v; want no name", h.ServerName, err)
	}
}

// Regression (code review): a duplicate Host must be rejected even when the
// FIRST Host is an IPv6 literal (which yields an empty ServerName). The prior
// "already saw a Host" test keyed on a non-empty ServerName and so missed this.
func TestParseHTTPRequestHost_DuplicateHostAfterIPv6Literal(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: [::1]\r\nHost: allowed.example.com\r\n\r\n"
	if _, err := ParseHTTPRequestHost([]byte(req)); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed (duplicate Host after an IPv6 literal)", err)
	}
}

// The shared-edge threat model pins on Host: a request-target that names a
// different host than Host is a smuggling attempt (route on one, be filtered on
// the other), so it must be rejected, not resolved to either.
func TestParseHTTPRequestHost_TargetHostMismatchIsMalformed(t *testing.T) {
	req := "GET http://real.example.com/p HTTP/1.1\r\nHost: decoy.example.com\r\n\r\n"
	if _, err := ParseHTTPRequestHost([]byte(req)); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed (Host/absolute-form mismatch)", err)
	}
}

// obs-fold (a header line continued with leading whitespace) must be refused
// outright, not silently treated as the end of the headers — a folded Host is a
// smuggling vector.
func TestParseHTTPRequestHost_ObsFoldRefused(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\tevil.example.com\r\n\r\n"
	if _, err := ParseHTTPRequestHost([]byte(req)); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed (obs-fold must be refused)", err)
	}
}

// TestParseHTTPRequestHost_OversizedHeadRejected: maxRequestHead bounds what we
// PARSE, not merely how long we wait for a terminator. A head that does
// terminate, but past the bound, must be refused exactly like one that never
// terminates — otherwise the limit is enforced only for the case that cannot
// reach the parser anyway.
func TestParseHTTPRequestHost_OversizedHeadRejected(t *testing.T) {
	pad := strings.Repeat("X-Pad: 0123456789abcdef\r\n", 400) // ~10KB > maxRequestHead
	req := "GET / HTTP/1.1\r\nHost: allowed.example\r\n" + pad + "\r\n"
	if len(req) <= maxRequestHead {
		t.Fatalf("test premise: request is %d bytes, want > %d", len(req), maxRequestHead)
	}
	if _, err := ParseHTTPRequestHost([]byte(req)); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed for a head terminating past maxRequestHead", err)
	}

	// Control: a head comfortably under the bound still parses its Host.
	small := "GET / HTTP/1.1\r\nHost: allowed.example\r\n" +
		strings.Repeat("X-Pad: 0123456789abcdef\r\n", 40) + "\r\n"
	h, err := ParseHTTPRequestHost([]byte(small))
	if err != nil || h.ServerName != "allowed.example" {
		t.Errorf("control: got %q / %v, want allowed.example", h.ServerName, err)
	}
}
