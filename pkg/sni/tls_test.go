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
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// helloOpts builds a ClientHello for tests. A zero value produces a plain hello
// with the given SNI.
type helloOpts struct {
	sni       string
	withECH   bool
	extraExts [][2]any // [type uint16, data []byte]
	noExts    bool
}

// buildClientHello hand-assembles a TLS record wrapping a ClientHello. Using a
// hand build (not crypto/tls) lets us inject ECH, GREASE, and malformations.
func buildClientHello(o helloOpts) []byte {
	var exts bytes.Buffer
	putExt := func(typ uint16, data []byte) {
		exts.WriteByte(byte(typ >> 8))
		exts.WriteByte(byte(typ))
		exts.WriteByte(byte(len(data) >> 8))
		exts.WriteByte(byte(len(data)))
		exts.Write(data)
	}
	// GREASE extension first, to prove unknown types are skipped.
	putExt(0x0a0a, []byte{})
	if o.sni != "" {
		var sniData bytes.Buffer
		var entry bytes.Buffer
		entry.WriteByte(0x00) // host_name
		entry.WriteByte(byte(len(o.sni) >> 8))
		entry.WriteByte(byte(len(o.sni)))
		entry.WriteString(o.sni)
		sniData.WriteByte(byte(entry.Len() >> 8))
		sniData.WriteByte(byte(entry.Len()))
		sniData.Write(entry.Bytes())
		putExt(extServerName, sniData.Bytes())
	}
	if o.withECH {
		putExt(extECH, []byte{0x00, 0x01, 0x02})
	}
	for _, e := range o.extraExts {
		putExt(e[0].(uint16), e[1].([]byte))
	}

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // client_version TLS 1.2
	body.Write(make([]byte, 32))   // random
	body.WriteByte(0x00)           // session_id len 0
	body.Write([]byte{0x00, 0x02}) // cipher_suites len 2
	body.Write([]byte{0x13, 0x01}) // TLS_AES_128_GCM_SHA256
	body.WriteByte(0x01)           // compression_methods len 1
	body.WriteByte(0x00)           // null compression
	if !o.noExts {
		body.WriteByte(byte(exts.Len() >> 8))
		body.WriteByte(byte(exts.Len()))
		body.Write(exts.Bytes())
	}

	var hs bytes.Buffer
	hs.WriteByte(tlsHandshakeHello)
	hs.WriteByte(byte(body.Len() >> 16))
	hs.WriteByte(byte(body.Len() >> 8))
	hs.WriteByte(byte(body.Len()))
	hs.Write(body.Bytes())

	return wrapRecord(hs.Bytes())
}

// wrapRecord wraps handshake bytes in a single TLS record.
func wrapRecord(hs []byte) []byte {
	var rec bytes.Buffer
	rec.WriteByte(tlsRecordHandshake)
	rec.Write([]byte{0x03, 0x01}) // record version TLS 1.0 (as clients send)
	rec.WriteByte(byte(len(hs) >> 8))
	rec.WriteByte(byte(len(hs)))
	rec.Write(hs)
	return rec.Bytes()
}

func TestParseTLSClientHello_SNI(t *testing.T) {
	buf := buildClientHello(helloOpts{sni: "Auth.Docker.IO"})
	h, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.ServerName != "auth.docker.io" {
		t.Errorf("ServerName = %q, want auth.docker.io (lowercased)", h.ServerName)
	}
	if h.ECHPresent {
		t.Errorf("ECHPresent = true, want false")
	}
	if h.Protocol != ProtoTLS {
		t.Errorf("Protocol = %v, want tls", h.Protocol)
	}
}

func TestParseTLSClientHello_NoSNI(t *testing.T) {
	h, err := ParseTLSClientHello(buildClientHello(helloOpts{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.HasName() {
		t.Errorf("HasName = true, want false for no-SNI hello")
	}
}

func TestParseTLSClientHello_NoExtensionsBlock(t *testing.T) {
	h, err := ParseTLSClientHello(buildClientHello(helloOpts{noExts: true}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.HasName() {
		t.Errorf("HasName = true, want false")
	}
}

// GREASE-ECH: an ECH extension AND a valid cleartext SNI. The name must still
// be recovered — we key fail-closed on "no usable SNI", never "ECH present".
func TestParseTLSClientHello_GREASEEch(t *testing.T) {
	h, err := ParseTLSClientHello(buildClientHello(helloOpts{sni: "github.com", withECH: true}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.ServerName != "github.com" {
		t.Errorf("ServerName = %q, want github.com", h.ServerName)
	}
	if !h.ECHPresent {
		t.Errorf("ECHPresent = false, want true")
	}
}

// Real ECH shape: ECH present, no cleartext SNI. Parser succeeds; the oracle
// (not the parser) turns this into a deny.
func TestParseTLSClientHello_ECHNoSNI(t *testing.T) {
	h, err := ParseTLSClientHello(buildClientHello(helloOpts{withECH: true}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.HasName() {
		t.Errorf("HasName = true, want false")
	}
	if !h.ECHPresent {
		t.Errorf("ECHPresent = false, want true")
	}
}

func TestParseTLSClientHello_Incomplete(t *testing.T) {
	full := buildClientHello(helloOpts{sni: "example.com"})
	// Every strict prefix must be ErrIncomplete, never a name and never a
	// spurious malformed.
	for n := 1; n < len(full); n++ {
		h, err := ParseTLSClientHello(full[:n])
		if !errors.Is(err, ErrIncomplete) {
			t.Fatalf("prefix len %d: err = %v, want ErrIncomplete", n, err)
		}
		if h.HasName() {
			t.Fatalf("prefix len %d: recovered a name from a partial hello", n)
		}
	}
}

func TestParseTLSClientHello_RecordFragmented(t *testing.T) {
	full := buildClientHello(helloOpts{sni: "split.example.com"})
	// Re-fragment the handshake across two records at an awkward boundary.
	hs := full[5:] // strip the single record header
	mid := len(hs) / 2
	frag := append(wrapRecord(hs[:mid]), wrapRecord(hs[mid:])...)
	h, err := ParseTLSClientHello(frag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.ServerName != "split.example.com" {
		t.Errorf("ServerName = %q, want split.example.com", h.ServerName)
	}
}

func TestParseTLSClientHello_NotTLS(t *testing.T) {
	// An SSH banner on :443.
	if _, err := ParseTLSClientHello([]byte("SSH-2.0-OpenSSH_9.6\r\n")); !errors.Is(err, ErrNotTLS) {
		t.Errorf("err = %v, want ErrNotTLS", err)
	}
}

func TestParseTLSClientHello_MalformedInternalOverrun(t *testing.T) {
	buf := buildClientHello(helloOpts{sni: "example.com"})
	// Corrupt the cipher_suites length to claim far more than the body holds.
	// Body starts after 5-byte record + 4-byte handshake headers; layout:
	// version(2) random(32) sid_len(1)=0 => cipher_len at offset 9+2+32+1.
	idx := 5 + 4 + 2 + 32 + 1
	buf[idx] = 0xff
	buf[idx+1] = 0xff
	if _, err := ParseTLSClientHello(buf); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

// sniExtData builds a server_name extension body carrying the given
// host_name entries — more than one is the multi-entry attack shape.
func sniExtData(names ...string) []byte {
	var entries bytes.Buffer
	for _, n := range names {
		entries.WriteByte(0x00) // host_name
		entries.WriteByte(byte(len(n) >> 8))
		entries.WriteByte(byte(len(n)))
		entries.WriteString(n)
	}
	var data bytes.Buffer
	data.WriteByte(byte(entries.Len() >> 8))
	data.WriteByte(byte(entries.Len()))
	data.Write(entries.Bytes())
	return data.Bytes()
}

// TestParseTLSClientHello_RejectsDuplicateSNI: identity pinning that takes
// "some" SNI is not pinning. A hello carrying two names — as two server_name
// extensions (TLS forbids duplicate extensions outright) or two host_name
// entries in one list (RFC 6066 §3 forbids two entries of one name_type) —
// is ambiguous: the enforcer and the server may pick different names, which
// is the exact shared-edge swap this layer exists to close. Both shapes must
// be ErrMalformed, never first-wins or last-wins.
func TestParseTLSClientHello_RejectsDuplicateSNI(t *testing.T) {
	// Two server_name EXTENSIONS: an allowed-looking name and an attacker's.
	buf := buildClientHello(helloOpts{sni: "allowed.example", extraExts: [][2]any{
		{uint16(extServerName), sniExtData("evil.attacker.example")},
	}})
	if _, err := ParseTLSClientHello(buf); !errors.Is(err, ErrMalformed) {
		t.Errorf("duplicate server_name extension: err = %v, want ErrMalformed", err)
	}

	// Two host_name ENTRIES in a single extension's list.
	buf = buildClientHello(helloOpts{extraExts: [][2]any{
		{uint16(extServerName), sniExtData("allowed.example", "evil.attacker.example")},
	}})
	if _, err := ParseTLSClientHello(buf); !errors.Is(err, ErrMalformed) {
		t.Errorf("multi-entry server_name list: err = %v, want ErrMalformed", err)
	}
}

func TestParseTLSClientHello_MalformedNotClientHello(t *testing.T) {
	buf := buildClientHello(helloOpts{sni: "example.com"})
	buf[5] = 0x02 // ServerHello msg_type inside a handshake record
	if _, err := ParseTLSClientHello(buf); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

// Cross-check against a real crypto/tls-generated ClientHello so the hand-built
// fixtures aren't testing a private dialect.
func TestParseTLSClientHello_RealCryptoTLS(t *testing.T) {
	rec := realClientHelloRecord(t, "cdn.example.org")
	h, err := ParseTLSClientHello(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.ServerName != "cdn.example.org" {
		t.Errorf("ServerName = %q, want cdn.example.org", h.ServerName)
	}
}

// realClientHelloRecord captures the first flight crypto/tls writes for a
// given SNI by handing it a synchronous pipe, reading the first record it
// sends, then closing the pipe to unblock the doomed handshake.
func realClientHelloRecord(t *testing.T, serverName string) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	go func() {
		c := tls.Client(cli, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
		_ = c.Handshake() // fails at the pipe; we only need the ClientHello it writes first
	}()
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(srv, hdr); err != nil {
		t.Fatalf("reading record header: %v", err)
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, n)
	if _, err := io.ReadFull(srv, body); err != nil {
		t.Fatalf("reading record body: %v", err)
	}
	_ = srv.Close()
	_ = cli.Close()
	return append(hdr, body...)
}

// Regression (found by FuzzParseTLSClientHello): a hello carrying a valid SNI
// followed by a malformed extension must yield the error and NO name. A caller
// that read the name before checking the error would otherwise trust a name
// from a message we rejected.
func TestParseTLSClientHello_ErrorNeverCarriesName(t *testing.T) {
	buf := buildClientHello(helloOpts{
		sni: "allowed.example.com",
		// A trailing extension whose declared length overruns the block.
		extraExts: [][2]any{{uint16(0x1234), []byte{0x00}}},
	})
	// Corrupt that last extension's length to overrun.
	buf[len(buf)-3] = 0xff
	buf[len(buf)-2] = 0xff
	h, err := ParseTLSClientHello(buf)
	if err == nil {
		t.Fatal("expected an error for the overrunning extension")
	}
	if h.HasName() {
		t.Errorf("ServerName = %q alongside error %v; want no name", h.ServerName, err)
	}
}

// Regression (code review nit): empty labels must be rejected so the parser's
// notion of a valid name matches the hostname rules it will be checked against.
func TestParseTLSClientHello_EmptyLabelsRejected(t *testing.T) {
	for _, bad := range []string{"foo..bar", ".example.com", "example.com..", "..", "a."} {
		buf := buildClientHello(helloOpts{sni: bad})
		h, err := ParseTLSClientHello(buf)
		if err != nil || !h.HasName() {
			continue // rejected outright: correct
		}
		// A RECOVERED name must be a clean one. Asserting only "not accepted
		// verbatim" is too weak — it let "example.com.." through as
		// "example.com." (one dot stripped, the rest unchecked), which matches
		// no rule and no per-IP binding since both are keyed dot-stripped.
		got := h.ServerName
		if strings.HasPrefix(got, ".") || strings.HasSuffix(got, ".") || strings.Contains(got, "..") {
			t.Errorf("%q recovered as %q, which still has an empty label", bad, got)
		}
	}
	// A single trailing dot is still fine (fully-qualified form).
	h, err := ParseTLSClientHello(buildClientHello(helloOpts{sni: "example.com."}))
	if err != nil || h.ServerName != "example.com" {
		t.Errorf("FQDN 'example.com.' -> %q / %v, want example.com", h.ServerName, err)
	}
}

// TestParseTLSClientHello_ZeroRTT: a TLS 1.3 0-RTT first flight is a
// ClientHello record followed by an application_data (early data) record in
// one flight. The trailing non-handshake record must END the handshake bytes,
// not poison them — the SNI is fully present in the ClientHello.
func TestParseTLSClientHello_ZeroRTT(t *testing.T) {
	hello := buildClientHello(helloOpts{sni: "allowed.example.com"}) // one handshake record
	// Append an application_data record (early data): type 23, ver 0x0303, len 4.
	earlyData := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef}
	flight := append(append([]byte{}, hello...), earlyData...)

	h, err := ParseTLSClientHello(flight)
	if err != nil {
		t.Fatalf("0-RTT flight must parse, got %v", err)
	}
	if h.ServerName != "allowed.example.com" {
		t.Errorf("ServerName = %q, want allowed.example.com", h.ServerName)
	}
}

// helloWithBodyTail builds a ClientHello whose extensions vector is well formed
// but does not CONSUME the body: tail undeclared bytes follow it, covered by
// the handshake length.
func helloWithBodyTail(sni string, tail []byte) []byte {
	rec := buildClientHello(helloOpts{sni: sni})
	body := rec[5+4:] // past the record header and the handshake header
	full := append(append([]byte{}, body...), tail...)

	var hs bytes.Buffer
	hs.WriteByte(tlsHandshakeHello)
	hs.WriteByte(byte(len(full) >> 16))
	hs.WriteByte(byte(len(full) >> 8))
	hs.WriteByte(byte(len(full)))
	hs.Write(full)
	return wrapRecord(hs.Bytes())
}

// TestParseTLSClientHelloRejectsBodyTail: the extensions vector must consume
// the ClientHello body. Bytes past it are bytes we never parsed, and a peer
// that reads them as further extensions can recover a different server_name —
// the same ambiguity the duplicate-extension rule refuses, reached through the
// outer length instead.
func TestParseTLSClientHelloRejectsBodyTail(t *testing.T) {
	// The tail is itself a well-formed server_name extension for another name,
	// which is exactly what a lenient peer would pick up.
	var entry bytes.Buffer
	entry.WriteByte(0x00)
	entry.Write([]byte{0x00, byte(len("evil.example"))})
	entry.WriteString("evil.example")
	var sniData bytes.Buffer
	sniData.Write([]byte{0x00, byte(entry.Len())})
	sniData.Write(entry.Bytes())
	var tail bytes.Buffer
	tail.Write([]byte{0x00, 0x00}) // extension_type = server_name
	tail.Write([]byte{0x00, byte(sniData.Len())})
	tail.Write(sniData.Bytes())

	_, err := ParseTLSClientHello(helloWithBodyTail("good.example", tail.Bytes()))
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed for undeclared bytes after the extensions vector", err)
	}

	// Control: the same hello with no tail parses.
	h, err := ParseTLSClientHello(helloWithBodyTail("good.example", nil))
	if err != nil || h.ServerName != "good.example" {
		t.Errorf("control hello: got %q / %v, want good.example", h.ServerName, err)
	}
}

// TestParseSNIExtensionRejectsListTail: the server_name_list length must
// consume the extension data. Trailing bytes are an entry we never look at, so
// a peer iterating the full extension_data would select a name we did not pin.
func TestParseSNIExtensionRejectsListTail(t *testing.T) {
	sniExt := func(name string, tail []byte) []byte {
		var entry bytes.Buffer
		entry.WriteByte(0x00) // host_name
		entry.Write([]byte{0x00, byte(len(name))})
		entry.WriteString(name)
		var data bytes.Buffer
		data.Write([]byte{0x00, byte(entry.Len())}) // server_name_list length
		data.Write(entry.Bytes())
		data.Write(tail) // undeclared bytes past the list
		return data.Bytes()
	}

	// A second host_name entry hidden past the declared list length.
	var hidden bytes.Buffer
	hidden.WriteByte(0x00)
	hidden.Write([]byte{0x00, byte(len("evil.example"))})
	hidden.WriteString("evil.example")

	hello := buildClientHello(helloOpts{
		extraExts: [][2]any{{uint16(extServerName), sniExt("good.example", hidden.Bytes())}},
	})
	if _, err := ParseTLSClientHello(hello); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed for bytes after server_name_list", err)
	}

	// Control: no tail parses and pins the single name.
	ok := buildClientHello(helloOpts{
		extraExts: [][2]any{{uint16(extServerName), sniExt("good.example", nil)}},
	})
	h, err := ParseTLSClientHello(ok)
	if err != nil || h.ServerName != "good.example" {
		t.Errorf("control: got %q / %v, want good.example", h.ServerName, err)
	}
}
