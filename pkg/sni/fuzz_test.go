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
	"testing"

	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// Every parser here consumes bytes an attacker fully controls, so the contract
// they must never break is: no panic, and never a recovered name from input the
// parser reported an error on.

func FuzzParseTLSClientHello(f *testing.F) {
	f.Add(buildClientHello(helloOpts{sni: "example.com"}))
	f.Add(buildClientHello(helloOpts{withECH: true}))
	f.Add([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseTLSClientHello(data)
		if err != nil && h.HasName() {
			t.Fatalf("returned name %q alongside error %v", h.ServerName, err)
		}
	})
}

func FuzzParseHTTPRequestHost(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("GET http://a.b/c HTTP/1.1\r\n\r\n"))
	f.Add([]byte("POST"))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseHTTPRequestHost(data)
		if err != nil && h.HasName() {
			t.Fatalf("returned name %q alongside error %v", h.ServerName, err)
		}
	})
}

func FuzzDecodeInitialCrypto(f *testing.F) {
	f.Add(snitest.RFC9001ClientInitial())
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08})
	f.Add([]byte{0x40, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		chunks, err := DecodeInitialCrypto(data)
		if err != nil && len(chunks) > 0 {
			t.Fatalf("returned %d chunks alongside error %v", len(chunks), err)
		}
		var a Assembler
		for _, c := range chunks {
			_ = a.Add(c.Offset, c.Data)
		}
		_, _ = ParseQUICClientHello(a.Bytes())
	})
}

func FuzzAssembler(f *testing.F) {
	f.Add(uint64(0), []byte("abc"), uint64(3), []byte("def"))
	f.Add(uint64(5), []byte("x"), uint64(0), []byte("yyyyy"))
	f.Fuzz(func(t *testing.T, o1 uint64, d1 []byte, o2 uint64, d2 []byte) {
		var a Assembler
		_ = a.Add(o1%(MaxAssembly+64), d1)
		_ = a.Add(o2%(MaxAssembly+64), d2)
		if a.Len() > MaxAssembly {
			t.Fatalf("assembled %d bytes, over the %d cap", a.Len(), MaxAssembly)
		}
	})
}
