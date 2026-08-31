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

import "errors"

// MaxAssembly bounds the handshake bytes we will hold for one flow. A
// ClientHello — even with post-quantum key shares — is far under this; the cap
// exists so a flood of tiny punted segments cannot grow userspace memory.
const MaxAssembly = 16 << 10

// ErrOverlapConflict signals two chunks claimed the same offset range with
// different bytes. That is never benign retransmission — it is an attempt to
// show the parser one name and the server another, so the caller fails closed.
var ErrOverlapConflict = errors.New("sni: conflicting overlap in reassembly")

// ErrAssemblyOverflow signals the flow exceeded MaxAssembly.
var ErrAssemblyOverflow = errors.New("sni: reassembly buffer overflow")

// Assembler reassembles a handshake byte stream from chunks that may arrive out
// of order, duplicated, or overlapping — TCP segments keyed by their offset
// from the start of the client's first flight, or QUIC CRYPTO frames keyed by
// their stream offset. It is not safe for concurrent use.
//
// Retransmitted bytes that agree are absorbed silently; bytes that disagree are
// a conflict, because an attacker who can rewrite already-delivered handshake
// bytes could otherwise desynchronize our view from the server's.
type Assembler struct {
	buf    []byte
	filled []bool
	high   int // one past the highest byte ever written
	// contig is the length of the contiguous prefix from offset 0, advanced
	// incrementally by Add. Recomputing it by walking `filled` on every
	// Bytes()/Len() call — which the oracle makes once per punted segment —
	// made reassembling a hello from many small chunks quadratic.
	contig int
}

// Add merges one chunk at the given offset.
func (a *Assembler) Add(offset uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	// Bound offset and length independently, without ever computing offset+len:
	// that sum can wrap uint64 for a caller-supplied offset near 2^64, slip past
	// an end check, and then panic on the negative int(offset) index below. Add
	// is exported, so this must hold for any caller, not just the QUIC decoder
	// that already bounds offsets.
	if offset >= MaxAssembly || uint64(len(data)) > MaxAssembly-offset {
		return ErrAssemblyOverflow
	}
	end := offset + uint64(len(data))
	if int(end) > len(a.buf) {
		// Grow with append's amortized doubling rather than an exact-size
		// allocation per chunk: an exact fit reallocates and copies BOTH
		// slices on every extending chunk, which is quadratic over a hello
		// delivered as many small segments.
		a.buf = append(a.buf, make([]byte, int(end)-len(a.buf))...)
		a.filled = append(a.filled, make([]bool, int(end)-len(a.filled))...)
	}
	for i, b := range data {
		pos := int(offset) + i
		if a.filled[pos] {
			if a.buf[pos] != b {
				return ErrOverlapConflict
			}
			continue
		}
		a.buf[pos] = b
		a.filled[pos] = true
	}
	if int(end) > a.high {
		a.high = int(end)
	}
	// Advance the contiguous prefix over whatever this chunk just closed. Each
	// byte is visited at most once across the Assembler's life, so maintaining
	// it costs O(total bytes), not O(bytes x chunks).
	for a.contig < a.high && a.filled[a.contig] {
		a.contig++
	}
	return nil
}

// Bytes returns the contiguous prefix assembled so far, starting at offset 0.
// A gap truncates the result: parsers must never see bytes from beyond a hole
// as if they were adjacent to what precedes it.
func (a *Assembler) Bytes() []byte { return a.buf[:a.contig] }

// Len is the length of the contiguous prefix.
func (a *Assembler) Len() int { return a.contig }

// Reset drops all state so the Assembler can be reused.
func (a *Assembler) Reset() {
	a.buf = nil
	a.filled = nil
	a.high = 0
	a.contig = 0
}
