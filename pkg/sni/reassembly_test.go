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
	"testing"
)

func TestAssembler_InOrder(t *testing.T) {
	var a Assembler
	mustAdd(t, &a, 0, []byte("hello "))
	mustAdd(t, &a, 6, []byte("world"))
	if got := string(a.Bytes()); got != "hello world" {
		t.Errorf("Bytes = %q, want %q", got, "hello world")
	}
}

func TestAssembler_OutOfOrder(t *testing.T) {
	var a Assembler
	mustAdd(t, &a, 6, []byte("world"))
	if got := string(a.Bytes()); got != "" {
		t.Errorf("Bytes = %q, want empty while offset 0 is missing", got)
	}
	mustAdd(t, &a, 0, []byte("hello "))
	if got := string(a.Bytes()); got != "hello world" {
		t.Errorf("Bytes = %q, want %q", got, "hello world")
	}
}

// A gap must truncate: the parser must never see post-gap bytes as if they
// followed the prefix directly.
func TestAssembler_GapTruncates(t *testing.T) {
	var a Assembler
	mustAdd(t, &a, 0, []byte("abc"))
	mustAdd(t, &a, 10, []byte("xyz"))
	if got := string(a.Bytes()); got != "abc" {
		t.Errorf("Bytes = %q, want %q (gap must truncate)", got, "abc")
	}
}

// Identical retransmission is absorbed silently — normal TCP behavior.
func TestAssembler_DuplicateAgreeing(t *testing.T) {
	var a Assembler
	mustAdd(t, &a, 0, []byte("hello"))
	mustAdd(t, &a, 0, []byte("hello"))
	mustAdd(t, &a, 2, []byte("llo"))
	if got := string(a.Bytes()); got != "hello" {
		t.Errorf("Bytes = %q, want %q", got, "hello")
	}
}

// Disagreeing overlap is an attack signature (show the parser one name, the
// server another), so it must be rejected rather than resolved by a policy.
func TestAssembler_ConflictingOverlap(t *testing.T) {
	var a Assembler
	mustAdd(t, &a, 0, []byte("allowed.example.com"))
	err := a.Add(0, []byte("evil.example.com!!!"))
	if !errors.Is(err, ErrOverlapConflict) {
		t.Errorf("err = %v, want ErrOverlapConflict", err)
	}
}

func TestAssembler_Overflow(t *testing.T) {
	var a Assembler
	if err := a.Add(MaxAssembly-1, []byte("ab")); !errors.Is(err, ErrAssemblyOverflow) {
		t.Errorf("err = %v, want ErrAssemblyOverflow", err)
	}
	if err := a.Add(0, bytes.Repeat([]byte("x"), MaxAssembly+1)); !errors.Is(err, ErrAssemblyOverflow) {
		t.Errorf("err = %v, want ErrAssemblyOverflow", err)
	}
}

func TestAssembler_Reset(t *testing.T) {
	var a Assembler
	mustAdd(t, &a, 0, []byte("data"))
	a.Reset()
	if a.Len() != 0 {
		t.Errorf("Len = %d after Reset, want 0", a.Len())
	}
	mustAdd(t, &a, 0, []byte("new"))
	if got := string(a.Bytes()); got != "new" {
		t.Errorf("Bytes = %q, want %q", got, "new")
	}
}

// A split ClientHello reassembles into a parseable hello — the split-hello case
// that motivates the punt path in the first place.
func TestAssembler_SplitClientHello(t *testing.T) {
	full := buildClientHello(helloOpts{sni: "pq.example.com"})
	var a Assembler
	// Deliver the second half first, mimicking reordering.
	mid := len(full) / 2
	mustAdd(t, &a, uint64(mid), full[mid:])
	if _, err := ParseTLSClientHello(a.Bytes()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want ErrIncomplete before the head arrives", err)
	}
	mustAdd(t, &a, 0, full[:mid])
	h, err := ParseTLSClientHello(a.Bytes())
	if err != nil {
		t.Fatalf("unexpected error after reassembly: %v", err)
	}
	if h.ServerName != "pq.example.com" {
		t.Errorf("ServerName = %q, want pq.example.com", h.ServerName)
	}
}

func mustAdd(t *testing.T, a *Assembler, off uint64, data []byte) {
	t.Helper()
	if err := a.Add(off, data); err != nil {
		t.Fatalf("Add(%d, %d bytes): %v", off, len(data), err)
	}
}

// Regression (code review): a huge offset must be rejected rather than wrap
// uint64 and panic on a negative int index. Add is exported, so any caller can
// reach this.
func TestAssembler_HugeOffsetNoPanic(t *testing.T) {
	var a Assembler
	if err := a.Add(^uint64(0)-2, []byte("abc")); !errors.Is(err, ErrAssemblyOverflow) {
		t.Errorf("err = %v, want ErrAssemblyOverflow for a near-2^64 offset", err)
	}
	if a.Len() != 0 {
		t.Errorf("Len = %d, want 0 (nothing should have been stored)", a.Len())
	}
}
