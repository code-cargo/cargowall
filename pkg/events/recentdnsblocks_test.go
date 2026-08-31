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

//go:build linux

package events

import (
	"fmt"
	"testing"
	"time"
)

func dnsBlock(domain string, at time.Time) AuditEvent {
	return AuditEvent{
		Timestamp:       at,
		EventType:       EventDNSBlocked,
		DstHostname:     domain,
		Process:         "Runner.Worker",
		PID:             1893,
		StepOrdinal:     4,
		StepAttrOutcome: StepAttrOK,
	}
}

func TestRecentDNSBlocks_ConsumeAndTake(t *testing.T) {
	rb := NewRecentDNSBlocks(time.Minute)
	at := time.Now()
	rb.Consume(dnsBlock("blob.core.windows.net", at))

	if got := rb.Domains(); len(got) != 1 || got[0] != "blob.core.windows.net" {
		t.Fatalf("Domains() = %v, want [blob.core.windows.net]", got)
	}

	b, ok := rb.Take("blob.core.windows.net")
	if !ok {
		t.Fatal("Take() = false, want the recorded refusal")
	}
	if b.At != at || b.PID != 1893 || b.Process != "Runner.Worker" ||
		b.StepOrdinal != 4 || b.StepAttrOutcome != StepAttrOK {
		t.Errorf("Take() lost attribution: %+v", b)
	}

	// Taken entries are gone: a second reconcile must not re-report them.
	if _, ok := rb.Take("blob.core.windows.net"); ok {
		t.Error("second Take() = true, want false")
	}
	if got := rb.Domains(); len(got) != 0 {
		t.Errorf("Domains() after Take = %v, want empty", got)
	}
}

// DNS is case-insensitive, and the refusal path lowercases before logging —
// but a hand-written or replayed event may not, and a case mismatch would
// silently strand the entry.
func TestRecentDNSBlocks_CaseInsensitive(t *testing.T) {
	rb := NewRecentDNSBlocks(time.Minute)
	rb.Consume(dnsBlock("Blob.Core.Windows.NET", time.Now()))

	if got := rb.Domains(); len(got) != 1 || got[0] != "blob.core.windows.net" {
		t.Fatalf("Domains() = %v, want the lower-cased name", got)
	}
	if _, ok := rb.Take("BLOB.CORE.WINDOWS.NET"); !ok {
		t.Error("Take() with different casing = false, want true")
	}
}

// Only refusals are buffered. Feeding the buffer its own output (it rides the
// same audit stream) must not create entries — nor may any other event type.
func TestRecentDNSBlocks_IgnoresOtherEventTypes(t *testing.T) {
	rb := NewRecentDNSBlocks(time.Minute)
	now := time.Now()

	rb.Consume(AuditEvent{Timestamp: now, EventType: EventDNSQueryLateAllowed, DstHostname: "a.example.com"})
	rb.Consume(AuditEvent{Timestamp: now, EventType: EventConnectionBlocked, DstIP: "1.2.3.4"})
	rb.Consume(AuditEvent{Timestamp: now, EventType: EventDNSBlocked}) // no hostname

	if got := rb.Domains(); len(got) != 0 {
		t.Errorf("Domains() = %v, want empty", got)
	}
}

// The latest refusal's timestamp wins so the supersede window covers every
// retry, and identity fields the retries disagree on are blanked rather than
// letting the last writer speak for all of them.
func TestRecentDNSBlocks_DegradesDisagreement(t *testing.T) {
	rb := NewRecentDNSBlocks(time.Minute)
	first := time.Now()
	second := first.Add(10 * time.Millisecond)

	a := dnsBlock("shared.example.com", first)
	b := dnsBlock("shared.example.com", second)
	b.PID = 2222
	b.Process = "curl"
	rb.Consume(a)
	rb.Consume(b)

	got, ok := rb.Take("shared.example.com")
	if !ok {
		t.Fatal("Take() = false")
	}
	if got.At != second {
		t.Errorf("At = %v, want the latest refusal %v", got.At, second)
	}
	if got.PID != 0 || got.Process != "" {
		t.Errorf("contested identity survived: PID=%d Process=%q, want blanked", got.PID, got.Process)
	}
	if got.StepOrdinal != 4 {
		t.Errorf("StepOrdinal = %d, want 4 (agreed fields are kept)", got.StepOrdinal)
	}
}

// An out-of-order arrival must not shrink the supersede window.
func TestRecentDNSBlocks_KeepsLatestTimestampOnOutOfOrderArrival(t *testing.T) {
	rb := NewRecentDNSBlocks(time.Minute)
	late := time.Now()
	early := late.Add(-time.Second)

	rb.Consume(dnsBlock("x.example.com", late))
	rb.Consume(dnsBlock("x.example.com", early))

	got, _ := rb.Take("x.example.com")
	if got.At != late {
		t.Errorf("At = %v, want the later timestamp %v", got.At, late)
	}
}

func TestRecentDNSBlocks_ExpiresEntries(t *testing.T) {
	rb := NewRecentDNSBlocks(50 * time.Millisecond)
	rb.Consume(dnsBlock("stale.example.com", time.Now().Add(-time.Second)))

	if got := rb.Domains(); len(got) != 0 {
		t.Errorf("Domains() = %v, want empty (entry is past its TTL)", got)
	}
	if _, ok := rb.Take("stale.example.com"); ok {
		t.Error("Take() of an expired entry = true, want false")
	}
}

// Domains() is ordered oldest refusal first so reporting is deterministic.
func TestRecentDNSBlocks_DomainsOrderedByRefusalTime(t *testing.T) {
	rb := NewRecentDNSBlocks(time.Minute)
	now := time.Now()
	rb.Consume(dnsBlock("third.example.com", now.Add(2*time.Millisecond)))
	rb.Consume(dnsBlock("first.example.com", now))
	rb.Consume(dnsBlock("second.example.com", now.Add(time.Millisecond)))

	want := []string{"first.example.com", "second.example.com", "third.example.com"}
	got := rb.Domains()
	if len(got) != len(want) {
		t.Fatalf("Domains() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Domains() = %v, want %v", got, want)
		}
	}
}

// The cap bounds a tunneling flood — the very traffic query filtering exists
// to refuse. Overflow drops new names rather than evicting live ones.
func TestRecentDNSBlocks_CapsBufferGrowth(t *testing.T) {
	rb := NewRecentDNSBlocks(time.Minute)
	now := time.Now()
	for i := range maxRecentDNSBlocks + 100 {
		rb.Consume(dnsBlock(fmt.Sprintf("label%d.tunnel.example.com", i), now))
	}
	if got := len(rb.Domains()); got != maxRecentDNSBlocks {
		t.Errorf("buffered entries = %d, want the cap %d", got, maxRecentDNSBlocks)
	}
}

// An expired entry must not hold a slot against a live refusal once the
// buffer is full.
func TestRecentDNSBlocks_PrunesExpiredToAdmitNewEntries(t *testing.T) {
	rb := NewRecentDNSBlocks(50 * time.Millisecond)
	stale := time.Now().Add(-time.Second)
	for i := range maxRecentDNSBlocks {
		rb.Consume(dnsBlock(fmt.Sprintf("stale%d.example.com", i), stale))
	}

	rb.Consume(dnsBlock("fresh.example.com", time.Now()))
	if _, ok := rb.Take("fresh.example.com"); !ok {
		t.Error("a live refusal was dropped while the buffer held only expired entries")
	}
}

// TestRecentDNSBlocksRestore: the reconcile has to Take a refusal BEFORE
// writing its late-allow event (the take is what claims it, so two concurrent
// passes cannot both re-report), which made a failed audit write destroy the
// only record that the refusal was superseded — the run then reports a denial
// the policy never intended, with no later pass able to fix it. Restore puts
// it back for the next pass.
func TestRecentDNSBlocksRestore(t *testing.T) {
	now := time.Now()
	rb := NewRecentDNSBlocks(time.Minute)
	rb.Consume(AuditEvent{Timestamp: now, EventType: EventDNSBlocked, DstHostname: "a.example.com"})

	block, ok := rb.Take("a.example.com")
	if !ok {
		t.Fatal("Take must return the buffered refusal")
	}
	if got := rb.Domains(); len(got) != 0 {
		t.Fatalf("Take must remove the entry, got %v", got)
	}

	rb.Restore(block)
	if got := rb.Domains(); len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("Restore must make the refusal takeable again, got %v", got)
	}
	if _, ok := rb.Take("a.example.com"); !ok {
		t.Fatal("the restored refusal must be takeable")
	}

	// A refusal recorded since the take is newer evidence of the same
	// refusal (Consume already folded any disagreement into it), so the
	// restore must not overwrite it.
	rb.Consume(AuditEvent{
		Timestamp: now.Add(time.Second), EventType: EventDNSBlocked,
		DstHostname: "a.example.com", Process: "curl",
	})
	rb.Restore(block)
	restored, ok := rb.Take("a.example.com")
	if !ok {
		t.Fatal("the live entry must survive a restore")
	}
	if restored.Process != "curl" {
		t.Errorf("restore clobbered the newer refusal: process = %q, want curl", restored.Process)
	}

	// An entry older than the TTL is not resurrected.
	stale := RecentDNSBlock{Domain: "stale.example.com", At: now.Add(-2 * time.Minute)}
	rb.Restore(stale)
	for _, d := range rb.Domains() {
		if d == "stale.example.com" {
			t.Error("Restore must not resurrect an expired refusal")
		}
	}
}
