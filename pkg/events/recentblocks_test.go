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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
)

func blockedAuditEvent(dstIP string, port uint16, protocol string, at time.Time) AuditEvent {
	return AuditEvent{
		Timestamp: at,
		EventType: EventConnectionBlocked,
		SrcIP:     "10.0.0.1",
		DstIP:     dstIP,
		DstPort:   port,
		Protocol:  protocol,
		Process:   "curl",
		PID:       42,
	}
}

func TestRecentBlocks_ConsumeOnlyRecordsBlockedTCPUDP(t *testing.T) {
	rb := NewRecentBlocks(0)

	rb.Consume(blockedAuditEvent("20.0.0.1", 443, "TCP", time.Now()))
	rb.Consume(blockedAuditEvent("20.0.0.2", 53, "UDP", time.Now()))

	// None of these are reconcilable and must be ignored.
	rb.Consume(blockedAuditEvent("20.0.0.3", 0, "ICMP", time.Now()))
	rb.Consume(blockedAuditEvent("", 443, "TCP", time.Now()))
	allowed := blockedAuditEvent("20.0.0.4", 443, "TCP", time.Now())
	allowed.EventType = EventConnectionAllowed
	rb.Consume(allowed)
	dnsBlocked := AuditEvent{Timestamp: time.Now(), EventType: EventDNSBlocked, DstHostname: "evil.example.com"}
	rb.Consume(dnsBlocked)

	assert.Len(t, rb.TakeMatching("20.0.0.1", nil, nil, false), 1)
	assert.Len(t, rb.TakeMatching("20.0.0.2", nil, nil, false), 1)
	assert.Empty(t, rb.TakeMatching("20.0.0.3", nil, nil, false))
	assert.Empty(t, rb.TakeMatching("20.0.0.4", nil, nil, false))
}

func TestRecentBlocks_LatestAttemptWins(t *testing.T) {
	rb := NewRecentBlocks(0)
	first := time.Now().Add(-10 * time.Second)
	last := time.Now().Add(-1 * time.Second)

	rb.Consume(blockedAuditEvent("20.0.0.1", 443, "TCP", first))
	rb.Consume(blockedAuditEvent("20.0.0.1", 443, "TCP", last))

	taken := rb.TakeMatching("20.0.0.1", nil, nil, false)
	require.Len(t, taken, 1)
	assert.True(t, taken[0].At.Equal(last), "the latest attempt's timestamp must be kept so it supersedes every retry")
}

func TestRecentBlocks_TakeMatchingPortAndProtocolFilter(t *testing.T) {
	rb := NewRecentBlocks(0)
	rb.Consume(blockedAuditEvent("20.0.0.1", 443, "TCP", time.Now()))

	// Wrong port: entry stays buffered.
	assert.Empty(t, rb.TakeMatching("20.0.0.1", []config.Port{{Port: 80, Protocol: config.ProtocolTCP}}, nil, false))
	// Wrong protocol: entry stays buffered.
	assert.Empty(t, rb.TakeMatching("20.0.0.1", []config.Port{{Port: 443, Protocol: config.ProtocolUDP}}, nil, false))
	// Matching port+protocol: taken and removed.
	assert.Len(t, rb.TakeMatching("20.0.0.1", []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}, nil, false), 1)
	assert.Empty(t, rb.TakeMatching("20.0.0.1", nil, nil, false), "taken entries must not be returned twice")
}

func TestRecentBlocks_TakeMatchingAllPortsAndProtocolAll(t *testing.T) {
	rb := NewRecentBlocks(0)
	rb.Consume(blockedAuditEvent("20.0.0.1", 443, "TCP", time.Now()))
	rb.Consume(blockedAuditEvent("20.0.0.1", 8080, "TCP", time.Now()))

	// Empty allow ports = all ports; ProtocolAll overlaps TCP.
	taken := rb.TakeMatching("20.0.0.1", nil, nil, false)
	assert.Len(t, taken, 2)

	rb.Consume(blockedAuditEvent("20.0.0.2", 443, "TCP", time.Now()))
	taken = rb.TakeMatching("20.0.0.2", []config.Port{{Port: 443, Protocol: config.ProtocolAll}}, nil, false)
	assert.Len(t, taken, 1)
}

func TestRecentBlocks_DenySideExcludes(t *testing.T) {
	rb := NewRecentBlocks(0)
	rb.Consume(blockedAuditEvent("20.0.0.1", 80, "TCP", time.Now()))
	rb.Consume(blockedAuditEvent("20.0.0.1", 443, "TCP", time.Now()))

	// Mixed verdict: allow all ports, deny 80. Only the 443 block is
	// late-allowed; the 80 block stays correct and is dropped silently.
	taken := rb.TakeMatching("20.0.0.1", nil, []config.Port{{Port: 80, Protocol: config.ProtocolTCP}}, true)
	require.Len(t, taken, 1)
	assert.Equal(t, uint16(443), taken[0].DstPort)
	assert.Empty(t, rb.TakeMatching("20.0.0.1", nil, nil, false), "deny-covered entry must be removed, not left for a later pass")

	// Deny-all (hasDeny with empty ports) reconciles nothing.
	rb.Consume(blockedAuditEvent("20.0.0.2", 443, "TCP", time.Now()))
	assert.Empty(t, rb.TakeMatching("20.0.0.2", nil, nil, true))
}

func TestRecentBlocks_TTLExpiry(t *testing.T) {
	rb := NewRecentBlocks(50 * time.Millisecond)
	rb.Consume(blockedAuditEvent("20.0.0.1", 443, "TCP", time.Now()))
	time.Sleep(80 * time.Millisecond)
	assert.Empty(t, rb.TakeMatching("20.0.0.1", nil, nil, false))
}

// reachableEntries counts entries actually reachable from byIP, so a test can
// assert rb.size against reality rather than against itself.
func (rb *RecentBlocks) reachableEntries() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	n := 0
	for _, byKey := range rb.byIP {
		n += len(byKey)
	}
	return n
}

// fillRecentBlocks adds n fresh blocks on distinct destination IPs.
func fillRecentBlocks(rb *RecentBlocks, n int, at time.Time) {
	for i := range n {
		rb.Consume(blockedAuditEvent(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), 443, "TCP", at))
	}
}

// A block arriving while the buffer is full, for a destination whose existing
// entries are all expired, must survive the overflow prune. The prune deletes
// that destination's emptied map from byIP, so Consume has to resolve the map
// AFTER pruning — reading it beforehand orphaned the write (the block was lost
// and unreconcilable) and leaked rb.size, which never recovers and eventually
// wedges the buffer at capacity, silently disabling reconciliation for the
// rest of the run.
func TestRecentBlocks_ConsumeAtCapacityAfterPruningDestination(t *testing.T) {
	rb := NewRecentBlocks(5 * time.Minute)
	fresh := time.Now()

	// The victim's only entry is already past the TTL.
	rb.Consume(blockedAuditEvent("20.209.113.193", 443, "TCP", fresh.Add(-10*time.Minute)))
	fillRecentBlocks(rb, maxRecentBlocks-1, fresh)
	require.Equal(t, maxRecentBlocks, rb.size, "precondition: buffer at capacity")

	// New port on the victim IP: not an existing key, so this prunes.
	rb.Consume(blockedAuditEvent("20.209.113.193", 8443, "TCP", fresh))

	taken := rb.TakeMatching("20.209.113.193", nil, nil, false)
	require.Len(t, taken, 1, "block must be reconcilable, not written to an orphaned map")
	assert.Equal(t, uint16(8443), taken[0].DstPort)
	assert.Equal(t, rb.reachableEntries(), rb.size, "size must track reachable entries, not leak")
}

// Once the buffer is genuinely full of live entries, new destinations are
// dropped rather than evicting — reconciliation is best-effort reporting, and
// enforcement is unaffected. The size counter must stay exact across the drop.
func TestRecentBlocks_ConsumeAtCapacityDropsNewDestinations(t *testing.T) {
	rb := NewRecentBlocks(5 * time.Minute)
	fresh := time.Now()

	fillRecentBlocks(rb, maxRecentBlocks, fresh)
	require.Equal(t, maxRecentBlocks, rb.size)

	rb.Consume(blockedAuditEvent("20.209.113.193", 443, "TCP", fresh))
	assert.Empty(t, rb.TakeMatching("20.209.113.193", nil, nil, false), "overflow drops rather than evicting")
	assert.Equal(t, rb.reachableEntries(), rb.size)

	// A repeat block on an already-buffered tuple still refreshes in place:
	// it needs no new slot, so capacity must not turn it away.
	last := fresh.Add(time.Second)
	rb.Consume(blockedAuditEvent("10.0.0.0", 443, "TCP", last))
	taken := rb.TakeMatching("10.0.0.0", nil, nil, false)
	require.Len(t, taken, 1)
	assert.True(t, taken[0].At.Equal(last), "latest attempt must win even at capacity")
	assert.Equal(t, rb.reachableEntries(), rb.size)
}

// The buffer plugs into the audit stream as an EventSink; verify events
// logged through the AuditLogger are recorded with their attribution intact.
func TestRecentBlocks_AsAuditSink(t *testing.T) {
	rb := NewRecentBlocks(0)
	al, err := NewAuditLogger("", false)
	require.NoError(t, err)
	defer al.Close()
	al.AddSink(rb)

	require.NoError(t, al.LogConnectionBlocked("10.0.0.1", "20.209.112.225", "", 443, "MainThread", 2411, "TCP", nil))

	taken := rb.TakeMatching("20.209.112.225", nil, nil, false)
	require.Len(t, taken, 1)
	assert.Equal(t, "10.0.0.1", taken[0].SrcIP)
	assert.Equal(t, "MainThread", taken[0].Process)
	assert.Equal(t, uint32(2411), taken[0].PID)
	assert.False(t, taken[0].At.IsZero())
}
