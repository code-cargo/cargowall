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

// Container identity must survive the buffer round-trip: a reconciled
// late-allow is a re-report of the recorded attempt, and losing these
// fields would demote the event from the container tier to unknown in the
// summary and strip cargowall.container_id from its OTLP record.
func TestRecentBlocks_CarriesContainerIdentity(t *testing.T) {
	rb := NewRecentBlocks(0)
	ev := blockedAuditEvent("20.0.0.1", 443, "TCP", time.Now())
	ev.ContainerID = "abc123def456"
	ev.ContainerOrigin = true
	rb.Consume(ev)

	taken := rb.TakeMatching("20.0.0.1", nil, nil, false)
	require.Len(t, taken, 1)
	assert.Equal(t, "abc123def456", taken[0].ContainerID)
	assert.True(t, taken[0].ContainerOrigin)
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

	require.NoError(t, al.LogEvent(AuditEvent{
		EventType: EventConnectionBlocked,
		SrcIP:     "10.0.0.1", DstIP: "20.209.112.225", DstPort: 443,
		Protocol: "TCP", Process: "MainThread", PID: 2411, StepOrdinal: 3,
	}))

	taken := rb.TakeMatching("20.209.112.225", nil, nil, false)
	require.Len(t, taken, 1)
	assert.Equal(t, "10.0.0.1", taken[0].SrcIP)
	assert.Equal(t, "MainThread", taken[0].Process)
	assert.Equal(t, uint32(2411), taken[0].PID)
	assert.Equal(t, uint32(3), taken[0].StepOrdinal, "step attribution must survive the reconcile round-trip")
	assert.False(t, taken[0].At.IsZero())
}

// Mid-stream drops (established connections killed at attach) log as
// connection_blocked with the MidStream marker; the reconciler must recover
// them like any other block.
func TestRecentBlocks_MidStreamBlockIsReconcilable(t *testing.T) {
	rb := NewRecentBlocks(0)
	al, err := NewAuditLogger("", false)
	require.NoError(t, err)
	defer al.Close()
	al.AddSink(rb)

	require.NoError(t, al.LogEvent(AuditEvent{
		EventType: EventConnectionBlocked,
		SrcIP:     "10.0.0.1", DstIP: "20.209.112.225", DstPort: 443,
		Protocol: "TCP", Process: "curl", PID: 42, MidStream: true,
	}))

	taken := rb.TakeMatching("20.209.112.225", nil, nil, false)
	require.Len(t, taken, 1)
	assert.Equal(t, uint16(443), taken[0].DstPort)
}

// Two ORIGINS contesting one destination tuple must degrade, not
// last-writer-win: the single late-allow re-report would otherwise state
// the last writer's identity as fact for every attempt — the coin-flip
// attribution resolveJoin's disagreement policy exists to prevent, on a
// different path. The model matches joinAmbiguousContainers: two
// containers keep ContainerOrigin (SOME container did this) with the id
// blanked; a container/host mix drops the claim entirely. When adding an
// identity field to RecentBlock, give it the same treatment in
// degradeDisagreement.
func TestRecentBlocks_ContestedDestinationDegradesIdentity(t *testing.T) {
	now := time.Now()

	// Two containers of one step: origin survives, id does not.
	rb := NewRecentBlocks(0)
	a := blockedAuditEvent("20.0.0.1", 443, "TCP", now.Add(-2*time.Second))
	a.ContainerID, a.ContainerOrigin, a.StepOrdinal = "aaa111", true, 3
	b := blockedAuditEvent("20.0.0.1", 443, "TCP", now.Add(-1*time.Second))
	b.ContainerID, b.ContainerOrigin, b.StepOrdinal = "bbb222", true, 3
	b.SrcIP, b.PID = "10.0.0.2", 43
	rb.Consume(a)
	rb.Consume(b)
	taken := rb.TakeMatching("20.0.0.1", nil, nil, false)
	require.Len(t, taken, 1)
	assert.Empty(t, taken[0].ContainerID, "naming either container would be a coin flip")
	assert.True(t, taken[0].ContainerOrigin, "both attempts were containers; the tier claim stands")
	assert.Equal(t, uint32(3), taken[0].StepOrdinal, "both were the step's")
	assert.Zero(t, taken[0].PID)
	assert.Empty(t, taken[0].SrcIP)

	// Container vs host: even the origin claim goes.
	rb2 := NewRecentBlocks(0)
	c := blockedAuditEvent("20.0.0.2", 443, "TCP", now.Add(-2*time.Second))
	c.ContainerID, c.ContainerOrigin = "ccc333", true
	h := blockedAuditEvent("20.0.0.2", 443, "TCP", now.Add(-1*time.Second))
	rb2.Consume(c)
	rb2.Consume(h)
	taken = rb2.TakeMatching("20.0.0.2", nil, nil, false)
	require.Len(t, taken, 1)
	assert.False(t, taken[0].ContainerOrigin)
	assert.Empty(t, taken[0].ContainerID)

	// Same origin retrying: identity is intact — degradation is only for
	// genuine disagreement.
	rb3 := NewRecentBlocks(0)
	r1 := blockedAuditEvent("20.0.0.3", 443, "TCP", now.Add(-2*time.Second))
	r1.ContainerID, r1.ContainerOrigin = "ddd444", true
	r2 := blockedAuditEvent("20.0.0.3", 443, "TCP", now.Add(-1*time.Second))
	r2.ContainerID, r2.ContainerOrigin = "ddd444", true
	rb3.Consume(r1)
	rb3.Consume(r2)
	taken = rb3.TakeMatching("20.0.0.3", nil, nil, false)
	require.Len(t, taken, 1)
	assert.Equal(t, "ddd444", taken[0].ContainerID)
	assert.True(t, taken[0].ContainerOrigin)
}

// The supersede window must cover every recorded retry even when events
// arrive out of timestamp order: an older contested attempt landing second
// must not shrink At.
func TestRecentBlocks_ContestedKeepsNewestTimestamp(t *testing.T) {
	rb := NewRecentBlocks(0)
	now := time.Now()
	newer := blockedAuditEvent("20.0.0.1", 443, "TCP", now.Add(-1*time.Second))
	newer.ContainerID, newer.ContainerOrigin = "aaa111", true
	older := blockedAuditEvent("20.0.0.1", 443, "TCP", now.Add(-5*time.Second))
	older.ContainerID, older.ContainerOrigin = "bbb222", true
	rb.Consume(newer)
	rb.Consume(older) // out of order

	taken := rb.TakeMatching("20.0.0.1", nil, nil, false)
	require.Len(t, taken, 1)
	assert.True(t, taken[0].At.Equal(newer.Timestamp), "At is max(prev, next), not last-writer")
}

// Blocks are kept per step: two steps blocked on one destination are two
// entries, each with its own identity, and a step's own rules opening the
// destination (TakeMatchingFor) re-report that step's alone. What the job's
// rules open (TakeMatching) they open for every step.
func TestRecentBlocks_PerStep(t *testing.T) {
	now := time.Now()
	rb := NewRecentBlocks(0)
	for _, ordinal := range []uint32{3, 5, 0} {
		e := blockedAuditEvent("20.0.0.1", 443, "TCP", now.Add(-time.Second))
		e.StepOrdinal, e.PID = ordinal, 40+ordinal
		rb.Consume(e)
	}
	taken := rb.TakeMatchingFor("20.0.0.1", func(o uint32) bool { return o == 5 }, nil, nil, false)
	require.Len(t, taken, 1)
	assert.Equal(t, uint32(5), taken[0].StepOrdinal)
	assert.Equal(t, uint32(45), taken[0].PID, "its own identity, not degraded by another step's")
	assert.Empty(t, rb.TakeMatchingFor("20.0.0.1", func(uint32) bool { return false }, nil, nil, false))

	taken = rb.TakeMatching("20.0.0.1", nil, nil, false)
	require.Len(t, taken, 2, "the others stay until the job's rules open them")
	assert.ElementsMatch(t, []uint32{3, 0}, []uint32{taken[0].StepOrdinal, taken[1].StepOrdinal})
	assert.Empty(t, rb.TakeMatching("20.0.0.1", nil, nil, false))
}

// A step tier's takes leave every block a container contributed to, though
// a disagreement with a host attempt on the same tuple blanked its
// container's identity: TC may judge a container's packets as the job's.
// The job tier's take still has it.
func TestRecentBlocks_StepTakesLeaveContainers(t *testing.T) {
	rb := NewRecentBlocks(time.Minute)
	now := time.Now()
	host := blockedAuditEvent("10.1.2.3", 443, "TCP", now.Add(-2*time.Second))
	host.StepOrdinal = 7
	ctr := host
	ctr.Timestamp, ctr.ContainerID, ctr.PID = now.Add(-time.Second), "c0ffee", 77
	rb.Consume(host)
	rb.Consume(ctr)
	all := func(uint32) bool { return true }
	assert.Empty(t, rb.TakeStep(7, func(RecentBlock) bool { return true }))
	assert.Empty(t, rb.TakeMatchingFor("10.1.2.3", all, nil, nil, false))
	taken := rb.TakeMatching("10.1.2.3", nil, nil, false)
	require.Len(t, taken, 1)
	assert.Empty(t, taken[0].ContainerID, "the identity degraded")
}

// TakeStep judges outside the buffer's lock, so a block consumed meanwhile
// waits on nothing, and an entry that moved on meanwhile, folded into a
// later attempt, is left for that attempt's own reconcile.
func TestRecentBlocks_TakeStepJudgesOutsideTheLock(t *testing.T) {
	rb := NewRecentBlocks(time.Minute)
	now := time.Now()
	first := blockedAuditEvent("10.1.2.4", 443, "TCP", now.Add(-2*time.Second))
	first.StepOrdinal = 7
	other := blockedAuditEvent("10.1.2.5", 443, "TCP", now.Add(-2*time.Second))
	other.StepOrdinal = 7
	rb.Consume(first)
	rb.Consume(other)
	later := first
	later.Timestamp = now.Add(-time.Second)

	done := make(chan []RecentBlock)
	go func() {
		done <- rb.TakeStep(7, func(b RecentBlock) bool {
			if b.DstIP == "10.1.2.4" {
				rb.Consume(later) // a retry, blocked while the step is judged
			}
			return true
		})
	}()
	select {
	case taken := <-done:
		require.Len(t, taken, 1)
		assert.Equal(t, "10.1.2.5", taken[0].DstIP)
	case <-time.After(5 * time.Second):
		t.Fatal("TakeStep held the lock while judging")
	}
	left := rb.TakeMatching("10.1.2.4", nil, nil, false)
	require.Len(t, left, 1)
	assert.True(t, left[0].At.Equal(later.Timestamp))
}
