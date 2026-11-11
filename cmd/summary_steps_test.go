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

package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/code-cargo/cargowall/pkg/events"
)

// A late-allow supersedes its own step's blocks on the destination and no
// other's: one step's own rules opening an address open it for that step
// alone, so another step's block there, or an untagged one, still stands.
// Each late-allow re-reports its own block's ordinal, so what the job's
// rules open supersedes every step's blocks, one late-allow each.
func TestReconcileLateAllowedBlocks_PerStep(t *testing.T) {
	t0 := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	ev := func(kind events.AuditEventType, ordinal uint32, at time.Duration) events.AuditEvent {
		return events.AuditEvent{
			Timestamp: t0.Add(at), EventType: kind,
			DstIP: "203.0.113.5", DstPort: 443, Protocol: "TCP", StepOrdinal: ordinal,
		}
	}
	got := reconcileLateAllowedBlocks([]events.AuditEvent{
		ev(events.EventConnectionBlocked, 7, 0),
		ev(events.EventConnectionBlocked, 8, time.Second),
		ev(events.EventConnectionBlocked, 0, time.Second),
		ev(events.EventConnectionLateAllowed, 7, 2*time.Second),
	})
	var blocked []uint32
	for _, e := range got {
		if e.EventType == events.EventConnectionBlocked {
			blocked = append(blocked, e.StepOrdinal)
		}
	}
	assert.ElementsMatch(t, []uint32{8, 0}, blocked, "step 7's late-allow supersedes step 7's block alone")

	got = reconcileLateAllowedBlocks([]events.AuditEvent{
		ev(events.EventConnectionBlocked, 7, 0),
		ev(events.EventConnectionBlocked, 8, time.Second),
		ev(events.EventConnectionLateAllowed, 7, 0),
		ev(events.EventConnectionLateAllowed, 8, time.Second),
	})
	for _, e := range got {
		assert.NotEqual(t, events.EventConnectionBlocked, e.EventType, "the job's rules opened it for both")
	}
}
