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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collectingSink keeps every event it consumes.
type collectingSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (s *collectingSink) Consume(e AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

// An event logged with no timestamp is stamped with the time it is logged;
// one that carries its own keeps it.
func TestLogEvent_StampsAZeroTimestamp(t *testing.T) {
	al, err := NewAuditLogger("", false)
	require.NoError(t, err)
	sink := &collectingSink{}
	al.AddSink(sink)

	require.NoError(t, al.LogEvent(AuditEvent{EventType: EventDNSBlocked, DstHostname: "evil.example.com"}))
	given := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, al.LogEvent(AuditEvent{EventType: EventDNSBlocked, DstIP: "192.0.2.7", Timestamp: given}))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.events, 2)
	assert.WithinDuration(t, time.Now(), sink.events[0].Timestamp, time.Minute)
	assert.Equal(t, given, sink.events[1].Timestamp)
}
