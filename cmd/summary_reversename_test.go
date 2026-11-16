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
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/code-cargo/cargowall/pkg/events"
)

// A refused reverse lookup, recorded by its address with no hostname, and a
// reverse-lookup name, are never suggested as hosts to allow; a real blocked
// host still is.
func TestSummary_AllowlistSuggestionsSkipReverseLookups(t *testing.T) {
	ts := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	stepEvents := []StepEvents{{
		Step: GitHubStep{Name: "build"},
		Events: []events.AuditEvent{
			makeEvent(t, events.EventDNSBlocked, "", "192.0.2.7", "dig", 0, ts),
			makeEvent(t, events.EventDNSBlocked, "7.2.0.192.in-addr.arpa", "", "dig", 0, ts),
			makeEvent(t, events.EventDNSBlocked, "needed.example.com", "", "curl", 0, ts),
		},
	}}
	var buf bytes.Buffer
	(&SummaryCmd{output: &buf}).generateAllowlistSuggestions(stepEvents)
	out := buf.String()
	assert.Contains(t, out, "needed.example.com")
	assert.NotContains(t, out, "192.0.2.7")
	assert.NotContains(t, out, "arpa")

	buf.Reset()
	(&SummaryCmd{output: &buf}).generateAllowlistSuggestions([]StepEvents{{
		Step:   GitHubStep{Name: "build"},
		Events: stepEvents[0].Events[:2],
	}})
	assert.Empty(t, buf.String(), "only reverse lookups: nothing to suggest")
}
