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

// A refused reverse lookup is a lookup of an address's name, not a host the
// job needed, so the summary never suggests allowing one.
func TestSummary_AllowlistSuggestionsSkipReverseLookupNames(t *testing.T) {
	ts := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	stepEvents := []StepEvents{{
		Step: GitHubStep{Name: "build", Number: 1, StartedAt: ts, CompletedAt: ts.Add(time.Minute)},
		Events: []events.AuditEvent{
			makeEvent(t, events.EventDNSBlocked, "7.2.0.192.in-addr.arpa", "", "dig", 0, ts),
			makeEvent(t, events.EventDNSBlocked,
				"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa", "", "dig", 0, ts),
			makeEvent(t, events.EventDNSBlocked, "Not.Canonical.IN-ADDR.ARPA.", "", "dig", 0, ts),
			makeEvent(t, events.EventDNSBlocked, "needed.example.com", "", "curl", 0, ts),
		},
	}}
	var buf bytes.Buffer
	(&SummaryCmd{output: &buf}).generateAllowlistSuggestions(stepEvents)
	out := buf.String()
	assert.Contains(t, out, "`needed.example.com` (1 connection attempt)")
	assert.Contains(t, out, "      needed.example.com\n")
	assert.NotContains(t, out, "arpa")
	assert.NotContains(t, out, "ARPA")

	buf.Reset()
	(&SummaryCmd{output: &buf}).generateAllowlistSuggestions([]StepEvents{{
		Step:   stepEvents[0].Step,
		Events: stepEvents[0].Events[:3],
	}})
	assert.Empty(t, buf.String(), "only reverse lookups: nothing to suggest")

	for name, want := range map[string]bool{
		"in-addr.arpa": true, "ip6.arpa.": true, "x.ip6.arpa": true,
		"arpa": false, "in-addr.arpa.example.com": false, "myin-addr.arpa": false,
	} {
		assert.Equal(t, want, reverseLookupName(name), name)
	}
}
