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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/containers"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/origin"
	"github.com/code-cargo/cargowall/pkg/sni"
)

type auditCapture struct{ events []events.AuditEvent }

func (c *auditCapture) Consume(e events.AuditEvent) { c.events = append(c.events, e) }

// The sink reports a bare-label pass as its own telemetry event, never a
// block or a would-block, while an ordinary admitted flow still produces no
// record.
func TestL7Sink_BareLabelPass(t *testing.T) {
	for _, enforce := range []bool{true, false} {
		al, err := events.NewAuditLogger("", false)
		require.NoError(t, err)
		capture := &auditCapture{}
		al.AddSink(capture)
		var logs bytes.Buffer
		sink := l7Sink(&origin.Observer{}, &containers.Enricher{}, nil, al, nil,
			slog.New(slog.NewTextHandler(&logs, nil)))

		base := origin.L7Outcome{
			SrcIP:    netip.MustParseAddr("10.1.0.5"),
			DstIP:    netip.MustParseAddr("54.80.12.34"),
			DstPort:  443,
			IPProto:  6,
			Protocol: sni.ProtoTLS,
			Enforce:  enforce,
		}
		allowed := base
		allowed.Name, allowed.Reason, allowed.Allowed = "github.com", origin.L7Allowed, true
		sink(allowed)
		require.Empty(t, capture.events, "an allowed name produces no record")

		passed := base
		passed.Name, passed.Reason, passed.Allowed = "kq563vfqzm", origin.L7BareLabel, true
		sink(passed)
		require.Len(t, capture.events, 1)
		ev := capture.events[0]
		assert.Equal(t, events.EventL7Passed, ev.EventType)
		assert.Equal(t, "bare_label", ev.L7Reason)
		assert.Equal(t, "kq563vfqzm", ev.L7Name)
		assert.Equal(t, "tls", ev.L7Protocol)
		assert.Equal(t, "54.80.12.34", ev.DstIP)
		assert.False(t, ev.Blocked, "enforce=%v: a pass is no block", enforce)
		assert.False(t, ev.WouldDeny, "enforce=%v: a pass is no would-block", enforce)
		assert.Contains(t, logs.String(), "level=INFO msg=\"L7 identity passed as a bare label\"")

		// The same destination and name again: not reported again.
		sink(passed)
		require.Len(t, capture.events, 1, "a pass is reported once per destination and name")
		assert.Equal(t, 1, strings.Count(logs.String(), "passed as a bare label"))

		// Under an audit posture too, normalization must leave it alone;
		// another name at the same destination is a record of its own.
		al.SetAuditMode(true)
		other := passed
		other.Name = "zz9plural"
		sink(other)
		require.Len(t, capture.events, 2)
		assert.Equal(t, "zz9plural", capture.events[1].L7Name)
		assert.False(t, capture.events[1].Blocked)
		assert.False(t, capture.events[1].WouldDeny)
	}
}

// The set of reported passes is bounded: past l7PassedOnceMax it starts
// over rather than growing with a workload's labels.
func TestL7PassedOnce_Bounded(t *testing.T) {
	p := newL7PassedOnce()
	o := origin.L7Outcome{DstIP: netip.MustParseAddr("54.80.12.34"), DstPort: 443}
	for i := 0; i < l7PassedOnceMax+10; i++ {
		o.Name = fmt.Sprintf("label%d", i)
		require.True(t, p.first(o))
	}
	assert.LessOrEqual(t, len(p.seen), l7PassedOnceMax)
	o.Name = "label0"
	assert.True(t, p.first(o), "the set started over")
	assert.False(t, p.first(o))
}

// The summary treats l7_passed as telemetry: not counted, not pushed, never
// an allowlist suggestion. The l7_blocked beside it shows the pipeline does
// report the denial.
func TestSummary_L7PassedIsTelemetry(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id": "job-1"}`))
	}))
	t.Cleanup(srv.Close)

	ts := time.Date(2025, 1, 1, 10, 0, 5, 0, time.UTC)
	var log bytes.Buffer
	for _, e := range []events.AuditEvent{
		{
			Timestamp: ts, EventType: events.EventL7Passed, DstIP: "54.80.12.34", DstPort: 443, Protocol: "TCP",
			L7Name: "kq563vfqzm", L7Protocol: "tls", L7Reason: "bare_label", Process: "depot",
		},
		{
			Timestamp: ts, EventType: events.EventL7Blocked, DstIP: "54.80.12.35", DstPort: 443, Protocol: "TCP",
			L7Name: "evil.example", L7Protocol: "tls", L7Reason: "name_mismatch", Process: "curl", Blocked: true,
		},
	} {
		line, err := json.Marshal(e)
		require.NoError(t, err)
		log.Write(append(line, '\n'))
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	require.NoError(t, os.WriteFile(path, log.Bytes(), 0o644))

	var out bytes.Buffer
	c := &SummaryCmd{
		AuditLog: path,
		Steps:    `[{"name":"build","number":1,"started_at":"2025-01-01T10:00:00Z","completed_at":"2025-01-01T10:00:10Z"}]`,
		ApiUrl:   srv.URL, Token: "t", JobName: "j", output: &out,
	}
	require.NoError(t, c.Run())

	pushed, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(pushed), "kq563vfqzm", "an l7_passed is never pushed")
	assert.Contains(t, string(pushed), "evil.example", "control: the l7_blocked is pushed")
	assert.NotContains(t, out.String(), "kq563vfqzm", "an l7_passed is never rendered or suggested")
	assert.Contains(t, out.String(), "evil.example", "control: the l7_blocked is rendered")

	summary, ok := got["summary"].(map[string]any)
	require.True(t, ok, "summary in push: %s", pushed)
	assert.EqualValues(t, 1, summary["denied_connections"], "only the l7_blocked counts")
}
