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

package otlp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/common/v1"
	logspb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/logs/v1"
	"github.com/code-cargo/cargowall/pkg/events"
)

func attrMap(t *testing.T, attrs []*commonpb.KeyValue) map[string]*commonpb.AnyValue {
	t.Helper()
	out := make(map[string]*commonpb.AnyValue, len(attrs))
	for _, kv := range attrs {
		_, dup := out[kv.Key]
		require.False(t, dup, "duplicate attribute %q", kv.Key)
		out[kv.Key] = kv.Value
	}
	return out
}

func TestLogRecordFromEvent_Blocked(t *testing.T) {
	ts := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	rec := logRecordFromEvent(events.AuditEvent{
		Timestamp:   ts,
		EventType:   events.EventConnectionBlocked,
		SrcIP:       "10.0.0.1",
		DstIP:       "93.184.216.34",
		DstHostname: "example.com",
		DstPort:     443,
		Protocol:    "TCP",
		Process:     "curl",
		PID:         1234,
		CNAMEChain:  []string{"example.com", "edge.cdn.net"},
		Blocked:     true,
	})

	assert.Equal(t, uint64(ts.UnixNano()), rec.TimeUnixNano)
	assert.Equal(t, uint64(ts.UnixNano()), rec.ObservedTimeUnixNano)
	assert.Equal(t, "cargowall.connection_blocked", rec.EventName)
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_WARN, rec.SeverityNumber)
	assert.Equal(t, "WARN", rec.SeverityText)
	assert.Equal(t, "connection blocked example.com:443", rec.Body.GetStringValue())

	attrs := attrMap(t, rec.Attributes)
	assert.Equal(t, "10.0.0.1", attrs["source.address"].GetStringValue())
	assert.Equal(t, "93.184.216.34", attrs["destination.address"].GetStringValue())
	assert.Equal(t, int64(443), attrs["destination.port"].GetIntValue())
	assert.Equal(t, "example.com", attrs["server.address"].GetStringValue())
	assert.Equal(t, "tcp", attrs["network.transport"].GetStringValue())
	assert.Equal(t, "curl", attrs["process.executable.name"].GetStringValue())
	assert.Equal(t, int64(1234), attrs["process.pid"].GetIntValue())
	assert.Equal(t, "TCP", attrs["cargowall.protocol"].GetStringValue())
	assert.Equal(t, "deny", attrs["cargowall.verdict"].GetStringValue())
	assert.True(t, attrs["cargowall.blocked"].GetBoolValue())
	assert.False(t, attrs["cargowall.would_deny"].GetBoolValue())

	chain := attrs["cargowall.cname_chain"].GetArrayValue().GetValues()
	require.Len(t, chain, 2)
	assert.Equal(t, "example.com", chain[0].GetStringValue())
	assert.Equal(t, "edge.cdn.net", chain[1].GetStringValue())
}

func TestLogRecordFromEvent_AllowedOmitsEmptyFields(t *testing.T) {
	rec := logRecordFromEvent(events.AuditEvent{
		Timestamp: time.Now(),
		EventType: events.EventConnectionAllowed,
		DstIP:     "93.184.216.34",
		DstPort:   443,
		Protocol:  "TCP",
	})

	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, rec.SeverityNumber)
	assert.Equal(t, "INFO", rec.SeverityText)
	assert.Equal(t, "connection allowed 93.184.216.34:443", rec.Body.GetStringValue())
	assert.Equal(t, "allow", attrMap(t, rec.Attributes)["cargowall.verdict"].GetStringValue())

	attrs := attrMap(t, rec.Attributes)
	for _, absent := range []string{
		"source.address", "server.address", "process.executable.name",
		"process.pid", "cargowall.matched_rule", "cargowall.auto_allowed_type",
		"cargowall.cname_chain", "cargowall.mid_stream",
	} {
		assert.NotContains(t, attrs, absent)
	}
}

// Mid-stream blocks (established connections killed by attach) carry the
// cargowall.mid_stream attribute so backends can distinguish a killed
// connection from a refused new one.
func TestLogRecordFromEvent_MidStreamBlocked(t *testing.T) {
	rec := logRecordFromEvent(events.AuditEvent{
		Timestamp: time.Now(),
		EventType: events.EventConnectionBlocked,
		DstIP:     "93.184.216.34",
		DstPort:   443,
		Protocol:  "TCP",
		MidStream: true,
		Blocked:   true,
	})

	attrs := attrMap(t, rec.Attributes)
	assert.True(t, attrs["cargowall.mid_stream"].GetBoolValue())
	assert.Equal(t, "deny", attrs["cargowall.verdict"].GetStringValue())
	assert.Equal(t, "cargowall.connection_blocked", rec.EventName)
}

func TestLogRecordFromEvent_WouldDeny(t *testing.T) {
	rec := logRecordFromEvent(events.AuditEvent{
		Timestamp:   time.Now(),
		EventType:   events.EventConnectionBlocked,
		DstHostname: "example.com",
		WouldDeny:   true,
	})
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_WARN, rec.SeverityNumber)
	assert.Equal(t, "would_deny", attrMap(t, rec.Attributes)["cargowall.verdict"].GetStringValue())
}

func TestLogRecordFromEvent_LateAllowed(t *testing.T) {
	rec := logRecordFromEvent(events.AuditEvent{
		Timestamp:   time.Now(),
		EventType:   events.EventConnectionLateAllowed,
		DstHostname: "ec2-1-2-3-4.compute-1.amazonaws.com",
		DstPort:     443,
		MatchedRule: "*.compute-1.amazonaws.com",
	})
	assert.Equal(t, "cargowall.connection_late_allowed", rec.EventName)
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, rec.SeverityNumber)
	assert.Equal(t, "connection late allowed ec2-1-2-3-4.compute-1.amazonaws.com:443", rec.Body.GetStringValue())
	assert.Equal(t, "*.compute-1.amazonaws.com", attrMap(t, rec.Attributes)["cargowall.matched_rule"].GetStringValue())
}

func TestLogRecordFromEvent_ProtocolBlocked(t *testing.T) {
	rec := logRecordFromEvent(events.AuditEvent{
		Timestamp: time.Now(),
		EventType: events.EventProtocolBlocked,
		DstIP:     "93.184.216.34",
		Protocol:  "ICMP",
		Blocked:   true,
	})
	assert.Equal(t, "cargowall.protocol_blocked", rec.EventName)
	assert.Equal(t, "protocol ICMP blocked 93.184.216.34", rec.Body.GetStringValue())
	attrs := attrMap(t, rec.Attributes)
	// ICMP is not an OTel network.transport value; only cargowall.protocol carries it.
	assert.NotContains(t, attrs, "network.transport")
	assert.Equal(t, "ICMP", attrs["cargowall.protocol"].GetStringValue())
}

func TestLogRecordFromEvent_DNSBlocked(t *testing.T) {
	rec := logRecordFromEvent(events.AuditEvent{
		Timestamp:   time.Now(),
		EventType:   events.EventDNSBlocked,
		DstHostname: "blocked.example.com",
		Blocked:     true,
	})
	assert.Equal(t, "cargowall.dns_blocked", rec.EventName)
	assert.Equal(t, "dns blocked blocked.example.com", rec.Body.GetStringValue())
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_WARN, rec.SeverityNumber)
}

func TestLogRecordFromEvent_ExistingConnection(t *testing.T) {
	allowed := logRecordFromEvent(events.AuditEvent{
		Timestamp:   time.Now(),
		EventType:   events.EventExistingConnection,
		DstIP:       "93.184.216.34",
		DstHostname: "example.com",
	})
	assert.Equal(t, "cargowall.existing_connection", allowed.EventName)
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, allowed.SeverityNumber)
	assert.Equal(t, "existing connection allow example.com", allowed.Body.GetStringValue())

	blocked := logRecordFromEvent(events.AuditEvent{
		Timestamp: time.Now(),
		EventType: events.EventExistingConnection,
		DstIP:     "93.184.216.34",
		Blocked:   true,
		WouldDeny: true,
	})
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_WARN, blocked.SeverityNumber)
	assert.Equal(t, "existing connection deny 93.184.216.34", blocked.Body.GetStringValue())

	// Body must agree with the cargowall.verdict attribute for a
	// hypothetical would-deny-only event too (no rewrite to "blocked").
	wouldDeny := logRecordFromEvent(events.AuditEvent{
		Timestamp: time.Now(),
		EventType: events.EventExistingConnection,
		DstIP:     "93.184.216.34",
		WouldDeny: true,
	})
	assert.Equal(t, "would_deny", attrMap(t, wouldDeny.Attributes)["cargowall.verdict"].GetStringValue())
	assert.Equal(t, "existing connection would deny 93.184.216.34", wouldDeny.Body.GetStringValue())
}

func TestBuildResource(t *testing.T) {
	res := buildResource(Config{
		ServiceName:   "cargowall",
		ResourceAttrs: map[string]string{"team": "infra", "host.name": "override-host"},
	}, "1.2.3")

	attrs := attrMap(t, res.Attributes)
	assert.Equal(t, "cargowall", attrs["service.name"].GetStringValue())
	assert.Equal(t, "1.2.3", attrs["service.version"].GetStringValue())
	assert.Equal(t, "infra", attrs["team"].GetStringValue())
	// User-supplied resource attributes override detected defaults.
	assert.Equal(t, "override-host", attrs["host.name"].GetStringValue())
}
