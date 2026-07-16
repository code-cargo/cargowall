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
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"

	commonpb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/common/v1"
	logspb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/logs/v1"
	resourcepb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/resource/v1"
	"github.com/code-cargo/cargowall/pkg/events"
)

func stringAttr(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}},
	}
}

func intAttr(key string, value int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: value}},
	}
}

func boolAttr(key string, value bool) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: value}},
	}
}

func stringArrayAttr(key string, values []string) *commonpb.KeyValue {
	arr := make([]*commonpb.AnyValue, len(values))
	for i, v := range values {
		arr[i] = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}
	}
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: arr}}},
	}
}

// verdict derives the policy outcome for an event: allow, deny, or
// would_deny (audit mode).
func verdict(ev events.AuditEvent) string {
	switch {
	case ev.Blocked:
		return "deny"
	case ev.WouldDeny:
		return "would_deny"
	default:
		return "allow"
	}
}

// logRecordFromEvent maps an audit event to an OTLP log record. Attribute
// names follow OTel semantic conventions where one fits; cargowall-specific
// fields use the cargowall.* namespace.
func logRecordFromEvent(ev events.AuditEvent) *logspb.LogRecord {
	ts := uint64(ev.Timestamp.UnixNano())
	rec := &logspb.LogRecord{
		TimeUnixNano:         ts,
		ObservedTimeUnixNano: ts,
		EventName:            "cargowall." + string(ev.EventType),
	}

	if verdict(ev) == "allow" {
		rec.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_INFO
		rec.SeverityText = "INFO"
	} else {
		rec.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_WARN
		rec.SeverityText = "WARN"
	}

	rec.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: eventBody(ev)}}

	attrs := make([]*commonpb.KeyValue, 0, 16)
	if ev.SrcIP != "" {
		attrs = append(attrs, stringAttr("source.address", ev.SrcIP))
	}
	if ev.DstIP != "" {
		attrs = append(attrs, stringAttr("destination.address", ev.DstIP))
	}
	if ev.DstPort != 0 {
		attrs = append(attrs, intAttr("destination.port", int64(ev.DstPort)))
	}
	if ev.DstHostname != "" {
		attrs = append(attrs, stringAttr("server.address", ev.DstHostname))
	}
	switch strings.ToLower(ev.Protocol) {
	case "tcp":
		attrs = append(attrs, stringAttr("network.transport", "tcp"))
	case "udp":
		attrs = append(attrs, stringAttr("network.transport", "udp"))
	}
	if ev.Process != "" {
		attrs = append(attrs, stringAttr("process.executable.name", ev.Process))
	}
	if ev.PID != 0 {
		attrs = append(attrs, intAttr("process.pid", int64(ev.PID)))
	}
	if ev.Protocol != "" {
		attrs = append(attrs, stringAttr("cargowall.protocol", ev.Protocol))
	}
	if ev.MatchedRule != "" {
		attrs = append(attrs, stringAttr("cargowall.matched_rule", ev.MatchedRule))
	}
	if ev.AutoAllowedType != "" {
		attrs = append(attrs, stringAttr("cargowall.auto_allowed_type", ev.AutoAllowedType))
	}
	if len(ev.CNAMEChain) > 0 {
		attrs = append(attrs, stringArrayAttr("cargowall.cname_chain", ev.CNAMEChain))
	}
	attrs = append(
		attrs,
		boolAttr("cargowall.would_deny", ev.WouldDeny),
		boolAttr("cargowall.blocked", ev.Blocked),
		stringAttr("cargowall.verdict", verdict(ev)),
	)
	rec.Attributes = attrs
	return rec
}

// eventBody renders the short human-readable log body.
func eventBody(ev events.AuditEvent) string {
	action := strings.ReplaceAll(strings.TrimPrefix(string(ev.EventType), "connection_"), "_", " ")
	if ev.EventType == events.EventExistingConnection {
		// Keep the body consistent with the cargowall.verdict attribute.
		action = "existing connection " + strings.ReplaceAll(verdict(ev), "_", " ")
	}
	target := ev.DstHostname
	if target == "" {
		target = ev.DstIP
	}
	if ev.DstPort != 0 {
		target = fmt.Sprintf("%s:%d", target, ev.DstPort)
	}
	switch ev.EventType {
	case events.EventDNSBlocked:
		return "dns blocked " + target
	case events.EventProtocolBlocked:
		return fmt.Sprintf("protocol %s blocked %s", ev.Protocol, target)
	case events.EventExistingConnection:
		return action + " " + target
	default:
		return "connection " + action + " " + target
	}
}

// buildResource assembles the OTLP resource: service.name/version and
// host.name defaults, overridable by user-supplied OTEL_RESOURCE_ATTRIBUTES
// (service.name precedence is already resolved in ConfigFromEnv).
func buildResource(cfg Config, version string) *resourcepb.Resource {
	merged := map[string]string{"service.name": cfg.ServiceName}
	if version != "" {
		merged["service.version"] = version
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		merged["host.name"] = hostname
	}
	maps.Copy(merged, cfg.ResourceAttrs)
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	attrs := make([]*commonpb.KeyValue, 0, len(merged))
	for _, k := range keys {
		attrs = append(attrs, stringAttr(k, merged[k]))
	}
	return &resourcepb.Resource{Attributes: attrs}
}
