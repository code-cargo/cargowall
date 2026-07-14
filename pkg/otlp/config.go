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

// Package otlp implements a minimal OTLP/HTTP log exporter for audit events.
// It is configured entirely through the standard OTEL_* environment
// variables (https://opentelemetry.io/docs/specs/otel/protocol/exporter/)
// and supports only the http/protobuf transport.
package otlp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultServiceName = "cargowall"

// Config is the resolved OTLP/HTTP exporter configuration.
type Config struct {
	Endpoint      string            // final URL with /v1/logs path already applied
	Headers       map[string]string // extra HTTP headers for each export request
	Timeout       time.Duration     // per-attempt HTTP timeout
	Compression   string            // "gzip" or "none"
	ServiceName   string            // resource service.name
	ResourceAttrs map[string]string // parsed OTEL_RESOURCE_ATTRIBUTES (excluding service.name)
}

// ConfigFromEnv resolves the exporter configuration from OTEL_* environment
// variables via getenv (pass os.Getenv outside tests). It returns enabled ==
// false when no OTLP endpoint is configured; an error means an endpoint was
// configured but unusable, in which case export stays disabled.
func ConfigFromEnv(getenv func(string) string) (cfg Config, enabled bool, err error) {
	logsEndpoint := strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"))
	genericEndpoint := strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if logsEndpoint == "" && genericEndpoint == "" {
		return Config{}, false, nil
	}

	protocol := logsFirst(getenv, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "OTEL_EXPORTER_OTLP_PROTOCOL")
	if protocol != "" && protocol != "http/protobuf" {
		return Config{}, false, fmt.Errorf("unsupported OTLP protocol %q (only http/protobuf is supported)", protocol)
	}

	// Per the OTLP exporter spec, the signal-specific endpoint is used as-is
	// while the generic endpoint gets the signal path appended.
	endpoint := logsEndpoint
	if endpoint == "" {
		endpoint = strings.TrimSuffix(genericEndpoint, "/") + "/v1/logs"
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return Config{}, false, fmt.Errorf("invalid OTLP endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Config{}, false, fmt.Errorf("invalid OTLP endpoint %q: scheme must be http or https", endpoint)
	}

	headers, err := parseKeyValueList(logsFirst(getenv, "OTEL_EXPORTER_OTLP_LOGS_HEADERS", "OTEL_EXPORTER_OTLP_HEADERS"))
	if err != nil {
		return Config{}, false, fmt.Errorf("invalid OTLP headers: %w", err)
	}

	timeout := 10 * time.Second
	if v := logsFirst(getenv, "OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "OTEL_EXPORTER_OTLP_TIMEOUT"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil || ms <= 0 {
			return Config{}, false, fmt.Errorf("invalid OTLP timeout %q: expected positive milliseconds", v)
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	compression := logsFirst(getenv, "OTEL_EXPORTER_OTLP_LOGS_COMPRESSION", "OTEL_EXPORTER_OTLP_COMPRESSION")
	switch compression {
	case "":
		compression = "none"
	case "gzip", "none":
	default:
		return Config{}, false, fmt.Errorf("invalid OTLP compression %q (expected gzip or none)", compression)
	}

	resourceAttrs, err := parseKeyValueList(getenv("OTEL_RESOURCE_ATTRIBUTES"))
	if err != nil {
		return Config{}, false, fmt.Errorf("invalid OTEL_RESOURCE_ATTRIBUTES: %w", err)
	}
	serviceName := strings.TrimSpace(getenv("OTEL_SERVICE_NAME"))
	if serviceName == "" {
		serviceName = resourceAttrs["service.name"]
	}
	if serviceName == "" {
		serviceName = defaultServiceName
	}
	delete(resourceAttrs, "service.name")

	return Config{
		Endpoint:      endpoint,
		Headers:       headers,
		Timeout:       timeout,
		Compression:   compression,
		ServiceName:   serviceName,
		ResourceAttrs: resourceAttrs,
	}, true, nil
}

// logsFirst returns the logs-specific env var when set, otherwise the
// generic one, trimmed either way.
func logsFirst(getenv func(string) string, logsKey, genericKey string) string {
	if v := strings.TrimSpace(getenv(logsKey)); v != "" {
		return v
	}
	return strings.TrimSpace(getenv(genericKey))
}

// parseKeyValueList parses the W3C-baggage-style "k1=v1,k2=v2" format used
// by OTEL_EXPORTER_OTLP_HEADERS and OTEL_RESOURCE_ATTRIBUTES; values may be
// percent-encoded.
func parseKeyValueList(s string) (map[string]string, error) {
	out := map[string]string{}
	for pair := range strings.SplitSeq(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("malformed entry %q: expected key=value", pair)
		}
		value = strings.TrimSpace(value)
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}
		out[key] = value
	}
	return out, nil
}
