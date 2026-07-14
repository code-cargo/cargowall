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
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestConfigFromEnv_Disabled(t *testing.T) {
	_, enabled, err := ConfigFromEnv(envMap(nil))
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestConfigFromEnv_GenericEndpointAppendsLogsPath(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{"bare", "http://collector:4318", "http://collector:4318/v1/logs"},
		{"trailing slash", "http://collector:4318/", "http://collector:4318/v1/logs"},
		{"base path", "https://collector.example.com/otlp", "https://collector.example.com/otlp/v1/logs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, enabled, err := ConfigFromEnv(envMap(map[string]string{
				"OTEL_EXPORTER_OTLP_ENDPOINT": tt.endpoint,
			}))
			require.NoError(t, err)
			require.True(t, enabled)
			assert.Equal(t, tt.want, cfg.Endpoint)
		})
	}
}

func TestConfigFromEnv_LogsEndpointUsedVerbatim(t *testing.T) {
	cfg, enabled, err := ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT":      "http://generic:4318",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://logs:4318/custom/path",
	}))
	require.NoError(t, err)
	require.True(t, enabled)
	assert.Equal(t, "http://logs:4318/custom/path", cfg.Endpoint)
}

func TestConfigFromEnv_Defaults(t *testing.T) {
	cfg, enabled, err := ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
	}))
	require.NoError(t, err)
	require.True(t, enabled)
	assert.Equal(t, 10*time.Second, cfg.Timeout)
	assert.Equal(t, "none", cfg.Compression)
	assert.Equal(t, "cargowall", cfg.ServiceName)
	assert.Empty(t, cfg.Headers)
}

func TestConfigFromEnv_UnsupportedProtocol(t *testing.T) {
	for _, protocol := range []string{"grpc", "http/json"} {
		_, enabled, err := ConfigFromEnv(envMap(map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
			"OTEL_EXPORTER_OTLP_PROTOCOL": protocol,
		}))
		assert.Error(t, err)
		assert.False(t, enabled)
	}
}

func TestConfigFromEnv_HttpProtobufProtocolAccepted(t *testing.T) {
	_, enabled, err := ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT":      "http://collector:4318",
		"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL": "http/protobuf",
	}))
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestConfigFromEnv_InvalidEndpointScheme(t *testing.T) {
	_, enabled, err := ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "grpc://collector:4317",
	}))
	assert.Error(t, err)
	assert.False(t, enabled)
}

func TestConfigFromEnv_Headers(t *testing.T) {
	cfg, _, err := ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
		"OTEL_EXPORTER_OTLP_HEADERS":  "Authorization=Bearer%20secret, X-Tenant=acme",
	}))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"Authorization": "Bearer secret",
		"X-Tenant":      "acme",
	}, cfg.Headers)
}

func TestConfigFromEnv_MalformedHeaders(t *testing.T) {
	_, enabled, err := ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
		"OTEL_EXPORTER_OTLP_HEADERS":  "not-a-pair",
	}))
	assert.Error(t, err)
	assert.False(t, enabled)
}

func TestConfigFromEnv_TimeoutAndCompression(t *testing.T) {
	cfg, _, err := ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT":    "http://collector:4318",
		"OTEL_EXPORTER_OTLP_TIMEOUT":     "2500",
		"OTEL_EXPORTER_OTLP_COMPRESSION": "gzip",
	}))
	require.NoError(t, err)
	assert.Equal(t, 2500*time.Millisecond, cfg.Timeout)
	assert.Equal(t, "gzip", cfg.Compression)

	_, _, err = ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
		"OTEL_EXPORTER_OTLP_TIMEOUT":  "not-a-number",
	}))
	assert.Error(t, err)

	_, _, err = ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT":    "http://collector:4318",
		"OTEL_EXPORTER_OTLP_COMPRESSION": "zstd",
	}))
	assert.Error(t, err)
}

func TestConfigFromEnv_ServiceNamePrecedence(t *testing.T) {
	// OTEL_SERVICE_NAME wins over OTEL_RESOURCE_ATTRIBUTES.
	cfg, _, err := ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
		"OTEL_SERVICE_NAME":           "from-env",
		"OTEL_RESOURCE_ATTRIBUTES":    "service.name=from-attrs,team=infra",
	}))
	require.NoError(t, err)
	assert.Equal(t, "from-env", cfg.ServiceName)
	assert.Equal(t, map[string]string{"team": "infra"}, cfg.ResourceAttrs)

	// Falls back to resource attributes, then the default.
	cfg, _, err = ConfigFromEnv(envMap(map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
		"OTEL_RESOURCE_ATTRIBUTES":    "service.name=from-attrs",
	}))
	require.NoError(t, err)
	assert.Equal(t, "from-attrs", cfg.ServiceName)
}
