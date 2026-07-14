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
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	collogspb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/collector/logs/v1"
	"github.com/code-cargo/cargowall/pkg/events"
)

// collector is an httptest-backed OTLP endpoint that records decoded
// export requests.
type collector struct {
	mu       sync.Mutex
	requests []*collogspb.ExportLogsServiceRequest
	headers  []http.Header
	respond  func(w http.ResponseWriter, requestIndex int) // optional custom response
	server   *httptest.Server
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(bytes.NewReader(body))
			require.NoError(t, err)
			body, err = io.ReadAll(gz)
			require.NoError(t, err)
			require.NoError(t, gz.Close())
		}
		var req collogspb.ExportLogsServiceRequest
		require.NoError(t, proto.Unmarshal(body, &req))

		c.mu.Lock()
		idx := len(c.requests)
		c.requests = append(c.requests, &req)
		c.headers = append(c.headers, r.Header.Clone())
		respond := c.respond
		c.mu.Unlock()

		if respond != nil {
			respond(w, idx)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *collector) recorded() []*collogspb.ExportLogsServiceRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.requests)
}

func testConfig(endpoint string) Config {
	return Config{
		Endpoint:    endpoint + "/v1/logs",
		Timeout:     5 * time.Second,
		Compression: "none",
		ServiceName: "cargowall-test",
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testEvent() events.AuditEvent {
	return events.AuditEvent{
		Timestamp:   time.Now(),
		EventType:   events.EventConnectionBlocked,
		SrcIP:       "10.0.0.1",
		DstIP:       "93.184.216.34",
		DstHostname: "example.com",
		DstPort:     443,
		Protocol:    "TCP",
		Blocked:     true,
	}
}

func TestExporter_ShutdownFlushesQueuedEvents(t *testing.T) {
	c := newCollector(t)
	cfg := testConfig(c.server.URL)
	cfg.Headers = map[string]string{"Authorization": "Bearer secret"}
	e := New(cfg, "1.2.3", discardLogger())

	for range 3 {
		e.Consume(testEvent())
	}
	require.NoError(t, e.Shutdown(context.Background()))

	reqs := c.recorded()
	require.Len(t, reqs, 1)
	require.Len(t, reqs[0].ResourceLogs, 1)
	scopeLogs := reqs[0].ResourceLogs[0].ScopeLogs
	require.Len(t, scopeLogs, 1)
	assert.Len(t, scopeLogs[0].LogRecords, 3)
	assert.Equal(t, scopeName, scopeLogs[0].Scope.GetName())
	assert.Equal(t, "1.2.3", scopeLogs[0].Scope.GetVersion())

	resAttrs := reqs[0].ResourceLogs[0].Resource.GetAttributes()
	names := make(map[string]string, len(resAttrs))
	for _, kv := range resAttrs {
		names[kv.Key] = kv.Value.GetStringValue()
	}
	assert.Equal(t, "cargowall-test", names["service.name"])

	assert.Equal(t, "Bearer secret", c.headers[0].Get("Authorization"))
	assert.Equal(t, "application/x-protobuf", c.headers[0].Get("Content-Type"))
}

func TestExporter_BatchesBySize(t *testing.T) {
	c := newCollector(t)
	e := New(testConfig(c.server.URL), "test", discardLogger())

	for range maxBatchSize + 1 {
		e.Consume(testEvent())
	}
	require.NoError(t, e.Shutdown(context.Background()))

	reqs := c.recorded()
	require.Len(t, reqs, 2)
	assert.Len(t, reqs[0].ResourceLogs[0].ScopeLogs[0].LogRecords, maxBatchSize)
	assert.Len(t, reqs[1].ResourceLogs[0].ScopeLogs[0].LogRecords, 1)
}

func TestExporter_GzipRoundTrip(t *testing.T) {
	c := newCollector(t)
	cfg := testConfig(c.server.URL)
	cfg.Compression = "gzip"
	e := New(cfg, "test", discardLogger())

	e.Consume(testEvent())
	require.NoError(t, e.Shutdown(context.Background()))

	require.Len(t, c.recorded(), 1)
	assert.Equal(t, "gzip", c.headers[0].Get("Content-Encoding"))
	assert.Len(t, c.recorded()[0].ResourceLogs[0].ScopeLogs[0].LogRecords, 1)
}

func TestExporter_RetriesOn503(t *testing.T) {
	c := newCollector(t)
	c.respond = func(w http.ResponseWriter, requestIndex int) {
		if requestIndex == 0 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	e := New(testConfig(c.server.URL), "test", discardLogger())

	e.Consume(testEvent())
	require.NoError(t, e.Shutdown(context.Background()))
	assert.Len(t, c.recorded(), 2)
}

func TestExporter_PermanentErrorNotRetried(t *testing.T) {
	c := newCollector(t)
	c.respond = func(w http.ResponseWriter, _ int) {
		w.WriteHeader(http.StatusBadRequest)
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	e := New(testConfig(c.server.URL), "test", logger)

	e.Consume(testEvent())
	require.NoError(t, e.Shutdown(context.Background()))
	assert.Len(t, c.recorded(), 1)
	assert.Contains(t, logBuf.String(), "dropping batch")
}

func TestExporter_PartialSuccessLogged(t *testing.T) {
	c := newCollector(t)
	c.respond = func(w http.ResponseWriter, _ int) {
		resp := &collogspb.ExportLogsServiceResponse{
			PartialSuccess: &collogspb.ExportLogsPartialSuccess{
				RejectedLogRecords: 1,
				ErrorMessage:       "attribute limit exceeded",
			},
		}
		body, err := proto.Marshal(resp)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(body)
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	e := New(testConfig(c.server.URL), "test", logger)

	e.Consume(testEvent())
	require.NoError(t, e.Shutdown(context.Background()))
	assert.Contains(t, logBuf.String(), "rejected")
	assert.Contains(t, logBuf.String(), "attribute limit exceeded")
}

func TestExporter_DropOnFull(t *testing.T) {
	// Construct without a worker so nothing drains the queue.
	e := &Exporter{
		queue:  make(chan events.AuditEvent, 1),
		logger: discardLogger(),
	}
	e.Consume(testEvent())
	e.Consume(testEvent())
	assert.Equal(t, uint64(1), e.dropped.Load())
}

func TestExporter_ConsumeAfterShutdownDrops(t *testing.T) {
	c := newCollector(t)
	e := New(testConfig(c.server.URL), "test", discardLogger())
	require.NoError(t, e.Shutdown(context.Background()))

	e.Consume(testEvent())
	assert.Equal(t, uint64(1), e.dropped.Load())
	assert.Empty(t, c.recorded())

	// Second shutdown is a no-op.
	require.NoError(t, e.Shutdown(context.Background()))
}

func TestExporter_ShutdownRespectsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := New(testConfig(server.URL), "test", discardLogger())
	e.Consume(testEvent())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := e.Shutdown(ctx)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "deadline"))
}
