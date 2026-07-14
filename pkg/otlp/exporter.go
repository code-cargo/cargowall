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
	"fmt"
	"io"
	"log/slog"
	rand "math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	collogspb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/collector/logs/v1"
	commonpb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/common/v1"
	logspb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/logs/v1"
	resourcepb "github.com/code-cargo/cargowall/pb/otlp/opentelemetry/proto/resource/v1"
	"github.com/code-cargo/cargowall/pkg/events"
)

const (
	queueCapacity = 2048
	maxBatchSize  = 512
	flushInterval = 5 * time.Second
	maxAttempts   = 4
	scopeName     = "github.com/code-cargo/cargowall"
)

// Exporter batches audit events and ships them to an OTLP/HTTP logs
// endpoint. It implements events.EventSink; Consume never blocks — events
// are dropped when the queue is full or after shutdown.
type Exporter struct {
	cfg      Config
	client   *http.Client
	queue    chan events.AuditEvent
	resource *resourcepb.Resource
	scope    *commonpb.InstrumentationScope
	done     chan struct{}
	closed   atomic.Bool
	dropped  atomic.Uint64
	logger   *slog.Logger
}

// NewFromEnv builds an exporter from the standard OTEL_* environment
// variables. It returns (nil, nil) when no OTLP endpoint is configured and
// (nil, err) when the configuration is present but unusable.
func NewFromEnv(version string, logger *slog.Logger) (*Exporter, error) {
	cfg, enabled, err := ConfigFromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	return New(cfg, version, logger), nil
}

// New creates an exporter and starts its background worker.
func New(cfg Config, version string, logger *slog.Logger) *Exporter {
	e := &Exporter{
		cfg:      cfg,
		client:   &http.Client{Timeout: cfg.Timeout},
		queue:    make(chan events.AuditEvent, queueCapacity),
		resource: buildResource(cfg, version),
		scope:    &commonpb.InstrumentationScope{Name: scopeName, Version: version},
		done:     make(chan struct{}),
		logger:   logger,
	}
	go e.run()
	return e
}

// Endpoint returns the resolved OTLP logs endpoint URL.
func (e *Exporter) Endpoint() string {
	return e.cfg.Endpoint
}

// Consume implements events.EventSink. It never blocks: when the queue is
// full or the exporter has been shut down, the event is counted as dropped.
func (e *Exporter) Consume(ev events.AuditEvent) {
	if e.closed.Load() {
		e.dropped.Add(1)
		return
	}
	select {
	case e.queue <- ev:
	default:
		e.dropped.Add(1)
	}
}

// Shutdown stops the worker and flushes any queued events, bounded by ctx.
func (e *Exporter) Shutdown(ctx context.Context) error {
	if e.closed.Swap(true) {
		return nil
	}
	close(e.queue)
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run is the background worker: it accumulates events and exports a batch
// whenever it reaches maxBatchSize or flushInterval elapses.
func (e *Exporter) run() {
	defer close(e.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]*logspb.LogRecord, 0, maxBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		e.export(batch)
		batch = batch[:0]
	}

	for {
		select {
		case ev, ok := <-e.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, logRecordFromEvent(ev))
			if len(batch) >= maxBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
			if n := e.dropped.Swap(0); n > 0 {
				e.logger.Warn("OTLP exporter dropped events (queue full)", "count", n)
			}
		}
	}
}

// export sends one batch, retrying transient failures with jittered
// exponential backoff. Batches that exhaust retries or hit a permanent
// error are dropped with a warning.
func (e *Exporter) export(batch []*logspb.LogRecord) {
	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: e.resource,
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope:      e.scope,
				LogRecords: batch,
			}},
		}},
	}
	body, err := proto.Marshal(req)
	if err != nil {
		e.logger.Warn("OTLP export failed to marshal batch", "error", err)
		return
	}

	backoff := time.Second
	for attempt := 1; ; attempt++ {
		retryable, retryAfter, err := e.send(body)
		if err == nil {
			return
		}
		if !retryable || attempt >= maxAttempts {
			e.logger.Warn("OTLP export failed, dropping batch",
				"error", err, "attempts", attempt, "records", len(batch))
			return
		}
		delay := backoff + time.Duration(rand.Int64N(int64(backoff/2)))
		if retryAfter > 0 {
			delay = retryAfter
		}
		backoff *= 2
		time.Sleep(delay)
	}
}

// send performs a single HTTP POST attempt. It reports whether a failure is
// retryable and any server-requested Retry-After delay.
func (e *Exporter) send(body []byte) (retryable bool, retryAfter time.Duration, err error) {
	payload := body
	encoding := ""
	if e.cfg.Compression == "gzip" {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(body); err == nil && gz.Close() == nil {
			payload = buf.Bytes()
			encoding = "gzip"
		}
	}

	req, err := http.NewRequest(http.MethodPost, e.cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return true, 0, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return false, 0, nil // exported; response decode is best-effort
		}
		var exportResp collogspb.ExportLogsServiceResponse
		if err := proto.Unmarshal(respBody, &exportResp); err == nil {
			if ps := exportResp.GetPartialSuccess(); ps.GetRejectedLogRecords() > 0 {
				e.logger.Warn("OTLP endpoint rejected some log records",
					"rejected", ps.GetRejectedLogRecords(), "message", ps.GetErrorMessage())
			}
		}
		return false, 0, nil
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusGatewayTimeout:
		return true, parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("OTLP endpoint returned status %d", resp.StatusCode)
	default:
		return false, 0, fmt.Errorf("OTLP endpoint returned status %d", resp.StatusCode)
	}
}

// parseRetryAfter handles both delta-seconds and HTTP-date forms.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
