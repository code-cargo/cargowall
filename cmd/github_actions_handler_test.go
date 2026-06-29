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
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStderr redirects os.Stderr around fn and returns what was written. The
// GitHubActionsHandler writes to os.Stderr directly, so the test swaps the global
// for the duration of the call. A goroutine drains the read end concurrently, so
// a write larger than the OS pipe buffer can't deadlock and the read end is
// always consumed and closed; os.Stderr is restored and the write end closed even
// if fn panics.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		_ = r.Close()
		done <- string(data)
	}()

	func() {
		defer func() {
			os.Stderr = old
			_ = w.Close()
		}()
		fn()
	}()

	return <-done
}

// TestGitHubActionsHandler_TimestampPrefix verifies plain (Info) lines get a
// leading UTC millisecond timestamp, while workflow-command levels (::error::,
// ::warning::) keep the command at column 0 with NO injected timestamp (so
// GitHub still de-duplicates identical annotations).
func TestGitHubActionsHandler_TimestampPrefix(t *testing.T) {
	h := NewGitHubActionsHandler(false)
	ts := time.Date(2026, 6, 29, 15, 24, 8, 456_000_000, time.UTC)

	out := captureStderr(t, func() {
		info := slog.NewRecord(ts, slog.LevelInfo, "Connection blocked", 0)
		info.AddAttrs(slog.Int("dst_port", 443))
		require.NoError(t, h.Handle(context.Background(), info))

		errRec := slog.NewRecord(ts, slog.LevelError, "boom", 0)
		require.NoError(t, h.Handle(context.Background(), errRec))
	})

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 2)

	// Info line: "<timestamp> <message> <attrs>", no prefix.
	assert.Regexp(t, `^2026-06-29 15:24:08\.456 Connection blocked\b`, lines[0])
	assert.Contains(t, lines[0], "dst_port=443")

	// Error line: bare workflow command, no timestamp injected (preserves dedup).
	assert.Equal(t, "::error::boom", lines[1])
}

// TestGitHubActionsHandler_TimestampUTC verifies the timestamp is rendered in
// UTC regardless of the record's location, so it aligns with GitHub's UTC gutter.
func TestGitHubActionsHandler_TimestampUTC(t *testing.T) {
	h := NewGitHubActionsHandler(false)
	// A fixed instant expressed in a non-UTC zone; the handler must print its UTC
	// wall-clock (17:00 in -05:00 == 22:00 UTC), not the local 17:00.
	loc := time.FixedZone("X", -5*60*60)
	ts := time.Date(2026, 6, 29, 17, 0, 0, 250_000_000, loc)

	out := captureStderr(t, func() {
		rec := slog.NewRecord(ts, slog.LevelInfo, "hello", 0)
		require.NoError(t, h.Handle(context.Background(), rec))
	})

	assert.Equal(t, "2026-06-29 22:00:00.250 hello", strings.TrimRight(out, "\n"))
}

// TestGitHubActionsHandler_MultiLine verifies a multi-line attribute value
// timestamps every physical line on a plain record, and stays a single escaped
// annotation on a workflow-command record.
func TestGitHubActionsHandler_MultiLine(t *testing.T) {
	h := NewGitHubActionsHandler(false)
	ts := time.Date(2026, 6, 29, 15, 24, 8, 456_000_000, time.UTC)

	out := captureStderr(t, func() {
		info := slog.NewRecord(ts, slog.LevelInfo, "validation failed", 0)
		info.AddAttrs(slog.String("error", "line1\nline2"))
		require.NoError(t, h.Handle(context.Background(), info))

		errRec := slog.NewRecord(ts, slog.LevelError, "boom", 0)
		errRec.AddAttrs(slog.String("detail", "a\nb"))
		require.NoError(t, h.Handle(context.Background(), errRec))
	})

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 3)

	// Each physical line of the plain record is independently timestamped.
	assert.Equal(t, "2026-06-29 15:24:08.456 validation failed error=line1", lines[0])
	assert.Equal(t, "2026-06-29 15:24:08.456 line2", lines[1])

	// The workflow command stays one line with newlines escaped as %0A.
	assert.Equal(t, "::error::boom detail=a%0Ab", lines[2])
}

// TestGitHubActionsHandler_TrailingNewline verifies a plain record whose body
// ends in a newline does not emit a stray timestamp-only line.
func TestGitHubActionsHandler_TrailingNewline(t *testing.T) {
	h := NewGitHubActionsHandler(false)
	ts := time.Date(2026, 6, 29, 15, 24, 8, 456_000_000, time.UTC)

	out := captureStderr(t, func() {
		rec := slog.NewRecord(ts, slog.LevelInfo, "ran", 0)
		rec.AddAttrs(slog.String("output", "done\n"))
		require.NoError(t, h.Handle(context.Background(), rec))
	})

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 1)
	assert.Equal(t, "2026-06-29 15:24:08.456 ran output=done", lines[0])
}
