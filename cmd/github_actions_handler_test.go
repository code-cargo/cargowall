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

// TestGitHubActionsHandler_TimestampPrefix verifies every emitted line carries a
// leading millisecond timestamp, and that for annotated levels the ::error:: /
// ::warning:: workflow command stays at column 0 (timestamp after the prefix).
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

	// Error line: prefix stays at column 0, timestamp follows it.
	assert.Regexp(t, `^::error::2026-06-29 15:24:08\.456 boom\b`, lines[1])
}
