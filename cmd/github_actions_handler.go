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
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// GitHubActionsHandler is a slog.Handler that formats logs for GitHub Actions.
// It uses GitHub's workflow commands for annotations:
// - ::debug::message
// - ::notice::message
// - ::warning::message
// - ::error::message
type GitHubActionsHandler struct {
	debug bool
	attrs []slog.Attr
}

// NewGitHubActionsHandler creates a new GitHub Actions compatible log handler.
func NewGitHubActionsHandler(debug bool) *GitHubActionsHandler {
	return &GitHubActionsHandler{
		debug: debug,
	}
}

func (h *GitHubActionsHandler) Enabled(_ context.Context, level slog.Level) bool {
	if h.debug {
		return true
	}
	return level >= slog.LevelInfo
}

func (h *GitHubActionsHandler) Handle(_ context.Context, r slog.Record) error {
	var prefix string
	switch {
	case r.Level >= slog.LevelError:
		prefix = "::error::"
	case r.Level >= slog.LevelWarn:
		prefix = "::warning::"
	case r.Level >= slog.LevelInfo:
		prefix = ""
	default:
		prefix = "::debug::"
	}

	// Build the message with attributes
	var sb strings.Builder
	sb.WriteString(r.Message)

	// Add stored attrs
	for _, attr := range h.attrs {
		sb.WriteString(fmt.Sprintf(" %s=%v", attr.Key, attr.Value))
	}

	// Add record attrs
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(fmt.Sprintf(" %s=%v", a.Key, a.Value))
		return true
	})
	body := sb.String()

	// UTC so the timestamp aligns with GitHub's own per-line log timestamps and
	// is unambiguous across runner timezones. Millisecond precision because the
	// startup race this surfaces is sub-second.
	ts := r.Time.UTC().Format("2006-01-02 15:04:05.000")

	var out strings.Builder
	if prefix == "" {
		// Plain log line. Timestamp every physical line so a multi-line attribute
		// value (e.g. a wrapped, multi-line error) stays timestamped instead of
		// only its first line. Trim a single trailing newline first so a value
		// ending in "\n" doesn't produce a stray timestamp-only line.
		for line := range strings.SplitSeq(strings.TrimSuffix(body, "\n"), "\n") {
			fmt.Fprintf(&out, "%s %s\n", ts, line)
		}
	} else {
		// Workflow command (::error::/::warning::/::debug::). Emit a single command
		// and do NOT inject the timestamp: a unique value per line would defeat
		// GitHub's de-duplication of identical annotations and inflate the per-run
		// annotation count. GitHub already timestamps the raw log line. Escape so an
		// embedded newline stays one annotation rather than leaking un-prefixed
		// continuation lines.
		fmt.Fprintf(&out, "%s%s\n", prefix, escapeWorkflowMessage(body))
	}

	// Write the whole record in one call so a concurrent log from another
	// goroutine can't interleave between a multi-line record's lines.
	_, _ = os.Stderr.WriteString(out.String())
	return nil
}

// escapeWorkflowMessage encodes a string for use as the message of a GitHub
// Actions workflow command, per GitHub's data-escaping rules (% first, then CR
// and LF), so multi-line or percent-bearing messages parse as a single command.
func escapeWorkflowMessage(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func (h *GitHubActionsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &GitHubActionsHandler{
		debug: h.debug,
		attrs: newAttrs,
	}
}

func (h *GitHubActionsHandler) WithGroup(_ string) slog.Handler {
	// Group prefixing is not implemented for GitHub Actions log format.
	return h
}
