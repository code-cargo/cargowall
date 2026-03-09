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

	fmt.Fprintf(os.Stderr, "%s%s\n", prefix, sb.String())
	return nil
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
