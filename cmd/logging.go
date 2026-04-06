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
	"log/slog"
	"sync/atomic"
)

// swappableHandler is an slog.Handler that delegates to an atomically-swappable
// inner handler. This allows LoggerShutdown to swap the handler without
// invalidating *slog.Logger pointers held by long-lived goroutines.
type swappableHandler struct {
	inner atomic.Pointer[slog.Handler]
}

func (h *swappableHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return (*h.inner.Load()).Enabled(ctx, level)
}

func (h *swappableHandler) Handle(ctx context.Context, r slog.Record) error {
	return (*h.inner.Load()).Handle(ctx, r)
}

func (h *swappableHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return (*h.inner.Load()).WithAttrs(attrs)
}

func (h *swappableHandler) WithGroup(name string) slog.Handler {
	return (*h.inner.Load()).WithGroup(name)
}
