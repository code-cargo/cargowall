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
	"sync"
	"sync/atomic"
)

// swappableHandler is an slog.Handler that delegates to an atomically-swappable
// inner handler. This allows LoggerShutdown to swap the handler without
// invalidating *slog.Logger pointers held by long-lived goroutines.
//
// WithAttrs and WithGroup return a new swappableHandler sharing the same atomic
// pointer, so derived loggers (logger.With(...)) are also affected by the swap.
// Resolved handlers are cached lazily and only rebuilt when the inner swaps.
type swappableHandler struct {
	inner *atomic.Pointer[slog.Handler]
	apply func(slog.Handler) slog.Handler // nil for root handler
	cache sync.Map                        // *slog.Handler → slog.Handler
}

func (h *swappableHandler) resolve() slog.Handler {
	base := h.inner.Load()
	if h.apply == nil {
		return *base
	}
	if cached, ok := h.cache.Load(base); ok {
		return cached.(slog.Handler)
	}
	resolved := h.apply(*base)
	h.cache.Store(base, resolved)
	return resolved
}

func (h *swappableHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.resolve().Enabled(ctx, level)
}

func (h *swappableHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.resolve().Handle(ctx, r)
}

func (h *swappableHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	parent := h.apply
	return &swappableHandler{
		inner: h.inner,
		apply: func(base slog.Handler) slog.Handler {
			if parent != nil {
				base = parent(base)
			}
			return base.WithAttrs(attrs)
		},
	}
}

func (h *swappableHandler) WithGroup(name string) slog.Handler {
	parent := h.apply
	return &swappableHandler{
		inner: h.inner,
		apply: func(base slog.Handler) slog.Handler {
			if parent != nil {
				base = parent(base)
			}
			return base.WithGroup(name)
		},
	}
}
