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
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSwappableHandler(h slog.Handler) (*swappableHandler, *atomic.Pointer[slog.Handler]) {
	inner := &atomic.Pointer[slog.Handler]{}
	inner.Store(&h)
	return &swappableHandler{inner: inner}, inner
}

func TestSwappableHandler_DelegatesToInner(t *testing.T) {
	text := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})
	sh, _ := newSwappableHandler(text)

	assert.True(t, sh.Enabled(context.Background(), slog.LevelDebug))
	assert.False(t, sh.Enabled(context.Background(), slog.Level(-8))) // below debug
}

func TestSwappableHandler_Swap(t *testing.T) {
	debug := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})
	info := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})
	sh, inner := newSwappableHandler(debug)

	assert.True(t, sh.Enabled(context.Background(), slog.LevelDebug))

	h := slog.Handler(info)
	inner.Store(&h)

	assert.False(t, sh.Enabled(context.Background(), slog.LevelDebug))
	assert.True(t, sh.Enabled(context.Background(), slog.LevelInfo))
}

func TestSwappableHandler_WithAttrs_FollowsSwap(t *testing.T) {
	debug := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})
	info := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})
	sh, inner := newSwappableHandler(debug)

	derived := sh.WithAttrs([]slog.Attr{slog.String("key", "val")})

	_, ok := derived.(*swappableHandler)
	require.True(t, ok, "WithAttrs should return a *swappableHandler")
	assert.True(t, derived.Enabled(context.Background(), slog.LevelDebug))

	h := slog.Handler(info)
	inner.Store(&h)

	assert.False(t, derived.Enabled(context.Background(), slog.LevelDebug), "derived handler should follow the swap")
}

func TestSwappableHandler_WithGroup_FollowsSwap(t *testing.T) {
	debug := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})
	info := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})
	sh, inner := newSwappableHandler(debug)

	derived := sh.WithGroup("grp")

	_, ok := derived.(*swappableHandler)
	require.True(t, ok, "WithGroup should return a *swappableHandler")
	assert.True(t, derived.Enabled(context.Background(), slog.LevelDebug))

	h := slog.Handler(info)
	inner.Store(&h)

	assert.False(t, derived.Enabled(context.Background(), slog.LevelDebug), "grouped handler should follow the swap")
}

func TestSwappableHandler_WithAttrs_Chained(t *testing.T) {
	debug := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})
	info := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})
	sh, inner := newSwappableHandler(debug)

	derived := sh.WithAttrs([]slog.Attr{slog.String("a", "1")}).WithGroup("grp").WithAttrs([]slog.Attr{slog.String("b", "2")})

	_, ok := derived.(*swappableHandler)
	require.True(t, ok)

	h := slog.Handler(info)
	inner.Store(&h)

	assert.False(t, derived.Enabled(context.Background(), slog.LevelDebug), "chained derived handler should follow the swap")
}
