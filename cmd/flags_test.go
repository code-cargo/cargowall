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
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noopExecute(_ *StartCmd, _ *StartHooks) error { return nil }

func saveSlogDefault(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// innerHandler extracts the inner handler from a swappableHandler-backed logger.
func innerHandler(t *testing.T, logger *slog.Logger) slog.Handler {
	t.Helper()
	sh, ok := logger.Handler().(*swappableHandler)
	require.True(t, ok, "expected *swappableHandler, got %T", logger.Handler())
	return *sh.inner.Load()
}

func testTextHandler() slog.Handler {
	return slog.NewTextHandler(io.Discard, nil)
}

// --- Run: default logger (no hooks) ---

func TestStartCmd_Run_DefaultLogger(t *testing.T) {
	saveSlogDefault(t)
	cmd := &StartCmd{Execute: noopExecute}
	err := cmd.Run(&Globals{})
	require.NoError(t, err)
	require.NotNil(t, cmd.Logger)
	_, ok := cmd.Logger.Handler().(*slog.JSONHandler)
	assert.True(t, ok, "expected *slog.JSONHandler, got %T", cmd.Logger.Handler())
	assert.Nil(t, cmd.LoggerShutdown)
}

func TestStartCmd_Run_DefaultLoggerDebug(t *testing.T) {
	saveSlogDefault(t)
	cmd := &StartCmd{Execute: noopExecute}
	err := cmd.Run(&Globals{Debug: true})
	require.NoError(t, err)
	assert.True(t, cmd.Logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestStartCmd_Run_GithubActionLogger(t *testing.T) {
	saveSlogDefault(t)
	cmd := &StartCmd{Execute: noopExecute, GithubAction: true}
	err := cmd.Run(&Globals{})
	require.NoError(t, err)
	_, ok := cmd.Logger.Handler().(*GitHubActionsHandler)
	assert.True(t, ok, "expected *GitHubActionsHandler, got %T", cmd.Logger.Handler())
	assert.Nil(t, cmd.LoggerShutdown)
}

// --- Run: InitLogger hook ---

func TestStartCmd_Run_InitLoggerHookSetsLogger(t *testing.T) {
	saveSlogDefault(t)
	hooks := &StartHooks{
		InitLogger: func(_ context.Context, _ string, _ bool) (slog.Handler, func(context.Context) error, error) {
			return testTextHandler(), func(context.Context) error { return nil }, nil
		},
	}
	cmd := &StartCmd{Execute: noopExecute, Hooks: hooks}
	err := cmd.Run(&Globals{})
	require.NoError(t, err)
	_, ok := innerHandler(t, cmd.Logger).(*slog.TextHandler)
	assert.True(t, ok, "expected inner *slog.TextHandler, got %T", innerHandler(t, cmd.Logger))
	assert.NotNil(t, cmd.LoggerShutdown)
}

func TestStartCmd_Run_InitLoggerHookError(t *testing.T) {
	saveSlogDefault(t)
	hooks := &StartHooks{
		InitLogger: func(_ context.Context, _ string, _ bool) (slog.Handler, func(context.Context) error, error) {
			return nil, nil, fmt.Errorf("connection refused")
		},
	}
	cmd := &StartCmd{Execute: noopExecute, Hooks: hooks}
	err := cmd.Run(&Globals{})
	require.NoError(t, err, "InitLogger error is warned, not fatal")
	_, ok := cmd.Logger.Handler().(*slog.JSONHandler)
	assert.True(t, ok, "logger should remain the default JSON logger")
	assert.Nil(t, cmd.LoggerShutdown)
}

func TestStartCmd_Run_InitLoggerHookWithGithubAction(t *testing.T) {
	saveSlogDefault(t)
	hooks := &StartHooks{
		InitLogger: func(_ context.Context, _ string, _ bool) (slog.Handler, func(context.Context) error, error) {
			return testTextHandler(), func(context.Context) error { return nil }, nil
		},
	}
	cmd := &StartCmd{Execute: noopExecute, Hooks: hooks, GithubAction: true}
	err := cmd.Run(&Globals{})
	require.NoError(t, err)
	_, ok := innerHandler(t, cmd.Logger).(*slog.TextHandler)
	assert.True(t, ok, "InitLogger hook should override GithubAction logger")
	assert.NotNil(t, cmd.LoggerShutdown)
}

// --- Run: Execute/hooks passthrough ---

func TestStartCmd_Run_ExecuteReceivesHooks(t *testing.T) {
	saveSlogDefault(t)
	readyHook := func() error { return nil }
	hooks := &StartHooks{Ready: readyHook}
	var receivedHooks *StartHooks
	cmd := &StartCmd{
		Execute: func(_ *StartCmd, h *StartHooks) error {
			receivedHooks = h
			return nil
		},
		Hooks: hooks,
	}
	err := cmd.Run(&Globals{})
	require.NoError(t, err)
	assert.Same(t, hooks, receivedHooks)
	assert.NotNil(t, receivedHooks.Ready)
}

func TestStartCmd_Run_ExecuteError(t *testing.T) {
	saveSlogDefault(t)
	cmd := &StartCmd{
		Execute: func(_ *StartCmd, _ *StartHooks) error {
			return fmt.Errorf("execute failed")
		},
	}
	err := cmd.Run(&Globals{})
	assert.EqualError(t, err, "execute failed")
}

// --- LoggerShutdown behavior ---

func TestStartCmd_LoggerShutdown_CallsHookShutdown(t *testing.T) {
	saveSlogDefault(t)
	shutdownCalled := false
	hooks := &StartHooks{
		InitLogger: func(_ context.Context, _ string, _ bool) (slog.Handler, func(context.Context) error, error) {
			return testTextHandler(), func(context.Context) error {
				shutdownCalled = true
				return nil
			}, nil
		},
	}
	cmd := &StartCmd{Execute: noopExecute, Hooks: hooks}
	require.NoError(t, cmd.Run(&Globals{}))
	require.NotNil(t, cmd.LoggerShutdown)

	err := cmd.LoggerShutdown(context.Background())
	require.NoError(t, err)
	assert.True(t, shutdownCalled)
}

func TestStartCmd_LoggerShutdown_RestoresDefaultLogger(t *testing.T) {
	saveSlogDefault(t)
	hooks := &StartHooks{
		InitLogger: func(_ context.Context, _ string, _ bool) (slog.Handler, func(context.Context) error, error) {
			return testTextHandler(), func(context.Context) error { return nil }, nil
		},
	}
	cmd := &StartCmd{Execute: noopExecute, Hooks: hooks}
	require.NoError(t, cmd.Run(&Globals{}))

	// Before shutdown: inner handler is the hook's TextHandler
	_, isText := innerHandler(t, cmd.Logger).(*slog.TextHandler)
	require.True(t, isText)

	require.NoError(t, cmd.LoggerShutdown(context.Background()))

	// After shutdown: inner handler swapped to default JSONHandler
	_, isJSON := innerHandler(t, cmd.Logger).(*slog.JSONHandler)
	assert.True(t, isJSON, "expected inner *slog.JSONHandler after shutdown, got %T", innerHandler(t, cmd.Logger))
}

func TestStartCmd_LoggerShutdown_RestoresGithubActionLogger(t *testing.T) {
	saveSlogDefault(t)
	hooks := &StartHooks{
		InitLogger: func(_ context.Context, _ string, _ bool) (slog.Handler, func(context.Context) error, error) {
			return testTextHandler(), func(context.Context) error { return nil }, nil
		},
	}
	cmd := &StartCmd{Execute: noopExecute, Hooks: hooks, GithubAction: true}
	require.NoError(t, cmd.Run(&Globals{}))

	require.NoError(t, cmd.LoggerShutdown(context.Background()))

	_, isGHA := innerHandler(t, cmd.Logger).(*GitHubActionsHandler)
	assert.True(t, isGHA, "expected inner *GitHubActionsHandler after shutdown, got %T", innerHandler(t, cmd.Logger))
}

func TestStartCmd_LoggerShutdown_PropagatesError(t *testing.T) {
	saveSlogDefault(t)
	hooks := &StartHooks{
		InitLogger: func(_ context.Context, _ string, _ bool) (slog.Handler, func(context.Context) error, error) {
			return testTextHandler(), func(context.Context) error {
				return fmt.Errorf("flush failed")
			}, nil
		},
	}
	cmd := &StartCmd{Execute: noopExecute, Hooks: hooks}
	require.NoError(t, cmd.Run(&Globals{}))

	err := cmd.LoggerShutdown(context.Background())
	assert.EqualError(t, err, "flush failed")

	// Inner handler should still be restored despite the error
	_, isJSON := innerHandler(t, cmd.Logger).(*slog.JSONHandler)
	assert.True(t, isJSON, "inner handler should be restored even when shutdown returns an error")
}

// --- Edge cases ---

func TestStartCmd_Run_NilHooks(t *testing.T) {
	saveSlogDefault(t)
	cmd := &StartCmd{Execute: noopExecute, Hooks: nil}
	err := cmd.Run(&Globals{})
	require.NoError(t, err)
	assert.Nil(t, cmd.LoggerShutdown)
}

func TestStartCmd_Run_HooksWithNilInitLogger(t *testing.T) {
	saveSlogDefault(t)
	cmd := &StartCmd{Execute: noopExecute, Hooks: &StartHooks{}}
	err := cmd.Run(&Globals{})
	require.NoError(t, err)
	assert.Nil(t, cmd.LoggerShutdown)
	_, isJSON := cmd.Logger.Handler().(*slog.JSONHandler)
	assert.True(t, isJSON)
}
