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

package network

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestDaemonConfig points a daemonConfig at a temp dir and counts reloads.
func newTestDaemonConfig(t *testing.T) (daemonConfig, *int) {
	t.Helper()
	dir := t.TempDir()
	reloads := 0
	return daemonConfig{
		path:   filepath.Join(dir, "daemon.json"),
		backup: filepath.Join(dir, "daemon.json.cargowall.bak"),
		absent: filepath.Join(dir, "daemon.json.cargowall.absent"),
		reload: func(*slog.Logger) error { reloads++; return nil },
	}, &reloads
}

func readDaemonJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(data, &cfg))
	return cfg
}

func requireNotExist(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist, path)
}

func TestDaemonConfig_RewritesAndRestoresOriginal(t *testing.T) {
	c, reloads := newTestDaemonConfig(t)
	original := []byte(`{"log-driver": "json-file", "dns": ["8.8.8.8"]}`)
	require.NoError(t, os.WriteFile(c.path, original, 0o644))

	require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
	cfg := readDaemonJSON(t, c.path)
	require.Equal(t, []any{"172.17.0.1"}, cfg["dns"])
	require.Equal(t, "json-file", cfg["log-driver"], "other settings survive the rewrite")

	require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
	got, err := os.ReadFile(c.path)
	require.NoError(t, err)
	require.Equal(t, original, got)
	requireNotExist(t, c.backup)
	require.Equal(t, 1, *reloads)
}

func TestDaemonConfig_NoOriginalIsRemovedOnRestore(t *testing.T) {
	c, _ := newTestDaemonConfig(t)

	require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
	require.Equal(t, []any{"172.17.0.1"}, readDaemonJSON(t, c.path)["dns"])

	require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
	requireNotExist(t, c.path)
	requireNotExist(t, c.absent)
}

// The undo is registered before the rewrite, so it runs when a signal lands
// before configure, or after configure failed: with nothing recorded it must
// leave the operator's daemon.json alone, not delete it.
func TestDaemonConfig_RestoreWithoutRewriteLeavesFileAlone(t *testing.T) {
	c, reloads := newTestDaemonConfig(t)
	original := []byte(`{"log-driver": "json-file"}`)
	require.NoError(t, os.WriteFile(c.path, original, 0o644))

	require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
	got, err := os.ReadFile(c.path)
	require.NoError(t, err)
	require.Equal(t, original, got)
	require.Zero(t, *reloads)
}

// A run that dies without restoring leaves its rewrite and its record. The
// next run must restore from that record, not back up the rewrite as if it
// were the original.
func TestDaemonConfig_RecoversRewriteLeftByUncleanExit(t *testing.T) {
	t.Run("original existed", func(t *testing.T) {
		c, _ := newTestDaemonConfig(t)
		original := []byte(`{"log-driver": "json-file"}`)
		require.NoError(t, os.WriteFile(c.path, original, 0o644))

		require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
		// No restore: the first run was killed.
		require.NoError(t, c.configure("172.18.0.1", slog.New(slog.DiscardHandler)))
		require.Equal(t, []any{"172.18.0.1"}, readDaemonJSON(t, c.path)["dns"])

		require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
		got, err := os.ReadFile(c.path)
		require.NoError(t, err)
		require.Equal(t, original, got)
	})
	t.Run("no original", func(t *testing.T) {
		c, _ := newTestDaemonConfig(t)

		require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
		require.NoError(t, c.configure("172.18.0.1", slog.New(slog.DiscardHandler)))

		require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
		requireNotExist(t, c.path)
		requireNotExist(t, c.backup)
	})
}

// Without a record of the original there is nothing to restore from, so a
// failed backup must stop the rewrite rather than log and carry on.
func TestDaemonConfig_BackupFailureLeavesOriginalUntouched(t *testing.T) {
	c, _ := newTestDaemonConfig(t)
	c.backup = filepath.Join(t.TempDir(), "missing-dir", "daemon.json.cargowall.bak")
	original := []byte(`{"log-driver": "json-file"}`)
	require.NoError(t, os.WriteFile(c.path, original, 0o644))

	require.Error(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
	require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
	got, err := os.ReadFile(c.path)
	require.NoError(t, err)
	require.Equal(t, original, got)
}

func TestDaemonConfig_UnparsableOriginalIsRestoredVerbatim(t *testing.T) {
	for name, original := range map[string][]byte{
		"syntax error": []byte(`{"log-driver": `),
		"JSON null":    []byte(`null`),
		"JSON array":   []byte(`["not", "an", "object"]`),
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestDaemonConfig(t)
			require.NoError(t, os.WriteFile(c.path, original, 0o644))

			require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
			require.Equal(t, []any{"172.17.0.1"}, readDaemonJSON(t, c.path)["dns"])

			require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
			got, err := os.ReadFile(c.path)
			require.NoError(t, err)
			require.Equal(t, original, got)
		})
	}
}
