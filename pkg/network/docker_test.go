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
func newTestDaemonConfig(t *testing.T) (*daemonConfig, *int) {
	t.Helper()
	dir := t.TempDir()
	reloads := 0
	return &daemonConfig{
		path:    filepath.Join(dir, "daemon.json"),
		backup:  filepath.Join(dir, "daemon.json.cargowall.bak"),
		absent:  filepath.Join(dir, "daemon.json.cargowall.absent"),
		rewrite: filepath.Join(dir, "daemon.json.cargowall.rewrite"),
		reload:  func(*slog.Logger) error { reloads++; return nil },
	}, &reloads
}

func requireContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))
}

// setAside lists the backups restore set aside rather than deleted.
func setAside(t *testing.T, c *daemonConfig) []string {
	t.Helper()
	matches, err := filepath.Glob(c.backup + ".unrestored-*")
	require.NoError(t, err)
	return matches
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

// A record only proves what daemon.json held when cargowall rewrote it. A
// file changed since — config management installing one where there was
// none, an operator editing it — is not cargowall's to delete or replace.
func TestDaemonConfig_FileChangedSinceRewriteIsLeftAlone(t *testing.T) {
	installed := []byte(`{"registry-mirrors": ["https://mirror.example"]}`)

	t.Run("installed where there was none, then a new run", func(t *testing.T) {
		c, _ := newTestDaemonConfig(t)
		require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
		// The run is killed; config management installs a real file.
		require.NoError(t, os.WriteFile(c.path, installed, 0o644))

		require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
		require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
		requireContent(t, c.path, installed)
	})
	t.Run("edited after the rewrite, then restored", func(t *testing.T) {
		c, reloads := newTestDaemonConfig(t)
		original := []byte(`{"log-driver": "json-file"}`)
		require.NoError(t, os.WriteFile(c.path, original, 0o644))
		require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
		require.NoError(t, os.WriteFile(c.path, installed, 0o644))

		require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
		requireContent(t, c.path, installed)
		require.Zero(t, *reloads)
		aside := setAside(t, c)
		require.Len(t, aside, 1, "the pre-cargowall original is kept, not deleted")
		requireContent(t, aside[0], original)
		requireNotExist(t, c.backup)
		requireNotExist(t, c.rewrite)
	})
	// A backup left without a rewrite record (a run killed before the
	// rewrite landed, or an older build's) cannot be matched to the file.
	t.Run("backup without a rewrite record", func(t *testing.T) {
		c, _ := newTestDaemonConfig(t)
		require.NoError(t, os.WriteFile(c.path, installed, 0o644))
		require.NoError(t, os.WriteFile(c.backup, []byte(`{"old": true}`), 0o600))

		require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
		requireContent(t, c.path, installed)
		require.Len(t, setAside(t, c), 1)
	})
	t.Run("killed before the rewrite landed", func(t *testing.T) {
		c, _ := newTestDaemonConfig(t)
		original := []byte(`{"log-driver": "json-file"}`)
		require.NoError(t, os.WriteFile(c.path, original, 0o644))
		require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
		require.NoError(t, os.WriteFile(c.path, original, 0o644)) // as if the rename never ran

		require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
		requireContent(t, c.path, original)
		require.Empty(t, setAside(t, c), "a backup equal to the file is simply dropped")
		requireNotExist(t, c.backup)
	})
}

// A daemon.json that is a symlink into managed config, or kept 0600, must
// come back that way: the rename lands on the target and carries the mode.
func TestDaemonConfig_KeepsSymlinkAndMode(t *testing.T) {
	c, _ := newTestDaemonConfig(t)
	managed := filepath.Join(t.TempDir(), "managed-daemon.json")
	original := []byte(`{"log-driver": "json-file"}`)
	require.NoError(t, os.WriteFile(managed, original, 0o600))
	require.NoError(t, os.Symlink(managed, c.path))

	check := func(when string) {
		fi, err := os.Lstat(c.path)
		require.NoError(t, err)
		require.Equal(t, os.ModeSymlink, fi.Mode()&os.ModeSymlink, "%s: daemon.json is still the symlink", when)
		fi, err = os.Stat(managed)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "%s: the target keeps its mode", when)
	}

	require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
	check("after the rewrite")
	require.Equal(t, []any{"172.17.0.1"}, readDaemonJSON(t, managed)["dns"])

	require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
	check("after the restore")
	requireContent(t, managed, original)
}

// The undo is registered before configure and a second signal runs it on
// another goroutine. Whichever gets there first, the original survives: a
// restore first leaves configure refused, a configure first is undone.
func TestDaemonConfig_ConcurrentRestoreKeepsOriginal(t *testing.T) {
	original := []byte(`{"log-driver": "json-file"}`)
	for range 50 {
		c, _ := newTestDaemonConfig(t)
		require.NoError(t, os.WriteFile(c.path, original, 0o644))

		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = c.restore(slog.New(slog.DiscardHandler))
		}()
		_ = c.configure("172.17.0.1", slog.New(slog.DiscardHandler))
		<-done
		requireContent(t, c.path, original)
	}
}

func TestDaemonConfig_ConfigureAfterRestoreRefused(t *testing.T) {
	c, _ := newTestDaemonConfig(t)
	original := []byte(`{"log-driver": "json-file"}`)
	require.NoError(t, os.WriteFile(c.path, original, 0o644))

	require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
	require.Error(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
	requireContent(t, c.path, original)
	requireNotExist(t, c.backup)
}
