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
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestDaemonConfig points a daemonConfig at a temp dir and records, for
// each daemon restart, what daemon.json held as it ran ("" for no file): what
// the daemon came up on. A queued restart is recorded as queued(...).
func newTestDaemonConfig(t *testing.T) (*daemonConfig, *[]string) {
	t.Helper()
	dir := t.TempDir()
	var (
		mu       sync.Mutex
		restarts []string
	)
	c := &daemonConfig{
		path:    filepath.Join(dir, "daemon.json"),
		backup:  filepath.Join(dir, "daemon.json.cargowall.bak"),
		absent:  filepath.Join(dir, "daemon.json.cargowall.absent"),
		rewrite: filepath.Join(dir, "daemon.json.cargowall.rewrite"),
	}
	record := func(wrap func(string) string) func(*slog.Logger) error {
		return func(*slog.Logger) error {
			mu.Lock()
			defer mu.Unlock()
			data, _ := os.ReadFile(c.path)
			restarts = append(restarts, wrap(string(data)))
			return nil
		}
	}
	c.restart = record(func(s string) string { return s })
	c.queueRestart = record(queued)
	return c, &restarts
}

func queued(daemonJSON string) string { return "queued(" + daemonJSON + ")" }

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
	c, restarts := newTestDaemonConfig(t)
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
	require.Empty(t, *restarts, "a daemon never restarted onto the rewrite is left alone")
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
	c, restarts := newTestDaemonConfig(t)
	original := []byte(`{"log-driver": "json-file"}`)
	require.NoError(t, os.WriteFile(c.path, original, 0o644))

	require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
	got, err := os.ReadFile(c.path)
	require.NoError(t, err)
	require.Equal(t, original, got)
	require.Empty(t, *restarts)
}

// A daemon restarted onto the rewrite points its containers at the listener
// until it restarts again, so restore queues a restart onto the original: a
// reload leaves it handing them an empty nameserver. That holds when the restart
// onto the rewrite failed too, since a failed or timed-out restart may still
// have applied it. A daemon only ever restarted onto the original still runs
// its own settings, and restore leaves it alone.
func TestDaemonConfig_RestoreRestartsADaemonOnTheRewrite(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	original := `{"log-driver": "json-file"}`
	for _, c := range []struct {
		name     string
		original string // "" for no daemon.json
		fail     bool   // the restart onto the rewrite reports failure
	}{
		{"original existed", original, false},
		{"no original", "", false},
		{"restart onto the rewrite failed", original, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dc, restarts := newTestDaemonConfig(t)
			if c.original != "" {
				require.NoError(t, os.WriteFile(dc.path, []byte(c.original), 0o644))
			}
			require.NoError(t, dc.configure("169.254.0.53", logger))
			rewrite, err := os.ReadFile(dc.path)
			require.NoError(t, err)
			if c.fail {
				restart := dc.restart
				dc.restart = func(l *slog.Logger) error {
					_ = restart(l)
					return errors.New("timeout waiting for Docker daemon to be ready after restart")
				}
			}

			err = dc.restartDaemon(logger)
			if c.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, dc.restore(logger))
			require.Equal(t, []string{string(rewrite), queued(c.original)}, *restarts,
				"the daemon comes up on the rewrite, then on the original")
		})
	}

	t.Run("restarted only onto the original", func(t *testing.T) {
		dc, restarts := newTestDaemonConfig(t)
		require.NoError(t, os.WriteFile(dc.path, []byte(original), 0o644))
		require.NoError(t, dc.configure("169.254.0.53", logger))
		recovered, err := dc.recover(logger) // a killed run's leftover, undone
		require.NoError(t, err)
		require.True(t, recovered)
		require.NoError(t, dc.restartDaemon(logger))
		require.NoError(t, dc.configure("169.254.0.53", logger))

		require.NoError(t, dc.restore(logger))
		requireContent(t, dc.path, []byte(original))
		require.Equal(t, []string{original}, *restarts, "no restart is due for a daemon that never ran the rewrite")
	})
}

// A second signal's teardown runs inside a short bound, so restore must not
// wait on startup's restart, which can take most of a minute: it puts the
// original back and queues its own restart while that one still runs.
func TestDaemonConfig_RestoreDoesNotWaitOnARunningRestart(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	c, restarts := newTestDaemonConfig(t)
	original := `{"log-driver": "json-file"}`
	require.NoError(t, os.WriteFile(c.path, []byte(original), 0o644))
	require.NoError(t, c.configure("169.254.0.53", logger))
	rewrite, err := os.ReadFile(c.path)
	require.NoError(t, err)

	running, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	restart := c.restart
	c.restart = func(l *slog.Logger) error {
		err := restart(l)
		close(running)
		<-release
		return err
	}
	go func() {
		defer close(finished)
		_ = c.restartDaemon(logger)
	}()
	<-running

	restored := make(chan error, 1)
	go func() { restored <- c.restore(logger) }()
	select {
	case err := <-restored:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("restore waited on the running restart")
	}
	close(release)
	<-finished
	requireContent(t, c.path, []byte(original))
	require.Equal(t, []string{string(rewrite), queued(original)}, *restarts)
}

// The restart onto the rewrite runs in startup, and a second signal can run
// the restore on another goroutine meanwhile. Whichever gets there first, the
// daemon comes up last on the original: a restore first leaves the restart
// applying the original, and a restart first is followed by restore's own.
// (systemd re-runs a restart that is still running when another is queued.)
func TestDaemonConfig_ConcurrentRestartAndRestoreEndOnOriginal(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	original := `{"log-driver": "json-file"}`
	for range 50 {
		c, restarts := newTestDaemonConfig(t)
		require.NoError(t, os.WriteFile(c.path, []byte(original), 0o644))
		require.NoError(t, c.configure("169.254.0.53", logger))

		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = c.restore(logger)
		}()
		_ = c.restartDaemon(logger)
		<-done
		requireContent(t, c.path, []byte(original))
		require.NotEmpty(t, *restarts)
		last := (*restarts)[len(*restarts)-1]
		require.Contains(t, []string{original, queued(original)}, last)
	}
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

// recover undoes the rewrite a killed run left and writes none of its own,
// so a run that will not point the daemon at its listener still puts the
// original back. It says whether there was a rewrite to undo, leaves a
// daemon.json with no record of ours alone, and restarts nothing: the
// caller's restart applies the original to a daemon started on the rewrite.
func TestDaemonConfig_RecoverUndoesOnlyALeftover(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for _, c := range []struct {
		name     string
		original []byte
	}{{"original existed", []byte(`{"log-driver": "json-file"}`)}, {"no original", nil}} {
		t.Run(c.name, func(t *testing.T) {
			dc, restarts := newTestDaemonConfig(t)
			if c.original != nil {
				require.NoError(t, os.WriteFile(dc.path, c.original, 0o644))
			}
			require.NoError(t, dc.configure("172.17.0.1", logger))
			// No restore: that run was killed.

			recovered, err := dc.recover(logger)
			require.NoError(t, err)
			require.True(t, recovered)
			if c.original != nil {
				requireContent(t, dc.path, c.original)
			} else {
				requireNotExist(t, dc.path)
			}
			for _, record := range []string{dc.backup, dc.absent, dc.rewrite} {
				requireNotExist(t, record)
			}
			require.Empty(t, *restarts)

			recovered, err = dc.recover(logger)
			require.NoError(t, err)
			require.False(t, recovered, "a rewrite is undone once")
		})
	}

	dc, _ := newTestDaemonConfig(t)
	mine := []byte(`{"dns": ["10.0.0.2"]}`)
	require.NoError(t, os.WriteFile(dc.path, mine, 0o644))
	recovered, err := dc.recover(logger)
	require.NoError(t, err)
	require.False(t, recovered)
	requireContent(t, dc.path, mine)
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
		c, restarts := newTestDaemonConfig(t)
		original := []byte(`{"log-driver": "json-file"}`)
		require.NoError(t, os.WriteFile(c.path, original, 0o644))
		require.NoError(t, c.configure("172.17.0.1", slog.New(slog.DiscardHandler)))
		require.NoError(t, os.WriteFile(c.path, installed, 0o644))

		require.NoError(t, c.restore(slog.New(slog.DiscardHandler)))
		requireContent(t, c.path, installed)
		require.Empty(t, *restarts)
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

// daemon.json's "dns" as the daemon reads it: none without a file or the
// key, the servers with them, and an error for a file it cannot parse.
func TestDockerDNSServers(t *testing.T) {
	c, _ := newTestDaemonConfig(t)
	got, err := c.dnsServers()
	require.NoError(t, err)
	require.Nil(t, got, "no daemon.json sets no DNS")

	require.NoError(t, os.WriteFile(c.path, []byte(`{"log-level": "warn"}`), 0o644))
	got, err = c.dnsServers()
	require.NoError(t, err)
	require.Nil(t, got)

	require.NoError(t, os.WriteFile(c.path, []byte(`{"dns": ["169.254.0.53", "8.8.8.8"]}`), 0o644))
	got, err = c.dnsServers()
	require.NoError(t, err)
	require.Equal(t, []string{"169.254.0.53", "8.8.8.8"}, got)

	require.NoError(t, os.WriteFile(c.path, []byte(`{"dns": `), 0o644))
	_, err = c.dnsServers()
	require.ErrorContains(t, err, c.path)
}

// A bridge's subnet is its first IPv4 address's network, masked; one that
// is not there names itself.
func TestBridgeSubnet(t *testing.T) {
	subnet, err := BridgeSubnet("lo")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("127.0.0.0/8"), subnet)
	_, err = BridgeSubnet("br-ffffffffffff")
	require.ErrorContains(t, err, "br-ffffffffffff interface not found")
}
