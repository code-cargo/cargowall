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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redirectStateFiles points the effective-mode, downgrade, postures and
// Docker state files at tempdir paths for the duration of the test,
// restoring the real paths on cleanup.
func redirectStateFiles(t *testing.T) (modePath, downgradePath string) {
	t.Helper()
	oldMode, oldDowngrade, oldPostures, oldDocker := modeFile, downgradeFile, posturesFile, dockerFile
	dir := t.TempDir()
	modeFile = filepath.Join(dir, "cargowall-mode")
	downgradeFile = filepath.Join(dir, "cargowall-downgrade")
	posturesFile = filepath.Join(dir, "cargowall-postures")
	dockerFile = filepath.Join(dir, "cargowall-docker")
	t.Cleanup(func() {
		modeFile, downgradeFile, posturesFile, dockerFile = oldMode, oldDowngrade, oldPostures, oldDocker
	})
	return modeFile, downgradeFile
}

// TestWriteSentinel_AtomicReplaceIsSymlinkSafe: sentinels are written as
// root to fixed paths in world-writable /tmp. The temp-file+rename publish
// must replace a pre-planted symlink (or plain file) at the path itself
// without ever following it — the planted target's content stays untouched —
// and must leave no temp litter behind.
func TestWriteSentinel_AtomicReplaceIsSymlinkSafe(t *testing.T) {
	dir := t.TempDir()

	// Pre-planted plain file: replaced, not followed or refused.
	existing := filepath.Join(dir, "existing")
	require.NoError(t, os.WriteFile(existing, []byte("planted"), 0o644))
	require.NoError(t, writeSentinel(existing, []byte("new")))
	data, err := os.ReadFile(existing)
	require.NoError(t, err)
	assert.Equal(t, "new", string(data))

	// Pre-planted symlink: the LINK is replaced by a regular file; the
	// target an attacker chose is never written through.
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("victim"), 0o644))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	require.NoError(t, writeSentinel(link, []byte("ok")))
	data, err = os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "victim", string(data), "symlink target must not be written through")
	fi, err := os.Lstat(link)
	require.NoError(t, err)
	assert.True(t, fi.Mode().IsRegular(), "path must now be a regular file, not the symlink")
	data, err = os.ReadFile(link)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(data))

	// No temp files left behind.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.ElementsMatch(t, []string{"existing", "target", "link"}, names)
}

// The pid stamped into a sentinel identifies its run exactly — a leftover
// pidfile from a SIGKILLed run cannot legitimize that run's sentinel, which
// mtime-only anchoring could not prevent.
func TestWriteFailureSentinel_StampsPidAndSanitizes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failed")
	require.NoError(t, writeFailureSentinel(path, "boom\n::error::injected", ""))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	first, rest, _ := strings.Cut(string(data), "\n")
	assert.Equal(t, fmt.Sprintf("pid=%d", os.Getpid()), first)
	assert.NotContains(t, rest, "\n::error::", "control characters must be stripped from the reason")
	assert.Contains(t, rest, "::error::injected", "the text itself is kept, just never at a line start")
}

// A refused posture rides the sentinel the action already reads, on a line
// of its own after the pid stamp, so it cannot be lost to a second write.
// The readers' reason leaves it out.
func TestWriteFailureSentinel_NamesRefusedPosture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failed")
	lost := errors.New("--container-egress=enforce requested but could not be applied: x")
	publishStartupFailure(path, lost, postureContainerEgress, quietLogger())
	reason := "cargowall startup failed: " + lost.Error()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("pid=%d\nrefused=container-egress\n%s\n", os.Getpid(), reason), string(data))
	pid, ok := sentinelPid(data)
	assert.True(t, ok)
	assert.Equal(t, os.Getpid(), pid)
	assert.Equal(t, reason, sentinelReason(data))

	publishStartupFailure(path, errors.New("no eBPF"), "", quietLogger())
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "refused=", "any other failure names no posture")
}
