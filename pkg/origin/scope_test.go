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

package origin

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestScopeStatSlotsMatchKernel pins podScope's stat slots to
// SCOPE_STAT_* in scopebpf.c: a drift would report one shortfall as
// another, or read past the map.
func TestScopeStatSlotsMatchKernel(t *testing.T) {
	src, err := os.ReadFile("../../bpf/scopebpf.c")
	require.NoError(t, err)
	for name, want := range map[string]uint64{
		"SCOPE_STAT_FULL":   scopeStatFull,
		"SCOPE_STAT_ROOT":   scopeStatRoot,
		"SCOPE_STAT_FAILED": scopeStatFailed,
		"SCOPE_STATS_MAX":   scopeStatsMax,
	} {
		m := regexp.MustCompile(`(?m)^#define ` + name + `\s+(\d+)\b`).FindSubmatch(src)
		require.NotNil(t, m, "scopebpf.c must #define %s", name)
		got, err := strconv.ParseUint(string(m[1]), 10, 32)
		require.NoError(t, err)
		require.Equal(t, want, got, "%s drifted between scopebpf.c and pkg/origin", name)
	}
}

// A cgroup is shared when cgroup.threads lists a task as 0, which is how a
// reader's pid namespace numbers a task outside it.
func TestSharedCgroup(t *testing.T) {
	dir := t.TempDir()
	for threads, want := range map[string]bool{
		"":           false,
		"1\n7\n12\n": false,
		"10\n":       false,
		"1\n0\n7\n":  true,
		"0\n":        true,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cgroup.threads"), []byte(threads), 0o644))
		got, err := sharedCgroup(dir)
		require.NoError(t, err)
		require.Equal(t, want, got, "cgroup.threads %q", threads)
	}
	_, err := sharedCgroup(filepath.Join(dir, "gone"))
	require.True(t, errors.Is(err, fs.ErrNotExist), "a removed cgroup: %v", err)
}

// cgroupPaths names every directory under the root by its inode, the
// cgroup id a 64-bit kernel reports.
func TestCgroupPaths(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "kubepods.slice", "pod.slice"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "kubepods.slice", "cgroup.threads"), nil, 0o644))
	paths, err := cgroupPaths(root)
	require.NoError(t, err)
	ino := func(rel string) uint64 {
		fi, err := os.Stat(filepath.Join(root, rel))
		require.NoError(t, err)
		return fi.Sys().(*syscall.Stat_t).Ino
	}
	require.Equal(t, map[uint64]string{
		ino("."):                        "/",
		ino("kubepods.slice"):           "/kubepods.slice",
		ino("kubepods.slice/pod.slice"): "/kubepods.slice/pod.slice",
	}, paths)
}

// The startup walk, run from our own pid namespace as in a pod, records a
// cgroup only our tasks are in and leaves out one that a task outside the
// namespace is in too: there, a task of ours was left in a node daemon's
// cgroup, which recording would judge. The outer test makes that cgroup
// and its foreign task; the inner one runs in a new pid namespace.
func TestPodScopeWalkLeavesSharedCgroups(t *testing.T) {
	requireBPFOrigin(t)
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not available")
	}
	dir := fmt.Sprintf("/sys/fs/cgroup/cargowall-origin-test-%d", os.Getpid())
	shared := filepath.Join(dir, "shared")
	for _, d := range []string{dir, shared, filepath.Join(dir, "own")} {
		require.NoError(t, os.Mkdir(d, 0o755))
	}
	t.Cleanup(func() {
		for _, d := range []string{shared, filepath.Join(dir, "own"), dir} {
			for i := 0; i < 50 && os.Remove(d) != nil; i++ {
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	daemon := exec.Command("sleep", "60")
	require.NoError(t, daemon.Start())
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
	})
	require.NoError(t, os.WriteFile(filepath.Join(shared, "cgroup.procs"), []byte(strconv.Itoa(daemon.Process.Pid)), 0))

	cmd := exec.Command(unshare, "--pid", "--fork", "--mount-proc",
		os.Args[0], "-test.run", "^TestPodScopeWalkInner$", "-test.v")
	cmd.Env = append(os.Environ(), "CARGOWALL_SCOPE_TEST_CGROUPS="+dir)
	out, err := cmd.CombinedOutput()
	t.Logf("inside pid namespace:\n%s", out)
	require.NoError(t, err)
	require.Contains(t, string(out), "--- PASS: TestPodScopeWalkInner")
}

// TestPodScopeWalkInner is TestPodScopeWalkLeavesSharedCgroups' half in a
// pid namespace of its own; on its own it skips.
func TestPodScopeWalkInner(t *testing.T) {
	dir := os.Getenv("CARGOWALL_SCOPE_TEST_CGROUPS")
	if dir == "" {
		t.Skip("run by TestPodScopeWalkLeavesSharedCgroups")
	}
	requireBPFOrigin(t)
	ours := func(cgroup string) {
		c := exec.Command("sleep", "60")
		require.NoError(t, c.Start())
		t.Cleanup(func() {
			_ = c.Process.Kill()
			_ = c.Wait()
		})
		require.NoError(t, os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(c.Process.Pid)), 0))
	}
	shared, own := filepath.Join(dir, "shared"), filepath.Join(dir, "own")
	ours(shared)
	ours(own)

	var log bytes.Buffer
	s, err := startPodScope(slog.New(slog.NewTextHandler(&log, nil)))
	require.NoError(t, err)
	t.Cleanup(s.close)
	recorded := func(path string) bool {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		var v uint8
		return s.cgroups().Lookup(fi.Sys().(*syscall.Stat_t).Ino, &v) == nil
	}
	require.True(t, recorded(own), "a cgroup only our tasks are in")
	require.False(t, recorded(shared), "a cgroup a task outside our pid namespace is in too")
	require.Contains(t, log.String(), strings.TrimPrefix(shared, cgroupRoot), "the cgroup left out is reported")
}
