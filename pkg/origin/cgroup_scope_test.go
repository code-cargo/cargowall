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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

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

// A cgroup removed during the walk is skipped, not an error: its files are
// missing, or, opened before the removal, read ENODEV.
func TestCgroupGone(t *testing.T) {
	for err, want := range map[error]bool{
		&fs.PathError{Op: "open", Path: "x", Err: syscall.ENOENT}: true,
		&fs.PathError{Op: "read", Path: "x", Err: syscall.ENODEV}: true,
		&fs.PathError{Op: "open", Path: "x", Err: syscall.EACCES}: false,
		nil: false,
	} {
		require.Equal(t, want, cgroupGone(err), "%v", err)
	}
}

func TestUnder(t *testing.T) {
	const pod = "/kubepods.slice/kubepods-pod1.slice"
	require.True(t, under(pod, pod))
	require.True(t, under(pod+"/cri-containerd-a.scope", pod))
	require.False(t, under(pod+"x/cri-containerd-a.scope", pod), "a sibling whose name extends the pod's")
	require.False(t, under("/docker/a", pod))
	require.False(t, under(pod, ""), "no pod cgroup covers nothing")
}

// The startup walk, run from our own pid namespace as in a pod, records a
// cgroup only our tasks are in, whatever its name, and leaves out one that
// a task outside the namespace is in too: there, a task of ours was left
// in a node daemon's cgroup, which recording would judge. A cgroup under
// the pod's is left out silently, shared or not: the hook judges it as the
// pod's. The outer test makes the cgroups and the foreign tasks; the inner
// one runs in a new pid namespace.
func TestPodScopeWalkLeavesSharedCgroups(t *testing.T) {
	requireBPFOrigin(t)
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not available")
	}
	dir := fmt.Sprintf("/sys/fs/cgroup/cargowall-origin-test-%d", os.Getpid())
	pod := filepath.Join(dir, "pod")
	cgroups := []string{dir, filepath.Join(dir, "shared"), filepath.Join(dir, ".own"), pod, filepath.Join(pod, "shared")}
	for _, d := range cgroups {
		require.NoError(t, os.Mkdir(d, 0o755))
	}
	t.Cleanup(func() {
		for i := len(cgroups) - 1; i >= 0; i-- {
			for j := 0; j < 50 && os.Remove(cgroups[i]) != nil; j++ {
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	for _, cg := range []string{filepath.Join(dir, "shared"), filepath.Join(pod, "shared")} {
		daemon := exec.Command("sleep", "60")
		require.NoError(t, daemon.Start())
		t.Cleanup(func() {
			_ = daemon.Process.Kill()
			_ = daemon.Wait()
		})
		require.NoError(t, os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(daemon.Process.Pid)), 0))
	}

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
	shared, own := filepath.Join(dir, "shared"), filepath.Join(dir, ".own")
	pod := filepath.Join(dir, "pod")
	for _, cg := range []string{shared, own, filepath.Join(pod, "shared")} {
		c := exec.Command("sleep", "60")
		require.NoError(t, c.Start())
		t.Cleanup(func() {
			_ = c.Process.Kill()
			_ = c.Wait()
		})
		require.NoError(t, os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(c.Process.Pid)), 0))
	}

	var log bytes.Buffer
	sub, err := subtreeOf(strings.TrimPrefix(pod, podenv.CgroupRoot))
	require.NoError(t, err)
	s, err := startCgroupScope(slog.New(slog.NewTextHandler(&log, nil)), sub)
	require.NoError(t, err)
	t.Cleanup(s.close)
	idOf := func(path string) uint64 {
		id, err := podenv.CgroupID(strings.TrimPrefix(path, podenv.CgroupRoot))
		require.NoError(t, err)
		return id
	}
	recorded := func(path string) bool {
		var v uint8
		return s.cgroups().Lookup(idOf(path), &v) == nil
	}
	require.True(t, recorded(own), "a cgroup only our tasks are in, its name starting with a dot")
	require.False(t, recorded(shared), "a cgroup a task outside our pid namespace is in too")
	require.Contains(t, log.String(), strings.TrimPrefix(shared, podenv.CgroupRoot), "the cgroup left out is reported")
	require.False(t, recorded(filepath.Join(pod, "shared")), "a cgroup under the pod's is the hook's to judge")
	require.NotContains(t, log.String(), strings.TrimPrefix(filepath.Join(pod, "shared"), podenv.CgroupRoot),
		"and is not reported: its sockets do not pass")

	// A cgroup a task outside the namespace entered between the walk's look
	// and the record is taken out again by the second look, also when a
	// tracepoint had already made the entry.
	sharedRel := strings.TrimPrefix(shared, podenv.CgroupRoot)
	s.record(idOf(shared), sharedRel)
	require.False(t, recorded(shared), "a cgroup found shared once recorded is taken out")
	require.NoError(t, s.cgroups().Put(idOf(shared), uint8(1)))
	s.record(idOf(shared), sharedRel)
	require.False(t, recorded(shared), "and one a tracepoint recorded first")

	// A walk that finds a cgroup shared takes out an entry a tracepoint made
	// for it while the walk ran.
	require.NoError(t, s.cgroups().Put(idOf(shared), uint8(1)))
	require.NoError(t, s.walk(sub.path))
	require.False(t, recorded(shared), "the walk takes a shared cgroup out")
}

// loadWalkScope loads the scope collection for the pid namespace ino with a
// map of maxEntries, unattached, for the walk alone.
func loadWalkScope(t *testing.T, ino, maxEntries uint32) *cgroupScope {
	t.Helper()
	requireBPFOrigin(t)
	spec, err := bpf.LoadScopeBpf()
	require.NoError(t, err)
	require.NoError(t, spec.Variables[bpf.ScopeBpfVarPidnsIno].Set(ino))
	spec.Maps[bpf.ScopeBpfMapMapScopeCgroups].MaxEntries = maxEntries
	var log bytes.Buffer
	s := &cgroupScope{logger: slog.New(slog.NewTextHandler(&log, nil))}
	require.NoError(t, spec.LoadAndAssign(&s.objs, nil))
	t.Cleanup(s.release)
	return s
}

// A walk that lists no task of ours (here, of a pid namespace no task is
// in) fails rather than leave the scope empty under a hook that reports
// itself attached.
func TestPodScopeWalkNeedsOwnCgroup(t *testing.T) {
	s := loadWalkScope(t, 1, 64)
	require.ErrorContains(t, s.walk(""), "did not list this process's cgroup")
}

// A map too small for every cgroup the walk records costs those cgroups,
// with a warning, as in the kernel, and not the scope. From the host pid
// namespace every task on the machine is ours, so the walk finds plenty.
func TestPodScopeWalkFullMapWarns(t *testing.T) {
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	s := loadWalkScope(t, ino, 1)
	var log bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&log, nil))
	require.NoError(t, s.walk(""))
	require.Contains(t, log.String(), "could not record a cgroup")
}
