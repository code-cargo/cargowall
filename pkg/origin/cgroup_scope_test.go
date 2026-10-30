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
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// cgroup.threads lists a task outside the reader's pid namespace as 0, and
// each of the namespace's by its id there.
func TestCgroupMembers(t *testing.T) {
	tmp := t.TempDir()
	open := func(path string) *os.File {
		dir, err := os.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { dir.Close() })
		return dir
	}
	dir := open(tmp)
	for threads, want := range map[string]members{
		"":           {},
		"1\n7\n12\n": {ours: true},
		"10\n":       {ours: true},
		"1\n0\n7\n":  {ours: true, theirs: true},
		"0\n":        {theirs: true},
	} {
		require.NoError(t, os.WriteFile(filepath.Join(tmp, "cgroup.threads"), []byte(threads), 0o644))
		got, err := cgroupMembers(dir)
		require.NoError(t, err)
		require.Equal(t, want, got, "cgroup.threads %q", threads)
	}
	gone := filepath.Join(tmp, "gone")
	require.NoError(t, os.Mkdir(gone, 0o755))
	goneDir := open(gone)
	_, err := cgroupMembers(goneDir)
	require.True(t, cgroupGone(err), "a cgroup with no cgroup.threads reads as removed: %v", err)
}

// A cgroup removed during the walk is skipped, not an error: its handle is
// stale, its files are missing, or, opened before the removal, read ENODEV.
func TestCgroupGone(t *testing.T) {
	for err, want := range map[error]bool{
		fmt.Errorf("open cgroup 7 by its id: %w", syscall.ESTALE): true,
		&fs.PathError{Op: "open", Path: "x", Err: syscall.ENOENT}: true,
		&fs.PathError{Op: "read", Path: "x", Err: syscall.ENODEV}: true,
		&fs.PathError{Op: "open", Path: "x", Err: syscall.EACCES}: false,
		nil: false,
	} {
		require.Equal(t, want, cgroupGone(err), "%v", err)
	}
}

// The startup walk, run from our own pid namespace as in a pod, records a
// cgroup only our tasks are in, whatever its name, and leaves out one that
// a task outside the namespace is in too: there, a task of ours was left
// in a node daemon's cgroup, which recording would judge. A cgroup under
// the pod's is left out silently, shared or not: the hook judges it as the
// pod's. The outer test makes the cgroups and the foreign tasks; the inner
// one runs in a new pid namespace.
func TestCgroupScopeWalkLeavesSharedCgroups(t *testing.T) {
	requireBPFOrigin(t)
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not available")
	}
	dir := filepath.Join(podenv.CgroupRoot, fmt.Sprintf("cargowall-origin-test-%d", os.Getpid()))
	pod := filepath.Join(dir, "pod")
	cgroups := []string{
		dir, filepath.Join(dir, "shared"), filepath.Join(dir, ".own"), filepath.Join(dir, "theirs"),
		filepath.Join(dir, "gone"), filepath.Join(dir, "late"), pod, filepath.Join(pod, "shared"), filepath.Join(pod, "runner"),
	}
	for _, d := range cgroups {
		require.NoError(t, os.Mkdir(d, 0o755))
	}
	t.Cleanup(func() {
		for i := len(cgroups) - 1; i >= 0; i-- {
			removeTestCgroup(t, cgroups[i])
		}
	})
	for _, cg := range []string{filepath.Join(dir, "shared"), filepath.Join(dir, "theirs"), filepath.Join(pod, "shared")} {
		daemon := exec.Command("sleep", "60")
		require.NoError(t, daemon.Start())
		t.Cleanup(func() {
			_ = daemon.Process.Kill()
			_ = daemon.Wait()
		})
		require.NoError(t, os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(daemon.Process.Pid)), 0))
	}

	cmd := exec.Command(unshare, "--pid", "--fork", "--mount-proc",
		os.Args[0], "-test.run", "^TestCgroupScopeWalkInner$", "-test.v")
	cmd.Env = append(os.Environ(), "CARGOWALL_SCOPE_TEST_CGROUPS="+dir)
	out, err := cmd.CombinedOutput()
	t.Logf("inside pid namespace:\n%s", out)
	require.NoError(t, err)
	require.Contains(t, string(out), "--- PASS: TestCgroupScopeWalkInner")
}

// TestCgroupScopeWalkInner is TestCgroupScopeWalkLeavesSharedCgroups' half in a
// pid namespace of its own; on its own it skips.
func TestCgroupScopeWalkInner(t *testing.T) {
	dir := os.Getenv("CARGOWALL_SCOPE_TEST_CGROUPS")
	if dir == "" {
		t.Skip("run by TestCgroupScopeWalkLeavesSharedCgroups")
	}
	requireBPFOrigin(t)
	shared, own := filepath.Join(dir, "shared"), filepath.Join(dir, ".own")
	pod := filepath.Join(dir, "pod")
	root := podenv.CgroupRoot
	// cargowall runs in the pod, as it does on a runner: its own cgroup is
	// under the subtree, which is where the walk reads the subtree's level.
	require.NoError(t, os.WriteFile(filepath.Join(pod, "runner", "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0))
	for _, cg := range []string{shared, own, filepath.Join(pod, "shared"), root} {
		c := exec.Command("sleep", "60")
		require.NoError(t, c.Start())
		t.Cleanup(func() {
			_ = c.Process.Kill()
			_ = c.Wait()
		})
		require.NoError(t, os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(c.Process.Pid)), 0))
	}

	var log bytes.Buffer
	podRel := strings.TrimPrefix(pod, podenv.CgroupRoot)
	// The test walks by hand; the tick would race it.
	swap(t, &scopeStatsInterval, time.Hour)
	s, err := loadCgroupScope(slog.New(slog.NewTextHandler(&log, nil)), podRel)
	require.NoError(t, err)
	t.Cleanup(s.close)
	require.NoError(t, s.start())
	// In the host cgroup namespace a path's depth is the kernel's level.
	require.Equal(t, podenv.CgroupLevel(podRel), s.sub.level, "the walk read the subtree's level")
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
	// and a new entry is taken out again by the second look.
	sharedRel := strings.TrimPrefix(shared, podenv.CgroupRoot)
	sharedDir, path, inside, err := s.openCgroup(idOf(shared))
	require.NoError(t, err)
	require.True(t, inside)
	require.Equal(t, sharedRel, path, "a cgroup opened by its id is found at its path")
	s.record(idOf(shared), sharedDir, path)
	sharedDir.Close()
	require.False(t, recorded(shared), "a cgroup found shared once recorded is taken out")

	// A walk that finds a cgroup shared takes out an entry a tracepoint made
	// for it.
	require.NoError(t, s.cgroups().Put(idOf(shared), uint8(1)))
	require.NoError(t, s.walk())
	require.False(t, recorded(shared), "the walk takes a shared cgroup out")
	require.Equal(t, 1, strings.Count(log.String(), sharedRel), "and reports it once, not on every walk")

	// A cgroup found shared is marked, so that a task of ours entering it
	// again, however often, is not recorded; once only tasks of ours are in
	// it (here, as the stand-in reads it), the walk clears the mark and
	// records it, and once another is back, takes it out and marks it.
	marked := func(path string) bool {
		var v uint8
		return s.objs.MapScopeShared.Lookup(idOf(path), &v) == nil
	}
	require.True(t, marked(shared), "a cgroup the walk found shared is marked")
	self := []byte(strconv.Itoa(os.Getpid()))
	require.NoError(t, os.WriteFile(filepath.Join(shared, "cgroup.procs"), self, 0))
	require.NoError(t, os.WriteFile(filepath.Join(pod, "runner", "cgroup.procs"), self, 0))
	require.False(t, recorded(shared), "a task of ours entering a marked cgroup does not record it")
	restore := swap(t, &readThreads, func(dir *os.File) ([]byte, error) {
		var st unix.Stat_t
		if unix.Fstat(int(dir.Fd()), &st) == nil && st.Ino == idOf(shared) {
			return []byte("5\n"), nil
		}
		return readThreadsFile(dir)
	})
	require.NoError(t, s.walk())
	restore()
	require.True(t, recorded(shared) && !marked(shared), "a cgroup ours alone again is unmarked and recorded")
	require.NoError(t, s.walk())
	require.True(t, !recorded(shared) && marked(shared), "and shared again, taken out and marked")

	// A cgroup taken out while a task outside the namespace was in it, as a
	// tracepoint does, is recorded again by the next walk once it holds
	// only ours.
	require.NoError(t, s.cgroups().Delete(idOf(own)))
	require.NoError(t, s.walk())
	require.True(t, recorded(own), "a cgroup ours alone again is recorded again")

	// A recorded cgroup that holds no task of ours, only another's, is
	// taken out too, though the walk lists it nowhere: as one a task of
	// ours entered beside the other and has since left. Every walk checks
	// it, and one that cannot read it takes it out and marks it, as whether
	// a task outside is in it is unknown.
	theirs := filepath.Join(dir, "theirs")
	theirsRel := strings.TrimPrefix(theirs, podenv.CgroupRoot)
	require.NoError(t, s.cgroups().Put(idOf(theirs), uint8(1)))
	restore = swap(t, &readThreads, failReading(idOf(theirs), syscall.EIO))
	require.NoError(t, s.walk())
	restore()
	require.False(t, recorded(theirs), "a recorded cgroup the walk cannot read is taken out")
	require.True(t, marked(theirs), "and marked")
	require.Contains(t, log.String(), "cannot read a cgroup")
	require.NoError(t, s.objs.MapScopeShared.Delete(idOf(theirs)))
	require.NoError(t, s.cgroups().Put(idOf(theirs), uint8(1)))
	require.NoError(t, s.walk())
	require.False(t, recorded(theirs), "a recorded cgroup only another task is in")
	var theirsLine string
	for _, line := range strings.Split(log.String(), "\n") {
		if strings.Contains(line, theirsRel) {
			theirsLine = line
		}
	}
	require.Contains(t, theirsLine, "no longer one of this job's", "and it is reported, as holding none of ours")
	require.NotContains(t, theirsLine, "A task of this job is in")
	var v uint8
	require.NoError(t, s.objs.MapScopeShared.Lookup(idOf(theirs), &v), "and marked shared")
	// Its mark is cleared once no task outside is in it (here, as the
	// stand-in reads it), though the walk lists it nowhere: a task of ours
	// entering it then is recorded as it enters.
	restore = swap(t, &readThreads, func(dir *os.File) ([]byte, error) {
		var st unix.Stat_t
		if unix.Fstat(int(dir.Fd()), &st) == nil && st.Ino == idOf(theirs) {
			return nil, nil
		}
		return readThreadsFile(dir)
	})
	require.NoError(t, s.walk())
	restore()
	require.Error(t, s.objs.MapScopeShared.Lookup(idOf(theirs), &v), "a marked cgroup no task outside is in loses its mark")

	// A read of the scope cut short still checks the cgroups it read, and
	// is reported once for each map it fails (both, here), however many
	// walks it fails.
	restore = swap(t, &scopeCgroups, func(*ebpf.Map) ([]uint64, error) {
		return []uint64{idOf(theirs)}, ebpf.ErrIterationAborted
	})
	require.NoError(t, s.cgroups().Put(idOf(theirs), uint8(1)))
	require.NoError(t, s.walk())
	require.NoError(t, s.walk())
	restore()
	require.False(t, recorded(theirs), "a cgroup the cut-short read reached")
	require.Equal(t, 2, strings.Count(log.String(), "could not read all its cgroups"), "reported once a map")

	// A recorded cgroup since removed needs nothing: its release takes it
	// out, and the walk passes it over without a warning, and stops
	// opening it until release has.
	gone := filepath.Join(dir, "gone")
	goneID := idOf(gone)
	require.NoError(t, s.cgroups().Put(goneID, uint8(1)))
	require.NoError(t, os.Remove(gone))
	before := strings.Count(log.String(), "level=WARN")
	require.NoError(t, s.walk())
	require.Equal(t, before, strings.Count(log.String(), "level=WARN"), "a removed cgroup is not reported:\n%s", log.String())
	require.True(t, s.stale[goneID], "and it is not opened again")
	require.NoError(t, s.cgroups().Delete(goneID))
	require.NoError(t, s.walk())
	require.False(t, s.stale[goneID], "until its release has taken it out")

	// A cgroup recorded and then found removed by the second look may
	// have been released already, before the entry: the walk takes out
	// its own entry, which nothing else would.
	late := filepath.Join(dir, "late")
	lateRel := strings.TrimPrefix(late, podenv.CgroupRoot)
	lateDir, latePath, _, err := s.openCgroup(idOf(late))
	require.NoError(t, err)
	defer lateDir.Close()
	restore = swap(t, &readThreads, failReading(idOf(late), syscall.ENOENT))
	s.record(idOf(late), lateDir, latePath)
	restore()
	require.False(t, recorded(late), "an entry for a cgroup removed since the first look")

	// Taking out a cgroup that was never in the scope, with no task of
	// ours left in it, changes nothing and is not reported; one with a
	// task of ours in it is.
	s.leave(idOf(late), lateRel, false, false)
	require.NotContains(t, log.String(), lateRel, "nothing changed")
	s.leave(idOf(late), lateRel, true, false)
	require.Contains(t, log.String(), lateRel, "a task of ours passes the hook there")

	// A task of ours in the root cgroup is reported once, however many
	// walks find it there.
	require.Equal(t, 1, strings.Count(log.String(), "in the root cgroup"), "reported by the first walk")
	require.NoError(t, s.walk())
	require.Equal(t, 1, strings.Count(log.String(), "in the root cgroup"), "and not again")
}

// readThreadsFile is the real readThreads, for stubs that read through it.
var readThreadsFile = readThreads

// swap sets *v to stub until restore, which cleanup runs too, should the
// test stop first.
func swap[T any](t *testing.T, v *T, stub T) (restore func()) {
	saved := *v
	*v = stub
	var once sync.Once
	restore = func() { once.Do(func() { *v = saved }) }
	t.Cleanup(restore)
	return restore
}

// failReading is a readThreads that fails with err for the cgroup id and
// reads every other.
func failReading(id uint64, err error) func(*os.File) ([]byte, error) {
	read := readThreads
	return func(dir *os.File) ([]byte, error) {
		var st unix.Stat_t
		if unix.Fstat(int(dir.Fd()), &st) == nil && st.Ino == id {
			return nil, err
		}
		return read(dir)
	}
}

// The subtree's kernel level is our own cgroup's, less how far below the
// subtree we are: in a nested node's cgroup namespace the paths are the
// namespace's and the levels the machine's.
func TestSubtreeLevel(t *testing.T) {
	const pod = "/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b"
	got, err := subtreeLevel(pod, pod+"/0123abcd", 7)
	require.NoError(t, err)
	require.Equal(t, uint32(6), got, "a node namespace rooted 3 levels down")
	got, err = subtreeLevel(pod, pod, 6)
	require.NoError(t, err)
	require.Equal(t, uint32(6), got)
	_, err = subtreeLevel(pod, "/system.slice/x.scope", 7)
	require.Error(t, err, "our cgroup outside the subtree")
	_, err = subtreeLevel("/a", "/a/b/c", 2)
	require.Error(t, err, "a subtree at or above the root")
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
	spec.Maps[bpf.ScopeBpfMapMapScopeShared].MaxEntries = maxEntries
	require.NoError(t, spec.Variables[bpf.ScopeBpfVarSelfTgid].Set(uint32(os.Getpid())))
	var log bytes.Buffer
	s := &cgroupScope{logger: slog.New(slog.NewTextHandler(&log, nil)), warned: make(map[finding]time.Time), now: time.Now, stale: make(map[uint64]bool)}
	require.NoError(t, spec.LoadAndAssign(&s.objs, nil))
	t.Cleanup(s.release)
	s.mount, err = os.Open(podenv.CgroupRoot)
	require.NoError(t, err)
	s.iter, err = link.AttachIter(link.IterOptions{Program: s.objs.ScopeTaskIter})
	require.NoError(t, err)
	s.links = append(s.links, s.iter)
	return s
}

// removeTestCgroup removes a test cgroup at cleanup, waiting out a task
// still leaving it, and fails the test that leaked it if it stays: a later
// run with the same pid would otherwise fail to make it.
func removeTestCgroup(t *testing.T, path string) {
	t.Helper()
	var err error
	for i := 0; i < 250; i++ {
		if err = os.Remove(path); err == nil || errors.Is(err, fs.ErrNotExist) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("test cgroup %s left behind: %v", path, err)
}

// ownCgroupBelowRoot is the test process's cgroup, and skips the test
// where that is the root, as in a VM with no cgroups of its own: the walk
// reports the root's tasks and records nothing, so a test of recording has
// nothing to look at.
func ownCgroupBelowRoot(t *testing.T) string {
	t.Helper()
	own, err := podenv.ReadCgroupPath("/proc/self/cgroup")
	require.NoError(t, err)
	if own == "/" {
		t.Skip("the test process is in the root cgroup, which the walk never records")
	}
	return own
}

// Loading the scope finds our cgroup and the subtree's level with nothing
// attached but the walk's iterator, which hooks nothing until it is read;
// a scope closed before it starts does not wait for a watch that never
// ran.
func TestCgroupScopeLoadAttachesNothing(t *testing.T) {
	requireBPFOrigin(t)
	own := ownCgroupBelowRoot(t)
	s, err := loadCgroupScope(slog.New(slog.NewTextHandler(io.Discard, nil)), own)
	require.NoError(t, err)
	require.Equal(t, []link.Link{s.iter}, s.links, "only the iterator is attached")
	require.Equal(t, podenv.CgroupLevel(own), s.sub.level, "the subtree's level is read")
	closed := make(chan struct{})
	go func() {
		s.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("closing a scope that never started hangs")
	}
}

// A walk that lists no task of ours (here, of a pid namespace no task is
// in) fails rather than leave the scope empty under a hook that reports
// itself attached.
func TestCgroupScopeWalkNeedsOwnCgroup(t *testing.T) {
	s := loadWalkScope(t, 1, 64)
	require.ErrorContains(t, s.findOwn(), "did not list this process's cgroup")
	// Only at startup: a later walk reconciles whatever it lists, and one
	// fact that has changed since does not stop it.
	require.NoError(t, s.walk())
}

// A cgroup the walk cannot read is reported and passed over, once, and the
// walk still reconciles the rest. From the host pid namespace every task
// on the machine is ours, so the walk lists plenty.
func TestCgroupScopeWalkSkipsUnreadableCgroups(t *testing.T) {
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	s := loadWalkScope(t, ino, 65536)
	var log bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&log, nil))
	own := ownCgroupBelowRoot(t)
	ownID, err := podenv.CgroupID(own)
	require.NoError(t, err)
	swap(t, &readThreads, failReading(ownID, syscall.EIO))
	require.NoError(t, s.walk())
	require.NoError(t, s.walk())
	require.Equal(t, 1, strings.Count(log.String(), "cannot read a cgroup"), "reported once")
	var v uint8
	require.Error(t, s.cgroups().Lookup(ownID, &v), "the unreadable cgroup is left as it was")
	n := 0
	var k uint64
	for it := s.cgroups().Iterate(); it.Next(&k, &v); {
		n++
	}
	require.Positive(t, n, "and the rest are recorded")
}

// A walk stops between cgroups once close has asked, rather than make a
// close wait out the whole walk. From the host pid namespace every task on
// the machine is ours, so there is plenty it would otherwise record.
func TestCgroupScopeWalkStopsOnClose(t *testing.T) {
	ownCgroupBelowRoot(t)
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	s := loadWalkScope(t, ino, 65536)
	s.stop = make(chan struct{})
	close(s.stop)
	require.NoError(t, s.walk())
	ids, err := scopeCgroups(s.cgroups())
	require.NoError(t, err)
	require.Empty(t, ids, "a walk asked to stop records nothing")
}

// A failed walk recovers only once a walk reconciles again: one close cut
// short does not.
func TestCgroupScopeRewalkRecoversOnlyWhole(t *testing.T) {
	ownCgroupBelowRoot(t)
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	s := loadWalkScope(t, ino, 65536)
	var log bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&log, nil))
	s.stop = make(chan struct{})
	close(s.stop)
	require.Equal(t, "earlier", s.rewalk("earlier"))
	require.NotContains(t, log.String(), "recovered", "a walk cut short shows no recovery")
	s.stop = make(chan struct{})
	require.Empty(t, s.rewalk("earlier"))
	require.Contains(t, log.String(), "recovered", "a whole walk does")
}

// In a cgroup namespace rooted below the machine's, a cgroup outside the
// root is beyond the hook, so the walk takes out any entry for it, whether
// it lists the cgroup or only finds it in the scope. The outer test makes
// the cgroups and runs the inner one in a cgroup namespace of its own,
// rooted at a cgroup beside them, with cgroupfs mounted afresh.
func TestCgroupScopeWalkTakesOutCgroupsOutsideTheRoot(t *testing.T) {
	requireBPFOrigin(t)
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not available")
	}
	dir := filepath.Join(podenv.CgroupRoot, fmt.Sprintf("cargowall-origin-outside-%d", os.Getpid()))
	root, listed, empty := filepath.Join(dir, "root"), filepath.Join(dir, "listed"), filepath.Join(dir, "empty")
	cgroups := []string{dir, root, listed, empty}
	for _, d := range cgroups {
		require.NoError(t, os.Mkdir(d, 0o755))
	}
	t.Cleanup(func() {
		for i := len(cgroups) - 1; i >= 0; i-- {
			removeTestCgroup(t, cgroups[i])
		}
	})
	task := exec.Command("sleep", "60")
	require.NoError(t, task.Start())
	t.Cleanup(func() {
		_ = task.Process.Kill()
		_ = task.Wait()
	})
	require.NoError(t, os.WriteFile(filepath.Join(listed, "cgroup.procs"), []byte(strconv.Itoa(task.Process.Pid)), 0))
	idOf := func(path string) uint64 {
		id, err := podenv.CgroupID(strings.TrimPrefix(path, podenv.CgroupRoot))
		require.NoError(t, err)
		return id
	}
	rootDir, err := os.Open(root)
	require.NoError(t, err)
	defer rootDir.Close()
	cmd := exec.Command(unshare, "--cgroup", "--mount", "--propagation", "private", "sh", "-c",
		`umount -l /sys/fs/cgroup && mount -t cgroup2 cgroup2 /sys/fs/cgroup && exec "$0" -test.run '^TestCgroupScopeOutsideInner$' -test.v`,
		os.Args[0])
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(rootDir.Fd())}
	cmd.Env = append(os.Environ(), fmt.Sprintf("CARGOWALL_SCOPE_OUTSIDE=%d,%d", idOf(listed), idOf(empty)))
	out, err := cmd.CombinedOutput()
	t.Logf("inside cgroup namespace:\n%s", out)
	require.NoError(t, err)
	require.Contains(t, string(out), "--- PASS: TestCgroupScopeOutsideInner")
}

// TestCgroupScopeOutsideInner is TestCgroupScopeWalkTakesOutCgroupsOutsideTheRoot's
// half in a cgroup namespace of its own; on its own it skips.
func TestCgroupScopeOutsideInner(t *testing.T) {
	ids := os.Getenv("CARGOWALL_SCOPE_OUTSIDE")
	if ids == "" {
		t.Skip("run by TestCgroupScopeWalkTakesOutCgroupsOutsideTheRoot")
	}
	var listed, empty uint64
	_, err := fmt.Sscanf(ids, "%d,%d", &listed, &empty)
	require.NoError(t, err)
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	s := loadWalkScope(t, ino, 65536)
	for _, id := range []uint64{listed, empty} {
		require.NoError(t, s.cgroups().Put(id, uint8(1)))
	}
	require.NoError(t, s.walk())
	var v uint8
	require.Error(t, s.cgroups().Lookup(listed, &v), "a listed cgroup outside the root is taken out")
	require.Error(t, s.cgroups().Lookup(empty, &v), "and so is one the scope holds that nothing listed")
	dir, path, inside, err := s.openCgroup(empty)
	require.NoError(t, err)
	dir.Close()
	require.False(t, inside)
	require.Equal(t, "/..", path, "one outside the root is named as the kernel names it, not by a path of ours")
}

// A finding is logged no more than once in warnEvery, whether it persists
// or comes and goes, and what was logged longer ago is forgotten.
func TestCgroupScopeWarnsOnceAnInterval(t *testing.T) {
	clock := time.Unix(0, 0)
	s := &cgroupScope{warned: make(map[finding]time.Time), now: func() time.Time { return clock }}
	require.True(t, s.warn(findShared, 1), "the first time")
	require.False(t, s.warn(findShared, 1), "not again at once")
	require.True(t, s.warn(findShared, 2), "another finding is its own")
	require.True(t, s.warn(findUnreadable, 1), "and so is another kind of the same id")
	clock = clock.Add(warnEvery - time.Second)
	require.False(t, s.warn(findShared, 1), "nor within the interval")
	clock = clock.Add(time.Second)
	require.True(t, s.warn(findShared, 1), "and again once it has passed")
	s.forgetWarned()
	require.Len(t, s.warned, 1, "what was logged an interval ago is forgotten")
}

// Clearing a mark the listing did not reach: a cgroup a task of ours has
// entered since, which scope_enter left out for the mark, is recorded; one
// with none of ours is looked at twice, so that a task outside entering
// between the looks leaves it marked, as record's own second look does for
// the other. A mark the map cannot take is reported, once.
func TestCgroupScopeClearMark(t *testing.T) {
	own := ownCgroupBelowRoot(t)
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	s := loadWalkScope(t, ino, 1)
	ownID, err := podenv.CgroupID(own)
	require.NoError(t, err)
	dir, path, _, err := s.openCgroup(ownID)
	require.NoError(t, err)
	defer dir.Close()
	var v uint8
	marked := func() bool { return s.objs.MapScopeShared.Lookup(ownID, &v) == nil }
	recorded := func() bool { return s.cgroups().Lookup(ownID, &v) == nil }
	// looksRead stands in for cgroup.threads, a reading per look: its
	// contents, or the error reading it.
	looksRead := func(reads ...any) {
		t.Helper()
		looks := 0
		swap(t, &readThreads, func(*os.File) ([]byte, error) {
			r := reads[min(looks, len(reads)-1)]
			looks++
			if err, ok := r.(error); ok {
				return nil, err
			}
			return []byte(r.(string)), nil
		})
	}

	s.mark(ownID, path, true)
	looksRead("7\n")
	s.clearMark(ownID, dir, path, true)
	require.True(t, !marked() && recorded(), "a cgroup ours alone loses its mark and is recorded")

	require.NoError(t, s.cgroups().Delete(ownID))
	s.mark(ownID, path, true)
	looksRead("7\n", "7\n0\n")
	s.clearMark(ownID, dir, path, true)
	require.True(t, marked() && !recorded(), "a task outside entering before record's second look takes it out and marks it")

	// A task outside entering an empty cgroup between the looks puts back
	// the mark the walk cleared, held as it was, though the scope does not
	// hold the cgroup now; an unheld one, with none of ours there, stays
	// cleared, as scope_leave leaves what the scope does not hold.
	looksRead("", "0\n")
	s.clearMark(ownID, dir, path, true)
	require.True(t, s.heldMark(ownID) && !recorded(), "a held mark cleared on an empty look is put back, held")
	s.forgetMark(ownID)
	s.mark(ownID, path, false)
	looksRead("", "0\n")
	s.clearMark(ownID, dir, path, true)
	require.True(t, !marked() && !recorded(), "an unheld one stays cleared")

	// One a task of ours recorded meanwhile, beside it, is taken out and
	// marked.
	s.mark(ownID, path, true)
	require.NoError(t, s.cgroups().Put(ownID, uint8(1)))
	looksRead("", "7\n0\n")
	s.clearMark(ownID, dir, path, true)
	require.True(t, marked() && !recorded(), "an entry made between the looks is taken out, the mark kept")

	// A listed cgroup ours alone, recorded and marked at once (as
	// scope_leave leaves it for an instant), loses its mark and settles: a
	// task outside entering between the look and the clearing marks it
	// again and takes it out.
	require.NoError(t, s.cgroups().Put(ownID, uint8(1)))
	s.mark(ownID, path, true)
	looksRead("7\n", "7\n0\n")
	s.reconcileListed(ownID, &listed{tgids: map[uint32]bool{7: true}}, true)
	require.True(t, marked() && !recorded(), "a listed cgroup unmarked while a task outside entered is marked again")
	require.True(t, s.heldMark(ownID), "held, as it was")

	// The same with only a held mark, the scope not holding the cgroup: a
	// task outside rejoining ours between the looks keeps the mark held,
	// not one a later walk would forget.
	looksRead("7\n", "7\n0\n")
	s.reconcileListed(ownID, &listed{tgids: map[uint32]bool{7: true}}, true)
	require.True(t, s.heldMark(ownID) && !recorded(), "a held mark cleared and put back stays held")

	// A task of ours alone entering an empty cgroup between the looks,
	// which scope_enter passed over for the mark, is recorded.
	looksRead("", "7\n")
	s.clearMark(ownID, dir, path, true)
	require.True(t, !marked() && recorded(), "a task of ours entering between the looks is recorded")
	require.NoError(t, s.cgroups().Delete(ownID))
	s.mark(ownID, path, true)

	// A cgroup still shared with a task of ours there keeps its mark. One
	// shared with none of ours keeps it too where the scope held it, so a
	// task of ours entering again is not recorded beside the tasks outside;
	// one marked by the walk but never held loses it, which would otherwise
	// never clear. An unheld mark overwrites no held one.
	looksRead("7\n0\n")
	s.clearMark(ownID, dir, path, true)
	require.True(t, marked(), "a cgroup still shared with ours keeps its mark")
	looksRead("0\n")
	s.clearMark(ownID, dir, path, true)
	require.True(t, marked() && !recorded(), "a held one shared with none of ours keeps it")
	s.mark(ownID, path, false)
	require.True(t, s.heldMark(ownID), "an unheld mark does not overwrite a held one")
	s.forgetMark(ownID)
	s.mark(ownID, path, false)
	require.False(t, s.heldMark(ownID))
	s.clearMark(ownID, dir, path, true)
	require.True(t, !marked() && !recorded(), "an unheld one shared with none of ours loses it")
	s.mark(ownID, path, true)

	looksRead("7\n")
	s.clearMark(ownID, dir, path, false)
	require.True(t, !marked() && !recorded(), "one outside our cgroup namespace's root is unmarked, never recorded")

	// One under the job's subtree, which in_subtree's bound let a
	// tracepoint record or mark, is the hook's to judge whoever is in it:
	// the passes over recorded and marked cgroups leave it as it is.
	s.sub.path = path
	require.NoError(t, s.cgroups().Put(ownID, uint8(1)))
	looksRead("0\n")
	require.True(t, s.reconcileRecorded(map[uint64]*listed{}))
	require.True(t, recorded() && !marked(), "a recorded cgroup under the subtree is not taken out")
	s.mark(ownID, path, true)
	looksRead("7\n")
	s.reconcileMarked(map[uint64]*listed{}, map[uint64]bool{ownID: true})
	require.True(t, marked(), "nor is a marked one's mark cleared")
	s.sub.path = ""
	s.forgetMark(ownID)
	require.NoError(t, s.cgroups().Delete(ownID))

	var log bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&log, nil))

	// A cgroup a task outside keeps emptying of its entry between each
	// recording and the look after it, though only ours are in it at each
	// look, is looked at settleLooks times, then marked and left out.
	looks := 0
	swap(t, &readThreads, func(*os.File) ([]byte, error) {
		looks++
		_ = s.cgroups().Delete(ownID)
		return []byte("7\n"), nil
	})
	s.record(ownID, dir, path)
	require.Equal(t, settleLooks, looks, "the looks are bounded")
	require.True(t, marked() && !recorded(), "and past them the cgroup is marked and left out")
	s.forgetMark(ownID)

	// A second look the walk's own fault fails (EMFILE) says nothing of the
	// cgroup: the write is undone, the entry it made taken out and the mark
	// it cleared put back, without a mark the cgroup did not have.
	s.forgetMark(ownID)
	looksRead(syscall.EMFILE)
	s.record(ownID, dir, path)
	require.True(t, !marked() && !recorded(), "a recording whose look ran short of descriptors is undone")
	require.Contains(t, log.String(), "for want of its own", "and reported as the walk's own")
	s.warned = make(map[finding]time.Time)
	log.Reset()
	// A recorded cgroup a pass cannot read for the same reason stays
	// recorded, where another error takes it out.
	require.NoError(t, s.cgroups().Put(ownID, uint8(1)))
	restoreOwn := swap(t, &readThreads, failReading(ownID, syscall.EMFILE))
	require.True(t, s.reconcileRecorded(map[uint64]*listed{}))
	restoreOwn()
	require.True(t, recorded() && !marked(), "a recorded cgroup read short of descriptors stays recorded")
	require.NoError(t, s.cgroups().Delete(ownID))
	s.warned = make(map[finding]time.Time)
	log.Reset()

	// A second look that cannot read the cgroup leaves it as it was, which
	// judges no task outside: clearMark puts the mark back, and record
	// takes out the entry it made and marks it. Both are reported.
	s.mark(ownID, path, true)
	looksRead("", syscall.EIO)
	s.clearMark(ownID, dir, path, true)
	require.True(t, marked() && !recorded(), "clearMark's unread second look puts the mark back")
	require.Contains(t, log.String(), "cannot read a cgroup", "and reports it")
	s.forgetMark(ownID)
	s.warned = make(map[finding]time.Time)
	log.Reset()
	looksRead(syscall.EIO)
	s.record(ownID, dir, path)
	require.True(t, marked() && !recorded(), "record's unread second look takes the entry out and marks it")
	require.Contains(t, log.String(), "cannot read a cgroup", "and reports it")

	// A read of either map cut short is reported apart from the other's.
	for range 2 {
		s.cutShort(s.objs.MapScopeShared, syscall.EINTR)
		s.cutShort(s.objs.MapScopeCgroups, syscall.EINTR)
	}
	require.Equal(t, 2, strings.Count(log.String(), "could not read all its cgroups"), "once for each map")

	require.NoError(t, s.objs.MapScopeShared.Put(ownID, uint8(1)))
	s.mark(ownID+1, "/full", true)
	s.mark(ownID+1, "/full", true)
	require.Equal(t, 1, strings.Count(log.String(), "could not mark a cgroup shared"), "a full mark map is reported once")
}

// A recorded cgroup found removed is not opened again until its release,
// whether its handle is stale or, opened before the removal, its read
// finds it gone.
func TestCgroupScopeRemembersRemovedCgroups(t *testing.T) {
	own := ownCgroupBelowRoot(t)
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	s := loadWalkScope(t, ino, 64)
	ownID, err := podenv.CgroupID(own)
	require.NoError(t, err)
	require.NoError(t, s.cgroups().Put(ownID, uint8(1)))
	swap(t, &readThreads, failReading(ownID, syscall.ENODEV))
	require.True(t, s.reconcileRecorded(map[uint64]*listed{}))
	require.True(t, s.stale[ownID], "a cgroup whose read finds it removed is remembered")
	require.NotContains(t, s.warned, finding{findUnreadable, ownID}, "and not reported")
}

// A map too small for every cgroup the walk records costs those cgroups,
// with a warning, as in the kernel, and not the scope. From the host pid
// namespace every task on the machine is ours, so the walk finds plenty.
func TestCgroupScopeWalkFullMapWarns(t *testing.T) {
	ownCgroupBelowRoot(t)
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	s := loadWalkScope(t, ino, 1)
	var log bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&log, nil))
	require.NoError(t, s.walk())
	logged := strings.Count(log.String(), "could not record a cgroup")
	require.Positive(t, logged)
	require.NoError(t, s.walk())
	require.Equal(t, logged, strings.Count(log.String(), "could not record a cgroup"), "and not again by the next walk")
}
