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

package bpf

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/podenv"
)

// TestScopeStatSlotsMatchSource pins the ScopeStat* slots to SCOPE_STAT_*
// in scopebpf.c: a drift would report one shortfall as another, or read
// past the map.
func TestScopeStatSlotsMatchSource(t *testing.T) {
	src, err := os.ReadFile("scopebpf.c")
	require.NoError(t, err)
	for name, want := range map[string]uint64{
		"SCOPE_STAT_FULL":       ScopeStatFull,
		"SCOPE_STAT_ROOT":       ScopeStatRoot,
		"SCOPE_STAT_FAILED":     ScopeStatFailed,
		"SCOPE_STAT_SHARED":     ScopeStatShared,
		"SCOPE_STAT_UNRELEASED": ScopeStatUnreleased,
		"SCOPE_STATS_MAX":       ScopeStatsMax,
	} {
		m := regexp.MustCompile(`(?m)^#define ` + name + `\s+(\d+)\b`).FindSubmatch(src)
		require.NotNil(t, m, "scopebpf.c must #define %s", name)
		got, err := strconv.ParseUint(string(m[1]), 10, 32)
		require.NoError(t, err)
		require.Equal(t, want, got, "%s drifted between scopebpf.c and scope_stats.go", name)
	}
}

// loadScope loads the scope collection for the pid namespace ino. Each
// test attaches only the program it is about, so no other path can record
// what that one should. A load failure fails: these are the only tests
// that run the scope programs.
func loadScope(t *testing.T, ino uint32, maxEntries uint32) *ScopeBpfObjects {
	t.Helper()
	requireBPF(t)
	spec, err := LoadScopeBpf()
	require.NoError(t, err)
	require.NoError(t, spec.Variables[ScopeBpfVarPidnsIno].Set(ino))
	if maxEntries > 0 {
		spec.Maps[ScopeBpfMapMapScopeCgroups].MaxEntries = maxEntries
	}
	var objs ScopeBpfObjects
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() { objs.Close() })
	return &objs
}

func attachScopeTracing(t *testing.T, p *ebpf.Program) {
	t.Helper()
	l, err := link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachTraceRawTp})
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
}

// scopeRecord is one record of the startup walk.
type scopeRecord struct {
	cgroup uint64
	tgid   uint32
	level  uint32
}

// scopeWalk runs the startup walk and returns its records, each a cgroup
// id, a process id and the cgroup's level.
func scopeWalk(t *testing.T, objs *ScopeBpfObjects) []scopeRecord {
	t.Helper()
	it, err := link.AttachIter(link.IterOptions{Program: objs.ScopeTaskIter})
	require.NoError(t, err)
	defer it.Close()
	rd, err := it.Open()
	require.NoError(t, err)
	defer rd.Close()
	out, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Zero(t, len(out)%24, "the walk writes whole records")
	var recs []scopeRecord
	for i := 0; i < len(out); i += 24 {
		r := scopeRecord{
			cgroup: binary.NativeEndian.Uint64(out[i:]),
			tgid:   uint32(binary.NativeEndian.Uint64(out[i+8:])),
			level:  uint32(binary.NativeEndian.Uint64(out[i+16:])),
		}
		require.NotZero(t, r.tgid, "each record names its process")
		recs = append(recs, r)
	}
	return recs
}

// runScopeWalk runs the startup walk and returns the cgroups it lists, by
// id, with the level it wrote for each.
func runScopeWalk(t *testing.T, objs *ScopeBpfObjects) map[uint64]uint32 {
	t.Helper()
	levels := make(map[uint64]uint32)
	for _, r := range scopeWalk(t, objs) {
		levels[r.cgroup] = r.level
	}
	return levels
}

// nsPid is pid's process id in its own pid namespace, the innermost.
func nsPid(t *testing.T, pid int) uint32 {
	t.Helper()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	require.NoError(t, err)
	for _, line := range strings.Split(string(status), "\n") {
		if ids, ok := strings.CutPrefix(line, "NSpid:"); ok {
			f := strings.Fields(ids)
			n, err := strconv.ParseUint(f[len(f)-1], 10, 32)
			require.NoError(t, err)
			return uint32(n)
		}
	}
	t.Fatalf("no NSpid in /proc/%d/status", pid)
	return 0
}

func scopeRecorded(t *testing.T, objs *ScopeBpfObjects, path string) bool {
	t.Helper()
	var v uint8
	return objs.MapScopeCgroups.Lookup(cgroupID(t, path), &v) == nil
}

func scopeStat(t *testing.T, objs *ScopeBpfObjects, slot uint32) uint64 {
	t.Helper()
	var n uint64
	require.NoError(t, objs.MapScopeStats.Lookup(slot, &n))
	return n
}

// siblingCgroup creates a cgroup beside the one enterTestCgroup makes.
func siblingCgroup(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(podenv.CgroupRoot, fmt.Sprintf("cargowall-bpf-test-%d-%s", os.Getpid(), name))
	require.NoError(t, os.Mkdir(path, 0o755))
	t.Cleanup(func() { removeCgroup(t, path) })
	return path
}

func moveInto(t *testing.T, cgroup string, pid int) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0))
}

// startPinned starts cmd and kills it at cleanup, before the cgroups the
// test made are removed.
func startPinned(t *testing.T, cmd *exec.Cmd) *exec.Cmd {
	t.Helper()
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// childOf waits for parent's first child and returns its pid.
func childOf(t *testing.T, parent int) int {
	t.Helper()
	var child int
	require.Eventually(t, func() bool {
		kids, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", parent, parent))
		if f := strings.Fields(string(kids)); err == nil && len(f) > 0 {
			child, _ = strconv.Atoi(f[0])
			return true
		}
		return false
	}, 5*time.Second, 20*time.Millisecond)
	return child
}

// heldPidNamespace makes a pid namespace that lives until cleanup, and
// returns its inode and a way to start a process in it from outside (sleep
// unless a command is given), as a
// runtime's exec does: the process is in the namespace and still in the
// test's cgroup, which it shares with its parent outside. With it as the
// scope's namespace, nothing else on the machine counts as ours.
func heldPidNamespace(t *testing.T) (uint32, func(command ...string) int) {
	t.Helper()
	ino, initPid := heldPidNamespaceInit(t)
	nsInit := strconv.Itoa(initPid)
	enter := func(command ...string) int {
		if len(command) == 0 {
			command = []string{"sleep", "60"}
		}
		cmd := startPinned(t, exec.Command("nsenter", append([]string{"-t", nsInit, "-p", "--"}, command...)...))
		pid := childOf(t, cmd.Process.Pid)
		// Killing nsenter leaves its child behind, which would keep the
		// cgroups it moved into from being removed.
		t.Cleanup(func() { killAndWait(pid) })
		return pid
	}
	return ino, enter
}

// heldPidNamespaceInit makes a pid namespace that lives until cleanup, and
// returns its inode and its init's pid.
func heldPidNamespaceInit(t *testing.T) (uint32, int) {
	t.Helper()
	holder := startPinned(t, exec.Command("unshare", "-p", "-f", "--kill-child", "sleep", "60"))
	nsInit := childOf(t, holder.Process.Pid)
	fi, err := os.Stat(fmt.Sprintf("/proc/%d/ns/pid", nsInit))
	require.NoError(t, err)
	// The init dies with the holder, on a signal that may still be on its
	// way when the holder has been reaped: wait for it, or a cgroup it was
	// forked into is still busy when the test removes it.
	t.Cleanup(func() { killAndWait(nsInit) })
	return uint32(fi.Sys().(*syscall.Stat_t).Ino), nsInit
}

// killAndWait kills pid and waits for it to exit, which is when it leaves
// its cgroup: it is gone from /proc, or a zombie its parent has not reaped.
func killAndWait(pid int) {
	_ = syscall.Kill(pid, syscall.SIGKILL)
	for i := 0; i < 250; i++ {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil || strings.Contains(string(stat), ") Z ") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A move records its destination, for our pid namespace only, and never
// the root cgroup, which is counted instead.
func TestScopeAttachRecordsMoves(t *testing.T) {
	t.Run("our pid namespace", func(t *testing.T) {
		requireBPF(t)
		dst := siblingCgroup(t, "dst")
		ino, enter := heldPidNamespace(t)
		objs := loadScope(t, ino, 0)
		attachScopeTracing(t, objs.ScopeAttach)
		pid := enter()
		moveInto(t, dst, pid)
		require.True(t, scopeRecorded(t, objs, dst), "moving into a cgroup records it")

		moveInto(t, podenv.CgroupRoot, pid)
		require.False(t, scopeRecorded(t, objs, podenv.CgroupRoot), "the root cgroup is never recorded")
		require.Equal(t, uint64(1), scopeStat(t, objs, ScopeStatRoot), "entering the root cgroup is counted")
	})
	t.Run("another pid namespace", func(t *testing.T) {
		objs := loadScope(t, 1, 0)
		attachScopeTracing(t, objs.ScopeAttach)
		cg := enterTestCgroup(t)
		require.False(t, scopeRecorded(t, objs, cg), "a task outside the pid namespace records nothing")
	})
}

// zombieLeaderSrc exits its main thread while a second thread lives on, so
// the thread-group leader is a zombie that a move leaves behind.
const zombieLeaderSrc = `#include <pthread.h>
#include <unistd.h>
static void *park(void *a) { (void)a; for (;;) pause(); return 0; }
int main(void) { pthread_t t; pthread_create(&t, 0, park, 0); pthread_exit(0); }
`

// zombieLeader builds and starts the zombieLeaderSrc helper, and returns
// its pid once its leader has exited.
func zombieLeader(t *testing.T) int {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler for the zombie-leader helper")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "zl.c"), []byte(zombieLeaderSrc), 0o644))
	bin := filepath.Join(dir, "zl")
	out, err := exec.Command(cc, "-o", bin, filepath.Join(dir, "zl.c"), "-pthread").CombinedOutput()
	require.NoError(t, err, "compile helper: %s", out)
	pid := startPinned(t, exec.Command(bin)).Process.Pid
	require.Eventually(t, func() bool {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		return err == nil && strings.Contains(string(status), "State:\tZ")
	}, 5*time.Second, 20*time.Millisecond, "helper leader must exit")
	return pid
}

// A move records where the live threads went, not where the leader is: a
// leader that has exited is skipped by the migration and stays put.
func TestScopeAttachRecordsDestinationPastAZombieLeader(t *testing.T) {
	objs := loadScope(t, pidnsInode(t), 0)
	dst := siblingCgroup(t, "dst")
	pid := zombieLeader(t)

	attachScopeTracing(t, objs.ScopeAttach)
	moveInto(t, dst, pid)
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	require.NoError(t, err)
	moved := false
	for _, task := range tasks {
		if task.Name() == strconv.Itoa(pid) {
			continue
		}
		cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/cgroup", pid, task.Name()))
		require.NoError(t, err)
		moved = moved || strings.TrimSpace(string(cg)) == "0::"+strings.TrimPrefix(dst, podenv.CgroupRoot)
	}
	require.True(t, moved, "the live thread must have moved")
	require.True(t, scopeRecorded(t, objs, dst), "the destination is recorded")
}

// A fork records the child's cgroup only when clone3's CLONE_INTO_CGROUP
// created it there. A child in its parent's cgroup records nothing.
func TestScopeForkRecordsCloneIntoCgroup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ino      func(*testing.T) uint32
		recorded bool
	}{
		{"our pid namespace", pidnsInode, true},
		{"another pid namespace", func(*testing.T) uint32 { return 1 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := loadScope(t, tc.ino(t), 0)
			cg := enterTestCgroup(t) // before attach: the move is not the fork path's
			attachScopeTracing(t, objs.ScopeFork)

			require.NoError(t, exec.Command("/bin/true").Run())
			require.False(t, scopeRecorded(t, objs, cg), "a child in its parent's cgroup records nothing")

			into := siblingCgroup(t, "fork")
			dir, err := os.Open(into)
			require.NoError(t, err)
			defer dir.Close()
			child := exec.Command("/bin/true")
			child.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
			require.NoError(t, child.Run())
			require.Equal(t, tc.recorded, scopeRecorded(t, objs, into), "a child created in another cgroup")
		})
	}
}

// A parent outside our pid namespace forking into it, as nsenter does,
// while something moves the parent between two cgroups. Each child
// inherits whichever the parent was in, so neither is ever entered by a
// task of ours. A fork hook that compared the child's cgroup with the
// parent's would see a parent moved after the child inherited and record
// one: in Lima that happened within a second.
func TestScopeForkIgnoresAParentMovedMidFork(t *testing.T) {
	requireBPF(t)
	a := siblingCgroup(t, "race-a")
	b := siblingCgroup(t, "race-b")
	moveSelf(t, a)
	ino, nsInit := heldPidNamespaceInit(t)
	objs := loadScope(t, ino, 0)
	attachScopeTracing(t, objs.ScopeFork)

	ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/pid", nsInit))
	require.NoError(t, err)
	defer ns.Close()
	var stop atomic.Bool
	var forks atomic.Int64
	forked := make(chan error, 1)
	go func() {
		// Left locked: Go ends a thread whose goroutine exits locked, so the
		// namespace it joined never reaches another goroutine.
		runtime.LockOSThread()
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWPID); err != nil {
			forked <- err
			return
		}
		for !stop.Load() {
			pid, err := syscall.ForkExec("/bin/true", []string{"true"}, &syscall.ProcAttr{})
			if err != nil {
				forked <- err
				return
			}
			var ws syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &ws, 0, nil)
			forks.Add(1)
		}
		forked <- nil
	}()
	self := []byte(strconv.Itoa(os.Getpid()))
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		require.NoError(t, os.WriteFile(filepath.Join(b, "cgroup.procs"), self, 0))
		require.NoError(t, os.WriteFile(filepath.Join(a, "cgroup.procs"), self, 0))
	}
	stop.Store(true)
	require.NoError(t, <-forked)
	require.Positive(t, forks.Load(), "the children must have been forked")
	require.False(t, scopeRecorded(t, objs, a), "a cgroup the children only inherited (%d forks)", forks.Load())
	require.False(t, scopeRecorded(t, objs, b), "a cgroup the children only inherited (%d forks)", forks.Load())
}

// The startup walk lists the cgroup of each task of ours, with its level,
// and records nothing itself: pkg/origin decides which to record, and
// reports a task of ours in the root cgroup.
func TestScopeWalkListsOurCgroups(t *testing.T) {
	requireBPF(t)
	t.Run("our pid namespace", func(t *testing.T) {
		objs := loadScope(t, pidnsInode(t), 0)
		cg := enterTestCgroup(t)
		levels := runScopeWalk(t, objs)
		level, listed := levels[cgroupID(t, cg)]
		require.True(t, listed, "the test process's cgroup")
		require.Equal(t, podenv.CgroupLevel(strings.TrimPrefix(cg, podenv.CgroupRoot)), level,
			"at the kernel's level, which in the host cgroup namespace is the path's depth")
		require.False(t, scopeRecorded(t, objs, cg), "the walk records nothing")
	})
	t.Run("another pid namespace", func(t *testing.T) {
		dst := siblingCgroup(t, "walk")
		foreign := siblingCgroup(t, "foreign")
		moveInto(t, foreign, startPinned(t, exec.Command("sleep", "60")).Process.Pid)
		ino, enter := heldPidNamespace(t)
		objs := loadScope(t, ino, 0)
		pid := enter()
		moveInto(t, dst, pid)
		levels := runScopeWalk(t, objs)
		_, listed := levels[cgroupID(t, dst)]
		require.True(t, listed, "the namespace's task's cgroup")
		_, listed = levels[cgroupID(t, foreign)]
		require.False(t, listed, "a cgroup only a task outside the namespace is in")

		moveInto(t, podenv.CgroupRoot, pid)
		levels = runScopeWalk(t, objs)
		_, listed = levels[cgroupID(t, dst)]
		require.False(t, listed, "the task has left")
		level, listed := levels[cgroupID(t, podenv.CgroupRoot)]
		require.True(t, listed, "the root cgroup is listed, for pkg/origin to report")
		require.Zero(t, level)
		require.Zero(t, scopeStat(t, objs, ScopeStatRoot), "the walk counts nothing: it runs on every tick")
	})
}

// The walk writes only what pkg/origin acts on: a record for a process in
// its leader's cgroup, one more for each of its threads elsewhere, and
// nothing for a task in the subtree, which the hook judges whole, except
// cargowall itself, whose record gives the subtree's level.
func TestScopeWalkWritesWhatTheWalkActsOn(t *testing.T) {
	requireBPF(t)
	t.Run("threads", func(t *testing.T) {
		objs := loadScope(t, pidnsInode(t), 0)
		cg := enterTestCgroup(t)
		dst := siblingCgroup(t, "threads")
		pid := zombieLeader(t)
		moveInto(t, dst, pid)
		var self, leader, thread int
		for _, r := range scopeWalk(t, objs) {
			switch {
			case r.tgid == uint32(os.Getpid()):
				self++
			case r.tgid == uint32(pid) && r.cgroup == cgroupID(t, cg):
				leader++
			case r.tgid == uint32(pid) && r.cgroup == cgroupID(t, dst):
				thread++
			}
		}
		require.Equal(t, 1, self, "the test process, whose threads share one cgroup")
		require.Equal(t, 1, leader, "the helper's exited leader, where it stayed")
		require.Equal(t, 1, thread, "and its live thread, where it moved")
	})
	t.Run("the subtree", func(t *testing.T) {
		sub := siblingCgroup(t, "walk-subtree")
		ino, enter := heldPidNamespace(t)
		self, other := enter(), enter()
		moveInto(t, sub, self)
		moveInto(t, sub, other)
		spec, err := LoadScopeBpf()
		require.NoError(t, err)
		require.NoError(t, spec.Variables[ScopeBpfVarPidnsIno].Set(ino))
		require.NoError(t, spec.Variables[ScopeBpfVarSubtreeCgroup].Set(cgroupID(t, sub)))
		require.NoError(t, spec.Variables[ScopeBpfVarSelfTgid].Set(nsPid(t, self)))
		objs := &ScopeBpfObjects{}
		require.NoError(t, spec.LoadAndAssign(objs, nil))
		t.Cleanup(func() { objs.Close() })
		listed := make(map[uint32]bool)
		for _, r := range scopeWalk(t, objs) {
			if r.cgroup == cgroupID(t, sub) {
				listed[r.tgid] = true
			}
		}
		require.Equal(t, map[uint32]bool{nsPid(t, self): true}, listed, "only cargowall's own process")
	})
}

// A runtime that runs a process in a container (runc exec, kubectl exec)
// creates it in the container's pid namespace while it is still in the
// runtime's own cgroup, and only then moves it. heldPidNamespace does the
// same from the test's cgroup: that cgroup is shared with a parent outside
// the namespace, so the fork must not record it, and the move then records
// the container's.
func TestScopeIgnoresARuntimesCgroup(t *testing.T) {
	requireBPF(t)
	container := siblingCgroup(t, "container")
	runtimeCg := enterTestCgroup(t)
	ino, enter := heldPidNamespace(t)
	objs := loadScope(t, ino, 0)
	attachScopeTracing(t, objs.ScopeFork)
	attachScopeTracing(t, objs.ScopeAttach)
	pid := enter()
	require.False(t, scopeRecorded(t, objs, runtimeCg), "a cgroup shared with a parent outside the namespace")

	moveInto(t, container, pid)
	require.True(t, scopeRecorded(t, objs, container), "the cgroup it then moves into")
}

// A released cgroup leaves the map, which is when nothing can carry its id
// again: not at removal, while a socket made in it is still open, but once
// that socket is gone too.
func TestScopeReleaseForgetsCgroups(t *testing.T) {
	requireBPF(t)
	objs := loadScope(t, pidnsInode(t), 0)
	attachScopeTracing(t, objs.ScopeRelease)
	recorded := func(id uint64) bool {
		var v uint8
		return objs.MapScopeCgroups.Lookup(id, &v) == nil
	}
	root := enterTestCgroup(t)
	made := func(t *testing.T, name string) (string, uint64) {
		t.Helper()
		dir := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(dir, 0o755))
		t.Cleanup(func() { removeCgroup(t, dir) })
		id := cgroupID(t, dir)
		require.NoError(t, objs.MapScopeCgroups.Put(id, uint8(1)))
		return dir, id
	}

	empty, emptyID := made(t, "empty")
	require.NoError(t, objs.MapScopeShared.Put(emptyID, uint8(1)))
	require.NoError(t, os.Remove(empty))
	require.Eventually(t, func() bool { return !recorded(emptyID) }, 5*time.Second, 20*time.Millisecond,
		"a removed cgroup with nothing in it is released and forgotten")
	var v uint8
	require.Error(t, objs.MapScopeShared.Lookup(emptyID, &v), "and so is its shared mark")

	held, heldID := made(t, "held")
	moveSelf(t, held)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	open := true
	t.Cleanup(func() {
		if open {
			_ = unix.Close(fd)
		}
	})
	require.NoError(t, os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0))
	require.NoError(t, os.Remove(held))
	time.Sleep(500 * time.Millisecond)
	require.True(t, recorded(heldID), "a removed cgroup a socket was made in stays while the socket is open")
	open = false
	require.NoError(t, unix.Close(fd))
	require.Eventually(t, func() bool { return !recorded(heldID) }, 5*time.Second, 20*time.Millisecond,
		"and is forgotten once the socket is gone")

	// The default hierarchy only: a v1 cgroup's id can repeat a v2 one's,
	// so the release of a cgroup in a v1 hierarchy (a named one, with no
	// controllers) must leave an entry with its id alone. A v2 cgroup
	// released alongside shows the releases have run. A kernel without v1
	// skips this part alone.
	t.Run("v1 hierarchy", func(t *testing.T) {
		mnt := t.TempDir()
		if err := unix.Mount("cgroup", mnt, "cgroup", 0, "none,name=cargowall-test"); err != nil {
			t.Skipf("cannot mount a v1 hierarchy: %v", err)
		}
		t.Cleanup(func() { _ = unix.Unmount(mnt, 0) })
		v1 := filepath.Join(mnt, "v1")
		require.NoError(t, os.Mkdir(v1, 0o755))
		t.Cleanup(func() { _ = os.Remove(v1) })
		fi, err := os.Stat(v1)
		require.NoError(t, err)
		v1ID := fi.Sys().(*syscall.Stat_t).Ino
		require.NoError(t, objs.MapScopeCgroups.Put(v1ID, uint8(1)))
		v2, v2ID := made(t, "v2")
		require.NoError(t, os.Remove(v1))
		require.NoError(t, os.Remove(v2))
		require.Eventually(t, func() bool { return !recorded(v2ID) }, 5*time.Second, 20*time.Millisecond)
		time.Sleep(200 * time.Millisecond)
		require.True(t, recorded(v1ID), "a v1 cgroup's release deletes nothing")
	})
}

// A cgroup leaves the scope as soon as a task outside our pid namespace
// enters it, by a move (systemd restarting a unit into the cgroup a job of
// ours was left in) or by clone3 into it: it is no longer this job's alone.
// Entering a cgroup that is not in the scope counts nothing.
func TestScopeLeavesCgroupsOthersEnter(t *testing.T) {
	requireBPF(t)
	moved := siblingCgroup(t, "moved-into")
	cloned := siblingCgroup(t, "cloned-into")
	other := siblingCgroup(t, "other")
	ino, enter := heldPidNamespace(t)
	objs := loadScope(t, ino, 0)
	attachScopeTracing(t, objs.ScopeAttach)
	attachScopeTracing(t, objs.ScopeFork)
	ours := enter()
	moveInto(t, moved, ours)
	moveInto(t, cloned, ours)
	require.True(t, scopeRecorded(t, objs, moved))
	require.True(t, scopeRecorded(t, objs, cloned))

	foreign := startPinned(t, exec.Command("sleep", "60")).Process.Pid
	moveInto(t, other, foreign)
	require.Zero(t, scopeStat(t, objs, ScopeStatShared), "a cgroup outside the scope")
	moveInto(t, moved, foreign)
	require.False(t, scopeRecorded(t, objs, moved), "a move into it by a task outside our pid namespace")
	require.Equal(t, uint64(1), scopeStat(t, objs, ScopeStatShared))
	var v uint8
	require.NoError(t, objs.MapScopeShared.Lookup(cgroupID(t, moved), &v), "and it is marked shared")
	require.Error(t, objs.MapScopeShared.Lookup(cgroupID(t, other), &v), "a cgroup the scope never held is left unmarked")
	// A task of ours entering it again does not record it while it is
	// marked, however often it enters: the walk clears the mark once the
	// other task has gone.
	moveInto(t, other, ours)
	moveInto(t, moved, ours)
	require.False(t, scopeRecorded(t, objs, moved), "a cgroup marked shared, entered again by a task of ours")

	dir, err := os.Open(cloned)
	require.NoError(t, err)
	defer dir.Close()
	child := exec.Command("/bin/true")
	child.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	require.NoError(t, child.Run())
	require.False(t, scopeRecorded(t, objs, cloned), "a clone3 child of a task outside our pid namespace")
	require.Equal(t, uint64(2), scopeStat(t, objs, ScopeStatShared))
}

// The job's subtree is the hook's whole: nothing in it is recorded, by a
// task of ours entering, or taken out, by any other, so an exec into our
// container from outside our pid namespace (runc 1.4 makes its first stage
// there with clone3) counts nothing. A cgroup outside it is recorded.
func TestScopeLeavesTheSubtreeAlone(t *testing.T) {
	requireBPF(t)
	sub := siblingCgroup(t, "subtree")
	inside := filepath.Join(sub, "container")
	require.NoError(t, os.Mkdir(inside, 0o755))
	t.Cleanup(func() { removeCgroup(t, inside) })
	outside := siblingCgroup(t, "outside")
	ino, enter := heldPidNamespace(t)
	spec, err := LoadScopeBpf()
	require.NoError(t, err)
	require.NoError(t, spec.Variables[ScopeBpfVarPidnsIno].Set(ino))
	require.NoError(t, spec.Variables[ScopeBpfVarSubtreeCgroup].Set(cgroupID(t, sub)))
	objs := &ScopeBpfObjects{}
	require.NoError(t, spec.LoadAndAssign(objs, nil))
	t.Cleanup(func() { objs.Close() })
	attachScopeTracing(t, objs.ScopeAttach)
	attachScopeTracing(t, objs.ScopeFork)

	ours := enter()
	moveInto(t, inside, ours)
	moveInto(t, sub, ours)
	require.False(t, scopeRecorded(t, objs, inside), "a cgroup below the subtree's")
	require.False(t, scopeRecorded(t, objs, sub), "the subtree's own")
	dir, err := os.Open(inside)
	require.NoError(t, err)
	defer dir.Close()
	child := exec.Command("/bin/true")
	child.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	require.NoError(t, child.Run())
	moveInto(t, sub, startPinned(t, exec.Command("sleep", "60")).Process.Pid)
	require.Zero(t, scopeStat(t, objs, ScopeStatShared), "tasks outside our pid namespace entering it count nothing")

	moveInto(t, outside, ours)
	require.True(t, scopeRecorded(t, objs, outside), "a cgroup outside the subtree")
}

// A cgroup that finds the map full is counted, not recorded.
func TestScopeFullIsCounted(t *testing.T) {
	requireBPF(t)
	first := siblingCgroup(t, "first")
	second := siblingCgroup(t, "second")
	ino, enter := heldPidNamespace(t)
	objs := loadScope(t, ino, 1)
	attachScopeTracing(t, objs.ScopeAttach)
	pid := enter()
	moveInto(t, first, pid)
	require.True(t, scopeRecorded(t, objs, first))
	moveInto(t, second, pid)
	require.False(t, scopeRecorded(t, objs, second))
	require.Equal(t, uint64(1), scopeStat(t, objs, ScopeStatFull))
	require.Zero(t, scopeStat(t, objs, ScopeStatFailed), "a full map is not another failure")
}
