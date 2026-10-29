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
)

// scopeStatSlot is the map_scope_stats slot scopebpf.c #defines as name,
// read from the source so these tests cannot drift from it.
func scopeStatSlot(t *testing.T, name string) uint32 {
	t.Helper()
	src, err := os.ReadFile("scopebpf.c")
	require.NoError(t, err)
	m := regexp.MustCompile(`(?m)^#define ` + name + `\s+(\d+)\b`).FindSubmatch(src)
	require.NotNil(t, m, "scopebpf.c must #define %s", name)
	slot, err := strconv.ParseUint(string(m[1]), 10, 32)
	require.NoError(t, err)
	return uint32(slot)
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

// runScopeWalk runs the startup walk and returns the cgroup ids it lists.
func runScopeWalk(t *testing.T, objs *ScopeBpfObjects) map[uint64]bool {
	t.Helper()
	it, err := link.AttachIter(link.IterOptions{Program: objs.ScopeTaskIter})
	require.NoError(t, err)
	defer it.Close()
	rd, err := it.Open()
	require.NoError(t, err)
	defer rd.Close()
	out, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Zero(t, len(out)%8, "the walk writes whole cgroup ids")
	ids := make(map[uint64]bool)
	for i := 0; i < len(out); i += 8 {
		ids[binary.NativeEndian.Uint64(out[i:])] = true
	}
	return ids
}

func scopeRecorded(t *testing.T, objs *ScopeBpfObjects, path string) bool {
	t.Helper()
	var v uint8
	return objs.MapScopeCgroups.Lookup(cgroupID(t, path), &v) == nil
}

func scopeStat(t *testing.T, objs *ScopeBpfObjects, name string) uint64 {
	t.Helper()
	var n uint64
	require.NoError(t, objs.MapScopeStats.Lookup(scopeStatSlot(t, name), &n))
	return n
}

// siblingCgroup creates a cgroup beside the one enterTestCgroup makes.
func siblingCgroup(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("cargowall-bpf-test-%d-%s", os.Getpid(), name))
	require.NoError(t, os.Mkdir(path, 0o755))
	t.Cleanup(func() { _ = os.Remove(path) })
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
// returns its inode and a way to start a process in it from outside, as a
// runtime's exec does: the process is in the namespace and still in the
// test's cgroup, which it shares with its parent outside. With it as the
// scope's namespace, nothing else on the machine counts as ours.
func heldPidNamespace(t *testing.T) (uint32, func() int) {
	t.Helper()
	ino, initPid := heldPidNamespaceInit(t)
	nsInit := strconv.Itoa(initPid)
	enter := func() int {
		cmd := startPinned(t, exec.Command("nsenter", "-t", nsInit, "-p", "--", "sleep", "60"))
		pid := childOf(t, cmd.Process.Pid)
		// Killing nsenter leaves its child behind, which would keep the
		// cgroups it moved into from being removed.
		t.Cleanup(func() {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			for i := 0; i < 250; i++ {
				stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if err != nil || strings.Contains(string(stat), ") Z ") {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
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
	return uint32(fi.Sys().(*syscall.Stat_t).Ino), nsInit
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

		moveInto(t, "/sys/fs/cgroup", pid)
		require.False(t, scopeRecorded(t, objs, "/sys/fs/cgroup"), "the root cgroup is never recorded")
		require.Equal(t, uint64(1), scopeStat(t, objs, "SCOPE_STAT_ROOT"), "entering the root cgroup is counted")
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

// A move records where the live threads went, not where the leader is: a
// leader that has exited is skipped by the migration and stays put.
func TestScopeAttachRecordsDestinationPastAZombieLeader(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler for the zombie-leader helper")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "zl.c"), []byte(zombieLeaderSrc), 0o644))
	bin := filepath.Join(dir, "zl")
	out, err := exec.Command(cc, "-o", bin, filepath.Join(dir, "zl.c"), "-pthread").CombinedOutput()
	require.NoError(t, err, "compile helper: %s", out)

	objs := loadScope(t, pidnsInode(t), 0)
	dst := siblingCgroup(t, "dst")
	helper := startPinned(t, exec.Command(bin))
	pid := helper.Process.Pid
	require.Eventually(t, func() bool {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		return err == nil && strings.Contains(string(status), "State:\tZ")
	}, 5*time.Second, 20*time.Millisecond, "helper leader must exit")

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
		moved = moved || strings.TrimSpace(string(cg)) == "0::"+strings.TrimPrefix(dst, "/sys/fs/cgroup")
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

// The startup walk lists the cgroup of each task of ours and records
// nothing itself (pkg/origin decides which to record); a task of ours in
// the root cgroup is counted instead.
func TestScopeWalkListsOurCgroups(t *testing.T) {
	requireBPF(t)
	t.Run("our pid namespace", func(t *testing.T) {
		objs := loadScope(t, pidnsInode(t), 0)
		cg := enterTestCgroup(t)
		ids := runScopeWalk(t, objs)
		require.True(t, ids[cgroupID(t, cg)], "the test process's cgroup")
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
		ids := runScopeWalk(t, objs)
		require.True(t, ids[cgroupID(t, dst)], "the namespace's task's cgroup")
		require.False(t, ids[cgroupID(t, foreign)], "a cgroup only a task outside the namespace is in")

		moveInto(t, "/sys/fs/cgroup", pid)
		ids = runScopeWalk(t, objs)
		require.False(t, ids[cgroupID(t, dst)], "the task has left")
		require.False(t, ids[cgroupID(t, "/sys/fs/cgroup")], "the root cgroup is never listed")
		require.Equal(t, uint64(1), scopeStat(t, objs, "SCOPE_STAT_ROOT"), "a task of ours there is counted")
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
	require.Equal(t, uint64(1), scopeStat(t, objs, "SCOPE_STAT_FULL"))
	require.Zero(t, scopeStat(t, objs, "SCOPE_STAT_FAILED"), "a full map is not another failure")
}
