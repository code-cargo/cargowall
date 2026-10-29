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
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/code-cargo/cargowall/bpf"
	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// Slots of map_scope_stats, mirroring SCOPE_STAT_* in bpf/scopebpf.c.
const (
	scopeStatFull   = iota // map_scope_cgroups was full
	scopeStatRoot          // a task of ours entered, or was in, the root cgroup
	scopeStatFailed        // any other update failure
	scopeStatsMax
)

// scopeStatsInterval is how often podScope checks what it could not record.
const scopeStatsInterval = 10 * time.Second

// podScope owns the scope collection (bpf/scopebpf.c): the cgroups that
// tasks in our pid namespace have entered, which a scoped hook judges
// beside our pod's cgroup subtree. Started before the hook attaches, so the
// hook never judges an empty scope, and closed after it detaches. A
// failure anywhere here costs the scoped hook only: the step tracker and TC
// never depend on it.
type podScope struct {
	objs     bpf.ScopeBpfObjects
	links    []link.Link
	logger   *slog.Logger
	stop     chan struct{}
	done     chan struct{}
	reported [scopeStatsMax]uint64 // last counts logged, owned by watch
}

// setScope sets the scoped hook's load-time constants: scoped, and our
// pod's cgroup when there is one.
func setScope(spec *ebpf.CollectionSpec, podCgroup string) error {
	scoped := spec.Variables[bpf.OriginBpfVarScoped]
	podID, podLevel := spec.Variables[bpf.OriginBpfVarScopePodCgroup], spec.Variables[bpf.OriginBpfVarScopePodLevel]
	if scoped == nil || podID == nil || podLevel == nil || spec.Maps[bpf.OriginBpfMapMapScopeCgroups] == nil {
		return errors.New("origin BPF spec has no scope variables or scope map (stale generated code)")
	}
	if err := scoped.Set(uint8(1)); err != nil {
		return fmt.Errorf("failed to set scoped: %w", err)
	}
	if podCgroup == "" {
		return nil
	}
	// A cgroup's id is its cgroupfs inode on 64-bit kernels, and its level
	// its depth below the root.
	fi, err := os.Stat(filepath.Join(podenv.CgroupRoot, podCgroup))
	if err != nil {
		return fmt.Errorf("pod cgroup: %w", err)
	}
	level := uint32(len(strings.Split(strings.Trim(podCgroup, "/"), "/")))
	if err := podID.Set(fi.Sys().(*syscall.Stat_t).Ino); err != nil {
		return fmt.Errorf("failed to set the pod cgroup: %w", err)
	}
	if err := podLevel.Set(level); err != nil {
		return fmt.Errorf("failed to set the pod cgroup's level: %w", err)
	}
	return nil
}

// startPodScope loads the scope collection for our pid namespace, attaches
// its tracepoints, then walks the tasks that predate them, so a task that
// enters a cgroup while the walk runs is recorded by one or the other.
// podCgroup is our pod's cgroup, which the hook judges whole, or "".
// The verifier logs only its statistics, as for the origin collection: a
// branch-level log of each program would be kept for the life of the
// process.
func startPodScope(logger *slog.Logger, podCgroup string) (*podScope, error) {
	ino, err := podenv.PidNamespaceInode()
	if err != nil {
		return nil, fmt.Errorf("pod scope: %w", err)
	}
	spec, err := bpf.LoadScopeBpf()
	if err != nil {
		return nil, fmt.Errorf("pod scope: failed to load BPF spec: %w", err)
	}
	if v := spec.Variables[bpf.ScopeBpfVarPidnsIno]; v == nil {
		return nil, errors.New("pod scope: BPF spec has no pidns_ino variable (stale generated code)")
	} else if err := v.Set(ino); err != nil {
		return nil, fmt.Errorf("pod scope: failed to set pidns_ino: %w", err)
	}
	s := &podScope{logger: logger, stop: make(chan struct{}), done: make(chan struct{})}
	if err := cargowallEbpf.LoadObjects(logger, "scopebpf", spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	}, &s.objs); err != nil {
		return nil, fmt.Errorf("pod scope: failed to load BPF objects: %w", err)
	}
	for _, p := range []*ebpf.Program{s.objs.ScopeFork, s.objs.ScopeAttach, s.objs.ScopeRelease} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachTraceRawTp})
		if err != nil {
			s.release()
			return nil, fmt.Errorf("pod scope: failed to attach %s: %w", p, err)
		}
		s.links = append(s.links, l)
	}
	if err := s.walk(podCgroup); err != nil {
		s.release()
		return nil, fmt.Errorf("pod scope: task walk: %w", err)
	}
	go s.watch()
	return s, nil
}

// cgroups is the map the scoped hook loads in place of its stand-in.
func (s *podScope) cgroups() *ebpf.Map { return s.objs.MapScopeCgroups }

// walk records the cgroups the startup walk lists, our tasks' cgroups,
// that are this job's alone: outside our pod's cgroup, which the hook
// judges whole, and holding no task outside our pid namespace. A task's
// cgroup does not say it entered it. A task of ours in the same cgroup as
// a node daemon or another pod's task was left there (a job an nsenter'd
// shell started) or is about to be moved out (a runtime's exec), and
// recording that cgroup would judge the daemon or the pod. Such a cgroup is
// reported and left out, and the task's sockets pass. The check reads
// cgroup.threads, which numbers each task as our pid namespace does, so a
// task outside it reads as 0. The walk must list this process's own
// cgroup: one that lists none of ours would leave the scope empty while
// the hook reports it attached.
func (s *podScope) walk(podCgroup string) error {
	tasks, err := s.walkTasks()
	if err != nil {
		return err
	}
	own, err := podenv.ReadCgroupPath("/proc/self/cgroup")
	if err != nil {
		return err
	}
	if _, ok := tasks[cgroupID(own)]; !ok {
		return fmt.Errorf("the task walk did not list this process's cgroup %s", own)
	}
	for id, tgids := range tasks {
		path, ok := cgroupPathOf(id, tgids)
		if !ok || under(path, podCgroup) {
			continue // its tasks have gone (a move was recorded), or the pod's cgroup covers it
		}
		shared, err := sharedCgroup(filepath.Join(podenv.CgroupRoot, path))
		if cgroupGone(err) {
			continue
		}
		if err != nil {
			return err
		}
		if shared {
			s.logger.Warn("A task of this job is in a cgroup shared with tasks outside it, "+
				"where its sockets pass the cgroup hook", "cgroup", path)
			continue
		}
		// As in the kernel, a cgroup the map cannot take costs its own
		// sockets, not the scope. One released since the walk listed it
		// stays, a dead id: ids are never reused.
		if err := s.objs.MapScopeCgroups.Update(id, uint8(1), ebpf.UpdateNoExist); err != nil &&
			!errors.Is(err, ebpf.ErrKeyExist) {
			s.logger.Warn("Container egress scope could not record a cgroup this job is in, "+
				"and its sockets pass the cgroup hook", "cgroup", path, "error", err,
				"capacity", s.objs.MapScopeCgroups.MaxEntries())
		}
	}
	return nil
}

// walkTasks runs the task walk and returns, for each cgroup id it listed,
// the processes (as numbered in our pid namespace) it listed there.
func (s *podScope) walkTasks() (map[uint64]map[uint32]bool, error) {
	it, err := link.AttachIter(link.IterOptions{Program: s.objs.ScopeTaskIter})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	rd, err := it.Open()
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	out, err := io.ReadAll(rd)
	if err != nil {
		return nil, err
	}
	if len(out)%16 != 0 {
		return nil, fmt.Errorf("task walk wrote %d bytes, not a whole number of records", len(out))
	}
	tasks := make(map[uint64]map[uint32]bool)
	for i := 0; i < len(out); i += 16 {
		id, tgid := binary.NativeEndian.Uint64(out[i:]), uint32(binary.NativeEndian.Uint64(out[i+8:]))
		if tasks[id] == nil {
			tasks[id] = make(map[uint32]bool)
		}
		tasks[id][tgid] = true
	}
	return tasks, nil
}

// cgroupPathOf finds the path of cgroup id through a process the walk
// listed in it: the process's own cgroup or, when that is no longer id
// (the process has moved, or the task was a thread in a cgroup of its
// own), one of its threads'. False when none of them is there now.
func cgroupPathOf(id uint64, tgids map[uint32]bool) (string, bool) {
	for tgid := range tgids {
		proc := fmt.Sprintf("/proc/%d", tgid)
		if path, err := podenv.ReadCgroupPath(proc + "/cgroup"); err == nil && cgroupID(path) == id {
			return path, true
		}
		threads, _ := filepath.Glob(proc + "/task/*/cgroup")
		for _, f := range threads {
			if path, err := podenv.ReadCgroupPath(f); err == nil && cgroupID(path) == id {
				return path, true
			}
		}
	}
	return "", false
}

// cgroupID is the id of the cgroup at path, its cgroupfs inode on 64-bit
// kernels, or 0 when it cannot be read.
func cgroupID(path string) uint64 {
	fi, err := os.Stat(filepath.Join(podenv.CgroupRoot, path))
	if err != nil {
		return 0
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// under reports whether the cgroup at path is pod's or below it.
func under(path, pod string) bool {
	return pod != "" && (path == pod || strings.HasPrefix(path, pod+"/"))
}

// cgroupGone reports whether err says the cgroup was removed: a file of a
// removed cgroup is missing, or, opened before the removal, reads ENODEV.
func cgroupGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENODEV)
}

// sharedCgroup reports whether the cgroup at dir holds a task outside our
// pid namespace: one cgroup.threads lists as 0.
func sharedCgroup(dir string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.threads"))
	if err != nil {
		return false, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if sc.Text() == "0" {
			return true, nil
		}
	}
	return false, sc.Err()
}

// watch reports, until close, what the scope could not record. Each leaves
// a task of ours whose sockets the hook passes, so each is a warning.
func (s *podScope) watch() {
	defer close(s.done)
	t := time.NewTicker(scopeStatsInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			s.report()
			return
		case <-t.C:
			s.report()
		}
	}
}

func (s *podScope) report() {
	for slot, msg := range [scopeStatsMax]string{
		scopeStatFull:   "Container egress scope full: cgroups this job entered were not recorded, and their sockets pass the cgroup hook",
		scopeStatRoot:   "A task of this job is in the root cgroup, where its sockets pass the cgroup hook",
		scopeStatFailed: "Container egress scope failed to record cgroups this job entered, and their sockets pass the cgroup hook",
	} {
		var n uint64
		if err := s.objs.MapScopeStats.Lookup(uint32(slot), &n); err != nil || n <= s.reported[slot] {
			continue
		}
		s.reported[slot] = n
		s.logger.Warn(msg, "times", n, "capacity", s.objs.MapScopeCgroups.MaxEntries())
	}
}

// close stops recording. The hook's collection holds its own reference to
// the map, so closing the scope first would leave the hook judging a scope
// nothing updates; Observer.Close detaches the hook before calling this.
func (s *podScope) close() {
	close(s.stop)
	<-s.done
	s.release()
}

func (s *podScope) release() {
	for _, l := range s.links {
		_ = l.Close()
	}
	s.objs.Close()
}
