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

// scopeStatsInterval is how often cgroupScope walks the tasks again and
// reports what it could not record. A test that walks by hand lengthens it.
var scopeStatsInterval = 10 * time.Second

// cgroupScope owns the scope collection (bpf/scopebpf.c): the cgroups that
// tasks in our pid namespace have entered, which a scoped hook judges
// beside the job's subtree (podenv.Scope.Subtree). Unrelated to the L7
// scope maps, which say which destinations get L7 checks. Started before
// the hook attaches, so the hook never judges an empty scope, and closed
// after it detaches. A failure anywhere here costs the scoped hook only:
// the step tracker and TC never depend on it.
//
// The programs record a cgroup as a task of ours enters it and take it
// out as another task enters it, which is immediate but sees only those
// events. The walk is the ground truth: at startup and on every tick it
// records each cgroup that holds a task of ours and no other, and takes
// out each one that holds another too, whatever the programs saw.
type cgroupScope struct {
	objs     bpf.ScopeBpfObjects
	links    []link.Link
	iter     *link.Iter // the task walk, attached once and opened per walk
	logger   *slog.Logger
	sub      subtree
	stop     chan struct{}
	done     chan struct{}
	reported [bpf.ScopeStatsMax]uint64 // last counts logged, owned by watch
	// What the last walk found and logged, so the next logs only what is
	// new, and keeps only what it finds again. Owned by the walk.
	last walkFindings
	// Where the walk last found each recorded cgroup, and the recorded
	// cgroups it can no longer find (removed, or outside our cgroup
	// namespace's root), which it stops looking for. Both hold only ids
	// still in the map. Owned by the walk.
	paths   map[uint64]string
	settled map[uint64]bool
}

// walkFindings is what one walk found that it logs: cgroups shared with a
// task outside our pid namespace, cgroups it could not record or read,
// and processes of ours in the root cgroup or outside our cgroup
// namespace's root, where the hook never sees their sockets.
type walkFindings struct {
	shared, unremoved, unrecorded, unreadable map[uint64]bool
	inRoot, outside                           map[uint32]bool
}

func newWalkFindings() walkFindings {
	return walkFindings{
		shared: make(map[uint64]bool), unremoved: make(map[uint64]bool),
		unrecorded: make(map[uint64]bool), unreadable: make(map[uint64]bool),
		inRoot: make(map[uint32]bool), outside: make(map[uint32]bool),
	}
}

// subtree is the cgroup whose whole subtree a scoped hook judges, as both
// collections take it: id 0 when there is none. Its level is the
// kernel's, which the walk reads: in a cgroup namespace rooted below the
// machine's, the path's depth is not it.
type subtree struct {
	path  string
	id    uint64
	level uint32
}

// subtreeLevel is the kernel's level of the subtree at sub, from our own
// cgroup at own, whose kernel level is ownLevel: both paths are below the
// same namespace root, so their depths differ as their levels do.
func subtreeLevel(sub, own string, ownLevel uint32) (uint32, error) {
	if !under(own, sub) {
		return 0, fmt.Errorf("this process's cgroup %s is not under the job's cgroup %s", own, sub)
	}
	below := podenv.CgroupLevel(own) - podenv.CgroupLevel(sub)
	if ownLevel <= below {
		return 0, fmt.Errorf("the job's cgroup %s would be at or above the root", sub)
	}
	return ownLevel - below, nil
}

// setCgroupScope sets the scoped hook's load-time constants, the job's
// subtree, once the walk has read its level.
func setCgroupScope(spec *ebpf.CollectionSpec, sub subtree) error {
	id, level := spec.Variables[bpf.OriginBpfVarScopeSubtreeCgroup], spec.Variables[bpf.OriginBpfVarScopeSubtreeLevel]
	if id == nil || level == nil || spec.Maps[bpf.OriginBpfMapMapScopeCgroups] == nil {
		return errors.New("origin BPF spec has no scope variables or scope map (stale generated code)")
	}
	if err := id.Set(sub.id); err != nil {
		return fmt.Errorf("failed to set the job's cgroup: %w", err)
	}
	if err := level.Set(sub.level); err != nil {
		return fmt.Errorf("failed to set the job's cgroup level: %w", err)
	}
	return nil
}

// startCgroupScope loads the scope collection for our pid namespace, attaches
// its tracepoints, then walks the tasks that predate them, so a task that
// enters a cgroup while the walk runs is recorded by one or the other.
// subtreePath is the job's subtree, which the hook judges whole: the
// programs leave it alone and the walk skips it. The verifier logs only
// its statistics, as for the origin collection: a branch-level log of each
// program would be kept for the life of the process.
func startCgroupScope(logger *slog.Logger, subtreePath string) (*cgroupScope, error) {
	ino, err := podenv.PidNamespaceInode()
	if err != nil {
		return nil, fmt.Errorf("cgroup scope: %w", err)
	}
	sub := subtree{path: subtreePath}
	if subtreePath != "" {
		if sub.id, err = podenv.CgroupID(subtreePath); err != nil {
			return nil, fmt.Errorf("cgroup scope: the job's cgroup: %w", err)
		}
	}
	spec, err := bpf.LoadScopeBpf()
	if err != nil {
		return nil, fmt.Errorf("cgroup scope: failed to load BPF spec: %w", err)
	}
	for name, value := range map[string]any{
		bpf.ScopeBpfVarPidnsIno:      ino,
		bpf.ScopeBpfVarSubtreeCgroup: sub.id,
	} {
		if v := spec.Variables[name]; v == nil {
			return nil, fmt.Errorf("cgroup scope: BPF spec has no %s variable (stale generated code)", name)
		} else if err := v.Set(value); err != nil {
			return nil, fmt.Errorf("cgroup scope: failed to set %s: %w", name, err)
		}
	}
	s := &cgroupScope{
		logger: logger, sub: sub, stop: make(chan struct{}), done: make(chan struct{}),
		last: newWalkFindings(), paths: make(map[uint64]string), settled: make(map[uint64]bool),
	}
	if err := cargowallEbpf.LoadObjects(logger, "scopebpf", spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	}, &s.objs); err != nil {
		return nil, fmt.Errorf("cgroup scope: failed to load BPF objects: %w", err)
	}
	for _, p := range []*ebpf.Program{s.objs.ScopeFork, s.objs.ScopeAttach, s.objs.ScopeRelease} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachTraceRawTp})
		if err != nil {
			s.release()
			return nil, fmt.Errorf("cgroup scope: failed to attach %s: %w", p, err)
		}
		s.links = append(s.links, l)
	}
	if s.iter, err = link.AttachIter(link.IterOptions{Program: s.objs.ScopeTaskIter}); err != nil {
		s.release()
		return nil, fmt.Errorf("cgroup scope: failed to attach the task walk: %w", err)
	}
	s.links = append(s.links, s.iter)
	if err := s.walk(true); err != nil {
		s.release()
		return nil, fmt.Errorf("cgroup scope: task walk: %w", err)
	}
	go s.watch()
	return s, nil
}

// cgroups is the map the scoped hook loads in place of its stand-in.
func (s *cgroupScope) cgroups() *ebpf.Map { return s.objs.MapScopeCgroups }

// walk records the cgroups the task walk lists, our tasks' cgroups, that
// are this job's alone: outside the job's subtree, which the hook judges
// whole, and holding no task outside our pid namespace; and it takes out
// each listed cgroup that does hold one. A task's cgroup does not say it
// entered it. A task of ours in the same cgroup as a node daemon or
// another pod's task was left there (a job an nsenter'd shell started) or
// is about to be moved out (a runtime's exec), and recording that cgroup
// would judge the daemon or the pod. Such a cgroup is reported and left
// out, and the task's sockets pass; once the other task has gone, a later
// walk records it again. The check reads cgroup.threads, which numbers
// each task as our pid namespace does, so a task outside it reads as 0.
// A cgroup that cannot be read is reported and passed over, and the rest
// are still reconciled. Then it checks the recorded cgroups the listing
// did not reach (reconcileRecorded).
//
// The first walk, at startup, must list this process's own cgroup, which
// is in the subtree: one that lists none of ours would leave the scope
// empty while the hook reports it attached. It reads the subtree's level
// from it too. Later walks only reconcile.
func (s *cgroupScope) walk(first bool) error {
	tasks, err := s.walkTasks()
	if err != nil {
		return err
	}
	if first {
		if err := s.checkOwn(tasks); err != nil {
			return err
		}
	}
	found := newWalkFindings()
	done := make(map[uint64]bool) // listed cgroups this pass reconciled, or the subtree covers
	for id, l := range tasks {
		if l.level == 0 {
			for tgid := range l.tgids {
				found.inRoot[tgid] = true
				if !s.last.inRoot[tgid] {
					s.logger.Warn("A task of this job is in the root cgroup, where its sockets pass the cgroup hook",
						"pid", tgid)
				}
			}
			continue
		}
		path, ok, outside := cgroupPathOf(id, l.tgids)
		for tgid, p := range outside {
			found.outside[tgid] = true
			if !s.last.outside[tgid] {
				s.logger.Warn("A task of this job is in a cgroup outside our cgroup namespace's root, "+
					"which the cgroup hook never sees", "pid", tgid, "cgroup", p)
			}
		}
		if !ok {
			continue // its tasks have gone (a move was recorded): reconcileRecorded has it
		}
		done[id] = true
		if under(path, s.sub.path) {
			continue
		}
		s.paths[id] = path
		existed := s.recorded(id)
		s.reconcile(id, path, &found, func() {
			if !existed {
				s.record(id, path, &found)
			}
		})
	}
	s.reconcileRecorded(done, &found)
	s.last = found
	return nil
}

// reconcile reads the cgroup at path, id, and takes it out of the scope if
// a task outside our pid namespace is in it, or else runs ours. A cgroup
// removed meanwhile is neither; one that cannot be read is reported.
func (s *cgroupScope) reconcile(id uint64, path string, found *walkFindings, ours func()) {
	shared, err := sharedCgroup(filepath.Join(podenv.CgroupRoot, path))
	switch {
	case cgroupGone(err):
	case err != nil:
		found.unreadable[id] = true
		if !s.last.unreadable[id] {
			s.logger.Warn("Container egress cgroup scope cannot read a cgroup this job is in, and leaves it as it is",
				"cgroup", path, "error", err)
		}
	case shared:
		s.leave(id, path, found)
	default:
		ours()
	}
}

// reconcileRecorded checks the cgroups in the scope that the listing did
// not reconcile, which hold no task of ours it could find: one a task of ours entered
// beside another task, or at the same moment as one, and has since left,
// or one a failed delete left in. Each is found where the walk last saw it
// or, failing that, by one look over the cgroup tree. One that is not
// there has been removed (no task can enter it again) or lies outside our
// cgroup namespace's root (beyond the hook), and is not looked for again.
func (s *cgroupScope) reconcileRecorded(done map[uint64]bool, found *walkFindings) {
	var ids []uint64
	var id uint64
	var v uint8
	for it := s.objs.MapScopeCgroups.Iterate(); it.Next(&id, &v); {
		ids = append(ids, id)
	}
	inMap := make(map[uint64]bool, len(ids))
	var lost []uint64
	for _, id := range ids {
		inMap[id] = true
		if done[id] || s.settled[id] {
			continue
		}
		if p, ok := s.paths[id]; !ok || !isCgroup(p, id) {
			lost = append(lost, id)
		}
	}
	if len(lost) > 0 {
		for id, p := range cgroupPaths(lost) {
			s.paths[id] = p
		}
		for _, id := range lost {
			if p, ok := s.paths[id]; !ok || !isCgroup(p, id) {
				s.settled[id] = true
				delete(s.paths, id)
			}
		}
	}
	for _, id := range ids {
		if done[id] || s.settled[id] {
			continue
		}
		s.reconcile(id, s.paths[id], found, func() {})
	}
	for id := range s.paths {
		if !inMap[id] {
			delete(s.paths, id)
		}
	}
	for id := range s.settled {
		if !inMap[id] {
			delete(s.settled, id)
		}
	}
}

// isCgroup reports whether the cgroup at path is still id.
func isCgroup(path string, id uint64) bool {
	got, err := podenv.CgroupID(path)
	return err == nil && got == id
}

// cgroupPaths looks over the cgroup tree for the cgroups with the given
// ids, and returns the paths it found them at.
func cgroupPaths(ids []uint64) map[uint64]string {
	want := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	paths := make(map[uint64]string)
	_ = filepath.WalkDir(podenv.CgroupRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if id := info.Sys().(*syscall.Stat_t).Ino; want[id] {
			rel, _ := filepath.Rel(podenv.CgroupRoot, path)
			paths[id] = filepath.Join("/", rel)
			if len(paths) == len(want) {
				return fs.SkipAll
			}
		}
		return nil
	})
	return paths
}

// checkOwn requires the task walk to have listed this process's own
// cgroup, and reads the subtree's level from it.
func (s *cgroupScope) checkOwn(tasks map[uint64]*listed) error {
	own, err := podenv.ReadCgroupPath("/proc/self/cgroup")
	if err != nil {
		return err
	}
	ownID, err := podenv.CgroupID(own)
	if err != nil {
		return err
	}
	ours, ok := tasks[ownID]
	if !ok {
		return fmt.Errorf("the task walk did not list this process's cgroup %s", own)
	}
	if s.sub.id != 0 {
		if s.sub.level, err = subtreeLevel(s.sub.path, own, ours.level); err != nil {
			return err
		}
	}
	return nil
}

func (s *cgroupScope) recorded(id uint64) bool {
	var v uint8
	return s.objs.MapScopeCgroups.Lookup(id, &v) == nil
}

// record puts a cgroup the walk found ours alone, and not yet in the
// scope, in the scope, then looks again: a task outside our pid namespace
// that entered it after the first look was not seen by the tracepoints,
// which take a cgroup out as such a task enters, because the entry did not
// exist yet. A tracepoint may have made it since, which changes nothing. A
// cgroup already in the scope before the first look needs neither: the
// tracepoints have seen every entry since. As in the kernel, a cgroup the
// map cannot take costs its own sockets, not the scope. One released since
// the walk listed it stays, a dead id: ids are never reused.
func (s *cgroupScope) record(id uint64, path string, found *walkFindings) {
	err := s.objs.MapScopeCgroups.Update(id, uint8(1), ebpf.UpdateNoExist)
	if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		found.unrecorded[id] = true
		if !s.last.unrecorded[id] {
			s.logger.Warn("Container egress cgroup scope could not record a cgroup this job is in, "+
				"and its sockets pass the cgroup hook", "cgroup", path, "error", err,
				"capacity", s.objs.MapScopeCgroups.MaxEntries())
		}
		return
	}
	if shared, err := sharedCgroup(filepath.Join(podenv.CgroupRoot, path)); err == nil && shared {
		s.leave(id, path, found)
	}
}

// leave takes a cgroup the walk found shared out of the scope, should a
// tracepoint or an earlier walk have recorded it: a task outside our pid
// namespace is in it, which the hook must not judge. Logged when the last
// walk did not find it shared.
func (s *cgroupScope) leave(id uint64, path string, found *walkFindings) {
	if err := s.objs.MapScopeCgroups.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		found.unremoved[id] = true
		if !s.last.unremoved[id] {
			s.logger.Warn("Container egress cgroup scope could not take out a cgroup it shares with tasks outside "+
				"this job, whose sockets the hook still judges", "cgroup", path, "error", err)
		}
		return
	}
	found.shared[id] = true
	if !s.last.shared[id] {
		s.logger.Warn("A task of this job is in a cgroup shared with tasks outside it, "+
			"where its sockets pass the cgroup hook", "cgroup", path)
	}
}

// listed is what the task walk wrote of a cgroup: the processes (as
// numbered in our pid namespace) it listed there, and its level.
type listed struct {
	tgids map[uint32]bool
	level uint32
}

// walkTasks runs the task walk and returns what it listed of each cgroup,
// by id.
func (s *cgroupScope) walkTasks() (map[uint64]*listed, error) {
	rd, err := s.iter.Open()
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	out, err := io.ReadAll(rd)
	if err != nil {
		return nil, err
	}
	const rec = 24 // cgroup id, process id, level: three u64s
	if len(out)%rec != 0 {
		return nil, fmt.Errorf("task walk wrote %d bytes, not a whole number of records", len(out))
	}
	tasks := make(map[uint64]*listed)
	for i := 0; i < len(out); i += rec {
		id := binary.NativeEndian.Uint64(out[i:])
		if tasks[id] == nil {
			tasks[id] = &listed{tgids: make(map[uint32]bool), level: uint32(binary.NativeEndian.Uint64(out[i+16:]))}
		}
		tasks[id].tgids[uint32(binary.NativeEndian.Uint64(out[i+8:]))] = true
	}
	return tasks, nil
}

// cgroupPathOf finds the path of cgroup id through a process the walk
// listed in it: the process's own cgroup or, when that is no longer id
// (the process has moved, or the task was a thread in a cgroup of its
// own), one of its threads'. False when none of them is in it now. It also
// returns, by process, a cgroup path it met outside our cgroup namespace's
// root (above /sys/fs/cgroup, where "/.." starts it), which cannot be read:
// that process is beyond the hook, whatever id is.
func cgroupPathOf(id uint64, tgids map[uint32]bool) (string, bool, map[uint32]string) {
	outside := make(map[uint32]string)
	for tgid := range tgids {
		proc := fmt.Sprintf("/proc/%d", tgid)
		files := []string{proc + "/cgroup"}
		for i := 0; i < len(files); i++ {
			path, err := podenv.ReadCgroupPath(files[i])
			switch {
			case err != nil:
			case strings.HasPrefix(path, "/.."):
				outside[tgid] = path
			case isCgroup(path, id):
				return path, true, outside
			}
			if i == 0 {
				threads, _ := filepath.Glob(proc + "/task/*/cgroup")
				files = append(files, threads...)
			}
		}
	}
	return "", false, outside
}

// under reports whether the cgroup at path is sub or below it, by path:
// scopebpf.c's in_subtree asks the same of an id, through at most 32
// parents, and past that records a cgroup the hook judges anyway.
func under(path, sub string) bool {
	return sub != "" && (path == sub || strings.HasPrefix(path, sub+"/"))
}

// cgroupGone reports whether err says the cgroup was removed: a file of a
// removed cgroup is missing, or, opened before the removal, reads ENODEV.
func cgroupGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENODEV)
}

// readThreads reads a cgroup.threads file; a test stands in for it.
var readThreads = os.ReadFile

// sharedCgroup reports whether the cgroup at dir holds a task outside our
// pid namespace: one cgroup.threads lists as 0.
func sharedCgroup(dir string) (bool, error) {
	data, err := readThreads(filepath.Join(dir, "cgroup.threads"))
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

// watch walks the tasks again and reports what the scope could not record,
// on every tick until close. Each shortfall leaves a task of ours whose
// sockets the hook passes, so each is a warning.
func (s *cgroupScope) watch() {
	defer close(s.done)
	t := time.NewTicker(scopeStatsInterval)
	defer t.Stop()
	var failing string // the walk's last error, logged once until it changes
	for {
		select {
		case <-s.stop:
			s.report()
			return
		case <-t.C:
			if err := s.walk(false); err != nil {
				if err.Error() != failing {
					failing = err.Error()
					s.logger.Warn("Container egress cgroup scope: task walk failed, and the scope stands as it was",
						"error", err)
				}
			} else if failing != "" {
				failing = ""
				s.logger.Info("Container egress cgroup scope: task walk recovered")
			}
			s.report()
		}
	}
}

func (s *cgroupScope) report() {
	for slot, msg := range [bpf.ScopeStatsMax]string{
		bpf.ScopeStatFull: "Container egress cgroup scope full: cgroups this job entered were not recorded, and their sockets pass the cgroup hook",
		bpf.ScopeStatRoot: "Tasks of this job entered the root cgroup, where their sockets pass the cgroup hook",
		bpf.ScopeStatFailed: "Container egress cgroup scope failed to record or take out cgroups as tasks entered them, " +
			"which stay as they were until the next walk",
		bpf.ScopeStatShared: "Cgroups this job entered were entered by tasks outside it and left the scope: " +
			"sockets there pass the cgroup hook",
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
func (s *cgroupScope) close() {
	close(s.stop)
	<-s.done
	s.release()
}

func (s *cgroupScope) release() {
	for _, l := range s.links {
		_ = l.Close()
	}
	s.objs.Close()
}
