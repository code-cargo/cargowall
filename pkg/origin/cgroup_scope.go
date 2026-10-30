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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

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
// out as another task enters it, marking it shared so that the job's next
// entry does not record it again, which is immediate but sees only those
// events. The walk is the ground truth: at startup and on every tick it
// records each cgroup that holds a task of ours and no other, clearing its
// mark, takes out and marks each one that holds another too, and clears
// the mark of one no other is in any more, whatever the programs saw. It
// opens each cgroup by its id (openCgroup), so it needs no path to find
// one, and reads who is in it there.
type cgroupScope struct {
	objs     bpf.ScopeBpfObjects
	links    []link.Link
	iter     *link.Iter // the task walk, attached once and opened per walk
	mount    *os.File   // podenv.CgroupRoot, which openCgroup opens cgroups through
	logger   *slog.Logger
	sub      subtree
	stop     chan struct{}
	done     chan struct{}
	reported [bpf.ScopeStatsMax]uint64 // last counts logged, owned by watch
	// What the last walk found and logged, so the next logs only what is
	// new, and keeps only what it finds again. Owned by the walk.
	last walkFindings
	// Recorded cgroups the walk found removed, which it no longer opens:
	// ids are never reused, and release takes their entries out. It keeps
	// only ids still in the map. Owned by the walk.
	stale map[uint64]bool
}

// walkFindings is what one walk found that it logs: cgroups shared with a
// task outside our pid namespace, cgroups it could not record or read,
// processes of ours in the root cgroup or outside our cgroup namespace's
// root, where the hook never sees their sockets, and whether it could not
// read the whole scope.
type walkFindings struct {
	shared, unremoved, unrecorded, unreadable map[uint64]bool
	inRoot, outside                           map[uint32]bool
	unlisted                                  bool
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
		bpf.ScopeBpfVarSelfTgid:      uint32(os.Getpid()),
	} {
		if v := spec.Variables[name]; v == nil {
			return nil, fmt.Errorf("cgroup scope: BPF spec has no %s variable (stale generated code)", name)
		} else if err := v.Set(value); err != nil {
			return nil, fmt.Errorf("cgroup scope: failed to set %s: %w", name, err)
		}
	}
	s := &cgroupScope{
		logger: logger, sub: sub, stop: make(chan struct{}), done: make(chan struct{}),
		last: newWalkFindings(), stale: make(map[uint64]bool),
	}
	if err := cargowallEbpf.LoadObjects(logger, "scopebpf", spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	}, &s.objs); err != nil {
		return nil, fmt.Errorf("cgroup scope: failed to load BPF objects: %w", err)
	}
	if s.mount, err = os.Open(podenv.CgroupRoot); err != nil {
		s.release()
		return nil, fmt.Errorf("cgroup scope: %w", err)
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
// walk records it again. A cgroup that cannot be read is reported and
// passed over, and the rest are still reconciled. Then it checks the
// recorded cgroups the listing did not reach (reconcileRecorded).
//
// The first walk, at startup, must list this process's own cgroup, which
// is in the subtree: one that lists none of ours would leave the scope
// empty while the hook reports it attached. It reads the subtree's level
// from it too. Later walks only reconcile, and stop between cgroups once
// close has asked, so a close waits out one cgroup, not the walk.
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
	marked := s.readMarks(&found)
	for id, l := range tasks {
		if s.stopping() {
			return nil
		}
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
		s.reconcileListed(id, l, marked[id], &found)
	}
	if s.reconcileRecorded(tasks, &found) && s.reconcileMarked(tasks, marked, &found) {
		s.last = found
	}
	return nil
}

// readMarks reads the cgroups marked shared (map_scope_shared). A read cut
// short is reported as the scope's is, and what it read still counts.
func (s *cgroupScope) readMarks(found *walkFindings) map[uint64]bool {
	ids, err := scopeCgroups(s.objs.MapScopeShared)
	if err != nil {
		s.cutShort(err, found)
	}
	marked := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		marked[id] = true
	}
	return marked
}

// reconcileMarked clears the mark of each cgroup marked shared that the
// listing did not reach and that no task outside our pid namespace is in
// any more, so that a task of ours entering it is recorded again as it
// enters. One removed loses its mark. False when close cut it short.
func (s *cgroupScope) reconcileMarked(listed map[uint64]*listed, marked map[uint64]bool, found *walkFindings) bool {
	for id := range marked {
		if s.stopping() {
			return false
		}
		if listed[id] != nil {
			continue
		}
		dir, path, _, err := s.openCgroup(id)
		if cgroupGone(err) {
			s.unmark(id)
			continue
		}
		if err != nil {
			s.unreadable(id, fmt.Sprintf("id %d", id), err, found)
			continue
		}
		m, err := cgroupMembers(dir)
		dir.Close()
		switch {
		case cgroupGone(err):
			s.unmark(id)
		case err != nil:
			s.unreadable(id, path, err, found)
		case !m.theirs:
			s.unmark(id)
		}
	}
	return true
}

// cutShort reports a read of the scope's maps that stopped early, once a
// walk and not again until a walk reads them whole.
func (s *cgroupScope) cutShort(err error, found *walkFindings) {
	if !found.unlisted && !s.last.unlisted {
		s.logger.Warn("Container egress cgroup scope could not read all its cgroups, "+
			"and those it missed stay as they are until a later walk", "error", err)
	}
	found.unlisted = true
}

// mark marks a cgroup shared, so that a task of ours entering it is not
// recorded (scope_enter); unmark clears that. A mark the map cannot take
// costs a recording that the next walk takes out again.
func (s *cgroupScope) mark(id uint64)   { _ = s.objs.MapScopeShared.Put(id, uint8(1)) }
func (s *cgroupScope) unmark(id uint64) { _ = s.objs.MapScopeShared.Delete(id) }

// stopping reports whether close has asked the walk to stop.
func (s *cgroupScope) stopping() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// reconcileListed reconciles cgroup id, which the task walk listed: one
// that holds a task of ours and no other is recorded, its shared mark
// cleared first. One outside our cgroup namespace's root is beyond the
// hook whatever it holds: an entry a tracepoint made for it is taken out
// (outsideRoot), and each process of ours there is reported.
func (s *cgroupScope) reconcileListed(id uint64, l *listed, marked bool, found *walkFindings) {
	dir, path, inside, err := s.openCgroup(id)
	if err != nil {
		s.unreadable(id, fmt.Sprintf("id %d", id), err, found)
		return
	}
	defer dir.Close()
	if !inside {
		s.outsideRoot(id)
		for tgid := range l.tgids {
			found.outside[tgid] = true
			if !s.last.outside[tgid] {
				p, _ := podenv.ReadCgroupPath(fmt.Sprintf("/proc/%d/cgroup", tgid))
				s.logger.Warn("A task of this job is in a cgroup outside our cgroup namespace's root, "+
					"which the cgroup hook never sees", "pid", tgid, "cgroup", p)
			}
		}
		return
	}
	if under(path, s.sub.path) {
		return
	}
	existed := s.recorded(id)
	s.reconcile(id, dir, path, found, func() {
		if marked {
			s.unmark(id)
		}
		if !existed {
			s.record(id, dir, path, found)
		}
	})
}

// reconcile reads who is in the cgroup open at dir, id, and takes it out
// of the scope if a task outside our pid namespace is in it, or else, if a
// task of ours is, runs ours. A cgroup removed meanwhile is neither; one
// that cannot be read is reported.
func (s *cgroupScope) reconcile(id uint64, dir *os.File, path string, found *walkFindings, ours func()) {
	m, err := cgroupMembers(dir)
	switch {
	case err != nil:
		s.unreadable(id, path, err, found)
	case m.theirs:
		s.leave(id, path, m.ours, found)
	case m.ours && ours != nil:
		ours()
	}
}

// unreadable reports a cgroup the walk could not open or read, which stays
// as it was, unless it has been removed, which needs nothing: no task can
// enter it again, and its release takes it out of the scope.
func (s *cgroupScope) unreadable(id uint64, path string, err error, found *walkFindings) {
	if cgroupGone(err) {
		return
	}
	found.unreadable[id] = true
	if !s.last.unreadable[id] {
		s.logger.Warn("Container egress cgroup scope cannot read a cgroup of this job's, and leaves it as it is",
			"cgroup", path, "error", err)
	}
}

// reconcileRecorded checks the cgroups in the scope that the listing did
// not reach, which held no task of ours when it ran: one a task of ours
// entered beside another task, or at the same moment as one, and has since
// left, or one a failed delete left in. One found removed is not opened
// again (stale), and one outside our cgroup namespace's root is taken out
// (outsideRoot). A read of the scope cut short still has the cgroups it
// read checked, and the rest wait for a later walk. False when close cut
// the pass short.
func (s *cgroupScope) reconcileRecorded(listed map[uint64]*listed, found *walkFindings) bool {
	ids, err := scopeCgroups(s.objs.MapScopeCgroups)
	if err != nil {
		s.cutShort(err, found)
	} else {
		inMap := make(map[uint64]bool, len(ids))
		for _, id := range ids {
			inMap[id] = true
		}
		for id := range s.stale {
			if !inMap[id] {
				delete(s.stale, id)
			}
		}
	}
	for _, id := range ids {
		if s.stopping() {
			return false
		}
		if listed[id] != nil || s.stale[id] {
			continue
		}
		dir, path, inside, err := s.openCgroup(id)
		if errors.Is(err, syscall.ESTALE) {
			s.stale[id] = true
			continue
		}
		if err != nil {
			s.unreadable(id, fmt.Sprintf("id %d", id), err, found)
			continue
		}
		if inside {
			s.reconcile(id, dir, path, found, nil)
		} else {
			s.outsideRoot(id)
		}
		dir.Close()
	}
	return true
}

// outsideRoot takes out of the scope a cgroup outside our cgroup
// namespace's root, which a task of ours entered: the hook, at that root,
// never sees its sockets, so its entry would only hold a place the map
// keeps for cgroups the hook does see. A tracepoint records it again on
// the next entry, and the next walk takes it out again.
func (s *cgroupScope) outsideRoot(id uint64) {
	_ = s.objs.MapScopeCgroups.Delete(id)
}

// scopeBatch is how many entries scopeCgroups reads per call.
const scopeBatch = 4096

// scopeCgroups reads the cgroup ids in the scope map in batches, bucket by
// bucket, which a concurrent delete does not restart, and returns those it
// read before an error. A test stands in for it.
var scopeCgroups = func(m *ebpf.Map) ([]uint64, error) {
	var ids []uint64
	var cursor ebpf.MapBatchCursor
	keys, values := make([]uint64, scopeBatch), make([]uint8, scopeBatch)
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		ids = append(ids, keys[:n]...)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ids, nil
		}
		if err != nil {
			return ids, err
		}
	}
}

// fileIDKernfs is the file handle type of a kernfs node (FILEID_KERNFS),
// whose handle is the node's 64-bit id: for a cgroup, the id a BPF program
// reads.
const fileIDKernfs = 0xfe

// openCgroup opens the cgroup with id, wherever it is, through the mount
// at podenv.CgroupRoot, and gives its path below that root. inside is false
// for a cgroup outside it, which is outside our cgroup namespace's root,
// where the kernel names no path in the mount. A removed cgroup's handle is
// stale even while the cgroup is dying (cgroupGone).
func (s *cgroupScope) openCgroup(id uint64) (dir *os.File, path string, inside bool, err error) {
	h := make([]byte, 8)
	binary.NativeEndian.PutUint64(h, id)
	fd, err := unix.OpenByHandleAt(int(s.mount.Fd()), unix.NewFileHandle(fileIDKernfs, h),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return nil, "", false, fmt.Errorf("open cgroup %d by its id: %w", id, err)
	}
	dir = os.NewFile(uintptr(fd), fmt.Sprintf("cgroup %d", id))
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		dir.Close()
		return nil, "", false, err
	}
	if target == podenv.CgroupRoot {
		return dir, "/", true, nil
	}
	rel, inside := strings.CutPrefix(target, podenv.CgroupRoot+"/")
	return dir, "/" + rel, inside, nil
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
	dir, _, _, err := s.openCgroup(ownID)
	if err != nil {
		return fmt.Errorf("the walk cannot open this process's cgroup %s by its id: %w", own, err)
	}
	dir.Close()
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
// map cannot take costs its own sockets, not the scope. One the second
// look finds removed may have been released before the entry was made, and
// release is all that takes an entry out, so the walk takes out its own:
// any socket of ours that outlives the cgroup passes, as it would had the
// walk come a moment later.
func (s *cgroupScope) record(id uint64, dir *os.File, path string, found *walkFindings) {
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
	made := err == nil
	m, err := cgroupMembers(dir)
	switch {
	case cgroupGone(err) && made:
		_ = s.objs.MapScopeCgroups.Delete(id)
	case err == nil && m.theirs:
		s.leave(id, path, m.ours, found)
	}
}

// leave takes a cgroup the walk found shared out of the scope, should a
// tracepoint or an earlier walk have recorded it, and marks it shared, so
// that a task of ours entering it again is not recorded: a task outside our
// pid namespace is in it, which the hook must not judge. ours says whether a
// task of ours is in it too. Logged when the last walk did not find it
// shared, and not at all when neither holds: a cgroup never in the scope
// that no task of ours is in now changes nothing (a runtime's exec stage
// listed in the runtime's cgroup has moved on).
func (s *cgroupScope) leave(id uint64, path string, ours bool, found *walkFindings) {
	s.mark(id)
	err := s.objs.MapScopeCgroups.Delete(id)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		found.unremoved[id] = true
		if !s.last.unremoved[id] {
			s.logger.Warn("Container egress cgroup scope could not take out a cgroup it shares with tasks outside "+
				"this job, whose sockets the hook still judges", "cgroup", path, "error", err)
		}
		return
	}
	if err != nil && !ours {
		return
	}
	found.shared[id] = true
	switch {
	case s.last.shared[id]:
	case ours:
		s.logger.Warn("A task of this job is in a cgroup shared with tasks outside it, "+
			"where its sockets pass the cgroup hook", "cgroup", path)
	default:
		s.logger.Warn("A cgroup a task of this job entered holds tasks outside it, and no longer one of "+
			"this job's: it leaves the scope, and sockets this job made there pass the cgroup hook", "cgroup", path)
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

// under reports whether the cgroup at path is sub or below it, by path:
// scopebpf.c's in_subtree asks the same of an id, through at most 32
// parents, and past that records a cgroup the hook judges anyway.
func under(path, sub string) bool {
	return sub != "" && (path == sub || strings.HasPrefix(path, sub+"/"))
}

// cgroupGone reports whether err says the cgroup was removed: its handle
// is stale, or a file opened through it is missing or, opened before the
// removal, reads ENODEV.
func cgroupGone(err error) bool {
	return errors.Is(err, syscall.ESTALE) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENODEV)
}

// readThreads reads the cgroup.threads of the cgroup open at dir; a test
// stands in for it.
var readThreads = func(dir *os.File) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), "cgroup.threads", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: dir.Name() + "/cgroup.threads", Err: err}
	}
	f := os.NewFile(uintptr(fd), dir.Name()+"/cgroup.threads")
	defer f.Close()
	return io.ReadAll(f)
}

// members is who a cgroup holds: tasks of our pid namespace, and tasks
// outside it (podenv.ThreadsMembers).
type members struct{ ours, theirs bool }

// cgroupMembers reads who the cgroup open at dir holds.
func cgroupMembers(dir *os.File) (members, error) {
	data, err := readThreads(dir)
	if err != nil {
		return members{}, err
	}
	var m members
	m.ours, m.theirs = podenv.ThreadsMembers(data)
	return m, nil
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
		bpf.ScopeStatUnreleased: "Container egress cgroup scope failed to forget released cgroups, " +
			"whose entries keep their places in it for good",
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
	if s.mount != nil {
		_ = s.mount.Close()
	}
}
