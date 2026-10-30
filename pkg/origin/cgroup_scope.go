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
	watching bool                      // start has run watch, which closes done
	reported [bpf.ScopeStatsMax]uint64 // last counts logged, owned by watch
	// When each finding was last logged (warn), and the clock that tells,
	// which a test stands in for. Owned by the walk.
	warned map[finding]time.Time
	now    func() time.Time
	// Recorded cgroups the walk found removed, which it no longer opens:
	// ids are never reused, and release takes their entries out. It keeps
	// only ids still in the map. Owned by the walk.
	stale map[uint64]bool
}

// finding is what a walk logs: a cgroup, by id, shared with a task outside
// our pid namespace, or one it could not take out, record, read or mark;
// a process of ours, by its pid in our namespace, in the root cgroup or
// outside our cgroup namespace's root, where the hook never sees its
// sockets; or a read of the scope's maps cut short.
type finding struct {
	kind findingKind
	id   uint64
}

type findingKind uint8

const (
	findShared findingKind = iota
	findLeft
	findUnremoved
	findUnrecorded
	findUnreadable
	findUnreadableOwn
	findUnmarked
	findInRoot
	findOutside
	findUnlisted
)

// warnEvery is how long a finding stays logged: it is logged again no
// sooner, whether it persists or comes and goes, as a runtime's periodic
// exec stage does.
const warnEvery = 5 * time.Minute

// warn reports whether a finding is to be logged now, not having been
// within warnEvery, and notes it as logged.
func (s *cgroupScope) warn(kind findingKind, id uint64) bool {
	k := finding{kind, id}
	now := s.now()
	if t, ok := s.warned[k]; ok && now.Sub(t) < warnEvery {
		return false
	}
	s.warned[k] = now
	return true
}

// forgetWarned forgets what was logged longer than warnEvery ago, which
// warn would log again anyway, so what the walk keeps stays bounded.
func (s *cgroupScope) forgetWarned() {
	now := s.now()
	for k, t := range s.warned {
		if now.Sub(t) >= warnEvery {
			delete(s.warned, k)
		}
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
	if !podenv.Under(own, sub) {
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

// loadCgroupScope loads the scope collection for our pid namespace and
// finds this process's cgroup in a first look over the tasks (findOwn),
// which gives the subtree's level, while nothing of the scope is attached:
// the hook is verified with the scope's map and that level before the
// scope's tracepoints change anything on the node (start). subtreePath is
// the job's subtree, which the hook judges whole: the programs leave it
// alone and the walk skips it. The verifier logs only its statistics, as
// for the origin collection: a branch-level log of each program would be
// kept for the life of the process.
func loadCgroupScope(logger *slog.Logger, subtreePath string) (*cgroupScope, error) {
	ino, err := podenv.PidNamespaceInode()
	if err != nil {
		return nil, fmt.Errorf("cgroup scope: %w", err)
	}
	// A scope always has its subtree (podenv.Scope.Limited); the programs'
	// subtree-less mode serves their tests alone.
	if subtreePath == "" {
		return nil, errors.New("cgroup scope: no job cgroup to scope to")
	}
	sub := subtree{path: subtreePath}
	if sub.id, err = podenv.CgroupID(subtreePath); err != nil {
		return nil, fmt.Errorf("cgroup scope: the job's cgroup: %w", err)
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
		warned: make(map[finding]time.Time), now: time.Now, stale: make(map[uint64]bool),
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
	// The walk's iterator runs only when read, so attaching it hooks
	// nothing.
	if s.iter, err = link.AttachIter(link.IterOptions{Program: s.objs.ScopeTaskIter}); err != nil {
		s.release()
		return nil, fmt.Errorf("cgroup scope: failed to attach the task walk: %w", err)
	}
	s.links = append(s.links, s.iter)
	if err := s.findOwn(); err != nil {
		s.release()
		return nil, fmt.Errorf("cgroup scope: task walk: %w", err)
	}
	return s, nil
}

// start attaches the scope's tracepoints, then walks the tasks that
// predate them, so a task that enters a cgroup while the walk runs is
// recorded by one or the other, and watches from then on. On an error the
// caller closes the scope.
func (s *cgroupScope) start() error {
	for _, p := range []*ebpf.Program{s.objs.ScopeFork, s.objs.ScopeAttach, s.objs.ScopeRelease} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachTraceRawTp})
		if err != nil {
			return fmt.Errorf("cgroup scope: failed to attach %s: %w", p, err)
		}
		s.links = append(s.links, l)
	}
	if err := s.walk(); err != nil {
		return fmt.Errorf("cgroup scope: task walk: %w", err)
	}
	s.watching = true
	go s.watch()
	return nil
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
// A walk stops between cgroups once close has asked, so a close waits out
// one cgroup, not the walk.
func (s *cgroupScope) walk() error {
	tasks, err := s.walkTasks()
	if err != nil {
		return err
	}
	s.forgetWarned()
	marked := s.readMarks()
	for id, l := range tasks {
		if s.stopping() {
			return nil
		}
		if l.level == 0 {
			for tgid := range l.tgids {
				if s.warn(findInRoot, uint64(tgid)) {
					s.logger.Warn("A task of this job is in the root cgroup, where its sockets pass the cgroup hook",
						"pid", tgid)
				}
			}
			continue
		}
		s.reconcileListed(id, l, marked[id])
	}
	if s.reconcileRecorded(tasks) {
		s.reconcileMarked(tasks, marked)
	}
	return nil
}

// readMarks reads the cgroups marked shared (map_scope_shared). A read cut
// short is reported as the scope's is, and what it read still counts.
func (s *cgroupScope) readMarks() map[uint64]bool {
	ids, err := scopeCgroups(s.objs.MapScopeShared)
	if err != nil {
		s.cutShort(s.objs.MapScopeShared, err)
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
// enters. One removed loses its mark, and one under the job's subtree is
// left as it is. It stops once close has asked.
func (s *cgroupScope) reconcileMarked(tasks map[uint64]*listed, marked map[uint64]bool) {
	for id := range marked {
		if s.stopping() {
			return
		}
		if tasks[id] != nil {
			continue
		}
		dir, path, inside, gone := s.open(id)
		if gone {
			s.forgetMark(id)
		}
		if dir == nil {
			continue
		}
		if !podenv.Under(path, s.sub.path) {
			s.clearMark(id, dir, path, inside)
		}
		dir.Close()
	}
}

// cutShort reports a read of one of the scope's maps, m, that stopped
// early, each map's apart.
func (s *cgroupScope) cutShort(m *ebpf.Map, err error) {
	var id uint64
	if m == s.objs.MapScopeShared {
		id = 1
	}
	if s.warn(findUnlisted, id) {
		s.logger.Warn("Container egress cgroup scope could not read all its cgroups, "+
			"and those it missed stay as they are until a later walk", "map", m.String(), "error", err)
	}
}

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
// cleared first (unmark, which records it once it has settled). One
// outside our cgroup namespace's root is beyond the hook whatever it
// holds: an entry a tracepoint made for it is taken out (outsideRoot), and
// each process of ours there is reported.
func (s *cgroupScope) reconcileListed(id uint64, l *listed, marked bool) {
	dir, path, inside, _ := s.open(id)
	if dir == nil {
		return
	}
	defer dir.Close()
	if !inside {
		s.outsideRoot(id)
		for tgid := range l.tgids {
			if s.warn(findOutside, uint64(tgid)) {
				p, _ := podenv.ReadCgroupPath(fmt.Sprintf("/proc/%d/cgroup", tgid))
				s.logger.Warn("A task of this job is in a cgroup outside our cgroup namespace's root, "+
					"which the cgroup hook never sees", "pid", tgid, "cgroup", p)
			}
		}
		return
	}
	if podenv.Under(path, s.sub.path) {
		return
	}
	existed := s.recorded(id)
	if m, ok, _ := s.look(id, dir, path); ok && m.ours {
		switch {
		case marked:
			s.unmark(id, dir, path, true)
		case !existed:
			s.record(id, dir, path)
		}
	}
}

// look reads who is in the cgroup open at dir, id, for a pass over it,
// and takes it out of the scope if a task outside our pid namespace is in
// it (leave). ok is whether none is, and m then says whether a task of
// ours is; gone, whether the cgroup has been removed. One that cannot be
// read is kept out of the scope (unreadable).
func (s *cgroupScope) look(id uint64, dir *os.File, path string) (m members, ok, gone bool) {
	m, err := cgroupMembers(dir)
	switch {
	case err != nil:
		s.unreadable(id, path, err)
		return m, false, cgroupGone(err)
	case m.theirs:
		s.leave(id, path, m.ours, false)
		return m, false, false
	}
	return m, true, false
}

// open opens cgroup id for a pass of the walk; one it cannot open is kept
// out of the scope (unreadable). gone says the cgroup has been removed,
// which needs nothing.
func (s *cgroupScope) open(id uint64) (dir *os.File, path string, inside, gone bool) {
	dir, path, inside, err := s.openCgroup(id)
	if err != nil {
		s.unreadable(id, fmt.Sprintf("id %d", id), err)
		return nil, "", false, cgroupGone(err)
	}
	return dir, path, inside, false
}

// unreadable keeps a cgroup the walk could not open or read out of the
// scope, as settle does, since whether a task outside is in it is unknown:
// one recorded is marked and taken out, and one marked keeps its mark. A
// fault of the walk's own (ownFault) says nothing of the cgroup, which is
// left as it was: a moment short of descriptors or memory would otherwise
// take every cgroup of the job's out of the scope. Both are reported. One
// removed needs nothing: no task can enter it again, and its release takes
// it out of the scope.
func (s *cgroupScope) unreadable(id uint64, path string, err error) {
	if cgroupGone(err) {
		return
	}
	own := ownFault(err)
	if !own && s.recorded(id) {
		s.mark(id, path, true)
		_ = s.objs.MapScopeCgroups.Delete(id)
	}
	kind := findUnreadable
	if own {
		kind = findUnreadableOwn
	}
	if !s.warn(kind, id) {
		return
	}
	if own {
		s.logger.Warn("Container egress cgroup scope could not read a cgroup of this job's for want of its own "+
			"descriptors or memory, and leaves it as it was until a walk can", "cgroup", path, "cgroup_id", id, "error", err)
		return
	}
	s.logger.Warn("Container egress cgroup scope cannot read a cgroup of this job's, and keeps it out of "+
		"the scope until a walk can: sockets of this job there pass the cgroup hook",
		"cgroup", path, "cgroup_id", id, "error", err)
}

// ownFault reports whether a failure to open or read a cgroup is the
// walk's own, for want of descriptors or memory, or an interruption past
// its retries, rather than anything the cgroup's state could explain.
func ownFault(err error) bool {
	for _, e := range []error{unix.EMFILE, unix.ENFILE, unix.ENOMEM, unix.ENOBUFS, unix.EAGAIN, unix.EINTR} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// retryEINTR runs a system call again, a few times, while a signal
// interrupts it.
func retryEINTR(call func() (int, error)) (int, error) {
	for range 3 {
		if fd, err := call(); !errors.Is(err, unix.EINTR) {
			return fd, err
		}
	}
	return call()
}

// reconcileRecorded checks the cgroups in the scope that the listing did
// not reach, which held no task of ours when it ran: one a task of ours
// entered beside another task, or at the same moment as one, and has since
// left, or one a failed delete left in. One found removed is not opened
// again (stale), and one outside our cgroup namespace's root is taken out
// (outsideRoot); one under the job's subtree, which in_subtree's bound
// let a tracepoint record, is the hook's to judge whatever is in it, and
// is left as it is. A read of the scope cut short still has the cgroups it
// read checked, and the rest wait for a later walk. False when close cut
// the pass short.
func (s *cgroupScope) reconcileRecorded(tasks map[uint64]*listed) bool {
	ids, err := scopeCgroups(s.objs.MapScopeCgroups)
	if err != nil {
		s.cutShort(s.objs.MapScopeCgroups, err)
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
		if tasks[id] != nil || s.stale[id] {
			continue
		}
		dir, path, inside, gone := s.open(id)
		if gone {
			s.stale[id] = true
		}
		if dir == nil {
			continue
		}
		switch {
		case !inside:
			s.outsideRoot(id)
		case podenv.Under(path, s.sub.path):
			// The hook judges it whole whoever enters it, as the listing
			// leaves it.
		default:
			if _, _, gone := s.look(id, dir, path); gone {
				s.stale[id] = true
			}
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
	fd, err := retryEINTR(func() (int, error) {
		return unix.OpenByHandleAt(int(s.mount.Fd()), unix.NewFileHandle(fileIDKernfs, h),
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	})
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
	if !inside {
		// Beyond our namespace's root, no path of ours names it: the
		// kernel's own notation says where, as /proc/<pid>/cgroup does.
		return dir, "/..", false, nil
	}
	return dir, "/" + rel, true, nil
}

// findOwn looks over the tasks for this process's own cgroup, which is in
// the subtree, and reads the subtree's level from it (checkOwn), at
// startup: a look that lists none of ours would leave the scope empty
// while the hook reports it attached.
func (s *cgroupScope) findOwn() error {
	tasks, err := s.walkTasks()
	if err != nil {
		return err
	}
	return s.checkOwn(tasks)
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
	s.sub.level, err = subtreeLevel(s.sub.path, own, ours.level)
	return err
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

// cgroupGone reports whether err says the cgroup was removed: its handle
// is stale, or a file opened through it is missing or, opened before the
// removal, reads ENODEV.
func cgroupGone(err error) bool {
	return errors.Is(err, syscall.ESTALE) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENODEV)
}

// readThreads reads the cgroup.threads of the cgroup open at dir; a test
// stands in for it.
var readThreads = func(dir *os.File) ([]byte, error) {
	fd, err := retryEINTR(func() (int, error) {
		return unix.Openat(int(dir.Fd()), "cgroup.threads", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	})
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
			failing = s.rewalk(failing)
			s.report()
		}
	}
}

// rewalk walks the tasks again for watch, and logs a change in how the
// walk fares: failing is the last walk's error, "" for none, and the new
// one is returned. A walk close cut short reconciled nothing, so it shows
// no recovery.
func (s *cgroupScope) rewalk(failing string) string {
	if err := s.walk(); err != nil {
		if err.Error() != failing {
			s.logger.Warn("Container egress cgroup scope: task walk failed, and the scope stands as it was",
				"error", err)
		}
		return err.Error()
	}
	if s.stopping() {
		return failing
	}
	if failing != "" {
		s.logger.Info("Container egress cgroup scope: task walk recovered")
	}
	return ""
}

func (s *cgroupScope) report() {
	scope, shared := s.objs.MapScopeCgroups.MaxEntries(), s.objs.MapScopeShared.MaxEntries()
	for slot, w := range [bpf.ScopeStatsMax]struct {
		msg  string
		args []any // the capacities the count is against, if any
	}{
		bpf.ScopeStatFull: {"Container egress cgroup scope full: cgroups this job entered were not recorded, " +
			"and their sockets pass the cgroup hook", []any{"capacity", scope}},
		bpf.ScopeStatRoot: {"Tasks of this job entered the root cgroup, where their sockets pass the cgroup hook", nil},
		bpf.ScopeStatFailed: {"Container egress cgroup scope failed to record, take out or mark cgroups as tasks " +
			"entered them, which stay as they were until the next walk", []any{"capacity", scope, "shared_capacity", shared}},
		bpf.ScopeStatShared: {"Cgroups this job entered were entered by tasks outside it and left the scope: " +
			"sockets there pass the cgroup hook", nil},
		bpf.ScopeStatUnreleased: {"Container egress cgroup scope failed to forget released cgroups, " +
			"whose entries keep their places in it for good", []any{"capacity", scope}},
	} {
		var n uint64
		if err := s.objs.MapScopeStats.Lookup(uint32(slot), &n); err != nil || n <= s.reported[slot] {
			continue
		}
		s.reported[slot] = n
		s.logger.Warn(w.msg, append([]any{"times", n}, w.args...)...)
	}
}

// close stops recording. The hook's collection holds its own reference to
// the map, so closing the scope first would leave the hook judging a scope
// nothing updates; Observer.Close detaches the hook before calling this.
func (s *cgroupScope) close() {
	close(s.stop)
	if s.watching {
		<-s.done
	}
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
