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
	"errors"
	"os"

	"github.com/cilium/ebpf"
)

// The scope holds two entries per cgroup that the tracepoints and the walk
// both write, recorded (map_scope_cgroups) and marked shared
// (map_scope_shared), and the walk decides from a look at the cgroup's
// members: a task entering between the look and the walk's write meets the
// state before the write. Two writes can lose such an entry, and settle
// looks again after each, which record and unmark, the only ways the walk
// makes them, always do. Recording a cgroup: a task outside our pid
// namespace entering just before found it unrecorded, which scope_leave
// does not mark. Clearing its mark: a task of ours alone entering just
// before found it marked, which scope_enter does not record, and a task
// outside found it marked already. Marking and taking out judge no task
// outside, and need no second look.

// clearMark clears the mark of the cgroup open at dir, id, if no task
// outside our pid namespace is in it, and settles it (unmark), or forgets
// an unheld one no task of ours is in (forgetMark): one a task
// of ours alone has entered since the listing, which scope_enter left out
// for the mark, is recorded, as the listing would have, where the hook can
// see it (inside).
func (s *cgroupScope) clearMark(id uint64, dir *os.File, path string, inside bool) {
	m, err := cgroupMembers(dir)
	switch {
	case cgroupGone(err):
		s.forgetMark(id)
	case err != nil:
		s.unreadable(id, path, err)
	case m.theirs && m.ours:
		// Still shared, with a task of ours there: the mark stays.
	case m.theirs:
		// Shared with none of ours: a mark the walk made of a cgroup the
		// scope never held goes, or it would never clear (markUnheld); a
		// held one stays, so that a task of ours entering again (an exec, a
		// healthcheck) is not recorded beside the tasks outside.
		if !s.heldMark(id) {
			s.forgetMark(id)
		}
	default:
		s.unmark(id, dir, path, inside)
	}
}

// A shared mark's value (map_scope_shared): markHeld, as scope_leave
// writes it, for a cgroup the scope held when it was found shared, which
// stays marked for as long as a task outside is in it; markUnheld for one
// the walk found shared with a task of ours in it, never in the scope,
// which loses the mark once none of ours is left (clearMark). Such marks,
// of node cgroups a runtime's exec stage has passed through, would
// otherwise pile up, while held ones are only of cgroups this job entered.
const (
	markHeld   uint8 = 1
	markUnheld uint8 = 2
)

// mark marks a cgroup shared, so that a task of ours entering it is not
// recorded (scope_enter): held, if the scope held it, which no unheld mark
// overwrites. A mark the map cannot take is reported (warn): each entry of
// ours records the cgroup again until the next walk takes it out.
func (s *cgroupScope) mark(id uint64, path string, held bool) {
	value, flags := markUnheld, ebpf.UpdateNoExist
	if held {
		value, flags = markHeld, ebpf.UpdateAny
	}
	err := s.objs.MapScopeShared.Update(id, value, flags)
	if err != nil && !errors.Is(err, ebpf.ErrKeyExist) && s.warn(findUnmarked, id) {
		s.logger.Warn("Container egress cgroup scope could not mark a cgroup shared with tasks outside this job, "+
			"which a task of this job entering it records again until the next walk", "cgroup", path, "cgroup_id", id, "error", err,
			"capacity", s.objs.MapScopeShared.MaxEntries())
	}
}

// markOf is a cgroup's shared mark (markHeld or markUnheld), 0 for none.
func (s *cgroupScope) markOf(id uint64) uint8 {
	var v uint8
	if s.objs.MapScopeShared.Lookup(id, &v) != nil {
		return 0
	}
	return v
}

// heldMark reports whether a cgroup's shared mark stood for a cgroup the
// scope held (markHeld), as every mark scope_leave makes does.
func (s *cgroupScope) heldMark(id uint64) bool { return s.markOf(id) == markHeld }

// unmark clears the shared mark of the cgroup open at dir, and settles it.
func (s *cgroupScope) unmark(id uint64, dir *os.File, path string, inside bool) {
	prev := s.markOf(id)
	_ = s.objs.MapScopeShared.Delete(id)
	s.settle(id, dir, path, inside, false, prev)
}

// forgetMark clears the shared mark of a cgroup that has been removed,
// which no task can enter again.
func (s *cgroupScope) forgetMark(id uint64) {
	_ = s.objs.MapScopeShared.Delete(id)
}

func (s *cgroupScope) recorded(id uint64) bool {
	var v uint8
	return s.objs.MapScopeCgroups.Lookup(id, &v) == nil
}

// record puts a cgroup the walk found ours alone, and not yet in the
// scope, in the scope, and settles it. A tracepoint may have made the
// entry since the look, which changes nothing. A cgroup already in the
// scope before the look needs neither: the tracepoints have seen every
// entry since. As in the kernel, a cgroup the map cannot take costs its
// own sockets, not the scope.
func (s *cgroupScope) record(id uint64, dir *os.File, path string) {
	if made, ok := s.put(id, path); ok {
		s.settle(id, dir, path, true, made, 0)
	}
}

// put puts a cgroup in the scope, and reports whether it is there (ok) and
// whether this put made the entry (made). One the map cannot take is
// reported.
func (s *cgroupScope) put(id uint64, path string) (made, ok bool) {
	err := s.objs.MapScopeCgroups.Update(id, uint8(1), ebpf.UpdateNoExist)
	if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		if s.warn(findUnrecorded, id) {
			s.logger.Warn("Container egress cgroup scope could not record a cgroup this job is in, "+
				"and its sockets pass the cgroup hook", "cgroup", path, "cgroup_id", id, "error", err,
				"capacity", s.objs.MapScopeCgroups.MaxEntries())
		}
		return false, false
	}
	return err == nil, true
}

// settle looks again at a cgroup the walk has just recorded (made, when
// this walk made the entry) or cleared the mark of (prev, the mark it was,
// 0 when settling a recording). A task outside our pid namespace in it now
// marks it and takes it out (leave), a held mark the walk cleared marking
// it held again however the scope holds it now; a task of ours alone,
// inside the root, records it. One removed since loses the entry this walk
// made: release, all that takes one out, may have passed before it, and
// any socket of ours that outlives the cgroup passes, as it would had the
// walk come a moment later. One the look cannot read is marked, as it was
// or as the scope holds it, and taken out, which judges no task outside,
// and reported, for a walk that reads it to record it again; when the
// fault is the walk's own (unreadable's ownFault), the write is undone
// instead. Each recording is looked at again, up to settleLooks looks in
// all.
func (s *cgroupScope) settle(id uint64, dir *os.File, path string, inside, made bool, prev uint8) {
	for look := 1; ; look++ {
		m, err := cgroupMembers(dir)
		switch {
		case cgroupGone(err):
			if made {
				_ = s.objs.MapScopeCgroups.Delete(id)
			}
			return
		case err != nil && ownFault(err):
			if made {
				_ = s.objs.MapScopeCgroups.Delete(id)
			}
			if prev != 0 {
				s.mark(id, path, prev == markHeld)
			}
			s.unreadable(id, path, err)
			return
		case err != nil:
			s.mark(id, path, prev == markHeld || s.recorded(id))
			s.unreadable(id, path, err)
			return
		case m.theirs:
			s.leave(id, path, m.ours, prev == markHeld)
			return
		case !m.ours || !inside || s.recorded(id):
			return
		case look == settleLooks:
			// Still unrecorded after as many recordings: a task outside
			// keeps entering between the put and the look. The mark keeps
			// the cgroup out, judging no task outside, until a walk finds
			// it settled.
			s.mark(id, path, true)
			return
		}
		var ok bool
		if made, ok = s.put(id, path); !ok {
			return
		}
	}
}

// settleLooks bounds settle's looks at a cgroup that tasks keep entering.
const settleLooks = 3

// leave takes a cgroup the walk found shared out of the scope, should a
// tracepoint or an earlier walk have recorded it, and marks it shared, so
// that a task of ours entering it again is not recorded: a task outside our
// pid namespace is in it, which the hook must not judge. ours says whether a
// task of ours is in it too, and wasHeld whether a held mark the walk just
// cleared stood for it, which keeps it held. One the scope does not hold is
// marked only then, as scope_leave marks only what the scope holds, and one
// with none of ours either changes nothing, and is neither marked nor
// logged (a runtime's exec stage listed in the runtime's cgroup has moved
// on). Logged at most once in warnEvery (warn) for as long as it stays
// shared.
func (s *cgroupScope) leave(id uint64, path string, ours, wasHeld bool) {
	held := wasHeld || s.recorded(id)
	if !ours && !held {
		return
	}
	s.mark(id, path, held)
	err := s.objs.MapScopeCgroups.Delete(id)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		if s.warn(findUnremoved, id) {
			s.logger.Warn("Container egress cgroup scope could not take out a cgroup it shares with tasks outside "+
				"this job, whose sockets the hook still judges", "cgroup", path, "cgroup_id", id, "error", err)
		}
		return
	}
	if !s.warn(findShared, id) {
		return
	}
	switch {
	case ours:
		s.logger.Warn("A task of this job is in a cgroup shared with tasks outside it, "+
			"where its sockets pass the cgroup hook", "cgroup", path, "cgroup_id", id)
	default:
		s.logger.Warn("A cgroup a task of this job entered holds tasks outside it, and no longer one of "+
			"this job's: it leaves the scope, and sockets this job made there pass the cgroup hook", "cgroup", path, "cgroup_id", id)
	}
}
