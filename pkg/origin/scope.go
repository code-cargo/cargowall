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

// cgroupRoot is the machine's cgroup tree in the scoped shape.
const cgroupRoot = "/sys/fs/cgroup"

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
	fi, err := os.Stat(filepath.Join(cgroupRoot, podCgroup))
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
// The verifier logs only its statistics, as for the origin collection: a
// branch-level log of each program would be kept for the life of the
// process.
func startPodScope(logger *slog.Logger) (*podScope, error) {
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
	for _, p := range []*ebpf.Program{s.objs.ScopeFork, s.objs.ScopeAttach} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachTraceRawTp})
		if err != nil {
			s.release()
			return nil, fmt.Errorf("pod scope: failed to attach %s: %w", p, err)
		}
		s.links = append(s.links, l)
	}
	if err := s.walk(); err != nil {
		s.release()
		return nil, fmt.Errorf("pod scope: task walk: %w", err)
	}
	go s.watch()
	return s, nil
}

// cgroups is the map the scoped hook loads in place of its stand-in.
func (s *podScope) cgroups() *ebpf.Map { return s.objs.MapScopeCgroups }

// walk records each cgroup the startup walk lists, our tasks' cgroups,
// that no task outside our pid namespace is in. A task's cgroup does not
// say it entered it. A task of ours in the same cgroup as a node daemon or
// another pod's task was left there (a job an nsenter'd shell started) or
// is about to be moved out (a runtime's exec), and recording that cgroup
// would judge the daemon or the pod. Such a cgroup is reported and left
// out, and the task's sockets pass. The check reads cgroup.threads, which
// numbers each task as our pid namespace does, so a task outside it reads
// as 0.
func (s *podScope) walk() error {
	ids, err := s.walkCgroups()
	if err != nil || len(ids) == 0 {
		return err
	}
	paths, err := cgroupPaths(cgroupRoot)
	if err != nil {
		return err
	}
	for id := range ids {
		path, ok := paths[id]
		if !ok {
			continue // removed since the walk
		}
		shared, err := sharedCgroup(filepath.Join(cgroupRoot, path))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return err
		}
		if shared {
			s.logger.Warn("A task of this job is in a cgroup shared with tasks outside it, "+
				"where its sockets pass the cgroup hook", "cgroup", path)
			continue
		}
		if err := s.objs.MapScopeCgroups.Update(id, uint8(1), ebpf.UpdateNoExist); err != nil &&
			!errors.Is(err, ebpf.ErrKeyExist) {
			return fmt.Errorf("recording cgroup %s: %w", path, err)
		}
	}
	return nil
}

// walkCgroups runs the task walk and returns the cgroup ids it wrote.
func (s *podScope) walkCgroups() (map[uint64]struct{}, error) {
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
	if len(out)%8 != 0 {
		return nil, fmt.Errorf("task walk wrote %d bytes, not a whole number of cgroup ids", len(out))
	}
	ids := make(map[uint64]struct{})
	for i := 0; i < len(out); i += 8 {
		ids[binary.NativeEndian.Uint64(out[i:])] = struct{}{}
	}
	return ids, nil
}

// cgroupPaths maps each cgroup under root to its path below it, by id: a
// cgroup's id is its cgroupfs inode on 64-bit kernels. A cgroup removed
// while the tree is read is left out.
func cgroupPaths(root string) (map[uint64]string, error) {
	paths := make(map[uint64]string)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		paths[info.Sys().(*syscall.Stat_t).Ino] = "/" + strings.TrimPrefix(rel, ".")
		return nil
	})
	return paths, err
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
