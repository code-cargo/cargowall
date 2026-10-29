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
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/code-cargo/cargowall/bpf"
	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// Slots of map_scope_stats, mirroring SCOPE_STAT_* in bpf/scopebpf.c.
const (
	scopeStatFull = iota // a cgroup we entered found map_scope_cgroups full
	scopeStatRoot        // a task of ours entered the root cgroup
	scopeStatsMax
)

// scopeStatsInterval is how often podScope checks what it could not record.
const scopeStatsInterval = 10 * time.Second

// podScope owns the scope collection (bpf/scopebpf.c): the cgroups that
// tasks in our pid namespace have entered, which a scoped hook judges.
// Started before the hook attaches, so the hook never judges an empty
// scope, and closed after it detaches. A failure anywhere here costs the
// scoped hook only: the step tracker and TC never depend on it.
type podScope struct {
	objs     bpf.ScopeBpfObjects
	links    []link.Link
	logger   *slog.Logger
	stop     chan struct{}
	done     chan struct{}
	reported [scopeStatsMax]uint64 // last counts logged, owned by watch
}

// startPodScope loads the scope collection for our pid namespace, attaches
// its tracepoints, then walks the tasks that predate them, so a task that
// enters a cgroup while the walk runs is recorded by one or the other.
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
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats},
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

func (s *podScope) walk() error {
	it, err := link.AttachIter(link.IterOptions{Program: s.objs.ScopeTaskIter})
	if err != nil {
		return err
	}
	defer it.Close()
	rd, err := it.Open()
	if err != nil {
		return err
	}
	defer rd.Close()
	_, err = io.Copy(io.Discard, rd)
	return err
}

// watch reports, until close, what the scope could not record. Both leave
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
		scopeStatFull: "Container egress scope full: cgroups this job entered were not recorded, and their sockets pass the cgroup hook",
		scopeStatRoot: "A task of this job entered the root cgroup, where its sockets pass the cgroup hook",
	} {
		var n uint64
		if err := s.objs.MapScopeStats.Lookup(uint32(slot), &n); err != nil || n <= s.reported[slot] {
			continue
		}
		s.reported[slot] = n
		s.logger.Warn(msg, "count", n, "capacity", s.objs.MapScopeCgroups.MaxEntries())
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
