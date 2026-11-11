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
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// Start in the scoped shape, as on ARC, whose jobs alone run it: the scope
// collection loads and finds our cgroup first, the hook's stand-in takes
// the scope map's size and is replaced by that map, the hook's subtree
// constants are the walk's, and Close releases the scope with the hook. A
// mismatch between the stand-in and the scope map fails only here, or on
// ARC. The hook attaches at a cgroup this process moves into, not the
// host's root, so only this process's sockets ever reach it.
func TestStartScoped(t *testing.T) {
	requireBPFOrigin(t)
	cg := attachAtTestCgroup(t, "start")
	own := strings.TrimPrefix(cg, podenv.CgroupRoot)
	spec, err := bpf.LoadTcBpf()
	require.NoError(t, err)
	var tc bpf.TcBpfObjects
	require.NoError(t, spec.LoadAndAssign(&tc, nil))
	t.Cleanup(func() { tc.Close() })

	var log bytes.Buffer
	o, err := Start(&tc, podenv.Scope{Subtree: own}, slog.New(slog.NewTextHandler(&log, nil)))
	require.NoError(t, err, log.String())
	closed := false
	t.Cleanup(func() {
		if !closed {
			o.Close()
		}
	})
	require.NotNil(t, o.cgroups, "a limited scope starts the scope collection")
	scope := o.cgroups.cgroups()
	require.Equal(t, scope.MaxEntries(), o.objs.MapScopeCgroups.MaxEntries(), "the stand-in takes the scope map's size")
	hookInfo, err := o.objs.MapScopeCgroups.Info()
	require.NoError(t, err)
	scopeInfo, err := scope.Info()
	require.NoError(t, err)
	hookID, _ := hookInfo.ID()
	scopeID, _ := scopeInfo.ID()
	require.Equal(t, scopeID, hookID, "the hook reads the scope collection's own map")

	ownID, err := podenv.CgroupID(own)
	require.NoError(t, err)
	var id uint64
	var level uint32
	require.NoError(t, o.objs.ScopeSubtreeCgroup.Get(&id))
	require.NoError(t, o.objs.ScopeSubtreeLevel.Get(&level))
	require.Equal(t, ownID, id, "the hook's subtree is the scope's")
	require.Equal(t, podenv.CgroupLevel(own), level, "at the level the walk read, in the host cgroup namespace the path's depth")
	progInfo, err := o.objs.CwCgEgress.Info()
	require.NoError(t, err)
	progID, _ := progInfo.ID()
	attached := func(path string) bool {
		f, err := os.Open(path)
		require.NoError(t, err)
		defer f.Close()
		res, err := link.QueryPrograms(link.QueryOptions{Target: int(f.Fd()), Attach: ebpf.AttachCGroupInetEgress})
		require.NoError(t, err)
		for _, p := range res.Programs {
			if p.ID == progID {
				return true
			}
		}
		return false
	}
	require.True(t, attached(cg), "the hook is attached at the test's cgroup")
	require.False(t, attached(podenv.CgroupRoot), "and not at the host's root")

	o.Close()
	closed = true
	_, err = scope.Info()
	require.Error(t, err, "Close releases the scope collection too")
}

// attachAtTestCgroup makes a cgroup for the test, moves this process into
// it until the test ends, and has Start attach the hook there, not at the
// host's root, so only this process's sockets ever reach it.
func attachAtTestCgroup(t *testing.T, name string) string {
	t.Helper()
	cg := filepath.Join(podenv.CgroupRoot, fmt.Sprintf("cargowall-origin-%s-%d", name, os.Getpid()))
	require.NoError(t, os.Mkdir(cg, 0o755))
	t.Cleanup(func() { removeTestCgroup(t, cg) })
	home, err := podenv.ReadCgroupPath("/proc/self/cgroup")
	require.NoError(t, err)
	self := []byte(strconv.Itoa(os.Getpid()))
	// Back home before the cgroup goes: cleanups run last first.
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(podenv.CgroupRoot, home, "cgroup.procs"), self, 0) })
	require.NoError(t, os.WriteFile(filepath.Join(cg, "cgroup.procs"), self, 0))
	swap(t, &cgroupAttachPath, cg)
	return cg
}

// Start against the tcbpf collection as cmd/start.go loads it with step
// attribution off (a non-GitHub run with the cgroup hook on): its step maps
// shrunk, and its rule maps sized for a policy without steps or with, which
// the hook's stand-ins must follow or the load is refused; and the
// step-rules gate both ways, which the hook must be built with. The hook
// must read TC's own rule maps, step tags and bindings, or a step's rules
// would never reach the traffic only it can judge.
func TestStartSharesStepPolicy(t *testing.T) {
	requireBPFOrigin(t)
	for _, gate := range []bool{false, true} {
		t.Run(fmt.Sprintf("step rules %v", gate), func(t *testing.T) {
			attachAtTestCgroup(t, fmt.Sprintf("steps-%v", gate))
			spec, err := bpf.LoadTcBpf()
			require.NoError(t, err)
			for _, name := range []string{"map_task_step", "map_sock_step", "map_task_nspid"} {
				spec.Maps[name].MaxEntries = 64
			}
			require.NoError(t, bpf.SetStepRules(spec, gate))
			require.NoError(t, bpf.SizeRuleMaps(spec, gate))
			var tc bpf.TcBpfObjects
			require.NoError(t, spec.LoadAndAssign(&tc, nil))
			t.Cleanup(func() { tc.Close() })
			require.Equal(t, gate, tc.StepRules(), "StepRules reads the gate tcbpf was built with")

			var log bytes.Buffer
			o, err := Start(&tc, podenv.Scope{}, slog.New(slog.NewTextHandler(&log, nil)))
			require.NoError(t, err, log.String())
			t.Cleanup(o.Close)

			var b uint8
			require.NoError(t, o.objs.StepRulesEnabled.Get(&b))
			require.Equal(t, gate, b != 0, "the hook is built with TC's gate")
			require.Equal(t, gate, o.StepRules())
			size := bpf.RuleMapEntriesJobOnly
			if gate {
				size = bpf.RuleMapEntries
			}
			for name, maps := range map[string][2]*ebpf.Map{
				"map_sock_step":   {o.objs.MapSockStep, tc.MapSockStep},
				"map_step_policy": {o.objs.MapStepPolicy, tc.MapStepPolicy},
				"map_cidrs":       {o.objs.MapCidrs, tc.MapCidrs},
				"map_ports":       {o.objs.MapPorts, tc.MapPorts},
				"map_cidrs_v6":    {o.objs.MapCidrsV6, tc.MapCidrsV6},
				"map_ports_v6":    {o.objs.MapPortsV6, tc.MapPortsV6},
			} {
				require.Equal(t, mapID(t, maps[1]), mapID(t, maps[0]), "the hook reads TC's %s", name)
			}
			require.Equal(t, size, o.objs.MapCidrs.MaxEntries(), "the rule maps at the size the policy gave them")
		})
	}
}

// mapID is m's kernel id.
func mapID(t *testing.T, m *ebpf.Map) ebpf.MapID {
	t.Helper()
	info, err := m.Info()
	require.NoError(t, err)
	id, ok := info.ID()
	require.True(t, ok, "kernel reports no id for %s", m)
	return id
}

// A kernel whose verifier rejects the step lookup at the hook alone loads
// the hook without it, with a Warn: the steps lose their own rules there,
// never the hook.
func TestStart_StepRulesFallBackOff(t *testing.T) {
	requireBPFOrigin(t)
	attachAtTestCgroup(t, "steps-fallback")
	spec, err := bpf.LoadTcBpf()
	require.NoError(t, err)
	for _, name := range []string{"map_task_step", "map_sock_step", "map_task_nspid"} {
		spec.Maps[name].MaxEntries = 64
	}
	require.NoError(t, bpf.SetStepRules(spec, true))
	require.NoError(t, bpf.SizeRuleMaps(spec, true))
	var tc bpf.TcBpfObjects
	require.NoError(t, spec.LoadAndAssign(&tc, nil))
	t.Cleanup(func() { tc.Close() })

	attempts := 0
	real := loadObjects
	swap(t, &loadObjects, func(logger *slog.Logger, collection string, spec *ebpf.CollectionSpec, opts ebpf.CollectionOptions, to any) error {
		attempts++
		var gate uint8
		require.NoError(t, spec.Variables[bpf.OriginBpfVarStepRulesEnabled].Get(&gate))
		if gate != 0 {
			return &ebpf.VerifierError{Cause: errors.New("too complex")}
		}
		return real(logger, collection, spec, opts, to)
	})
	var log bytes.Buffer
	o, err := Start(&tc, podenv.Scope{}, slog.New(slog.NewTextHandler(&log, nil)))
	require.NoError(t, err, log.String())
	t.Cleanup(o.Close)
	assert.Equal(t, 2, attempts)
	assert.False(t, o.StepRules())
	assert.True(t, tc.StepRules(), "TC keeps its own")
	assert.Contains(t, log.String(), "Step rules are off at the cgroup egress hook")
}
