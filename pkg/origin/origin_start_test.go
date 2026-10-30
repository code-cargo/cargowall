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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// Start in the scoped shape, as on ARC, whose jobs alone run it: the scope
// collection loads and walks first, the hook's stand-in takes the scope
// map's size and is replaced by that map, the hook's subtree constants
// are the walk's, and Close releases the scope with the hook. A mismatch
// between the stand-in and the scope map fails only here, or on ARC.
func TestStartScoped(t *testing.T) {
	requireBPFOrigin(t)
	own := ownCgroupBelowRoot(t)
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

	o.Close()
	closed = true
	_, err = scope.Info()
	require.Error(t, err, "Close releases the scope collection too")
}
