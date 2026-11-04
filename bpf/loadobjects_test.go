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
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
)

// TestLoadObjects covers the one startup load path every collection goes
// through: the bpf2go struct comes back populated and usable, the verifier
// count is logged, and a struct naming an object the collection does not
// have is an error rather than a half-assigned struct.
func TestLoadObjects(t *testing.T) {
	requireBPF(t)
	spec, err := LoadTcBpf()
	require.NoError(t, err)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var objs TcBpfObjects
	require.NoError(t, cargowallEbpf.LoadObjects(logger, "tcbpf", spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	}, &objs))
	t.Cleanup(func() { objs.Close() })

	require.NotNil(t, objs.CwTcEgress)
	info, err := objs.CwTcEgress.Info()
	require.NoError(t, err, "assigned program must be live after the collection is closed")
	assert.Equal(t, "cw_tc_egress", info.Name)
	require.NotNil(t, objs.MapCidrs)
	assert.Contains(t, buf.String(), "program=cw_tc_egress")
	assert.Contains(t, buf.String(), "processed_insns=")

	// A struct that names something the collection lacks: error, and the
	// collection is closed behind it.
	var wrong struct {
		Missing *ebpf.Program `ebpf:"no_such_program"`
	}
	spec2, err := LoadTcBpf()
	require.NoError(t, err)
	assert.Error(t, cargowallEbpf.LoadObjects(logger, "tcbpf", spec2, ebpf.CollectionOptions{}, &wrong))
}

// TestProgramNames holds every program's kernel-visible name to two rules.
// It starts with cw_, so `bpftool prog`, `bpftool net` and `tc filter show`
// tell cargowall's programs from other tools' (GitHub's Azure runner images
// attach their own clsact filter, tc_egress_traffic). And it fits the
// kernel's name field whole: a longer one is cut to its first 15 bytes,
// which can cut off the part that tells two programs apart. It reads every
// compiled object here, both byte orders, so a new collection is held to
// the rules without being listed.
func TestProgramNames(t *testing.T) {
	objects, err := filepath.Glob("*.o")
	require.NoError(t, err)
	require.NotEmpty(t, objects)
	for _, obj := range objects {
		spec, err := ebpf.LoadCollectionSpec(obj)
		require.NoError(t, err, obj)
		require.NotEmpty(t, spec.Programs, obj)
		for _, p := range spec.Programs {
			assert.True(t, strings.HasPrefix(p.Name, "cw_"), "%s: program %s: no cw_ prefix", obj, p.Name)
			assert.Less(t, len(p.Name), unix.BPF_OBJ_NAME_LEN, "%s: program %s: the kernel cuts it to %d bytes",
				obj, p.Name, unix.BPF_OBJ_NAME_LEN-1)
		}
	}
}
