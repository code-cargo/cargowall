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

package steps

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/events"
)

// Note: none of these tests assume Runner.Worker is absent — in CI the
// suite runs ON a GitHub-hosted runner, where the test binary's own
// ancestry contains a real Runner.Worker. Assertions are therefore made
// against processes the test controls (itself and its parent).

func TestReadPPid_Self(t *testing.T) {
	ppid, ok := readPPid(os.Getpid())
	require.True(t, ok)
	assert.Equal(t, os.Getppid(), ppid)
}

func TestReadPPid_Gone(t *testing.T) {
	// PID 0 has no /proc entry.
	_, ok := readPPid(0)
	assert.False(t, ok)
}

func TestReadCmdline_Self(t *testing.T) {
	cmdline := readCmdline(os.Getpid())
	require.NotEmpty(t, cmdline)
	// The test binary's argv[0] always names the compiled test executable.
	assert.Contains(t, cmdline, ".test")
}

func TestReadCmdline_GoneFallsBackEmpty(t *testing.T) {
	assert.Empty(t, readCmdline(0))
}

func TestReadComm_Self(t *testing.T) {
	comm := readComm(os.Getpid())
	require.NotEmpty(t, comm)
	// comm is the executable basename truncated to 15 chars.
	assert.LessOrEqual(t, len(comm), 15)
}

func TestBuildChildrenMap_ContainsSelf(t *testing.T) {
	children := buildChildrenMap()
	assert.Contains(t, children[os.Getppid()], os.Getpid())
}

func TestSubtreePids_IncludesSelfAndDescendants(t *testing.T) {
	children := map[int][]int{100: {200, 300}, 300: {400}}
	assert.ElementsMatch(t, []int{100, 200, 300, 400}, subtreePids(100, children))
	assert.Equal(t, []int{400}, subtreePids(400, children))
}

func TestFindAncestorByComm_FindsParent(t *testing.T) {
	parentComm := readComm(os.Getppid())
	require.NotEmpty(t, parentComm)
	pid, ok := findAncestorByComm(os.Getpid(), parentComm)
	require.True(t, ok)
	assert.Equal(t, os.Getppid(), pid)
}

func TestFindAncestorByComm_NoMatch(t *testing.T) {
	_, ok := findAncestorByComm(os.Getpid(), "no-such-comm-xx")
	assert.False(t, ok)
}

func TestScanUniqueByComm_FindsSelf(t *testing.T) {
	selfComm := readComm(os.Getpid())
	first, count := scanUniqueByComm(selfComm)
	require.GreaterOrEqual(t, count, 1)
	if count == 1 {
		assert.Equal(t, os.Getpid(), first)
	}
}

func TestScanUniqueByComm_NoMatch(t *testing.T) {
	_, count := scanUniqueByComm("no-such-comm-xx")
	assert.Zero(t, count)
}

func TestStart_RejectsOrdinalBaseNearSentinels(t *testing.T) {
	// Validation runs before any /proc or BPF work, so nil objects are safe.
	_, err := Start(nil, Options{OrdinalBase: uint64(events.StepOrdinalPreDaemon)},
		nil, slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ordinal base")

	_, err = Start(nil, Options{OrdinalBase: maxOrdinalBase}, nil, slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ordinal base")
}

func TestSanitizeCmdline(t *testing.T) {
	// Short command lines pass through untouched.
	assert.Equal(t, "/usr/bin/bash -e", sanitizeCmdline("/usr/bin/bash -e"))
	assert.Equal(t, "bash", sanitizeCmdline("bash"))
	assert.Equal(t, "", sanitizeCmdline(""))
	// The runner's own script/action paths are the correlation token and
	// must survive from ANY argv position: the standard run-step shape
	// buries the script behind several shell flags.
	assert.Equal(t,
		"/usr/bin/bash --noprofile /home/runner/work/_temp/abc123.sh ...",
		sanitizeCmdline("/usr/bin/bash --noprofile --norc -e -o pipefail /home/runner/work/_temp/abc123.sh"))
	assert.Equal(t,
		"node --enable-source-maps /home/runner/work/_actions/actions/checkout/v4/dist/index.js ...",
		sanitizeCmdline("node --enable-source-maps --no-warnings /home/runner/work/_actions/actions/checkout/v4/dist/index.js"))
	// Anything else beyond argv[1] is where flags/values (secrets) could live.
	assert.Equal(t, "docker run ...",
		sanitizeCmdline("docker run -e API_TOKEN=hunter2 alpine"))
	assert.NotContains(t, sanitizeCmdline("cmd sub --token hunter2"), "hunter2")
	// The path match is anchored: user-controlled tokens merely EMBEDDING
	// /_temp/ or /_actions/ (URLs, --flag=value, volume specs) must not
	// ride through the redaction.
	assert.NotContains(t,
		sanitizeCmdline("curl -s https://host/_temp/upload?token=SECRET"), "SECRET")
	assert.NotContains(t,
		sanitizeCmdline("tool run --out=/home/runner/work/_temp/SECRET.json"), "SECRET")
	assert.NotContains(t,
		sanitizeCmdline("docker run -v /home/x/_temp/SECRET:/mnt alpine"), "SECRET")
}

func TestStart_RejectsNilObjects(t *testing.T) {
	_, err := Start(nil, Options{OrdinalBase: 1}, nil, slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil TC BPF objects")
}
