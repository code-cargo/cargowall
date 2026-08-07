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
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

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

// --- OrdinalAt tests (issue #106 phase 3a) ---

// appendBoundaryCapped drives the same recordBoundary that run() calls, so
// the ring-cap tests below exercise the production trim, not a mirror.
func appendBoundaryCapped(tr *Tracker, b boundary) {
	tr.recordBoundary(b.ordinal, b.at)
}

func TestOrdinalAt(t *testing.T) {
	tr := &Tracker{}
	base := time.Now()

	// No boundaries observed yet: everything is untagged.
	assert.Zero(t, tr.OrdinalAt(base))

	tr.boundaryMu.Lock()
	tr.boundaries = []boundary{
		{ordinal: 3, at: base},
		{ordinal: 4, at: base.Add(10 * time.Second)},
		{ordinal: 5, at: base.Add(20 * time.Second)},
	}
	tr.boundaryMu.Unlock()

	// Before the first boundary: 0, which callers treat as untagged so the
	// attribution degrades to the stricter tier rather than guessing.
	assert.Zero(t, tr.OrdinalAt(base.Add(-time.Second)))
	// Exactly at a boundary: that step is already active ("at or before").
	assert.Equal(t, uint32(3), tr.OrdinalAt(base))
	assert.Equal(t, uint32(4), tr.OrdinalAt(base.Add(10*time.Second)))
	// Between boundaries: the earlier step is the one still running.
	assert.Equal(t, uint32(4), tr.OrdinalAt(base.Add(15*time.Second)))
	// After the last boundary: the latest step.
	assert.Equal(t, uint32(5), tr.OrdinalAt(base.Add(time.Hour)))
}

func TestOrdinalAt_RingOverflowKeepsNewest(t *testing.T) {
	tr := &Tracker{}
	base := time.Now()
	total := boundaryHistory + 10
	for i := range total {
		appendBoundaryCapped(tr, boundary{
			ordinal: uint32(i + 1),
			at:      base.Add(time.Duration(i) * time.Second),
		})
	}

	tr.boundaryMu.Lock()
	n := len(tr.boundaries)
	tr.boundaryMu.Unlock()
	assert.Equal(t, boundaryHistory, n, "ring must stay capped at boundaryHistory")

	// The newest boundary survives the trim...
	assert.Equal(t, uint32(total), tr.OrdinalAt(base.Add(time.Duration(total)*time.Second)))
	// ...and a time that falls where a trimmed entry used to sit resolves to
	// 0 (untagged), never to a stale evicted ordinal: entries 0..9 were
	// trimmed, so the oldest survivor is at base+10s.
	assert.Zero(t, tr.OrdinalAt(base.Add(5*time.Second)))
}

// --- TagContainerProcess tests (issue #106 phase 3a) ---

// newTaskMap creates a real BPF hash map with map_task_step's key/value
// shape. Map creation needs CAP_BPF (kernel.unprivileged_bpf_disabled is 2
// on typical hosts), so the tests below skip when unprivileged and only run
// under sudo/CAP_BPF.
func newTaskMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 128,
	})
	if err != nil {
		t.Skipf("cannot create BPF map (needs CAP_BPF, run under sudo): %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestTagContainerProcess_LeaderOverwriteDescendantCreateOnly(t *testing.T) {
	m := newTaskMap(t)
	tr := &Tracker{taskMap: m}

	// Pin this goroutine to one OS thread so its tid is guaranteed to exist
	// in /proc/<pid>/task both when pre-seeding and when asserting — the Go
	// runtime creates and parks threads at will, so any other tid could race.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	selfTid := uint32(unix.Gettid())

	// Two descendants of the leader (this test process): one already carries
	// an ordinal — standing in for a child the fork tracepoint tagged — and
	// one is untagged.
	startSleeper := func() int {
		cmd := exec.Command("sleep", "30")
		require.NoError(t, cmd.Start())
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		return cmd.Process.Pid
	}
	preTaggedPid := startSleeper()
	untaggedPid := startSleeper()

	// Pre-seed: our own tid simulates a stale leader entry (exec re-tag into
	// a long-lived container / recycled tid), the first child a
	// kernel-inherited descendant tag.
	require.NoError(t, m.Put(selfTid, uint32(99)))
	require.NoError(t, m.Put(uint32(preTaggedPid), uint32(7)))

	tr.TagContainerProcess(os.Getpid(), 42)

	// Leader threads are written UpdateAny: the stale ordinal must be replaced.
	var got uint32
	require.NoError(t, m.Lookup(selfTid, &got))
	assert.Equal(t, uint32(42), got, "leader tid must be overwritten (UpdateAny)")

	// Descendants are create-only: a kernel-inherited ordinal survives...
	require.NoError(t, m.Lookup(uint32(preTaggedPid), &got))
	assert.Equal(t, uint32(7), got, "pre-tagged descendant must keep its ordinal (UpdateNoExist)")

	// ...while an untagged descendant picks up the container's ordinal.
	require.NoError(t, m.Lookup(uint32(untaggedPid), &got))
	assert.Equal(t, uint32(42), got, "untagged descendant must be tagged")
}
