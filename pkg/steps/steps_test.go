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
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
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

// rec encodes one task_iter_rec as the step_task_iter iterator streams it.
func rec(tid, tgid, ppid, nsTgid uint32) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.NativeEndian, bpf.StepBpfTaskIterRec{Tid: tid, Tgid: tgid, Ppid: ppid, NsTgid: nsTgid})
	return buf.Bytes()
}

func concat(recs ...[]byte) []byte {
	var out []byte
	for _, r := range recs {
		out = append(out, r...)
	}
	return out
}

func TestParseTaskRecords_BuildsTreeAndTranslation(t *testing.T) {
	// Global ids on the left, namespace pids on the right — deliberately
	// different so a test that conflates them fails.
	snap := parseTaskRecords(concat(
		rec(1, 1, 0, 1),
		rec(100, 100, 1, 7),
		rec(101, 100, 1, 7), // thread of 100: contributes a tid, nothing else
		rec(200, 200, 100, 8),
		rec(300, 300, 200, 9),
		rec(400, 400, 1, 10),
		rec(5, 5, 5, 5), // self-parented: no child edge to itself
		[]byte{1, 2, 3}, // truncated trailing record: ignored
	))

	assert.Equal(t, []uint32{100, 101}, snap.tids[100])
	assert.Equal(t, uint32(100), snap.global[7])
	assert.Equal(t, uint32(200), snap.global[8])
	_, threadListed := snap.global[0]
	assert.False(t, threadListed)
	assert.Equal(t, []uint32{100, 400}, snap.children[1])
	assert.Equal(t, []uint32{200}, snap.children[100])
	assert.Empty(t, snap.children[5])
	assert.Equal(t, []uint32{100, 200, 300}, snap.subtree(100))
	assert.Equal(t, []uint32{400}, snap.subtree(400))
}

func TestProcSnapshot_SubtreeTerminatesOnCycle(t *testing.T) {
	snap := &procSnapshot{children: map[uint32][]uint32{1: {2}, 2: {1}}}
	assert.Equal(t, []uint32{1, 2}, snap.subtree(1))
}

func TestPidNamespaceInode_MatchesProcLink(t *testing.T) {
	got, err := pidNamespaceInode()
	require.NoError(t, err)
	link, err := os.Readlink("/proc/self/ns/pid")
	require.NoError(t, err)
	want, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "pid:["), "]"), 10, 32)
	require.NoError(t, err)
	assert.Equal(t, uint32(want), got)
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

// containerSnapshot is a synthetic task walk: leader global tgid 1000 (pid
// 50 in our namespace) with two threads, a pre-tagged child 2000 and an
// untagged child 3000, each with a grandchild.
func containerSnapshot() *procSnapshot {
	return &procSnapshot{
		tids:     map[uint32][]uint32{1000: {1000, 1001}, 2000: {2000}, 3000: {3000}, 3100: {3100}},
		children: map[uint32][]uint32{1000: {2000, 3000}, 3000: {3100}},
		global:   map[int]uint32{50: 1000, 51: 2000, 52: 3000, 53: 3100},
	}
}

func newSnapshotTracker(t *testing.T, snap *procSnapshot, err error) (*Tracker, *ebpf.Map) {
	t.Helper()
	m := newTaskMap(t)
	tr := &Tracker{
		taskMap:    m,
		logger:     slog.Default(),
		snapshotFn: func() (*procSnapshot, error) { return snap, err },
	}
	return tr, m
}

func TestTagContainerProcess_LeaderOverwriteDescendantCreateOnly(t *testing.T) {
	tr, m := newSnapshotTracker(t, containerSnapshot(), nil)

	// Pre-seed: a leader thread simulates a stale entry (exec re-tag into a
	// long-lived container / recycled tid), the first child a
	// kernel-inherited descendant tag.
	require.NoError(t, m.Put(uint32(1001), uint32(99)))
	require.NoError(t, m.Put(uint32(2000), uint32(7)))

	// The caller speaks namespace pids; the map is keyed by global tids.
	tr.TagContainerProcess(50, 42)

	var got uint32
	require.NoError(t, m.Lookup(uint32(1000), &got))
	assert.Equal(t, uint32(42), got, "leader must be tagged under its global tid")
	require.NoError(t, m.Lookup(uint32(1001), &got))
	assert.Equal(t, uint32(42), got, "leader thread must be overwritten (UpdateAny)")
	require.NoError(t, m.Lookup(uint32(2000), &got))
	assert.Equal(t, uint32(7), got, "pre-tagged descendant must keep its ordinal (UpdateNoExist)")
	require.NoError(t, m.Lookup(uint32(3000), &got))
	assert.Equal(t, uint32(42), got, "untagged descendant must be tagged")
	require.NoError(t, m.Lookup(uint32(3100), &got))
	assert.Equal(t, uint32(42), got, "grandchild must be tagged")
	assert.Error(t, m.Lookup(uint32(50), &got), "the namespace pid itself must never be used as a key")
}

func TestAdoptContainerProcess_CreateOnlyForLeaderToo(t *testing.T) {
	tr, m := newSnapshotTracker(t, containerSnapshot(), nil)
	require.NoError(t, m.Put(uint32(1000), uint32(7)))

	tr.AdoptContainerProcess(50, 42)

	var got uint32
	require.NoError(t, m.Lookup(uint32(1000), &got))
	assert.Equal(t, uint32(7), got, "adoption must not demote a live leader")
	require.NoError(t, m.Lookup(uint32(1001), &got))
	assert.Equal(t, uint32(42), got)
	require.NoError(t, m.Lookup(uint32(3000), &got))
	assert.Equal(t, uint32(42), got)
}

func TestTagContainerProcess_UnknownPidAndWalkFailureAreNoOps(t *testing.T) {
	tr, m := newSnapshotTracker(t, containerSnapshot(), nil)
	tr.TagContainerProcess(999, 42) // exited, or numbered in another namespace
	var got uint32
	assert.Error(t, m.Lookup(uint32(999), &got))

	failing, m2 := newSnapshotTracker(t, nil, errors.New("iterator closed"))
	failing.TagContainerProcess(50, 42)
	assert.Error(t, m2.Lookup(uint32(1000), &got))
}

// loadTcObjects loads the tcbpf collection that owns the tracker's shared
// maps, exactly as cmd/start.go does before steps.Start.
func loadTcObjects(t *testing.T) *bpf.TcBpfObjects {
	t.Helper()
	spec, err := bpf.LoadTcBpf()
	require.NoError(t, err)
	var objs bpf.TcBpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Skipf("tcbpf objects not loadable (needs root): %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// TestStart_TagsWorkerChild is the production path end to end: Start with
// this test process declared as Runner.Worker, then fork a child and check
// every id crossing — seeding keyed by global tids, the boundary event and
// map_task_nspid carrying our namespace's numbering. Run on its own it
// covers a plain VM; TestStart_InPidNamespace re-runs it inside a fresh pid
// namespace, where every one of those crossings used to be wrong.
func TestStart_TagsWorkerChild(t *testing.T) {
	objs := loadTcObjects(t)
	tr, err := Start(objs, Options{WorkerPID: os.Getpid(), OrdinalBase: 100}, nil, slog.Default())
	if err != nil && strings.Contains(err.Error(), "BTF") {
		t.Skipf("step tracker needs kernel BTF: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(tr.Close)

	snap, err := tr.snapshotFn()
	require.NoError(t, err)
	selfTgid, ok := snap.global[os.Getpid()]
	require.True(t, ok, "the daemon must see itself in the task walk")
	assert.Equal(t, selfTgid, tr.workerTgid)

	// Seeding: the worker's (our) threads are runner infrastructure, keyed
	// by global tid, and the namespace table names us by our own pid.
	var got uint32
	require.NoError(t, objs.MapTaskStep.Lookup(selfTgid, &got))
	assert.Equal(t, uint32(events.StepOrdinalRunner), got)
	require.NoError(t, objs.MapTaskNspid.Lookup(selfTgid, &got))
	assert.Equal(t, uint32(os.Getpid()), got)

	child := exec.Command("sleep", "5")
	require.NoError(t, child.Start())
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	childPID := child.Process.Pid

	snap, err = tr.snapshotFn()
	require.NoError(t, err)
	childTgid, ok := snap.global[childPID]
	require.True(t, ok, "child must be visible to the task walk")
	var ordinal uint32
	require.NoError(t, objs.MapTaskStep.Lookup(childTgid, &ordinal),
		"worker child must be tagged under its global tid")
	// Ordinals are opaque group ids, not positions: transient runtime forks
	// (Go's one-time pidfd probe) consume them too, so only the base is a
	// floor — see Options.OrdinalBase.
	assert.GreaterOrEqual(t, ordinal, uint32(100))
	require.NoError(t, objs.MapTaskNspid.Lookup(childTgid, &got))
	assert.Equal(t, uint32(childPID), got)

	// The reconciler saw the boundary event (its tgid is our numbering, so
	// the cmdline read behind it works too — visible in -v output).
	assert.Eventually(t, func() bool { return tr.OrdinalAt(time.Now()) >= ordinal },
		2*time.Second, 20*time.Millisecond, "boundary must reach the reconciler")
}

// TestStart_InPidNamespace re-executes TestStart_TagsWorkerChild inside a
// fresh pid (and mount, for /proc) namespace — the shape of an ARC runner
// pod, where /proc pids and kernel pids disagree.
func TestStart_InPidNamespace(t *testing.T) {
	runInPidNamespace(t, "^TestStart_TagsWorkerChild$")
}

// runInPidNamespace runs the named test of this binary under
// unshare --pid --fork --mount-proc and requires it to pass there. Needs
// root (like every BPF test here) and util-linux.
func runInPidNamespace(t *testing.T, run string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not available")
	}
	out, err := exec.Command(unshare, "--pid", "--fork", "--mount-proc",
		os.Args[0], "-test.run", run, "-test.v").CombinedOutput()
	t.Logf("inside pid namespace:\n%s", out)
	if strings.Contains(string(out), "--- SKIP") {
		t.Skip("inner test skipped")
	}
	require.NoError(t, err)
	require.Contains(t, string(out), "--- PASS")
}
