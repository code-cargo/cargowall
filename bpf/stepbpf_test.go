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
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/podenv"
)

// Step event kinds (STEP_EV_* in stepbpf.c).
const (
	stepEvFork = uint32(StepBpfStepEventKindSTEP_EV_FORK)
	stepEvExec = uint32(StepBpfStepEventKindSTEP_EV_EXEC)
	stepEvExit = uint32(StepBpfStepEventKindSTEP_EV_EXIT)
	stepEvEnd  = uint32(StepBpfStepEventKindSTEP_EV_END)
)

// readStepEvent reads the next step event: its kind, and the event decoded
// as the struct its kind says it is: a fork, an exit or an end is a child
// event, exactly that size, and an exec an exec event.
func readStepEvent(t *testing.T, rd *ringbuf.Reader) (uint32, StepBpfStepChildEvent, StepBpfStepExecEvent) {
	t.Helper()
	record, err := rd.Read()
	require.NoError(t, err, "a step event must arrive")
	raw := record.RawSample
	require.GreaterOrEqual(t, len(raw), 4)
	var fork StepBpfStepChildEvent
	var execEv StepBpfStepExecEvent
	switch kind := *(*uint32)(unsafe.Pointer(&raw[0])); kind {
	case stepEvFork, stepEvExit, stepEvEnd:
		require.Len(t, raw, int(unsafe.Sizeof(fork)))
		fork = *(*StepBpfStepChildEvent)(unsafe.Pointer(&raw[0]))
		return kind, fork, execEv
	case stepEvExec:
		require.GreaterOrEqual(t, len(raw), int(unsafe.Sizeof(execEv)))
		execEv = *(*StepBpfStepExecEvent)(unsafe.Pointer(&raw[0]))
		return kind, fork, execEv
	default:
		t.Fatalf("unknown step event kind %d", kind)
		return 0, fork, execEv
	}
}

// monoNow reads CLOCK_MONOTONIC, the clock bpf_ktime_get_ns reads.
func monoNow(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts))
	return uint64(ts.Nano())
}

// argvOf returns the argument bytes an exec event copied.
func argvOf(ev StepBpfStepExecEvent) string {
	n := min(int(ev.ArgvLen), len(ev.Argv))
	return string(unsafe.Slice((*byte)(unsafe.Pointer(&ev.Argv[0])), n))
}

// envOf returns the environment bytes an exec event copied.
func envOf(ev StepBpfStepExecEvent) string {
	n := min(int(ev.EnvLen), len(ev.Env))
	return string(unsafe.Slice((*byte)(unsafe.Pointer(&ev.Env[0])), n))
}

// awaitStepEvent reads step events until one of kind for ordinal (any
// ordinal when ordinal is 0) satisfies match, logging every event seen.
func awaitStepEvent(t *testing.T, rd *ringbuf.Reader, kind, ordinal uint32,
	match func(StepBpfStepChildEvent, StepBpfStepExecEvent) bool,
) (StepBpfStepChildEvent, StepBpfStepExecEvent) {
	t.Helper()
	rd.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		k, fork, execEv := readStepEvent(t, rd)
		ord := fork.Ordinal
		if k == stepEvExec {
			ord = execEv.Ordinal
		}
		t.Logf("step event: kind=%d ordinal=%d fork.tgid=%d exec.tgid=%d argv_len=%d", k, ord, fork.Tgid,
			execEv.Tgid, execEv.ArgvLen)
		if k == kind && (ordinal == 0 || ord == ordinal) && match(fork, execEv) {
			return fork, execEv
		}
	}
}

// pidnsInode is the daemon-side half of the namespace bridge: the nsfs
// inode of this process's pid namespace, as pkg/steps passes it in.
func pidnsInode(t *testing.T) uint32 {
	t.Helper()
	ino, err := podenv.PidNamespaceInode()
	require.NoError(t, err)
	return ino
}

// taskRecords runs the task iterator once and returns its records.
func taskRecords(t *testing.T, iter *link.Iter) []StepBpfTaskIterRec {
	t.Helper()
	rd, err := iter.Open()
	require.NoError(t, err)
	defer rd.Close()
	data, err := io.ReadAll(rd)
	require.NoError(t, err)
	const recSize = int(unsafe.Sizeof(StepBpfTaskIterRec{}))
	var recs []StepBpfTaskIterRec
	for off := 0; off+recSize <= len(data); off += recSize {
		recs = append(recs, *(*StepBpfTaskIterRec)(unsafe.Pointer(&data[off])))
	}
	return recs
}

// leaderRecord returns the iterator's record for the leader of the process
// numbered nsPid in this namespace.
func leaderRecord(t *testing.T, iter *link.Iter, nsPid int) (StepBpfTaskIterRec, bool) {
	t.Helper()
	for _, rec := range taskRecords(t, iter) {
		if rec.Tid == rec.Tgid && int(rec.NsTgid) == nsPid {
			return rec, true
		}
	}
	return StepBpfTaskIterRec{}, false
}

// globalTgid runs the task iterator and returns the global tgid of the
// process numbered nsPid in this namespace — the translation pkg/steps
// performs for the worker pid and for seeding.
func globalTgid(t *testing.T, iter *link.Iter, nsPid int) (uint32, bool) {
	t.Helper()
	rec, ok := leaderRecord(t, iter, nsPid)
	return rec.Tgid, ok
}

// loadStepObjects loads StepBpf against TcBpf's shared maps and attaches
// the fork, exec and exit tracepoints and the task iterator, as pkg/steps.Start
// does. It skips without kernel BTF; the step hooks stay disabled until a
// test writes map_step_state, and are disabled again on cleanup.
func loadStepObjects(t *testing.T) (*TcBpfObjects, *StepBpfObjects, *link.Iter) {
	t.Helper()
	tcObjs := loadBPFObjects(t)

	spec, err := LoadStepBpf()
	require.NoError(t, err)
	require.NoError(t, spec.Variables[StepBpfVarPidnsIno].Set(pidnsInode(t)))

	var objs StepBpfObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"map_task_step":  tcObjs.MapTaskStep,
			"map_sock_step":  tcObjs.MapSockStep,
			"map_step_state": tcObjs.MapStepState,
			"map_task_nspid": tcObjs.MapTaskNspid,
		},
	}); err != nil {
		t.Skipf("step BPF objects not loadable (kernel BTF required): %v", err)
	}
	t.Cleanup(func() { objs.Close() })

	forkLink, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.CwStepFork,
		AttachType: ebpf.AttachTraceRawTp,
	})
	require.NoError(t, err, "attach sched_process_fork")
	t.Cleanup(func() { forkLink.Close() })

	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.CwStepExit,
		AttachType: ebpf.AttachTraceRawTp,
	})
	require.NoError(t, err, "attach sched_process_exit")
	t.Cleanup(func() { exitLink.Close() })

	execLink, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.CwStepExec,
		AttachType: ebpf.AttachTraceRawTp,
	})
	require.NoError(t, err, "attach sched_process_exec")
	t.Cleanup(func() { execLink.Close() })

	iter, err := link.AttachIter(link.IterOptions{Program: objs.CwStepIter})
	require.NoError(t, err, "attach task iterator")
	t.Cleanup(func() { iter.Close() })

	// Disable so later tests in this package see inert step hooks.
	t.Cleanup(func() { _ = tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{}) })
	return tcObjs, &objs, iter
}

// TestStepFork verifies the step-attribution collection end to end on a real
// kernel: it loads StepBpf against TcBpf's shared maps, attaches the tp_btf
// tracepoints and the task iterator, declares the test process itself as
// Runner.Worker (by the global tgid the iterator reports for our /proc
// pid), forks a child, and asserts the kernel assigned it the configured
// ordinal under its global tid, recorded its namespace pid in
// map_task_nspid, and emitted the new-step ringbuf notification carrying
// that namespace pid — the exact contract pkg/steps.Start builds on.
// Requires root and kernel BTF. TestStepFork_InPidNamespace re-runs it
// where global and namespace pids differ.
func TestStepFork(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)

	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	// Declare this test process as the worker — by global tgid, which is
	// what cw_step_fork compares parent->tgid against — so its next direct
	// child gets ordinal 5. Uses the bpf2go-generated state struct so kernel
	// and Go layouts cannot drift.
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok, "the iterator must list this process")
	const wantOrdinal = 5
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{
		WorkerTgid:  selfTgid,
		Enabled:     1,
		NextOrdinal: wantOrdinal,
	}))

	before := monoNow(t)
	child := exec.Command("sleep", "1")
	require.NoError(t, child.Start())
	after := monoNow(t)
	childPID := uint32(child.Process.Pid)
	defer func() { _ = child.Wait() }()

	// The fork hook runs synchronously inside fork(), so both the tag (under
	// the child's global tid) and its namespace-pid entry must be visible as
	// soon as Start returns.
	childTgid, ok := globalTgid(t, iter, int(childPID))
	require.True(t, ok, "the iterator must list the child")
	var got uint32
	require.NoError(t, tcObjs.MapTaskStep.Lookup(childTgid, &got),
		"child tid must be tagged immediately after fork")
	var nsPid uint32
	require.NoError(t, tcObjs.MapTaskNspid.Lookup(childTgid, &nsPid))
	require.Equal(t, childPID, nsPid, "map_task_nspid must carry the child's pid as we number it")

	// The new-step notification must arrive for the reconciler. Other test
	// machinery may fork too (Go's pidfd probe is a worker child of its
	// own), so scan until the child's event or deadline.
	fork, _ := awaitStepEvent(t, rd, stepEvFork, 0, func(f StepBpfStepChildEvent, _ StepBpfStepExecEvent) bool {
		return f.Tgid == childPID
	})
	require.Equal(t, got, fork.Ordinal, "map tag and boundary event must agree")
	require.GreaterOrEqual(t, fork.Ordinal, uint32(wantOrdinal))
	require.Zero(t, fork.Pad)
	require.True(t, fork.Ktime >= before && fork.Ktime <= after,
		"the fork is dated when it happened: %d not in [%d, %d]", fork.Ktime, before, after)

	// Its first exec says what it runs, under the same ordinal and pid.
	_, execEv := awaitStepEvent(t, rd, stepEvExec, fork.Ordinal, func(StepBpfStepChildEvent, StepBpfStepExecEvent) bool {
		return true
	})
	require.Equal(t, childPID, execEv.Tgid)
	require.Equal(t, fork.Ktime, execEv.ForkKtime, "the exec event carries the fork's time")
	require.Equal(t, "sleep\x001\x00", argvOf(execEv))
	comm := unsafe.Slice((*byte)(unsafe.Pointer(&execEv.Comm[0])), len(execEv.Comm))
	require.Equal(t, "sleep", strings.TrimRight(string(comm), "\x00"), "the exec event carries the program's name")
	require.EqualValues(t, len("sleep\x001\x00"), execEv.ArgvLen)

	// Exit hygiene: once the child is reaped, its tag and namespace entry
	// must be gone.
	require.NoError(t, child.Wait())
	require.Eventually(t, func() bool {
		var v uint32
		return tcObjs.MapTaskStep.Lookup(childTgid, &v) != nil &&
			tcObjs.MapTaskNspid.Lookup(childTgid, &v) != nil
	}, 2*time.Second, 50*time.Millisecond, "exit tracepoint must delete the child's entries")
}

// TestStepExec_CutsLongArguments: an argument area longer than the event
// holds is copied up to the event's size, and its full length reported.
func TestStepExec_CutsLongArguments(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)
	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	arg := strings.Repeat("x", 300)
	child := exec.Command("true", arg)
	require.NoError(t, child.Start())
	pid := uint32(child.Process.Pid)
	require.NoError(t, child.Wait())

	_, execEv := awaitStepEvent(t, rd, stepEvExec, 0, func(_ StepBpfStepChildEvent, e StepBpfStepExecEvent) bool {
		return e.Tgid == pid
	})
	full := "true\x00" + arg + "\x00"
	require.EqualValues(t, len(full), execEv.ArgvLen)
	require.Equal(t, full[:len(execEv.Argv)], argvOf(execEv))
}

// TestStepExec_CarriesEnvironment: a step root's exec event carries the
// environment its parent gave it, as the kernel laid it out — where the
// runner names the step — and an environment longer than the event holds
// is copied up to the event's size, with its full length reported.
func TestStepExec_CarriesEnvironment(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)
	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	run := func(env ...string) StepBpfStepExecEvent {
		t.Helper()
		child := exec.Command("/bin/true")
		child.Env = env
		require.NoError(t, child.Start())
		pid := uint32(child.Process.Pid)
		require.NoError(t, child.Wait())
		_, execEv := awaitStepEvent(t, rd, stepEvExec, 0, func(_ StepBpfStepChildEvent, e StepBpfStepExecEvent) bool {
			return e.Tgid == pid
		})
		return execEv
	}

	small := run("HOME=/home/runner", "GITHUB_ACTION=build")
	want := "HOME=/home/runner\x00GITHUB_ACTION=build\x00"
	require.EqualValues(t, len(want), small.EnvLen)
	require.Equal(t, want, envOf(small))

	big := strings.Repeat("v", len(small.Env)+1000)
	cut := run("BIG="+big, "GITHUB_ACTION=build")
	full := "BIG=" + big + "\x00GITHUB_ACTION=build\x00"
	require.EqualValues(t, len(full), cut.EnvLen)
	require.Equal(t, full[:len(cut.Env)], envOf(cut))
}

// TestStepExec_FirstExecOnly: a step root that execs again (a shell's
// `exec`) is reported once, for what the worker started; its later exec
// says nothing, and its exit only ends the step, once.
func TestStepExec_FirstExecOnly(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)
	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	child := exec.Command("sh", "-c", "exec true")
	require.NoError(t, child.Start())
	pid := uint32(child.Process.Pid)
	require.NoError(t, child.Wait())

	_, first := awaitStepEvent(t, rd, stepEvExec, 0, func(_ StepBpfStepChildEvent, e StepBpfStepExecEvent) bool {
		return e.Tgid == pid
	})
	require.Equal(t, "sh\x00-c\x00exec true\x00", argvOf(first))
	// Drain what is left: nothing more for this ordinal but its end.
	rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
	ends := 0
	for {
		record, err := rd.Read()
		if err != nil {
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			break
		}
		raw := record.RawSample
		// Every kind carries its ordinal at the same offset.
		if kind := *(*uint32)(unsafe.Pointer(&raw[0])); len(raw) >= 12 && kind != stepEvFork {
			ord := *(*uint32)(unsafe.Pointer(&raw[8]))
			if kind == stepEvEnd && ord == first.Ordinal {
				ends++
				continue
			}
			require.NotEqual(t, first.Ordinal, ord, "a second event (kind %d) for the step", kind)
		}
	}
	require.Equal(t, 1, ends, "the root's exit ends the step, once")
}

// TestHelperExecFromThread is not a test: TestStepExec_FromThreadKeepsTag
// runs the test binary with STEPBPF_EXEC_FROM_THREAD set to a file, and
// this writes there the tid of a thread other than the leader, then execs
// `sleep 2` from it.
func TestHelperExecFromThread(t *testing.T) {
	tidFile := os.Getenv("STEPBPF_EXEC_FROM_THREAD")
	if tidFile == "" {
		t.Skip("helper process only")
	}
	errs := make(chan error, 1)
	var execFrom func()
	execFrom = func() {
		runtime.LockOSThread() // never unlocked: this thread execs, or stays busy
		if unix.Gettid() == unix.Getpid() {
			go execFrom() // the leader: try again from another thread
			select {}
		}
		if err := os.WriteFile(tidFile, []byte(strconv.Itoa(unix.Gettid())), 0o600); err != nil {
			errs <- err
			return
		}
		errs <- unix.Exec("/bin/sleep", []string{"sleep", "2"}, os.Environ())
	}
	go execFrom()
	t.Fatal(<-errs)
}

// TestStepExec_FromThreadKeepsTag: a process whose non-leader thread execs
// keeps its tag and namespace pid. The exec'ing thread takes the leader's
// tid, under which the leader's exit has already deleted both entries, and
// its own tid's entries move with it rather than staying behind.
func TestStepExec_FromThreadKeepsTag(t *testing.T) {
	tcObjs, _, iter := loadStepObjects(t)
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	if int(selfTgid) != os.Getpid() {
		// The maps are read by pid below: a task walk would re-seed the
		// namespace entry and hide a lost one.
		t.Skip("needs the initial pid namespace, where a pid is the tid the maps are keyed by")
	}
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	tidFile := t.TempDir() + "/tid"
	child := exec.Command(os.Args[0], "-test.run", "^TestHelperExecFromThread$")
	child.Env = append(os.Environ(), "STEPBPF_EXEC_FROM_THREAD="+tidFile)
	require.NoError(t, child.Start())
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	pid := child.Process.Pid
	require.Eventually(t, func() bool {
		comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
		return err == nil && strings.TrimSpace(string(comm)) == "sleep"
	}, 5*time.Second, 10*time.Millisecond, "the helper must exec sleep")

	raw, err := os.ReadFile(tidFile)
	require.NoError(t, err)
	oldTid, err := strconv.Atoi(string(raw))
	require.NoError(t, err)
	require.NotEqual(t, pid, oldTid, "the helper must exec from a thread other than the leader")

	// comm changes before sched_process_exec fires, so the move can still
	// be on its way.
	tgid := uint32(pid)
	var ord, nsPid uint32
	require.Eventually(t, func() bool {
		return tcObjs.MapTaskStep.Lookup(tgid, &ord) == nil && tcObjs.MapTaskNspid.Lookup(tgid, &nsPid) == nil
	}, 2*time.Second, 10*time.Millisecond, "the process must keep its tag and namespace pid")
	require.GreaterOrEqual(t, ord, uint32(5))
	require.EqualValues(t, pid, nsPid)
	var v uint32
	require.ErrorIs(t, tcObjs.MapTaskStep.Lookup(uint32(oldTid), &v), ebpf.ErrKeyNotExist,
		"the exec'ing thread's old tid must not keep a tag")
	require.ErrorIs(t, tcObjs.MapTaskNspid.Lookup(uint32(oldTid), &v), ebpf.ErrKeyNotExist,
		"nor a namespace pid")
}

// stepRootExecsFromThread is the worker for TestStepExec_FirstExecFromThread:
// it waits for a line on stdin, then forks a step root that never execs
// itself but starts a thread, and that thread execs: the root's first exec
// comes from a thread other than its leader.
const stepRootExecsFromThread = `
import os, sys, threading
sys.stdin.readline()
pid = os.fork()
if pid == 0:
    t = threading.Thread(target=lambda: os.execv("/bin/sleep", ["sleep", "1"]))
    t.start()
    t.join()
    os._exit(1)
os.waitpid(pid, 0)
`

// TestStepExec_FirstExecFromThread: a step root whose first exec comes from
// a thread other than its leader reports that exec, not an exit. de_thread
// makes the leader exit before the exec completes, and that exit is not the
// process's.
func TestStepExec_FirstExecFromThread(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	tcObjs, objs, iter := loadStepObjects(t)
	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	worker := exec.Command(python, "-c", stepRootExecsFromThread)
	stdin, err := worker.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, worker.Start())
	t.Cleanup(func() { _ = stdin.Close(); _ = worker.Process.Kill(); _ = worker.Wait() })
	workerTgid, ok := globalTgid(t, iter, worker.Process.Pid)
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: workerTgid, Enabled: 1, NextOrdinal: 5}))

	_, err = stdin.Write([]byte("\n"))
	require.NoError(t, err)
	fork, _ := awaitStepEvent(t, rd, stepEvFork, 0, func(StepBpfStepChildEvent, StepBpfStepExecEvent) bool { return true })
	rd.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		kind, _, ev := readStepEvent(t, rd)
		if kind == stepEvFork || ev.Ordinal != fork.Ordinal {
			continue
		}
		require.Equal(t, stepEvExec, kind, "the step must report its exec, not its leader's exit")
		require.Equal(t, "sleep\x001\x00", argvOf(ev))
		require.Equal(t, fork.Tgid, ev.Tgid)
		return
	}
}

// TestStepExit_WithoutExec: a step root that exits without exec'ing reports
// its exit instead, with no arguments. The worker here is a shell, whose
// subshell forks and exits without an exec.
func TestStepExit_WithoutExec(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)
	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	sh := exec.Command("sh", "-c", "read x; ( : ); read y")
	stdin, err := sh.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, sh.Start())
	t.Cleanup(func() { _ = stdin.Close(); _ = sh.Wait() })
	shTgid, ok := globalTgid(t, iter, sh.Process.Pid)
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: shTgid, Enabled: 1, NextOrdinal: 5}))

	_, err = stdin.Write([]byte("\n"))
	require.NoError(t, err)
	fork, _ := awaitStepEvent(t, rd, stepEvFork, 0, func(StepBpfStepChildEvent, StepBpfStepExecEvent) bool { return true })
	// An exit record has no room for an environment (readStepEvent pins its
	// size), so it can't carry what an older exec record left in the ring.
	exitEv, _ := awaitStepEvent(t, rd, stepEvExit, fork.Ordinal, func(StepBpfStepChildEvent, StepBpfStepExecEvent) bool {
		return true
	})
	require.Equal(t, fork.Tgid, exitEv.Tgid)
	require.Zero(t, exitEv.Pad)
	require.True(t, exitEv.Ktime >= fork.Ktime && exitEv.Ktime <= monoNow(t),
		"the exit is dated when it happened: %d not in [%d, now]", exitEv.Ktime, fork.Ktime)
	var k, v uint32
	require.False(t, objs.MapStepLive.Iterate().Next(&k, &v), "a root that never exec'd has no step to end")
}

// TestStepEnd_LostIsCounted: a step end the ring has no room for, its
// reader gone quiet and full with exec events, is counted.
func TestStepEnd_LostIsCounted(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	// With no reader, about sixty exec events (each over STEP_ENV_MAX) fill
	// the ring's 2MB but for less than one more, and the fork and end
	// events after take what is left, a few hundred roots on.
	lost := func() uint64 {
		var perCPU []uint64
		require.NoError(t, objs.MapStepEndsLost.Lookup(uint32(0), &perCPU))
		var n uint64
		for _, v := range perCPU {
			n += v
		}
		return n
	}
	for i := 0; i < 5000 && lost() == 0; i++ {
		require.NoError(t, exec.Command("true").Run())
	}
	require.NotZero(t, lost(), "the ends that found the ring full are counted")
}

// TestStepEnd_AfterExec: a step root that exits after its exec reports
// its step's end, once, dated when it exited, and leaves nothing behind.
func TestStepEnd_AfterExec(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)
	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	child := exec.Command("true")
	require.NoError(t, child.Start())
	childPID := uint32(child.Process.Pid)
	fork, _ := awaitStepEvent(t, rd, stepEvFork, 0, func(f StepBpfStepChildEvent, _ StepBpfStepExecEvent) bool {
		return f.Tgid == childPID
	})
	require.NoError(t, child.Wait())
	end, _ := awaitStepEvent(t, rd, stepEvEnd, fork.Ordinal, func(StepBpfStepChildEvent, StepBpfStepExecEvent) bool {
		return true
	})
	require.Zero(t, end.Pad)
	require.True(t, end.Ktime > fork.Ktime && end.Ktime <= monoNow(t),
		"the end is dated when the root exited: %d not in (%d, now]", end.Ktime, fork.Ktime)
	var k, v uint32
	require.False(t, objs.MapStepLive.Iterate().Next(&k, &v), "the ended root is out of map_step_live")
}

// readProcInt reads an integer /proc/sys value.
func readProcInt(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	return n
}

// onRecycledTid plants a stale tag at a free pid, steers the pid allocator
// onto it through ns_last_pid, runs spawn, and returns the lookup of that
// tid in map_task_step while spawn's task still lives (once it exits,
// cw_step_exit deletes the entry whatever cw_step_fork did). spawn reports
// whether its new task drew the pid, and returns how to end it. Something
// else on the host can take the pid first, so it tries again; it skips
// after 20 misses.
func onRecycledTid(t *testing.T, tcObjs *TcBpfObjects, spawn func(pid int) (bool, func())) error {
	t.Helper()
	const stale = uint32(77)
	pidMax := readProcInt(t, "/proc/sys/kernel/pid_max")
	for range 20 {
		pid := readProcInt(t, "/proc/sys/kernel/ns_last_pid") + 100
		if pid >= pidMax {
			pid = 1000 // allocation resumes above RESERVED_PIDS (300) after a wrap
		}
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
			continue
		}
		require.NoError(t, tcObjs.MapTaskStep.Put(uint32(pid), stale))
		require.NoError(t, os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(strconv.Itoa(pid-1)), 0))
		landed, end := spawn(pid)
		var got uint32
		err := tcObjs.MapTaskStep.Lookup(uint32(pid), &got)
		end()
		_ = tcObjs.MapTaskStep.Delete(uint32(pid))
		if !landed {
			continue
		}
		if err == nil {
			return fmt.Errorf("tid %d kept tag %d", pid, got)
		}
		return err
	}
	t.Skip("no new task landed on a chosen pid in 20 tries")
	return nil
}

// untagSelf readies this process to be the untagged creator of a recycled
// tid: it must run in the initial pid namespace, where a pid is the tid the
// maps are keyed by, and no thread of it (any may be the one that forks)
// may hold a tag.
func untagSelf(t *testing.T, tcObjs *TcBpfObjects, iter *link.Iter) {
	t.Helper()
	if self, ok := globalTgid(t, iter, os.Getpid()); !ok || int(self) != os.Getpid() {
		t.Skip("needs the initial pid namespace, where a pid is the tid the maps are keyed by")
	}
	for _, rec := range taskRecords(t, iter) {
		if int(rec.Tgid) == os.Getpid() {
			_ = tcObjs.MapTaskStep.Delete(rec.Tid)
		}
	}
}

// TestStepFork_RecycledTidStartsClean: a tid can come back from the pid
// allocator still holding a tag, one userspace wrote to a task that exited
// between its task walk and its map write, after cw_step_exit had run. A
// child of an untagged parent must come out untagged all the same, and so
// must any child while attribution is off, when a create-only seed pass
// would keep the stale value. No worker is set, so every fork is case 2.
func TestStepFork_RecycledTidStartsClean(t *testing.T) {
	tcObjs, _, iter := loadStepObjects(t)
	untagSelf(t, tcObjs, iter)
	for _, enabled := range []uint32{1, 0} {
		require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{Enabled: enabled}))
		err := onRecycledTid(t, tcObjs, func(pid int) (bool, func()) {
			child := exec.Command("sleep", "5")
			require.NoError(t, child.Start())
			return child.Process.Pid == pid, func() { _ = child.Process.Kill(); _ = child.Wait() }
		})
		require.ErrorIs(t, err, ebpf.ErrKeyNotExist, "enabled=%d", enabled)
	}
}

// TestStepFork_RecycledTidStartsClean_IoWorker: an io_uring worker never
// reaches sched_process_fork, so the tid it draws is cleared only because
// cw_step_fork runs at task_newtask. An SQPOLL ring makes one, a thread of
// this process, when it is set up.
func TestStepFork_RecycledTidStartsClean_IoWorker(t *testing.T) {
	tcObjs, _, iter := loadStepObjects(t)
	untagSelf(t, tcObjs, iter)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{Enabled: 1}))
	err := onRecycledTid(t, tcObjs, func(pid int) (bool, func()) {
		var params [120]byte // struct io_uring_params
		const setupSQPoll = 1 << 1
		binary.NativeEndian.PutUint32(params[8:], setupSQPoll)
		fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0)
		if errno != 0 {
			t.Skipf("io_uring SQPOLL unavailable: %v", errno)
		}
		_, err := os.Stat("/proc/self/task/" + strconv.Itoa(pid))
		return err == nil, func() { _ = unix.Close(int(fd)) }
	})
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}

// TestStepTaskIter_FlagsExitingTask: the walk lists a zombie, flagged as
// exiting, and does not put back the namespace entry cw_step_exit deleted.
// Userspace must not tag such a task: the tag would outlive it.
func TestStepTaskIter_FlagsExitingTask(t *testing.T) {
	tcObjs, _, iter := loadStepObjects(t)

	child := exec.Command("true")
	require.NoError(t, child.Start())
	pid := child.Process.Pid
	t.Cleanup(func() { _ = child.Wait() })
	// Unreaped, the child stays listed after it exits.
	require.Eventually(t, func() bool {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			return false
		}
		end := strings.LastIndexByte(string(stat), ')')
		return end > 0 && strings.HasPrefix(string(stat[end+1:]), " Z")
	}, 2*time.Second, 10*time.Millisecond, "the child must become a zombie")

	rec, ok := leaderRecord(t, iter, pid)
	require.True(t, ok, "the walk must still list the zombie")
	require.EqualValues(t, 1, rec.Exiting, "a zombie must be flagged as exiting")
	var nsPid uint32
	require.ErrorIs(t, tcObjs.MapTaskNspid.Lookup(rec.Tid, &nsPid), ebpf.ErrKeyNotExist,
		"the walk must not re-seed an exited task's namespace entry")

	self, ok := leaderRecord(t, iter, os.Getpid())
	require.True(t, ok)
	require.Zero(t, self.Exiting, "a live task must not be flagged")
}

// TestStepFork_InPidNamespace re-executes TestStepFork inside a fresh pid
// (and mount, for /proc) namespace — the shape of an ARC runner pod, where
// /proc pids and the kernel's global pids disagree and the pre-iterator
// contract failed on the very first lookup.
func TestStepFork_InPidNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not available")
	}
	out, err := exec.Command(unshare, "--pid", "--fork", "--mount-proc",
		os.Args[0], "-test.run", "^TestStepFork$", "-test.v").CombinedOutput()
	t.Logf("inside pid namespace:\n%s", out)
	if strings.Contains(string(out), "--- SKIP") {
		t.Skip("inner test skipped")
	}
	require.NoError(t, err)
	require.Contains(t, string(out), "--- PASS: TestStepFork")
}

// TestBlockedEventLayoutMatchesBTF pins the kernel↔userspace event layout:
// every member of the C struct blocked_event (as compiled, via BTF) must sit
// at the same offset as its field in the Go mirror, and the sizes must
// match. This is the guard the step_ordinal repurposing needs — a swapped
// or shifted field (e.g. pid↔step_ordinal) changes a BTF offset and fails
// here, where the ringbuf-decoding tests would silently mis-attribute.
// (A cookie-seeded end-to-end test is not possible: PROG_TEST_RUN allocates
// a real socket for the skb, so its cookie is fresh and unknowable.)
func TestBlockedEventLayoutMatchesBTF(t *testing.T) {
	spec, err := LoadTcBpf()
	require.NoError(t, err)

	typ, err := spec.Types.AnyTypeByName("blocked_event")
	require.NoError(t, err)
	st, ok := typ.(*btf.Struct)
	require.True(t, ok, "blocked_event must be a struct, got %T", typ)

	var evt bpfBlockedEvent
	require.Equal(t, uint32(unsafe.Sizeof(evt)), st.Size, "struct size")

	goOffsets := map[string]uintptr{
		"ip_version":   unsafe.Offsetof(evt.IpVersion),
		"allowed":      unsafe.Offsetof(evt.Allowed),
		"ip_proto":     unsafe.Offsetof(evt.IpProto),
		"flags":        unsafe.Offsetof(evt.Flags),
		"src_ip":       unsafe.Offsetof(evt.SrcIp),
		"dst_ip":       unsafe.Offsetof(evt.DstIp),
		"src_port":     unsafe.Offsetof(evt.SrcPort),
		"dst_port":     unsafe.Offsetof(evt.DstPort),
		"src_ip6":      unsafe.Offsetof(evt.SrcIp6),
		"dst_ip6":      unsafe.Offsetof(evt.DstIp6),
		"timestamp":    unsafe.Offsetof(evt.Timestamp),
		"pid":          unsafe.Offsetof(evt.Pid),
		"step_ordinal": unsafe.Offsetof(evt.StepOrdinal),
	}

	seen := make(map[string]bool)
	for _, m := range st.Members {
		want, known := goOffsets[m.Name]
		require.True(t, known, "C member %q has no Go mirror field", m.Name)
		require.Equal(t, want, uintptr(m.Offset.Bytes()), "offset of %q", m.Name)
		seen[m.Name] = true
	}
	require.Len(t, seen, len(goOffsets), "Go mirror has fields the C struct lacks")
}

// TestStepChildEventLayoutMatchesBTF pins the reconciler notification layout
// the same way.
func TestStepChildEventLayoutMatchesBTF(t *testing.T) {
	spec, err := LoadStepBpf()
	require.NoError(t, err)

	typ, err := spec.Types.AnyTypeByName("step_child_event")
	require.NoError(t, err)
	st, ok := typ.(*btf.Struct)
	require.True(t, ok, "step_child_event must be a struct, got %T", typ)

	var ev StepBpfStepChildEvent
	require.Equal(t, uint32(unsafe.Sizeof(ev)), st.Size, "struct size")
	require.Len(t, st.Members, 5)
	for i, w := range []struct {
		name string
		off  uintptr
	}{
		{"kind", unsafe.Offsetof(ev.Kind)},
		{"tgid", unsafe.Offsetof(ev.Tgid)},
		{"ordinal", unsafe.Offsetof(ev.Ordinal)},
		{"pad", unsafe.Offsetof(ev.Pad)},
		{"ktime", unsafe.Offsetof(ev.Ktime)},
	} {
		require.Equal(t, w.name, st.Members[i].Name)
		require.Equal(t, w.off, uintptr(st.Members[i].Offset.Bytes()))
	}

	typ, err = spec.Types.AnyTypeByName("step_exec_event")
	require.NoError(t, err)
	st, ok = typ.(*btf.Struct)
	require.True(t, ok, "step_exec_event must be a struct, got %T", typ)
	var execEv StepBpfStepExecEvent
	require.Equal(t, uint32(unsafe.Sizeof(execEv)), st.Size, "struct size")
	require.Len(t, st.Members, 9)
	for i, w := range []struct {
		name string
		off  uintptr
	}{
		{"kind", unsafe.Offsetof(execEv.Kind)},
		{"tgid", unsafe.Offsetof(execEv.Tgid)},
		{"ordinal", unsafe.Offsetof(execEv.Ordinal)},
		{"argv_len", unsafe.Offsetof(execEv.ArgvLen)},
		{"fork_ktime", unsafe.Offsetof(execEv.ForkKtime)},
		{"argv", unsafe.Offsetof(execEv.Argv)},
		{"comm", unsafe.Offsetof(execEv.Comm)},
		{"env_len", unsafe.Offsetof(execEv.EnvLen)},
		{"env", unsafe.Offsetof(execEv.Env)},
	} {
		require.Equal(t, w.name, st.Members[i].Name)
		require.Equal(t, w.off, uintptr(st.Members[i].Offset.Bytes()))
	}
}

// TestTaskIterRecLayoutMatchesBTF pins the iterator record layout against
// the bpf2go mirror pkg/steps decodes with: the C struct is four packed
// u32s, and a regenerated mirror that drifted (a field reordered or
// widened in C without `go generate`) would break the unsafe cast.
func TestTaskIterRecLayoutMatchesBTF(t *testing.T) {
	spec, err := LoadStepBpf()
	require.NoError(t, err)

	typ, err := spec.Types.AnyTypeByName("task_iter_rec")
	require.NoError(t, err)
	st, ok := typ.(*btf.Struct)
	require.True(t, ok, "task_iter_rec must be a struct, got %T", typ)

	var rec StepBpfTaskIterRec
	require.Equal(t, uint32(unsafe.Sizeof(rec)), st.Size, "struct size")
	require.Len(t, st.Members, 5)
	want := []struct {
		name string
		off  uintptr
	}{
		{"tid", unsafe.Offsetof(rec.Tid)},
		{"tgid", unsafe.Offsetof(rec.Tgid)},
		{"ppid", unsafe.Offsetof(rec.Ppid)},
		{"ns_tgid", unsafe.Offsetof(rec.NsTgid)},
		{"exiting", unsafe.Offsetof(rec.Exiting)},
	}
	for i, w := range want {
		require.Equal(t, w.name, st.Members[i].Name)
		require.Equal(t, w.off, uintptr(st.Members[i].Offset.Bytes()))
	}
}

// TestStepMapsShrunkLoad pins the memory optimization in cmd/start.go:
// with step attribution off, the step maps are resized down before load,
// and the collection must still pass the verifier at the small sizes.
func TestStepMapsShrunkLoad(t *testing.T) {
	requireBPF(t)
	spec, err := LoadTcBpf()
	require.NoError(t, err)
	spec.Maps["map_task_step"].MaxEntries = 64
	spec.Maps["map_sock_step"].MaxEntries = 64
	spec.Maps["map_task_nspid"].MaxEntries = 64

	var objs TcBpfObjects
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	objs.Close()
}
