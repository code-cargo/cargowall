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

// Package steps provides causal per-workflow-step attribution of network
// traffic. Runner.Worker forks one direct child process per workflow step;
// the cw_step_fork tracepoint (bpf/stepbpf.c) tags each such child with a
// monotonically increasing ordinal, every other fork inherits the forking
// thread's tag, and the cgroup hooks copy the tag onto each socket cookie —
// so every TC event carries the step that (transitively) created its socket.
// The verdict reads a socket's tag only to find its step's own allow
// rules, through the step's policy binding (map_step_policy).
//
// Pid numbering: the kernel side keys everything by global (init-namespace)
// ids; everything this package reads from /proc — the worker pid, the
// daemon's own pid, container leaders reported by dockerd — is numbered in
// the daemon's pid namespace, a different space whenever cargowall runs
// inside a container (ARC runners are Kubernetes pods). The cw_step_iter
// BPF iterator bridges the two: it walks the daemon's namespace subtree,
// seeds the kernel's global→namespace table (map_task_nspid, which is what
// makes boundary events and socket pids resolvable) and streams the
// process tree in global ids, so seeding and container tagging never scan
// /proc. On a plain VM the translation is the identity.
package steps

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/code-cargo/cargowall/bpf"
	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/podenv"
	"github.com/code-cargo/cargowall/pkg/procfs"
)

// workerComm is the /proc/<pid>/comm value of the GitHub Actions runner's
// per-job worker process (13 chars, fits TASK_COMM_LEN untruncated).
const workerComm = procfs.RunnerWorkerComm

// Options configures Start.
type Options struct {
	// WorkerPID is the Runner.Worker process ID. 0 auto-discovers it by
	// scanning /proc for the workerComm process name.
	WorkerPID int
	// OrdinalBase is the ordinal assigned to the next new worker child.
	// Ordinals are opaque causal group IDs, not job-plan positions:
	// transient runtime forks (e.g. Go's one-time pidfd probe, seen
	// empirically in TestStepFork) also consume ordinals, so plan
	// correlation happens downstream by matching step_boundary cmdlines,
	// never by assuming ordinal == plan index.
	OrdinalBase uint64
	// OnIdentified, if set, is told each step's identity once, when its
	// root's first exec event is read, however late. It runs on the
	// step-event reader, before the step's report unless the exec event
	// comes too late for it, and must not block.
	// The step's program is already running by then: nothing orders the
	// call ahead of the step's first connection. A step whose exec event
	// never comes, and a root that exits without exec'ing, are never
	// identified. Only events.StepClassStep identifies a step, and see
	// Identity for what it does and doesn't vouch for. Without it, the
	// steps identified are kept until SetOnIdentified.
	OnIdentified func(ordinal uint32, id Identity)
}

// maxEarlyIdentities bounds the steps kept for SetOnIdentified: one a step
// policy can be bound for each (map_step_policy's size).
const maxEarlyIdentities = 4096

// maxOrdinalBase bounds --step-ordinal-base away from the reserved
// StepOrdinal* sentinels: the kernel increments a u64 counter but truncates
// each assignment to u32, so a base near the top would collide real steps
// with StepOrdinalPreDaemon/Runner (or wrap to 0 = no ordinal). The margin
// inside MaxRealStepOrdinal leaves room for any realistic number of steps.
const maxOrdinalBase = uint64(events.MaxRealStepOrdinal)

// Tracker owns the step-attribution BPF programs and the reconciler
// goroutine that turns new-step ringbuf notifications into audit events.
type Tracker struct {
	workerPID     int    // as numbered in the daemon's pid namespace (/proc)
	workerTgid    uint32 // the same process, global — what cw_step_fork compares
	workerCmdline string
	objs          bpf.StepBpfObjects
	links         []link.Link
	iter          *link.Iter // cw_step_iter; also in links for Close
	reader        *ringbuf.Reader
	stateMap      *ebpf.Map
	taskMap       *ebpf.Map
	nspidMap      *ebpf.Map // map_task_nspid; cleared at Close, see there
	auditLogger   *events.AuditLogger
	logger        *slog.Logger
	done          chan struct{}

	// idMu guards onIdentified and the steps identified before it was set
	// (SetOnIdentified): early, idSettled once it was, and earlyLost, the
	// steps past maxEarlyIdentities.
	idMu         sync.Mutex
	onIdentified func(ordinal uint32, id Identity)
	early        []earlyIdentity
	idSettled    bool
	earlyLost    int

	// Boundary history for OrdinalAt and for reporting steps — see the
	// boundary type.
	boundaryMu sync.Mutex
	boundaries []boundary

	// endsLost counts the step ends the kernel had no room to report
	// (map_step_ends_lost), read by run() at most every reportAfter;
	// endsLostSeen is what it has warned of. See checkEndsLost.
	endsLost        func() (uint64, error)
	endsLostSeen    uint64
	endsLostChecked time.Time

	// DNS-path client attribution (sock_diag lookups, caching, map joins) —
	// see clientResolver. Constructed in Start, closed in Close.
	resolver *clientResolver

	// snapshotFn produces the process tree the seeding and container-tagging
	// paths work from; iterSnapshot in production, injectable for tests.
	snapshotFn func() (*procSnapshot, error)
}

// Start loads the step-attribution collection against tcObjs' shared maps,
// seeds existing processes, attaches the tracepoints and sock_create hook,
// and starts the reconciler. The collection needs kernel BTF (tp_btf); on
// kernels without it Start fails and the caller degrades gracefully — the
// firewall proper is unaffected by design.
func Start(tcObjs *bpf.TcBpfObjects, opts Options, auditLogger *events.AuditLogger, logger *slog.Logger) (*Tracker, error) {
	if opts.OrdinalBase >= maxOrdinalBase {
		return nil, fmt.Errorf("step ordinal base %d too close to the reserved sentinel values (max %d)",
			opts.OrdinalBase, maxOrdinalBase-1)
	}
	if tcObjs == nil {
		return nil, errors.New("nil TC BPF objects")
	}
	if logger == nil {
		return nil, errors.New("nil logger")
	}

	workerPID := opts.WorkerPID
	if workerPID == 0 {
		var err error
		workerPID, err = findWorkerPID()
		if err != nil {
			return nil, err
		}
	}
	// Kernel pids fit comfortably in uint32 (pid_max caps at 2^22), but the
	// step_state map field is u32, so bound the conversion explicitly.
	if workerPID <= 0 || workerPID > math.MaxUint32 {
		return nil, fmt.Errorf("worker pid %d out of range", workerPID)
	}

	// Which pid namespace "our" pids belong to. Every /proc-derived id in
	// this package (the worker pid above, seeding, container leaders) is
	// numbered in it; the kernel numbers tasks globally. Identical on a
	// plain VM, different inside a container (ARC runners).
	pidnsIno, err := podenv.PidNamespaceInode()
	if err != nil {
		return nil, err
	}

	spec, err := bpf.LoadStepBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load step BPF spec: %w", err)
	}
	if v := spec.Variables[bpf.StepBpfVarPidnsIno]; v == nil {
		return nil, errors.New("step BPF spec has no pidns_ino variable (stale generated code)")
	} else if err := v.Set(pidnsIno); err != nil {
		return nil, fmt.Errorf("failed to set pidns_ino: %w", err)
	}

	t := &Tracker{
		workerPID: workerPID,
		// The worker's argv: a step root that exits without exec'ing ran
		// a copy of it, and reports it as its command line.
		workerCmdline: readCmdline(workerPID),
		stateMap:      tcObjs.MapStepState,
		taskMap:       tcObjs.MapTaskStep,
		nspidMap:      tcObjs.MapTaskNspid,
		auditLogger:   auditLogger,
		logger:        logger,
		done:          make(chan struct{}),
		onIdentified:  opts.OnIdentified,
		idSettled:     opts.OnIdentified != nil,
		resolver:      newClientResolver(tcObjs.MapSockStep, tcObjs.MapSockPid, logger),
	}
	t.snapshotFn = t.iterSnapshot

	// The shared maps are owned by the tcbpf collection; replacing them here
	// makes both collections operate on the same kernel maps. Branch-level
	// logging as for TC: these programs are a few thousand instructions, so
	// the full log is cheap and a rejection stays diagnosable (cilium/ebpf
	// only retries a failed load with branch logging when no log level was
	// requested at all).
	if err := cargowallEbpf.LoadObjects(logger, "stepbpf", spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"map_task_step":  tcObjs.MapTaskStep,
			"map_sock_step":  tcObjs.MapSockStep,
			"map_step_state": tcObjs.MapStepState,
			"map_task_nspid": tcObjs.MapTaskNspid,
		},
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats},
	}, &t.objs); err != nil {
		return nil, fmt.Errorf("failed to load step BPF objects (kernel BTF required): %w", err)
	}

	if err := t.attach(); err != nil {
		t.Close()
		return nil, err
	}

	// First task walk: seeds map_task_nspid for everything that predates the
	// attach (the tracepoints keep it current from here on) and hands back
	// the process tree in global ids — which is how the worker's /proc pid
	// becomes the global tgid cw_step_fork compares against.
	snap, err := t.snapshotFn()
	if err != nil {
		t.Close()
		return nil, err
	}
	workerTgid, ok := snap.global[workerPID]
	if !ok {
		t.Close()
		return nil, fmt.Errorf("%s pid %d is not visible to the task iterator", workerComm, workerPID)
	}
	t.workerTgid = workerTgid
	if pidnsIno != podenv.InitPidNamespace {
		logger.Info("Running inside a pid namespace; translating task ids",
			"pidns_ino", pidnsIno, "worker_pid", workerPID, "worker_tgid", workerTgid)
	}

	// Seed while the programs are attached but still disabled (enabled=0 makes
	// the tagging hooks no-ops), then enable, then seed once more from a fresh
	// walk: the second pass catches processes forked during the first, so the
	// only unattributed window is forks that both start and create sockets
	// between the enable flip and the rescan. Seeding is strictly create-only
	// (BPF_NOEXIST), so the second pass can never clobber an ordinal the
	// now-live fork tracepoint assigned.
	t.seedExisting(snap)
	if err := t.stateMap.Put(uint32(0), bpf.TcBpfStepState{
		WorkerTgid:  workerTgid,
		Enabled:     1,
		NextOrdinal: max(opts.OrdinalBase, 1),
	}); err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to seed step state: %w", err)
	}
	if snap, err := t.snapshotFn(); err == nil {
		t.seedExisting(snap)
	} else {
		logger.Warn("Second seeding pass skipped", "error", err)
	}

	rd, err := ringbuf.NewReader(t.objs.MapStepEvents)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to create step event reader: %w", err)
	}
	t.reader = rd
	t.endsLost = func() (uint64, error) { return sumPerCPU(t.objs.MapStepEndsLost) }
	go t.run()

	return t, nil
}

// WorkerPID returns the Runner.Worker process ID being tracked.
func (t *Tracker) WorkerPID() int { return t.workerPID }

// Close disables tagging, detaches the programs, and stops the reconciler,
// waiting for an in-flight boundary event to finish writing before returning
// so the audit logger (whose deferred Close runs after ours) is still alive
// for it.
func (t *Tracker) Close() {
	// Best-effort disable so the tcbpf-side hooks stop tagging immediately,
	// even though the collection below is about to go away anyway.
	_ = t.stateMap.Put(uint32(0), bpf.TcBpfStepState{})
	if t.reader != nil {
		_ = t.reader.Close()
		<-t.done // run() exits promptly on ringbuf.ErrClosed
	}
	// Stop new sock_diag work (later StepForClient calls shed) and join the
	// per-table drainers, so no dump goroutine outlives the tracker.
	t.resolver.close()
	for _, l := range t.links {
		_ = l.Close()
	}
	// The tcbpf connect/sendmsg hooks outlive this tracker (they are
	// attached by cmd/start.go, and stay up when Start fails after the
	// iterator has already seeded the table). With the tracepoints gone
	// nothing maintains map_task_nspid, so a recycled tid would resolve to
	// a dead task's process. Empty it: the hooks then take their documented
	// global-tgid fallback, exactly as when attribution was never on.
	clearMap(t.nspidMap)
	t.objs.Close()
}

// clearMap deletes every entry of a u32→u32 hash map.
func clearMap(m *ebpf.Map) {
	if m == nil {
		return
	}
	var (
		keys []uint32
		k, v uint32
	)
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, k := range keys {
		_ = m.Delete(k)
	}
}

func (t *Tracker) attach() error {
	forkLink, err := link.AttachTracing(link.TracingOptions{
		Program:    t.objs.CwStepFork,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("failed to attach task_newtask: %w", err)
	}
	t.links = append(t.links, forkLink)

	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program:    t.objs.CwStepExit,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sched_process_exit: %w", err)
	}
	t.links = append(t.links, exitLink)

	execLink, err := link.AttachTracing(link.TracingOptions{
		Program:    t.objs.CwStepExec,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sched_process_exec: %w", err)
	}
	t.links = append(t.links, execLink)

	// Same root-cgroup attachment rationale as the connect/sendmsg hooks in
	// StartCargoWall: tag socket creation for every process on the machine.
	sockLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    podenv.CgroupRoot,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: t.objs.CwCgSockNew,
	})
	if err != nil {
		return fmt.Errorf("failed to attach cgroup sock_create: %w", err)
	}
	t.links = append(t.links, sockLink)

	iter, err := link.AttachIter(link.IterOptions{Program: t.objs.CwStepIter})
	if err != nil {
		return fmt.Errorf("failed to attach task iterator: %w", err)
	}
	t.links = append(t.links, iter)
	t.iter = iter
	return nil
}

// seedExisting tags processes that predate the daemon, from one task-walk
// snapshot. Worker threads get StepOrdinalRunner so infra traffic (log
// upload, action downloads) is labeled as runner overhead; existing worker
// child subtrees — steps that ran or started before cargowall attached —
// get StepOrdinalPreDaemon, except the daemon's own subtree, which gets
// StepOrdinalRunner (cargowall is infrastructure, not a workflow step).
// Every write is create-only: once the fork tracepoint is live it is the
// sole authority on new tags, and the post-enable rescan must never replace
// a kernel-assigned ordinal. Best-effort by nature: a walk races process
// creation, which is why Start runs it twice around the enable flip.
func (t *Tracker) seedExisting(snap *procSnapshot) {
	// Decide each pid's intended tag before writing anything, so a pid in
	// the daemon's subtree is written exactly once with the right value
	// (create-only writes mean there is no second chance).
	self := make(map[uint32]bool)
	selfTgid, selfVisible := snap.global[os.Getpid()]
	if selfVisible {
		for _, pid := range snap.subtree(selfTgid) {
			self[pid] = true
		}
	}

	t.tagTasks(snap, t.workerTgid, events.StepOrdinalRunner, ebpf.UpdateNoExist)
	for _, root := range snap.children[t.workerTgid] {
		for _, pid := range snap.subtree(root) {
			ordinal := events.StepOrdinalPreDaemon
			if self[pid] {
				ordinal = events.StepOrdinalRunner
			}
			t.tagTasks(snap, pid, ordinal, ebpf.UpdateNoExist)
		}
	}

	// Standalone runs (daemon not under the worker): still label our own
	// traffic as infrastructure. Create-only, so a no-op when the loop
	// above already covered us.
	if selfVisible {
		for _, pid := range snap.subtree(selfTgid) {
			t.tagTasks(snap, pid, events.StepOrdinalRunner, ebpf.UpdateNoExist)
		}
	}
}

// tagTasks writes ordinal for every live thread of the (global) tgid as
// listed in snap, and returns the ordinal they hold afterwards: ordinal
// where a write landed, what a create-only write found otherwise, the
// leader thread's own first. 0 with a nil error means snap lists no live
// thread of tgid; a failed write is an error only when no thread holds a
// tag. Seeding passes UpdateNoExist so a tid the fork tracepoint already
// tagged keeps its kernel-assigned ordinal; container leaders pass
// UpdateAny (see TagContainerProcess for why overwrite is safe there and
// only there).
func (t *Tracker) tagTasks(snap *procSnapshot, tgid, ordinal uint32, flags ebpf.MapUpdateFlags) (uint32, error) {
	var held, leaderHeld uint32
	var errs []error
	for _, tid := range snap.tids[tgid] {
		v := ordinal
		if err := t.taskMap.Update(tid, ordinal, flags); errors.Is(err, ebpf.ErrKeyExist) {
			if t.taskMap.Lookup(tid, &v) != nil {
				continue // exited between the two calls
			}
		} else if err != nil {
			errs = append(errs, err)
			continue
		}
		if held == 0 {
			held = v
		}
		if tid == tgid {
			leaderHeld = v
		}
	}
	if leaderHeld != 0 {
		return leaderHeld, nil
	}
	if held != 0 {
		return held, nil
	}
	return 0, errors.Join(errs...)
}

// TagContainerProcess tags a container workload subtree rooted at pid.
// Container ancestry runs through containerd-shim, never Runner.Worker, so
// kernel fork-inheritance cannot reach these processes — this is the
// userspace bridge that puts the launching step's ordinal on them, after
// which sock_create tags their sockets like any other tagged task.
//
// pid is as dockerd reported it, i.e. numbered in the daemon's namespace
// when dockerd shares it (the caller's cgroup identity check has already
// confirmed that pid is the expected container in our /proc).
//
// It returns the ordinal the subtree holds: the leader's, or the caller's
// when only children of an exiting leader took it. 0 with a nil error
// means the walk listed none of it alive: the task had exited, or was
// exiting, when the walk ran. One that exits between the walk and the write
// still counts as tagged, and its entry stays until cw_step_fork clears it for
// the tid's next task. An error means the walk or the writes failed, which
// says nothing of the task.
//
// The leader's threads are written with UpdateAny: a freshly shim-forked
// leader is untagged in the normal case, an exec re-tag into a long-lived
// container must replace the container's older ordinal, and overwrite
// self-heals a stale entry left by a recycled tid. Descendants are
// create-only — children forked after an earlier tag already carry correct
// kernel-inherited ordinals that must never be clobbered.
func (t *Tracker) TagContainerProcess(pid int, ordinal uint32) (uint32, error) {
	return t.tagSubtree(pid, ordinal, ebpf.UpdateAny)
}

// AdoptContainerProcess tags a container subtree like TagContainerProcess
// but create-only for the leader too. It is the reconcile-adoption write:
// adoption cannot distinguish "genuinely predates cargowall" from "live
// container wrongly swept after a partial daemon list and re-adopted", so
// an existing leader tag — the real ordinal from the container's original
// start — must survive and only truly untagged tasks take the caller's
// (sentinel) ordinal. The overwrite rationale above does not apply here:
// adoption is not an exec re-tag, and a recycled-tid stale entry is the
// rarer wrong to optimize for than demoting a live container. What it
// returns is as for TagContainerProcess: an existing leader tag is the
// ordinal held.
func (t *Tracker) AdoptContainerProcess(pid int, ordinal uint32) (uint32, error) {
	return t.tagSubtree(pid, ordinal, ebpf.UpdateNoExist)
}

// tagSubtree takes a fresh task walk, translates the daemon-namespace pid
// to the global tgid the step maps are keyed by, and tags its threads with
// leaderFlags and its descendants create-only. See TagContainerProcess for
// what it returns.
func (t *Tracker) tagSubtree(pid int, ordinal uint32, leaderFlags ebpf.MapUpdateFlags) (uint32, error) {
	snap, err := t.snapshotFn()
	if err != nil {
		return 0, fmt.Errorf("task walk: %w", err)
	}
	leader, ok := snap.global[pid]
	if !ok {
		return 0, nil // exited mid-flight, or not numbered in our namespace
	}
	held, err := t.tagTasks(snap, leader, ordinal, leaderFlags)
	// An exiting leader's children are still listed under it, and live.
	childTook := false
	for _, p := range snap.subtree(leader)[1:] {
		h, cerr := t.tagTasks(snap, p, ordinal, ebpf.UpdateNoExist)
		childTook = childTook || h == ordinal
		err = errors.Join(err, cerr)
	}
	switch {
	case held != 0:
		return held, nil
	case childTook:
		return ordinal, nil
	default:
		return 0, err
	}
}

// procSnapshot is one pass of the cw_step_iter walk: every task in the
// daemon's pid-namespace subtree, keyed by the global ids the step maps
// use, plus the translation from the daemon-namespace pids userspace
// discovers.
type procSnapshot struct {
	tids     map[uint32][]uint32 // global tgid → its threads' global tids
	children map[uint32][]uint32 // global parent tgid → child global tgids
	global   map[int]uint32      // daemon-namespace tgid → global tgid
}

// iterSnapshot runs the task iterator once and parses its output.
func (t *Tracker) iterSnapshot() (*procSnapshot, error) {
	rd, err := t.iter.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open task iterator: %w", err)
	}
	defer rd.Close()
	data, err := io.ReadAll(rd)
	if err != nil {
		return nil, fmt.Errorf("failed to read task iterator: %w", err)
	}
	return parseTaskRecords(data), nil
}

// parseTaskRecords decodes the iterator's stream of task_iter_rec (the
// bpf2go-generated mirror of the C struct, so the layout has one source).
// Threads contribute their tid to the leader's list and nothing else: they
// share the leader's tree position and namespace pid. An exiting task
// contributes no tid, since a tag written to it would outlive it, but an
// exiting leader keeps its place in the tree: its other threads can still
// be live. A trailing partial record (a truncated read) is ignored.
func parseTaskRecords(data []byte) *procSnapshot {
	snap := &procSnapshot{
		tids:     make(map[uint32][]uint32),
		children: make(map[uint32][]uint32),
		global:   make(map[int]uint32),
	}
	const recSize = int(unsafe.Sizeof(bpf.StepBpfTaskIterRec{}))
	for off := 0; off+recSize <= len(data); off += recSize {
		rec := (*bpf.StepBpfTaskIterRec)(unsafe.Pointer(&data[off]))
		if rec.Exiting == 0 {
			snap.tids[rec.Tgid] = append(snap.tids[rec.Tgid], rec.Tid)
		}
		if rec.Tid != rec.Tgid {
			continue
		}
		snap.global[int(rec.NsTgid)] = rec.Tgid
		if rec.Ppid != rec.Tgid {
			snap.children[rec.Ppid] = append(snap.children[rec.Ppid], rec.Tgid)
		}
	}
	return snap
}

// subtree returns root plus all its descendant tgids, breadth-first. The
// seen set guards against a cyclic snapshot; real trees terminate.
func (s *procSnapshot) subtree(root uint32) []uint32 {
	pids := []uint32{root}
	seen := map[uint32]bool{root: true}
	for i := 0; i < len(pids); i++ {
		for _, c := range s.children[pids[i]] {
			if !seen[c] {
				seen[c] = true
				pids = append(pids, c)
			}
		}
	}
	return pids
}

// findWorkerPID locates the Runner.Worker that owns THIS job. Ancestry
// first: the daemon is spawned inside the cargowall action's step, so at
// startup its parent chain runs through the right worker — on a host with
// several concurrent runners, comm-scanning /proc could lock onto another
// job's worker, silently voiding attribution and leaking that job's command
// lines into our audit stream. The scan survives only as a fallback for
// standalone starts, and then only when it is unambiguous.
func findWorkerPID() (int, error) {
	if pid, _, ok := procfs.AncestorByComm(os.Getpid(), workerComm); ok {
		return pid, nil
	}
	pid, count := scanUniqueByComm(workerComm)
	switch count {
	case 0:
		return 0, fmt.Errorf("%s process not found in /proc", workerComm)
	case 1:
		return pid, nil
	default:
		return 0, fmt.Errorf("%d %s processes found and none is an ancestor — refusing to guess (use --runner-worker-pid)", count, workerComm)
	}
}

// scanUniqueByComm returns the first /proc process with the given comm and
// how many matched in total.
func scanUniqueByComm(comm string) (first, count int) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		if procfs.Comm(pid) == comm {
			if count == 0 {
				first = pid
			}
			count++
		}
	}
	return first, count
}

// readCmdline returns a space-joined, length-capped /proc/<pid>/cmdline,
// falling back to comm for kernel threads or when the process is gone.
func readCmdline(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err == nil {
		if s := formatCmdline(data, false); s != "" {
			return s
		}
	}
	return procfs.Comm(pid)
}

// cmdlineMax caps a command line anywhere it is written. A step's exec
// event carries this many bytes of arguments (STEP_ARGV_MAX in
// bpf/stepbpf.c).
const cmdlineMax = 256

// formatCmdline joins a NUL-separated argument area with spaces and caps it
// at cmdlineMax, marking a cut, its own or one already made (cut), "...".
func formatCmdline(args []byte, cut bool) string {
	s := strings.TrimRight(strings.ReplaceAll(string(args), "\x00", " "), " ")
	if cut {
		// A cut already made can split a multi-byte character: drop an
		// incomplete one at the end, looking back no further than a rune.
		for i := len(s) - 1; i >= 0 && i > len(s)-utf8.UTFMax; i-- {
			if utf8.RuneStart(s[i]) {
				if !utf8.FullRuneInString(s[i:]) {
					s = s[:i]
				}
				break
			}
		}
	}
	if len(s) > cmdlineMax {
		// Back off to a rune boundary so the cap can't split a multi-byte
		// character. Bounded to one rune's width: cmdline is arbitrary
		// bytes, not guaranteed UTF-8, and a long run of continuation-range
		// bytes must not walk the cut back further — if no boundary is that
		// close, it isn't UTF-8 and the cap lands on the raw byte.
		end := cmdlineMax
		for end > cmdlineMax-utf8.UTFMax && !utf8.RuneStart(s[end]) {
			end--
		}
		if !utf8.RuneStart(s[end]) {
			end = cmdlineMax
		}
		s, cut = s[:end], true
	}
	if cut && s != "" {
		s += "..."
	}
	return s
}
