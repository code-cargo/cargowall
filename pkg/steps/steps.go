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
// the step_fork tracepoint (bpf/stepbpf.c) tags each such child with a
// monotonically increasing ordinal, every other fork inherits the forking
// thread's tag, and the cgroup hooks copy the tag onto each socket cookie —
// so every TC event carries the step that (transitively) created its socket.
// Attribution only: no verdict consults these maps.
//
// Pid numbering: the kernel side keys everything by global (init-namespace)
// ids; everything this package reads from /proc — the worker pid, the
// daemon's own pid, container leaders reported by dockerd — is numbered in
// the daemon's pid namespace, a different space whenever cargowall runs
// inside a container (ARC runners are Kubernetes pods). The step_task_iter
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
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/events"
)

// workerComm is the /proc/<pid>/comm value of the GitHub Actions runner's
// per-job worker process (13 chars, fits TASK_COMM_LEN untruncated).
const workerComm = "Runner.Worker"

// stepChildEvent mirrors struct step_child_event in bpf/stepbpf.c.
type stepChildEvent struct {
	Tgid    uint32
	Ordinal uint32
}

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
}

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
	workerTgid    uint32 // the same process, global — what step_fork compares
	workerCmdline string
	objs          bpf.StepBpfObjects
	links         []link.Link
	iter          *link.Iter // step_task_iter; also in links for Close
	reader        *ringbuf.Reader
	stateMap      *ebpf.Map
	taskMap       *ebpf.Map
	nspidMap      *ebpf.Map // map_task_nspid; cleared at Close, see there
	auditLogger   *events.AuditLogger
	logger        *slog.Logger
	done          chan struct{}

	// Boundary history for OrdinalAt — see the boundary type.
	boundaryMu sync.Mutex
	boundaries []boundary

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
	pidnsIno, err := pidNamespaceInode()
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
		// Snapshot the worker's argv so the reconciler can detect a
		// pre-exec cmdline read (the child briefly shares/copies it).
		workerCmdline: readCmdline(workerPID),
		stateMap:      tcObjs.MapStepState,
		taskMap:       tcObjs.MapTaskStep,
		nspidMap:      tcObjs.MapTaskNspid,
		auditLogger:   auditLogger,
		logger:        logger,
		done:          make(chan struct{}),
		resolver:      newClientResolver(tcObjs.MapSockStep, tcObjs.MapSockPid, logger),
	}
	t.snapshotFn = t.iterSnapshot

	// The shared maps are owned by the tcbpf collection; replacing them here
	// makes both collections operate on the same kernel maps.
	if err := spec.LoadAndAssign(&t.objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"map_task_step":  tcObjs.MapTaskStep,
			"map_sock_step":  tcObjs.MapSockStep,
			"map_step_state": tcObjs.MapStepState,
			"map_task_nspid": tcObjs.MapTaskNspid,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to load step BPF objects (kernel BTF required): %w", err)
	}

	if err := t.attach(); err != nil {
		t.Close()
		return nil, err
	}

	// First task walk: seeds map_task_nspid for everything that predates the
	// attach (the tracepoints keep it current from here on) and hands back
	// the process tree in global ids — which is how the worker's /proc pid
	// becomes the global tgid step_fork compares against.
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
	if pidnsIno != initPidNamespaceInode {
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
		Program:    t.objs.StepFork,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sched_process_fork: %w", err)
	}
	t.links = append(t.links, forkLink)

	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program:    t.objs.StepExit,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sched_process_exit: %w", err)
	}
	t.links = append(t.links, exitLink)

	// Same root-cgroup attachment rationale as the connect/sendmsg hooks in
	// StartCargoWall: tag socket creation for every process on the machine.
	sockLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: t.objs.CgSockCreate,
	})
	if err != nil {
		return fmt.Errorf("failed to attach cgroup sock_create: %w", err)
	}
	t.links = append(t.links, sockLink)

	iter, err := link.AttachIter(link.IterOptions{Program: t.objs.StepTaskIter})
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

// tagTasks writes ordinal for every thread of the (global) tgid as listed
// in snap. Seeding passes UpdateNoExist so a tid the fork tracepoint
// already tagged keeps its kernel-assigned ordinal; container leaders pass
// UpdateAny (see TagContainerProcess for why overwrite is safe there and
// only there).
func (t *Tracker) tagTasks(snap *procSnapshot, tgid, ordinal uint32, flags ebpf.MapUpdateFlags) {
	for _, tid := range snap.tids[tgid] {
		_ = t.taskMap.Update(tid, ordinal, flags)
	}
}

// TagContainerProcess tags a container workload subtree rooted at pid.
// Container ancestry runs through containerd-shim, never Runner.Worker, so
// kernel fork-inheritance cannot reach these processes — this is the
// userspace bridge that puts the launching step's ordinal on them, after
// which sock_create tags their sockets like any other tagged task.
//
// pid is as dockerd reported it, i.e. numbered in the daemon's namespace
// when dockerd shares it (the caller's cgroup identity check has already
// confirmed that pid is the expected container in our /proc). A pid the
// task walk cannot see — exited, or a dockerd outside our namespace — is
// skipped.
//
// The leader's threads are written with UpdateAny: a freshly shim-forked
// leader is untagged in the normal case, an exec re-tag into a long-lived
// container must replace the container's older ordinal, and overwrite
// self-heals a stale entry left by a recycled tid. Descendants are
// create-only — children forked after an earlier tag already carry correct
// kernel-inherited ordinals that must never be clobbered.
func (t *Tracker) TagContainerProcess(pid int, ordinal uint32) {
	snap, leader, ok := t.resolve(pid)
	if !ok {
		return
	}
	t.tagTasks(snap, leader, ordinal, ebpf.UpdateAny)
	for _, p := range snap.subtree(leader)[1:] {
		t.tagTasks(snap, p, ordinal, ebpf.UpdateNoExist)
	}
}

// AdoptContainerProcess tags a container subtree like TagContainerProcess
// but create-only for the leader too. It is the reconcile-adoption write:
// adoption cannot distinguish "genuinely predates cargowall" from "live
// container wrongly swept after a partial daemon list and re-adopted", so
// an existing leader tag — the real ordinal from the container's original
// start — must survive and only truly untagged tasks take the caller's
// (sentinel) ordinal. The overwrite rationale above does not apply here:
// adoption is not an exec re-tag, and a recycled-tid stale entry is the
// rarer wrong to optimize for than demoting a live container.
func (t *Tracker) AdoptContainerProcess(pid int, ordinal uint32) {
	snap, leader, ok := t.resolve(pid)
	if !ok {
		return
	}
	for _, p := range snap.subtree(leader) {
		t.tagTasks(snap, p, ordinal, ebpf.UpdateNoExist)
	}
}

// resolve takes a fresh task walk and translates a daemon-namespace pid to
// the global tgid the step maps are keyed by.
func (t *Tracker) resolve(pid int) (*procSnapshot, uint32, bool) {
	snap, err := t.snapshotFn()
	if err != nil {
		t.logger.Warn("Task walk failed", "error", err)
		return nil, 0, false
	}
	leader, ok := snap.global[pid]
	if !ok {
		return nil, 0, false // exited mid-flight, or not numbered in our namespace
	}
	return snap, leader, true
}

// initPidNamespaceInode is PROC_PID_INIT_INO, the fixed nsfs inode of the
// initial pid namespace — what a plain VM sees; anything else means the
// daemon is inside a container.
const initPidNamespaceInode uint32 = 0xEFFFFFFC

// pidNamespaceInode identifies the daemon's pid namespace the way the
// kernel does (ns_common.inum), for the step_task_iter/step_fork walk.
func pidNamespaceInode() (uint32, error) {
	fi, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return 0, fmt.Errorf("failed to stat pid namespace: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("pid namespace stat has no inode")
	}
	return uint32(st.Ino), nil
}

// procSnapshot is one pass of the step_task_iter walk: every task in the
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
// share the leader's tree position and namespace pid. A trailing partial
// record (a truncated read) is ignored.
func parseTaskRecords(data []byte) *procSnapshot {
	snap := &procSnapshot{
		tids:     make(map[uint32][]uint32),
		children: make(map[uint32][]uint32),
		global:   make(map[int]uint32),
	}
	const recSize = int(unsafe.Sizeof(bpf.StepBpfTaskIterRec{}))
	for off := 0; off+recSize <= len(data); off += recSize {
		rec := (*bpf.StepBpfTaskIterRec)(unsafe.Pointer(&data[off]))
		snap.tids[rec.Tgid] = append(snap.tids[rec.Tgid], rec.Tid)
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

// boundary records one step_child_event as observed by run(), stamped with
// wall-clock receive time so external event streams that carry their own
// timestamps (Docker's timeNano) can be resolved against the step that was
// active when the event happened, not whichever step is active when a
// possibly backlogged stream gets processed.
type boundary struct {
	ordinal uint32
	at      time.Time
}

// boundaryHistory bounds the ring; ordinals are monotonic so old entries
// only matter for as long as an external event could plausibly be delayed.
const boundaryHistory = 256

// recordBoundary appends one observed boundary, trimming the ring to
// boundaryHistory (append reallocation keeps the retained backing bounded).
func (t *Tracker) recordBoundary(ordinal uint32, at time.Time) {
	t.boundaryMu.Lock()
	defer t.boundaryMu.Unlock()
	t.boundaries = append(t.boundaries, boundary{ordinal: ordinal, at: at})
	if len(t.boundaries) > boundaryHistory {
		t.boundaries = t.boundaries[1:]
	}
}

// OrdinalAt returns the ordinal of the latest step boundary observed at or
// before tm, or 0 when tm predates every observed boundary (callers treat 0
// as untagged, which degrades to the stricter attribution tier by design).
func (t *Tracker) OrdinalAt(tm time.Time) uint32 {
	t.boundaryMu.Lock()
	defer t.boundaryMu.Unlock()
	for i := len(t.boundaries) - 1; i >= 0; i-- {
		if !t.boundaries[i].at.After(tm) {
			return t.boundaries[i].ordinal
		}
	}
	return 0
}

// run consumes new-step notifications and re-reports them as audit events
// with the child's command line attached, giving the summary pipeline a
// human-readable marker per step even before the action supplies plan names.
func (t *Tracker) run() {
	defer close(t.done)
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			t.logger.Error("Failed to read step event", "error", err)
			continue
		}
		if len(record.RawSample) < int(unsafe.Sizeof(stepChildEvent{})) {
			continue
		}
		ev := (*stepChildEvent)(unsafe.Pointer(&record.RawSample[0]))

		// Record the boundary before the cmdline retry loop below (which can
		// sleep tens of ms) so OrdinalAt callers racing a fresh boundary
		// resolve against it promptly.
		t.recordBoundary(ev.Ordinal, time.Now())

		// ev.Tgid is numbered in our pid namespace (see map_task_nspid), so
		// /proc reads work from inside a container too.
		cmdline := sanitizeCmdline(t.stepCmdline(int(ev.Tgid)))
		t.logger.Info("Workflow step process started",
			"step_ordinal", ev.Ordinal,
			"pid", ev.Tgid,
			"cmdline", cmdline)
		if t.auditLogger != nil {
			if err := t.auditLogger.LogEvent(events.AuditEvent{
				EventType:   events.EventStepBoundary,
				Process:     cmdline,
				PID:         ev.Tgid,
				StepOrdinal: ev.Ordinal,
			}); err != nil {
				t.logger.Error("Failed to write audit log", "error", err)
			}
		}
	}
}

// sanitizeCmdline reduces an emitted command line to its first two argv
// tokens plus any runner-generated script or action paths from later
// positions. Boundary events describe Runner.Worker's direct children: the
// step's own script path — the correlation token plan matching needs —
// lives under the runner's _temp (run: steps, composite blocks) or
// _actions (JS actions) directories, and sits at argv[2+] whenever shell
// flags are in play (`bash --noprofile --norc -e -o pipefail x.sh` is the
// standard run-step shape). Every other later token is where flags and
// values (and therefore secrets passed on a command line, e.g. docker
// args) could appear, and is dropped. Everything written to logs, the
// audit JSONL, or the summary goes through this; the full string stays
// internal to the fork→exec retry comparison.
func sanitizeCmdline(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) <= 2 {
		return cmdline
	}
	kept := append([]string(nil), fields[:2]...)
	dropped := false
	for _, f := range fields[2:] {
		if isRunnerPath(f) {
			kept = append(kept, f)
		} else {
			dropped = true
		}
	}
	out := strings.Join(kept, " ")
	if dropped {
		out += " ..."
	}
	return out
}

// isRunnerPath reports whether an argv token is a bare absolute path into
// the runner's _temp/_actions trees — the shape of the script and action
// paths the runner itself passes. Anchored, not a substring test: a
// user-controlled value merely EMBEDDING those substrings (a URL with a
// query string, a --flag=value, a volume spec) must not ride through the
// redaction, so anything that isn't a plain absolute path ('=' from
// flag-or-env values, ':' from URLs and mount specs) is rejected.
func isRunnerPath(tok string) bool {
	if !strings.HasPrefix(tok, "/") || strings.ContainsAny(tok, "=:") {
		return false
	}
	return strings.Contains(tok, "/_temp/") || strings.Contains(tok, "/_actions/")
}

// stepCmdline reads the child's command line, retrying briefly while it
// still shows the worker's own argv: the fork tracepoint fires before the
// child is scheduled, so an immediate /proc read can see the pre-exec
// COW/vfork copy of Runner.Worker's argv — the one value that would poison
// step correlation. If it still matches after the retries, the child is a
// genuine fork-without-exec and the parent's argv is its true cmdline.
func (t *Tracker) stepCmdline(pid int) string {
	var cmdline string
	for range 10 {
		cmdline = readCmdline(pid)
		if cmdline != "" && cmdline != t.workerCmdline {
			return cmdline
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cmdline
}

// findWorkerPID locates the Runner.Worker that owns THIS job. Ancestry
// first: the daemon is spawned inside the cargowall action's step, so at
// startup its parent chain runs through the right worker — on a host with
// several concurrent runners, comm-scanning /proc could lock onto another
// job's worker, silently voiding attribution and leaking that job's command
// lines into our audit stream. The scan survives only as a fallback for
// standalone starts, and then only when it is unambiguous.
func findWorkerPID() (int, error) {
	if pid, ok := findAncestorByComm(os.Getpid(), workerComm); ok {
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

// findAncestorByComm walks the parent chain from fromPid looking for a
// process whose comm matches. Bounded to defend against a cyclic/corrupt
// /proc snapshot; real chains reach pid 1 in far fewer hops.
func findAncestorByComm(fromPid int, comm string) (int, bool) {
	pid := fromPid
	for range 64 {
		if pid <= 1 {
			return 0, false
		}
		if readComm(pid) == comm {
			return pid, true
		}
		ppid, ok := readPPid(pid)
		if !ok {
			return 0, false
		}
		pid = ppid
	}
	return 0, false
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
		if readComm(pid) == comm {
			if count == 0 {
				first = pid
			}
			count++
		}
	}
	return first, count
}

// readComm returns the trimmed /proc/<pid>/comm, or "" when unreadable.
func readComm(pid int) string {
	comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}

// readPPid extracts the parent pid from /proc/<pid>/stat. The comm field
// (2) can contain spaces and parentheses, so parse from the last ')' —
// state is the field after it, ppid the one after that.
func readPPid(pid int) (int, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data[i+1:]))
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, false
	}
	return ppid, true
}

// readCmdline returns a space-joined, length-capped /proc/<pid>/cmdline,
// falling back to comm for kernel threads or when the process is gone.
func readCmdline(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err == nil && len(data) > 0 {
		s := strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
		const maxLen = 256
		if len(s) > maxLen {
			// Back off to a rune boundary so the cap can't split a
			// multi-byte character. Bounded to one rune's width: cmdline
			// is arbitrary bytes, not guaranteed UTF-8, and a long run of
			// continuation-range bytes must not walk the cut back
			// further — if no boundary is that close, it isn't UTF-8 and
			// the cap lands on the raw byte.
			cut := maxLen
			for cut > maxLen-utf8.UTFMax && !utf8.RuneStart(s[cut]) {
				cut--
			}
			if !utf8.RuneStart(s[cut]) {
				cut = maxLen
			}
			s = s[:cut] + "..."
		}
		if s != "" {
			return s
		}
	}
	comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}
