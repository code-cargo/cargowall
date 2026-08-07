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
package steps

import (
	"errors"
	"fmt"
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
// with StepOrdinalPreDaemon/Runner (or wrap to 0 = untagged). The 2^16
// margin leaves room for any realistic number of steps.
const maxOrdinalBase = uint64(events.StepOrdinalPreDaemon) - 1<<16

// Tracker owns the step-attribution BPF programs and the reconciler
// goroutine that turns new-step ringbuf notifications into audit events.
type Tracker struct {
	workerPID     int
	workerCmdline string
	objs          bpf.StepBpfObjects
	links         []link.Link
	reader        *ringbuf.Reader
	stateMap      *ebpf.Map
	taskMap       *ebpf.Map
	sockMap       *ebpf.Map
	auditLogger   *events.AuditLogger
	logger        *slog.Logger
	done          chan struct{}

	// DNS-path lookup guards — see StepForClient.
	stepCacheMu  sync.Mutex
	stepCache    map[stepCacheKey]stepCacheEntry
	diagSem      chan struct{}
	diagWarnMu   sync.Mutex
	diagLastWarn string
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

	spec, err := bpf.LoadStepBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load step BPF spec: %w", err)
	}

	t := &Tracker{
		workerPID: workerPID,
		// Snapshot the worker's argv so the reconciler can detect a
		// pre-exec cmdline read (the child briefly shares/copies it).
		workerCmdline: readCmdline(workerPID),
		stateMap:      tcObjs.MapStepState,
		taskMap:       tcObjs.MapTaskStep,
		sockMap:       tcObjs.MapSockStep,
		auditLogger:   auditLogger,
		logger:        logger,
		done:          make(chan struct{}),
		stepCache:     make(map[stepCacheKey]stepCacheEntry),
		diagSem:       make(chan struct{}, diagConcurrency),
	}

	// The three shared maps are owned by the tcbpf collection; replacing them
	// here makes both collections operate on the same kernel maps.
	if err := spec.LoadAndAssign(&t.objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"map_task_step":  tcObjs.MapTaskStep,
			"map_sock_step":  tcObjs.MapSockStep,
			"map_step_state": tcObjs.MapStepState,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to load step BPF objects (kernel BTF required): %w", err)
	}

	if err := t.attach(); err != nil {
		t.Close()
		return nil, err
	}

	// Seed while the programs are attached but still disabled (enabled=0 makes
	// them no-ops), then enable, then seed once more: the second pass catches
	// processes forked during the first scan, so the only unattributed window
	// is forks that both start and create sockets between the enable flip and
	// the rescan. Seeding is strictly create-only (BPF_NOEXIST), so the second
	// pass can never clobber an ordinal the now-live fork tracepoint assigned.
	t.seedExisting()
	if err := t.stateMap.Put(uint32(0), bpf.TcBpfStepState{
		WorkerTgid:  uint32(workerPID),
		Enabled:     1,
		NextOrdinal: max(opts.OrdinalBase, 1),
	}); err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to seed step state: %w", err)
	}
	t.seedExisting()

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
	for _, l := range t.links {
		_ = l.Close()
	}
	t.objs.Close()
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
	return nil
}

// seedExisting tags processes that predate the daemon. Worker threads get
// StepOrdinalRunner so infra traffic (log upload, action downloads) is
// labeled as runner overhead; existing worker child subtrees — steps that
// ran or started before cargowall attached — get StepOrdinalPreDaemon,
// except the daemon's own subtree, which gets StepOrdinalRunner (cargowall
// is infrastructure, not a workflow step). Every write is create-only:
// once the fork tracepoint is live it is the sole authority on new tags,
// and the post-enable rescan must never replace a kernel-assigned ordinal.
// Best-effort by nature: /proc scans race process creation, which is why
// Start runs it twice around the enable flip.
func (t *Tracker) seedExisting() {
	children := buildChildrenMap()

	// Decide each pid's intended tag before writing anything, so a pid in
	// the daemon's subtree is written exactly once with the right value
	// (create-only writes mean there is no second chance).
	self := make(map[int]bool)
	for _, pid := range subtreePids(os.Getpid(), children) {
		self[pid] = true
	}

	t.tagTasks(t.workerPID, events.StepOrdinalRunner)
	for _, root := range children[t.workerPID] {
		for _, pid := range subtreePids(root, children) {
			ordinal := events.StepOrdinalPreDaemon
			if self[pid] {
				ordinal = events.StepOrdinalRunner
			}
			t.tagTasks(pid, ordinal)
		}
	}

	// Standalone runs (daemon not under the worker): still label our own
	// traffic as infrastructure. Create-only, so a no-op when the loop
	// above already covered us.
	for _, pid := range subtreePids(os.Getpid(), children) {
		t.tagTasks(pid, events.StepOrdinalRunner)
	}
}

// subtreePids returns pid plus all its descendant process ids.
func subtreePids(pid int, children map[int][]int) []int {
	pids := []int{pid}
	for i := 0; i < len(pids); i++ {
		pids = append(pids, children[pids[i]]...)
	}
	return pids
}

// tagTasks writes ordinal for every thread of pid. Create-only (BPF_NOEXIST):
// a tid the fork tracepoint already tagged keeps its kernel-assigned ordinal.
func (t *Tracker) tagTasks(pid int, ordinal uint32) {
	tids, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
	if err != nil {
		return // process exited mid-scan
	}
	for _, tid := range tids {
		n, err := strconv.ParseUint(tid.Name(), 10, 32)
		if err != nil {
			continue
		}
		_ = t.taskMap.Update(uint32(n), ordinal, ebpf.UpdateNoExist)
	}
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

// buildChildrenMap snapshots the process tree as parent pid → child pids.
func buildChildrenMap() map[int][]int {
	children := make(map[int][]int)
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return children
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		ppid, ok := readPPid(pid)
		if !ok {
			continue
		}
		children[ppid] = append(children[ppid], pid)
	}
	return children
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
