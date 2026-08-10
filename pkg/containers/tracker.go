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

// Package containers correlates Docker containers and execs to workflow
// steps (issue #106). It is an ATTRIBUTION package: it supplies container
// identity, and never decides policy. Enforcement lives at the hooks
// (bpf/tcbpf.c, bpf/originbpf.c) and connection outcomes are reported by
// pkg/events; this package only decorates them with the container a flow
// came from. Container process ancestry runs
// through containerd-shim, never Runner.Worker, so the kernel-side fork
// inheritance that powers step attribution cannot reach them; this package
// closes the gap from userspace: it subscribes to Docker events, resolves
// each workload's host PID, confirms the PID's identity via its cgroup, and
// tags it with the step ordinal that was active when Docker reported the
// event. From there the existing kernel machinery takes over (sock_create
// tags the container's sockets; fork inheritance covers its descendants),
// and the pkg/origin observer makes the result visible on post-NAT TC
// events via Enrich.
//
// Every path here is best-effort: a failure means untagged traffic, which
// classifies to the container-unattributed tier — stricter, never looser.
//
// Scope boundaries (by design): docker-in-docker attribution stops at the
// outer container (inner workloads inherit the outer tag through fork);
// --privileged containers are host-root equivalent and are flagged in the
// audit stream rather than constrained; the window between container/exec
// start and tagging leaves early sockets untagged — the unattributed tier,
// never a step.
package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/origin"
)

// StepTagger is the seam to pkg/steps.Tracker: tag a container subtree, and
// resolve which step was active at a given time. Narrow on purpose — the
// step maps stay owned by pkg/steps.
type StepTagger interface {
	TagContainerProcess(pid int, ordinal uint32)
	OrdinalAt(t time.Time) uint32
}

// Enricher is a late-binding events.ContainerEnricher. The event pipeline
// starts early in daemon startup, but container tracking can only start
// after the dockerd restart severs-proofs the event subscription — so the
// pipeline gets this shell up front and Bind attaches the live Tracker once
// it exists. Until then (and if tracking never comes up) Enrich is a no-op,
// which is the correct degradation: unenriched events classify to the
// stricter tiers.
type Enricher struct {
	tracker atomic.Pointer[Tracker]
}

// Bind attaches the live tracker; safe to call once tracking starts.
func (e *Enricher) Bind(t *Tracker) { e.tracker.Store(t) }

// Enrich implements events.ContainerEnricher.
func (e *Enricher) Enrich(audit *events.AuditEvent, ev *events.BpfBlockedEvent) {
	if t := e.tracker.Load(); t != nil {
		t.Enrich(audit, ev)
	}
}

// DecorateVerdict adds container identity to a cgroup-hook outcome when the
// tracker is live. A verdict that beats docker tracking startup simply goes
// undecorated — it is still reported in full by pkg/events, just without a
// container id.
func (e *Enricher) DecorateVerdict(audit *events.AuditEvent, rec origin.Record) {
	if t := e.tracker.Load(); t != nil {
		t.DecorateVerdict(audit, rec)
	}
}

// Options configures Start. Zero values take the production defaults; the
// roots are injectable for tests.
type Options struct {
	Socket     string // Docker daemon socket, default /var/run/docker.sock
	ProcRoot   string // default /proc
	CgroupRoot string // default /sys/fs/cgroup
	// AllowLocalSubnet is called once per BRIDGE-DRIVER subnet discovered
	// on a tracked container (v4 or v6). Under --cgroup-enforce the hook
	// adjudicates local-only bridge traffic TC never saw — container→
	// container on user-defined networks, docker-proxy→container — and the
	// callback carves those subnets out of THAT HOOK ONLY (origin's
	// local-nets map, never the shared policy: a workload-influenced subnet
	// must not be able to widen TC's off-host enforcement). Non-bridge
	// drivers (macvlan/ipvlan — physical-network address space) are never
	// passed. An error means the carve-out was not applied; the tracker
	// retries on the next container of that network. Nil disables
	// discovery. Called without the tracker lock held.
	AllowLocalSubnet func(prefix netip.Prefix) error
}

type containerInfo struct {
	id               string
	initPID          int
	birthOrdinal     uint32
	effectiveOrdinal uint32 // latest exec re-tag wins; what DNS attribution uses
	privileged       bool
	cgroupID         uint64
	ips              []netip.Addr
}

// shortID is the 12-char id Docker surfaces everywhere user-facing.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// originLookup is the slice of origin.Observer the tracker consumes,
// separated so enrichment is testable against a fake join store.
type originLookup interface {
	LookupV4(dstIP uint32, dstPort uint16, proto uint8, srcPort uint16) []origin.Record
	LookupV6(dstIP [16]byte, dstPort uint16, proto uint8, srcPort uint16) []origin.Record
	Records() uint64
}

// Tracker owns the Docker event subscription, the container identity
// indexes, and the TC-event enricher.
type Tracker struct {
	client      *dockerClient
	tagger      StepTagger
	observer    originLookup // nil = observer unavailable; Enrich no-ops
	auditLogger *events.AuditLogger
	logger      *slog.Logger
	opts        Options

	cancel context.CancelFunc
	done   chan struct{}
	wg     sync.WaitGroup // in-flight exec handlers; Close waits so none outlives the audit logger
	// Bounds concurrent exec handling: exec-pid resolution can wait out
	// dockerd's publish race (~up to 1s), and that wait must never park
	// the shared event stream (see streamOnce).
	execSem chan struct{}

	mu         sync.Mutex
	containers map[string]*containerInfo
	byIP       map[netip.Addr]*containerInfo
	byCgroup   map[uint64]*containerInfo
	// seenExecs is keyed by container so remove() drops each container's
	// whole set — a long job with many docker execs must not accumulate an
	// unbounded map of 64-char ids.
	seenExecs map[string]map[string]bool
	// seenSubnets dedups AllowLocalSubnet callbacks: one per subnet, ever.
	seenSubnets map[string]bool
	latencies   []float64 // tag latencies (ms), bounded

	lastEventNano atomic.Int64

	// Correlation counters — the 3a telemetry, logged at Close.
	tagged           atomic.Uint64
	execTagged       atomic.Uint64
	reconciled       atomic.Uint64
	identityRejected atomic.Uint64
	tagSkipped       atomic.Uint64
	tcEnriched       atomic.Uint64
	tcContainerOnly  atomic.Uint64
	tcAmbiguous      atomic.Uint64
	tcNoRecord       atomic.Uint64
	dnsHits          atomic.Uint64
	dnsMisses        atomic.Uint64
}

const (
	maxLatencies     = 1024
	reconnectBackoff = 500 * time.Millisecond
	maxBackoff       = 5 * time.Second
	unaryTimeout     = 5 * time.Second
	// streamHealthyAfter is how long an event session must survive before
	// the reconnect backoff resets to its floor. Duration-based on purpose:
	// an event-based signal is defeated by docker's inclusive `since`
	// replay, which redelivers at least one event to every session that
	// gets past connect — pinning a flapping daemon at the 500ms floor.
	streamHealthyAfter = 30 * time.Second
	// execConcurrency bounds concurrent exec handling (execSem): exec-pid
	// resolution can wait out dockerd's publish race, and that wait must
	// never park the shared event stream.
	execConcurrency = 4
	// reconcileInspectConcurrency bounds the parallel PID-verification
	// inspects reconcile issues for already-known containers. Same shape
	// and rationale as execConcurrency: bounded parallelism against the
	// daemon, never an unbounded thundering herd, never fully serial.
	reconcileInspectConcurrency = 4
)

// Start connects to the Docker daemon and begins tracking. An error means
// container attribution is unavailable (no daemon, no socket access) and the
// caller degrades with a warning — same posture as steps.Start.
func Start(ctx context.Context, opts Options, tagger StepTagger, observer *origin.Observer, auditLogger *events.AuditLogger, logger *slog.Logger) (*Tracker, error) {
	if tagger == nil {
		return nil, errors.New("nil step tagger")
	}
	if logger == nil {
		return nil, errors.New("nil logger")
	}
	if opts.Socket == "" {
		opts.Socket = "/var/run/docker.sock"
	}
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.CgroupRoot == "" {
		opts.CgroupRoot = "/sys/fs/cgroup"
	}

	t := &Tracker{
		client:      newDockerClient(opts.Socket),
		tagger:      tagger,
		auditLogger: auditLogger,
		logger:      logger,
		opts:        opts,
		done:        make(chan struct{}),
		execSem:     make(chan struct{}, execConcurrency),
		containers:  make(map[string]*containerInfo),
		byIP:        make(map[netip.Addr]*containerInfo),
		byCgroup:    make(map[uint64]*containerInfo),
		seenExecs:   make(map[string]map[string]bool),
		seenSubnets: make(map[string]bool),
	}
	// Typed-nil guard: a nil *origin.Observer must stay a nil interface, or
	// Enrich's nil check would pass and call into a nil receiver.
	if observer != nil {
		t.observer = observer
	}

	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	err := t.client.ping(pingCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("docker daemon unreachable: %w", err)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	t.cancel = cancelRun
	go t.run(runCtx)
	return t, nil
}

// Close stops the tracker, waits for in-flight exec handlers (they write
// audit events, and the audit logger's deferred Close runs after ours),
// and logs the telemetry summary.
func (t *Tracker) Close() {
	t.cancel()
	<-t.done
	t.wg.Wait()
	t.logSummary()
}

// run is the reconnect loop: stream events, and on any error reconnect with
// backoff, resuming from the last seen event so nothing in the gap is lost.
// One mechanism covers daemon restarts and transient socket errors alike.
func (t *Tracker) run(ctx context.Context) {
	defer close(t.done)
	backoff := reconnectBackoff
	for {
		start := time.Now()
		err := t.streamOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) >= streamHealthyAfter {
			// A session that survived this long was genuinely healthy: the
			// next hiccup gets the 500ms floor back. Without this, a few
			// startup flakes pin backoff at maxBackoff for the process
			// lifetime; with an event-based signal instead, docker's
			// inclusive `since` replay (at least one redelivered event per
			// session that connects) would reset it even for a flapping
			// daemon.
			backoff = reconnectBackoff
		}
		t.logger.Warn("Docker event stream interrupted; reconnecting", "error", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (t *Tracker) streamOnce(ctx context.Context) error {
	// Open the stream before reconciling: a container starting between the
	// two is then either in the list or in the buffered stream, never lost.
	body, err := t.client.events(ctx, t.lastEventNano.Load())
	if err != nil {
		return err
	}
	defer body.Close()

	t.reconcile(ctx)

	dec := json.NewDecoder(body)
	for {
		var ev dockerEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return err
			}
			return fmt.Errorf("decode docker event: %w", err)
		}
		if ev.TimeNano > 0 {
			t.lastEventNano.Store(ev.TimeNano)
		}
		if ev.Type != "container" {
			continue
		}
		switch {
		case ev.Action == "start":
			t.handleStart(ctx, ev.Actor.ID, "start", ev.TimeNano)
		case strings.HasPrefix(ev.Action, "exec_start"):
			// Action is "exec_start: <cmd>"; the exec id rides in the actor
			// attributes (with an inspect-based fallback for daemons that
			// omit it). Handled concurrently: exec-pid resolution can wait
			// out dockerd's publish race (~1s), and parking the shared
			// stream on that would delay start tagging for unrelated
			// containers — exactly the window that files traffic into the
			// unattributed tier. Bounded by execSem; handlers are
			// idempotent (seenExecs) so ordering vs die/destroy is safe.
			containerID, execID, nano := ev.Actor.ID, ev.Actor.Attributes["execID"], ev.TimeNano
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				select {
				case t.execSem <- struct{}{}:
					defer func() { <-t.execSem }()
				case <-ctx.Done():
					return
				}
				t.handleExecStart(ctx, containerID, execID, nano)
			}()
		case ev.Action == "die", ev.Action == "destroy":
			t.remove(ev.Actor.ID)
		}
	}
}

// reconcile treats every running container we don't know as a start event of
// kind "reconcile". Containers that predate the tracker (job containers and
// services started before cargowall, or anything running across a
// reconnect) get StepOrdinalPreDaemon — mirroring seedExisting's semantics
// for pre-daemon processes — and their exec events re-tag real step
// ordinals from there.
//
// It also runs the diff the OTHER way: a tracked container absent from the
// list lost its die/destroy somewhere the `since` replay cannot reach (a
// dockerd restart empties the daemon's event buffer). Without the removal
// its stale byIP entry keeps answering DNS attribution lookups, crediting
// whatever later occupies that bridge address to a dead container.
func (t *Tracker) reconcile(ctx context.Context) {
	list, err := t.client.listContainers(ctx)
	if err != nil {
		t.logger.Warn("Cannot list containers for reconciliation", "error", err)
		return
	}
	live := make(map[string]bool, len(list))
	for _, c := range list {
		live[c.ID] = true
	}
	// Split the list: unknown IDs are adopted (below), known IDs are
	// verified — a known ID may be a NEW incarnation, because docker
	// restart keeps the container ID but mints a fresh init PID and cgroup,
	// and the die+start pair can both be lost in the same stream gap.
	// Verify by init PID; on mismatch re-adopt, or byCgroup keys a dead
	// inode and the new init process is never tagged.
	type incarnation struct {
		id             string
		oldPID, newPID int
	}
	var toVerify []incarnation
	for _, c := range list {
		t.mu.Lock()
		info := t.containers[c.ID]
		t.mu.Unlock()
		if info == nil {
			t.handleStart(ctx, c.ID, "reconcile", 0)
			continue
		}
		toVerify = append(toVerify, incarnation{id: c.ID, oldPID: info.initPID})
	}
	// Verification inspects run concurrently, bounded: this whole function
	// runs on the stream goroutine before event processing resumes, and a
	// large fleet against a slow daemon must not serialize N unary
	// timeouts in front of reconnect recovery.
	var (
		wg      sync.WaitGroup
		sem     = make(chan struct{}, reconcileInspectConcurrency)
		mu      sync.Mutex
		readopt []incarnation
	)
	for _, k := range toVerify {
		wg.Add(1)
		go func(k incarnation) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
			insp, ierr := t.client.inspectContainer(ictx, k.id)
			cancel()
			if ierr != nil || insp.State.Pid == 0 || insp.State.Pid == k.oldPID {
				return
			}
			k.newPID = insp.State.Pid
			mu.Lock()
			readopt = append(readopt, k)
			mu.Unlock()
		}(k)
	}
	wg.Wait()
	for _, k := range readopt {
		t.logger.Info("Container re-adopted during reconciliation (restarted across a stream gap)",
			"container", shortID(k.id), "old_pid", k.oldPID, "new_pid", k.newPID)
		t.remove(k.id)
		t.handleStart(ctx, k.id, "reconcile", 0)
	}

	// The diff the other way: a tracked container absent from the list lost
	// its die/destroy somewhere the `since` replay cannot reach. A container
	// started after the list call is either absent from t.containers (its
	// start event is still buffered in the stream — the sweep leaves it
	// alone) or was added by a handleStart above (in the list, so live).
	// Only genuinely dead containers are swept — unless the list came back
	// EMPTY while we track containers, which on a just-restarted dockerd is
	// far more plausibly an initializing daemon than a mass die-off; wiping
	// the indexes on that evidence would permanently demote every live
	// container (live-restore containers never re-emit a start event).
	t.mu.Lock()
	var stale []string
	for id := range t.containers {
		if !live[id] {
			stale = append(stale, id)
		}
	}
	tracked := len(t.containers)
	t.mu.Unlock()
	if len(list) == 0 && tracked > 0 {
		t.logger.Warn("Reconciliation list empty while containers are tracked; keeping indexes (initializing daemon?)",
			"tracked", tracked)
		return
	}
	for _, id := range stale {
		t.logger.Info("Container removed during reconciliation (die/destroy lost in a stream gap)",
			"container", shortID(id))
		t.remove(id)
	}

	// seenExecs sets can outlive their container: an exec handler parked in
	// resolveExecPid may re-create one after remove() ran (a race
	// markExecSeen deliberately tolerates). The container sweep above walks
	// t.containers, which such an orphan is not in — prune it here.
	t.mu.Lock()
	for id := range t.seenExecs {
		if !live[id] && t.containers[id] == nil {
			delete(t.seenExecs, id)
		}
	}
	t.mu.Unlock()
}

func (t *Tracker) handleStart(ctx context.Context, id, kind string, timeNano int64) {
	t.mu.Lock()
	_, known := t.containers[id]
	t.mu.Unlock()
	if known {
		return // replayed event after reconnect
	}

	ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
	insp, err := t.client.inspectContainer(ictx, id)
	cancel()
	if err != nil {
		t.logger.Debug("Container inspect failed", "container", shortID(id), "error", err)
		return
	}
	if insp.State.Pid == 0 {
		return // already gone; die/destroy would have nothing to remove
	}

	info := &containerInfo{
		id:         insp.ID,
		initPID:    insp.State.Pid,
		privileged: insp.HostConfig.Privileged,
	}
	for _, ipStr := range collectIPs(insp) {
		if ip, err := netip.ParseAddr(ipStr); err == nil {
			info.ips = append(info.ips, ip)
		}
	}

	// New bridge subnets are carved out before any tagging concerns: the
	// network exists whatever the identity check below decides.
	if t.opts.AllowLocalSubnet != nil {
		for _, s := range collectSubnets(insp) {
			t.allowSubnetOnce(ctx, s)
		}
	}

	// Identity check before any tagging: the inspected PID must currently
	// sit in this container's cgroup, or a recycled PID could tag an
	// unrelated host process.
	cgroupID, err := verifyContainerTask(t.opts.ProcRoot, t.opts.CgroupRoot, info.initPID, insp.ID)
	identityOK := err == nil
	if !identityOK {
		t.identityRejected.Add(1)
		t.logger.Warn("Container identity check failed; not tagging", "container", shortID(id), "error", err)
	}
	info.cgroupID = cgroupID

	var ordinal uint32
	if kind == "reconcile" {
		ordinal = events.StepOrdinalPreDaemon
	} else {
		ordinal = t.tagger.OrdinalAt(time.Unix(0, timeNano))
	}
	// The IP indexes keep the event-time ordinal even when tagging below is
	// refused: DNS attribution keys on the container's address (from
	// inspect), which the identity check — a guard against tagging a
	// recycled PID — says nothing about.
	info.birthOrdinal = ordinal
	info.effectiveOrdinal = ordinal

	// markerOrdinal is what the container_attribution audit event reports:
	// the TAGGING outcome. A refused or skipped tag reports 0 so consumers
	// (and the CI assertions) can never mistake "would have been step N"
	// for "tagged with step N".
	markerOrdinal := uint32(0)
	var latencyMS float64
	if identityOK && ordinal != 0 {
		t.tagger.TagContainerProcess(info.initPID, ordinal)
		markerOrdinal = ordinal
		if kind == "reconcile" {
			t.reconciled.Add(1)
		} else {
			t.tagged.Add(1)
			latencyMS = float64(time.Since(time.Unix(0, timeNano)).Microseconds()) / 1000
			t.recordLatency(latencyMS)
		}
	} else if ordinal == 0 {
		// Started before any step boundary (or outside a workflow): stays
		// untagged and classifies to the container-unattributed tier.
		t.tagSkipped.Add(1)
	}

	if info.privileged {
		t.logger.Warn("Privileged container started (host-root equivalent; observer coverage not guaranteed)",
			"container", shortID(id))
	}

	t.mu.Lock()
	// Newest inspect wins a conflicted address: for docker-IPAM recycling
	// (die/destroy lost in a stream gap) the newcomer genuinely holds the
	// address, and for manually-assigned duplicates (macvlan/static --ip,
	// where IPAM guarantees nothing) this matches the pre-existing
	// last-writer semantics. The displaced holder is NOT untracked — its
	// cgroup identity and other addresses may be live; if it is truly
	// dead, reconcile's sweep collects it. Logged after unlock: both
	// ringbuf reader paths contend on t.mu, and a slow slog handler must
	// not stall them.
	var displaced []string
	for _, ip := range info.ips {
		if prev := t.byIP[ip]; prev != nil && prev != info {
			displaced = append(displaced, shortID(prev.id)+" lost "+ip.String())
		}
	}
	t.containers[insp.ID] = info
	for _, ip := range info.ips {
		t.byIP[ip] = info
	}
	if info.cgroupID != 0 {
		t.byCgroup[info.cgroupID] = info
	}
	t.mu.Unlock()

	for _, d := range displaced {
		t.logger.Info("Address conflict: newest inspect wins", "displaced", d, "winner", shortID(id))
	}

	t.logger.Info("Container attributed",
		"container", shortID(id), "kind", kind, "pid", info.initPID,
		"step_ordinal", markerOrdinal, "tag_latency_ms", latencyMS, "privileged", info.privileged)
	t.logAttribution(events.AuditEvent{
		EventType:       events.EventContainerAttribution,
		ContainerID:     shortID(id),
		ContainerOrigin: true,
		AttributionKind: kind,
		StepOrdinal:     markerOrdinal,
		PID:             uint32(info.initPID),
		TagLatencyMS:    latencyMS,
		Privileged:      info.privileged,
	})
}

func (t *Tracker) handleExecStart(ctx context.Context, containerID, execID string, timeNano int64) {
	pid, err := t.resolveExecPid(ctx, containerID, execID)
	if err != nil {
		if errors.Is(err, errExecAlreadySeen) {
			// Replayed exec_start after a stream reconnect (docker's `since`
			// is inclusive): handled once already. A second pass would
			// re-inspect, double-count execTagged, skew the latency
			// percentiles with an event minutes old, and re-tag a PID that
			// may since have been recycled.
			return
		}
		t.tagSkipped.Add(1)
		t.logger.Debug("Exec PID unresolvable; traffic stays in the container tier",
			"container", shortID(containerID), "error", err)
		return
	}

	// Exec-time ordinal, never the container's birth ordinal: a `docker
	// exec` from step B into a container step A created belongs to B.
	ordinal := t.tagger.OrdinalAt(time.Unix(0, timeNano))
	if ordinal == 0 {
		t.tagSkipped.Add(1)
		return
	}

	if _, err := verifyContainerTask(t.opts.ProcRoot, t.opts.CgroupRoot, pid, containerID); err != nil {
		t.identityRejected.Add(1)
		t.logger.Warn("Exec identity check failed; not tagging", "container", shortID(containerID), "error", err)
		return
	}

	t.tagger.TagContainerProcess(pid, ordinal)
	t.execTagged.Add(1)
	latencyMS := float64(time.Since(time.Unix(0, timeNano)).Microseconds()) / 1000
	t.recordLatency(latencyMS)

	t.mu.Lock()
	if info := t.containers[containerID]; info != nil {
		info.effectiveOrdinal = ordinal
	}
	t.mu.Unlock()

	t.logger.Info("Container exec attributed",
		"container", shortID(containerID), "pid", pid,
		"step_ordinal", ordinal, "tag_latency_ms", latencyMS)
	t.logAttribution(events.AuditEvent{
		EventType:       events.EventContainerAttribution,
		ContainerID:     shortID(containerID),
		ContainerOrigin: true,
		AttributionKind: "exec",
		StepOrdinal:     ordinal,
		PID:             uint32(pid),
		TagLatencyMS:    latencyMS,
	})
}

// errExecAlreadySeen means the exec was handled on a previous delivery — a
// reconnect replay, not a failure; handleExecStart returns without counting
// or logging it as a skip.
var errExecAlreadySeen = errors.New("exec already handled")

// resolveExecPid turns an exec event into the exec leader's host PID. The
// execID attribute is the fast path; daemons that omit it fall back to
// diffing the container's live ExecIDs against what we've already handled.
// Both paths honour the seenExecs idempotency guard — the replay after a
// stream reconnect arrives on whichever path the daemon supports.
// The error exists for the Debug log: an unresolvable exec is expected
// degradation (exec already exited), but WHICH failure occurred must be
// diagnosable from a debug run.
func (t *Tracker) resolveExecPid(ctx context.Context, containerID, execID string) (int, error) {
	ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
	defer cancel()

	if execID != "" {
		if t.markExecSeen(containerID, execID) {
			return 0, errExecAlreadySeen
		}
		return t.inspectExecPid(ictx, execID)
	}

	cinsp, err := t.client.inspectContainer(ictx, containerID)
	if err != nil {
		return 0, fmt.Errorf("container inspect for exec fallback: %w", err)
	}
	sawSeen := false
	for _, id := range cinsp.ExecIDs {
		if t.markExecSeen(containerID, id) {
			sawSeen = true
			continue
		}
		if pid, err := t.inspectExecPid(ictx, id); err == nil {
			return pid, nil
		}
	}
	if sawSeen {
		// Every live exec was already handled — the signature of a replayed
		// event after a stream reconnect, so the guard must hold on this
		// path exactly as on the execID fast path. (Approximation: an
		// unseen exec that failed inspection alongside a seen one is also
		// classified as replay; it would have been unattributable anyway.)
		return 0, errExecAlreadySeen
	}
	return 0, fmt.Errorf("no execID attribute and no unseen running exec among %d", len(cinsp.ExecIDs))
}

// markExecSeen records execID under its container and reports whether it
// had already been handled. Per-container keying exists so remove() can
// reclaim the whole set when the container goes away.
func (t *Tracker) markExecSeen(containerID, execID string) (seen bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	set := t.seenExecs[containerID]
	if set == nil {
		set = make(map[string]bool)
		t.seenExecs[containerID] = set
	}
	seen = set[execID]
	set[execID] = true
	return seen
}

// inspectExecPid reads an exec's leader PID, retrying briefly: dockerd
// emits exec_start BEFORE it records the process pid from containerd, so an
// immediate inspect reads Pid 0 for an exec that is very much alive
// (confirmed against dockerd 28/29; same publish-race shape as the
// stepCmdline retry in pkg/steps). A genuinely exited exec keeps reading 0
// and falls out as unattributable — the stricter tier, by design. The retry
// window is small against any real exec workload and is included in the
// reported tag latency.
func (t *Tracker) inspectExecPid(ctx context.Context, execID string) (int, error) {
	for i := 0; ; i++ {
		insp, err := t.client.inspectExec(ctx, execID)
		if err != nil {
			return 0, fmt.Errorf("exec inspect %s: %w", shortID(execID), err)
		}
		if insp.Pid != 0 {
			return insp.Pid, nil
		}
		if i >= 19 {
			return 0, fmt.Errorf("exec %s has no pid after retries (already exited?)", shortID(execID))
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("exec %s pid wait: %w", shortID(execID), ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (t *Tracker) remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Unconditional: exec ids may have been seen for containers the start
	// handler never registered (inspect raced the container's death).
	delete(t.seenExecs, id)
	info := t.containers[id]
	if info == nil {
		return
	}
	delete(t.containers, id)
	for _, ip := range info.ips {
		if t.byIP[ip] == info {
			delete(t.byIP, ip)
		}
	}
	if info.cgroupID != 0 && t.byCgroup[info.cgroupID] == info {
		delete(t.byCgroup, info.cgroupID)
	}
	// Task-map cleanup is the kernel's sched_process_exit; nothing to undo.
}

// forEachInspectAddr visits every address docker reported for a container:
// the legacy top-level fields (the default bridge; network name "") and
// each named network's entry. THE one walker of the NetworkSettings shape —
// both DNS attribution (collectIPs) and the enforce-mode subnet carve-out
// (collectSubnets) ride it, so a new address source added here reaches
// both, and a source added elsewhere is a bug.
func forEachInspectAddr(insp containerInspect, visit func(network, ip string, prefixLen int)) {
	visit("", insp.NetworkSettings.IPAddress, insp.NetworkSettings.IPPrefixLen)
	visit("", insp.NetworkSettings.GlobalIPv6Address, insp.NetworkSettings.GlobalIPv6PrefixLen)
	for name, nw := range insp.NetworkSettings.Networks {
		visit(name, nw.IPAddress, nw.IPPrefixLen)
		visit(name, nw.GlobalIPv6Address, nw.GlobalIPv6PrefixLen)
	}
}

// collectIPs gathers every address docker assigned the container, v4 and
// v6 alike: the DNS client lookup keys on whichever family the container's
// resolver socket uses, so an IPv6-enabled bridge must not silently lose
// DNS attribution while the TC join (cgroup-id based) keeps working.
func collectIPs(insp containerInspect) []string {
	ips := []string{}
	forEachInspectAddr(insp, func(_, ip string, _ int) {
		if ip != "" && !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	})
	return ips
}

// localSubnet is one candidate carve-out: a subnet plus the network it was
// seen on ("" = the default bridge, which is bridge-driver by definition).
type localSubnet struct {
	network string
	prefix  netip.Prefix
}

// collectSubnets derives the subnets docker attached the container to, v4
// and v6, masked. Entries with no prefix length (host networking, daemons
// that omit it) are dropped — a zero prefix would shape into a catch-all.
// Driver gating happens later, in allowSubnetOnce: this function only
// reads the inspect payload.
func collectSubnets(insp containerInspect) []localSubnet {
	var subnets []localSubnet
	forEachInspectAddr(insp, func(network, ipStr string, prefixLen int) {
		if ipStr == "" || prefixLen <= 0 {
			return
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return
		}
		prefix, err := addr.Prefix(prefixLen)
		if err != nil {
			return // prefixLen wider than the address family
		}
		for _, s := range subnets {
			if s.prefix == prefix {
				return
			}
		}
		subnets = append(subnets, localSubnet{network: network, prefix: prefix})
	})
	return subnets
}

// allowSubnetOnce runs the once-per-subnet carve-out pipeline: resolve the
// network's driver (bridge-driver networks are local-only by construction —
// their routes are on-link; a macvlan/ipvlan subnet is physical-network
// space and MUST stay adjudicated), then hand the subnet to the callback.
// seenSubnets is stamped only once the decision is final — a failed driver
// inspect or a failed carve-out write is retried by the next container on
// the network.
func (t *Tracker) allowSubnetOnce(ctx context.Context, s localSubnet) {
	key := s.prefix.String()
	t.mu.Lock()
	seen := t.seenSubnets[key]
	t.mu.Unlock()
	if seen {
		return
	}
	if s.network != "" {
		ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
		nw, err := t.client.inspectNetwork(ictx, s.network)
		cancel()
		if err != nil {
			t.logger.Warn("Cannot inspect network for subnet carve-out; subnet stays adjudicated for now",
				"network", s.network, "subnet", key, "error", err)
			return
		}
		if nw.Driver != "bridge" {
			t.mu.Lock()
			t.seenSubnets[key] = true
			t.mu.Unlock()
			t.logger.Info("Non-bridge network subnet stays adjudicated (not local-only)",
				"network", s.network, "driver", nw.Driver, "subnet", key)
			return
		}
	}
	if err := t.opts.AllowLocalSubnet(s.prefix); err != nil {
		t.logger.Warn("Local subnet carve-out failed; will retry on the network's next container",
			"subnet", key, "error", err)
		return
	}
	t.mu.Lock()
	t.seenSubnets[key] = true
	t.mu.Unlock()
}

// DiscoverBridgeSubnets returns the bridge-driver subnets of every
// container currently running. cmd/start.go runs this BEFORE raising the
// cgroup hook out of observe: docker-event tracking starts only after the
// dockerd restart, and containers that predate cargowall (GitHub service
// containers, compose stacks) must not lose bridge-local traffic in that
// window.
func DiscoverBridgeSubnets(ctx context.Context, socket string) ([]netip.Prefix, error) {
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	c := newDockerClient(socket)
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	err := c.ping(pingCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("docker daemon unreachable: %w", err)
	}
	lctx, cancel := context.WithTimeout(ctx, unaryTimeout)
	list, err := c.listContainers(lctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	bridgeDriver := map[string]bool{} // network name → driver == "bridge"
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, sum := range list {
		ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
		insp, ierr := c.inspectContainer(ictx, sum.ID)
		cancel()
		if ierr != nil {
			continue // best-effort: the tracker re-covers it once running
		}
		for _, s := range collectSubnets(insp) {
			if seen[s.prefix] {
				continue
			}
			if s.network != "" {
				isBridge, known := bridgeDriver[s.network]
				if !known {
					nctx, cancel := context.WithTimeout(ctx, unaryTimeout)
					nw, nerr := c.inspectNetwork(nctx, s.network)
					cancel()
					isBridge = nerr == nil && nw.Driver == "bridge"
					bridgeDriver[s.network] = isBridge
				}
				if !isBridge {
					continue
				}
			}
			seen[s.prefix] = true
			out = append(out, s.prefix)
		}
	}
	return out, nil
}

func (t *Tracker) logAttribution(ev events.AuditEvent) {
	if t.auditLogger == nil {
		return
	}
	if err := t.auditLogger.LogEvent(ev); err != nil {
		t.logger.Error("Failed to write audit log", "error", err)
	}
}

func (t *Tracker) recordLatency(ms float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.latencies) < maxLatencies {
		t.latencies = append(t.latencies, ms)
	}
}

// logSummary emits the 3a telemetry: tag counts and latency distribution,
// TC-event correlation counters, and DNS hit rates. One line, greppable in
// CI and runner logs.
func (t *Tracker) logSummary() {
	var p50, p95, maxL float64
	t.mu.Lock()
	if len(t.latencies) > 0 {
		sorted := slices.Clone(t.latencies)
		slices.Sort(sorted)
		p50 = sorted[len(sorted)/2]
		p95 = sorted[len(sorted)*95/100]
		maxL = sorted[len(sorted)-1]
	}
	t.mu.Unlock()

	var observerRecords uint64
	if t.observer != nil {
		observerRecords = t.observer.Records()
	}
	t.logger.Info("Container attribution summary",
		"containers_tagged", t.tagged.Load(),
		"execs_tagged", t.execTagged.Load(),
		"reconciled", t.reconciled.Load(),
		"identity_rejected", t.identityRejected.Load(),
		"tag_skipped", t.tagSkipped.Load(),
		"tag_latency_ms_p50", p50,
		"tag_latency_ms_p95", p95,
		"tag_latency_ms_max", maxL,
		"origin_records", observerRecords,
		"tc_enriched", t.tcEnriched.Load(),
		"tc_container_only", t.tcContainerOnly.Load(),
		"tc_ambiguous", t.tcAmbiguous.Load(),
		"tc_no_record", t.tcNoRecord.Load(),
		"dns_hits", t.dnsHits.Load(),
		"dns_misses", t.dnsMisses.Load())
}
