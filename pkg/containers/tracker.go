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
	// preDaemon marks an adoption via reconcile (StepOrdinalPreDaemon): if
	// the container's REAL start event later replays from the stream gap,
	// handleStart upgrades the ordinal from the event's own timestamp
	// instead of discarding the replay against the `known` guard.
	preDaemon bool
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
	// netDrivers caches network name → (driver == "bridge") so the subnet
	// carve-out pays at most one inspect per network, not one per container
	// — the inspect runs on the event-stream goroutine, which must never be
	// serially parked (same rule execConcurrency exists for).
	netDrivers map[string]bool
	// missingCounts tracks consecutive reconcile passes a tracked container
	// was absent from listContainers; the stale sweep fires only on the
	// second consecutive absence, so one partial list from a settling
	// daemon cannot wipe live containers.
	missingCounts map[string]int
	latencies     []float64 // tag latencies (ms), bounded

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
		netDrivers:  make(map[string]bool),

		missingCounts: make(map[string]int),
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
		healthy, err := t.streamOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if healthy {
			// A session whose DECODE phase survived streamHealthyAfter was
			// genuinely healthy: the next hiccup gets the 500ms floor back.
			// Without this, a few startup flakes pin backoff at maxBackoff
			// for the process lifetime. The clock deliberately excludes
			// reconcile (a slow full-fleet reconcile against a wedged daemon
			// must not launder itself into a health signal) and events
			// (docker's inclusive `since` replay redelivers at least one per
			// session, which would reset even a flapping daemon).
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

// streamOnce runs one event-stream session. healthy reports whether the
// decode phase (not reconcile) outlived streamHealthyAfter — run()'s signal
// for resetting the reconnect backoff.
func (t *Tracker) streamOnce(ctx context.Context) (healthy bool, err error) {
	// Open the stream before reconciling: a container starting between the
	// two is then either in the list or in the buffered stream, never lost.
	body, err := t.client.events(ctx, t.lastEventNano.Load())
	if err != nil {
		return false, err
	}
	defer body.Close()

	t.reconcile(ctx)

	decodeStart := time.Now()
	defer func() { healthy = time.Since(decodeStart) >= streamHealthyAfter }()

	dec := json.NewDecoder(body)
	for {
		var ev dockerEvent
		if derr := dec.Decode(&ev); derr != nil {
			if errors.Is(derr, io.EOF) || ctx.Err() != nil {
				return healthy, derr // defer above computes healthy
			}
			return healthy, fmt.Errorf("decode docker event: %w", derr)
		}
		if ev.TimeNano > 0 {
			t.lastEventNano.Store(ev.TimeNano)
		}
		if ev.Type == "network" {
			// A bridge network created mid-run must be carved BEFORE its
			// first container's traffic, or that traffic meets enforce-mode
			// default-deny; container-driven discovery alone misses networks
			// whose containers are too short-lived to inspect.
			if ev.Action == "create" {
				t.handleNetworkCreate(ctx, ev)
			}
			continue
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
