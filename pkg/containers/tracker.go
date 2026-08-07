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
// steps (issue #106, phase 3a — audit-only). Container process ancestry runs
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
// Scope boundaries (by design, phase 3a): docker-in-docker attribution stops
// at the outer container (inner workloads inherit the outer tag through
// fork); --privileged containers are host-root equivalent and are flagged in
// the audit stream rather than constrained; the window between container/
// exec start and tagging leaves early sockets untagged — the unattributed
// tier, never a step.
package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// Options configures Start. Zero values take the production defaults; the
// roots are injectable for tests.
type Options struct {
	Socket     string // Docker daemon socket, default /var/run/docker.sock
	ProcRoot   string // default /proc
	CgroupRoot string // default /sys/fs/cgroup
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

	mu         sync.Mutex
	containers map[string]*containerInfo
	byIP       map[netip.Addr]*containerInfo
	byCgroup   map[uint64]*containerInfo
	seenExecs  map[string]bool
	latencies  []float64 // tag latencies (ms), bounded

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
		containers:  make(map[string]*containerInfo),
		byIP:        make(map[netip.Addr]*containerInfo),
		byCgroup:    make(map[uint64]*containerInfo),
		seenExecs:   make(map[string]bool),
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

// Close stops the tracker and logs the telemetry summary.
func (t *Tracker) Close() {
	t.cancel()
	<-t.done
	t.logSummary()
}

// run is the reconnect loop: stream events, and on any error reconnect with
// backoff, resuming from the last seen event so nothing in the gap is lost.
// One mechanism covers daemon restarts and transient socket errors alike.
func (t *Tracker) run(ctx context.Context) {
	defer close(t.done)
	backoff := reconnectBackoff
	for {
		err := t.streamOnce(ctx)
		if ctx.Err() != nil {
			return
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
			// omit it).
			t.handleExecStart(ctx, ev.Actor.ID, ev.Actor.Attributes["execID"], ev.TimeNano)
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
func (t *Tracker) reconcile(ctx context.Context) {
	list, err := t.client.listContainers(ctx)
	if err != nil {
		t.logger.Warn("Cannot list containers for reconciliation", "error", err)
		return
	}
	for _, c := range list {
		t.mu.Lock()
		_, known := t.containers[c.ID]
		t.mu.Unlock()
		if !known {
			t.handleStart(ctx, c.ID, "reconcile", 0)
		}
	}
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
	t.containers[insp.ID] = info
	for _, ip := range info.ips {
		t.byIP[ip] = info
	}
	if info.cgroupID != 0 {
		t.byCgroup[info.cgroupID] = info
	}
	t.mu.Unlock()

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
	pid := t.resolveExecPid(ctx, containerID, execID)
	if pid == 0 {
		t.tagSkipped.Add(1)
		t.logger.Debug("Exec PID unresolvable; traffic stays in the container tier",
			"container", shortID(containerID))
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

// resolveExecPid turns an exec event into the exec leader's host PID. The
// execID attribute is the fast path; daemons that omit it fall back to
// diffing the container's live ExecIDs against what we've already handled.
func (t *Tracker) resolveExecPid(ctx context.Context, containerID, execID string) int {
	ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
	defer cancel()

	if execID != "" {
		t.mu.Lock()
		t.seenExecs[execID] = true
		t.mu.Unlock()
		insp, err := t.client.inspectExec(ictx, execID)
		if err != nil || insp.Pid == 0 {
			return 0 // exec already exited: unattributable by design
		}
		return insp.Pid
	}

	cinsp, err := t.client.inspectContainer(ictx, containerID)
	if err != nil {
		return 0
	}
	for _, id := range cinsp.ExecIDs {
		t.mu.Lock()
		seen := t.seenExecs[id]
		if !seen {
			t.seenExecs[id] = true
		}
		t.mu.Unlock()
		if seen {
			continue
		}
		if insp, err := t.client.inspectExec(ictx, id); err == nil && insp.Running && insp.Pid != 0 {
			return insp.Pid
		}
	}
	return 0
}

func (t *Tracker) remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
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

func collectIPs(insp containerInspect) []string {
	ips := []string{}
	if insp.NetworkSettings.IPAddress != "" {
		ips = append(ips, insp.NetworkSettings.IPAddress)
	}
	for _, nw := range insp.NetworkSettings.Networks {
		if nw.IPAddress != "" && !slices.Contains(ips, nw.IPAddress) {
			ips = append(ips, nw.IPAddress)
		}
	}
	return ips
}

// LookupClient resolves a DNS client address to container attribution: the
// container IP is the source of both direct bridge queries and the embedded
// resolver's external forwards. Wired into pkg/dns via SetContainerLookup.
func (t *Tracker) LookupClient(addr net.Addr) (ordinal uint32, containerID string, ok bool) {
	var ip netip.Addr
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, ok = netip.AddrFromSlice(a.IP)
	case *net.TCPAddr:
		ip, ok = netip.AddrFromSlice(a.IP)
	}
	if !ok {
		return 0, "", false
	}
	ip = ip.Unmap()

	t.mu.Lock()
	info := t.byIP[ip]
	t.mu.Unlock()
	if info == nil {
		t.dnsMisses.Add(1)
		return 0, "", false
	}
	t.dnsHits.Add(1)
	return info.effectiveOrdinal, shortID(info.id), true
}

// Enrich implements events.ContainerEnricher: called for TC events whose
// socket carried no identity (pid 0, ordinal 0 — the NATed-container
// signature), it consults the origin observer's pre-NAT records and adopts
// what the flow's socket actually carried.
//
// Invariant: only the origin record's socket-tag ordinal is ever copied —
// never OrdinalAt or any "current step" notion — so traffic from the window
// between container start and tagging can only land in the
// container-unattributed tier, never on a step.
func (t *Tracker) Enrich(audit *events.AuditEvent, ev *events.BpfBlockedEvent) {
	if t.observer == nil {
		return
	}

	dstPort, srcPort := ev.DstPort, ev.SrcPort
	if ev.IsProtocolBlock() {
		// dst_port carried the protocol number; origin records for
		// non-TCP/UDP protocols carry ports 0 to match.
		dstPort, srcPort = 0, 0
	}
	var recs []origin.Record
	if ev.IpVersion == 6 {
		recs = t.observer.LookupV6(ev.DstIp6, dstPort, ev.IpProto, srcPort)
	} else {
		recs = t.observer.LookupV4(ev.DstIp, dstPort, ev.IpProto, srcPort)
	}
	// A record cannot postdate the TC event it explains (the cgroup hook
	// runs before TC on the same packet, in the same clock domain).
	recs = slices.DeleteFunc(recs, func(r origin.Record) bool { return r.Timestamp > ev.Timestamp })
	if len(recs) == 0 {
		t.tcNoRecord.Add(1)
		return
	}

	t.mu.Lock()
	classify := func(r origin.Record) *containerInfo {
		if r.CgroupID != 0 {
			if info := t.byCgroup[r.CgroupID]; info != nil {
				return info
			}
		}
		if r.SrcIP.IsValid() {
			return t.byIP[r.SrcIP]
		}
		return nil
	}
	first := classify(recs[0])
	agreed := true
	for _, r := range recs[1:] {
		if classify(r) != first || r.StepOrdinal != recs[0].StepOrdinal {
			agreed = false
			break
		}
	}
	allContainers := first != nil
	if !agreed {
		for _, r := range recs {
			if classify(r) == nil {
				allContainers = false
				break
			}
		}
	}
	t.mu.Unlock()

	if !agreed {
		// Candidates disagree: claiming a step would guess. Claim container
		// origin only when every candidate is a container — the stricter
		// tier — and nothing otherwise.
		t.tcAmbiguous.Add(1)
		if allContainers {
			audit.ContainerOrigin = true
		}
		return
	}

	rec := recs[0]
	if rec.StepOrdinal != 0 {
		audit.StepOrdinal = rec.StepOrdinal
	}
	if rec.PID != 0 {
		audit.PID = rec.PID
		if audit.Process == "" {
			audit.Process = readComm(t.opts.ProcRoot, int(rec.PID))
		}
	}
	if first != nil {
		audit.ContainerOrigin = true
		audit.ContainerID = shortID(first.id)
		if rec.StepOrdinal != 0 {
			t.tcEnriched.Add(1)
		} else {
			t.tcContainerOnly.Add(1)
		}
	} else if rec.StepOrdinal != 0 || rec.PID != 0 {
		// Host flow the TC join missed (e.g. map_sock_pid eviction): the
		// origin record still knows its socket. Pure bonus attribution.
		t.tcEnriched.Add(1)
	}
}

func readComm(procRoot string, pid int) string {
	comm, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
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
