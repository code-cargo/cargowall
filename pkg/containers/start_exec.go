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

// Container lifecycle handlers: start adoption (and its upgrade when a
// reconcile-adopted container's real start event replays), exec tagging
// with its replay guard, and removal.

package containers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/code-cargo/cargowall/pkg/events"
)

func (t *Tracker) handleStart(ctx context.Context, id, kind string, timeNano int64) {
	t.mu.Lock()
	existing := t.containers[id]
	t.mu.Unlock()
	if existing != nil {
		// Replayed event after reconnect — usually a no-op, EXCEPT when
		// reconcile got there first and adopted the container as pre-daemon:
		// the replayed start carries the real timeNano the sentinel adoption
		// lacked, and discarding it would leave the container filed under
		// "started before cargowall" for the run. Upgrade instead.
		if kind == "start" && timeNano > 0 && existing.preDaemon {
			t.upgradeReconciledStart(existing, id, timeNano)
		}
		return
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
			t.carvePrefix(ctx, s.network, s.prefix)
		}
	}

	// Identity check before any tagging: the inspected PID must currently
	// sit in this container's cgroup, or a recycled PID could tag an
	// unrelated host process.
	cgroupID, err := verifyContainerTask(t.opts.ProcRoot, t.opts.CgroupRoot, info.initPID, insp.ID)
	identityOK := err == nil
	if identityOK {
		t.pidsVisible.Store(true)
	} else if gone, derr := t.exitedFirst(ctx, err, t.containerRunning(id)); gone {
		// `docker run --rm alpine true`: its init was reaped before this
		// check, though inspect still gave its pid.
		t.exitedUntagged(id, err)
	} else if ctx.Err() == nil { // shutting down mid-check is not a finding
		t.identityRejected.Add(1)
		t.warnIdentity("Container identity check failed; not tagging", id, err, derr)
	}
	info.cgroupID = cgroupID

	var ordinal uint32
	if kind == "reconcile" {
		ordinal = events.StepOrdinalPreDaemon
		// Upgrade-on-replay is only armed when the identity check passed:
		// upgradeReconciledStart tags WITHOUT re-verification on the premise
		// that adoption verified the PID, and a refused container must stay
		// at the sentinel — the stricter outcome — not get tagged later by
		// its replayed start event.
		info.preDaemon = identityOK
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
		tag := t.tagger.TagContainerProcess
		if kind == "reconcile" {
			// Create-only: adoption cannot tell "predates cargowall" from
			// "wrongly swept and re-adopted", and the sentinel must never
			// overwrite a real tag the container's original start wrote.
			tag = t.tagger.AdoptContainerProcess
		}
		held, err := tag(info.initPID, ordinal)
		switch {
		case held != 0 && kind == "reconcile":
			t.reconciled.Add(1)
			markerOrdinal = held
			// A real tag the adoption kept: the container's address
			// belongs to that step too.
			info.birthOrdinal, info.effectiveOrdinal = held, held
		case held != 0:
			t.tagged.Add(1)
			markerOrdinal = held
			latencyMS = float64(time.Since(time.Unix(0, timeNano)).Microseconds()) / 1000
			t.recordLatency(latencyMS)
		case err != nil:
			// Says nothing of the task: an adopted one stays armed for its
			// replayed start to tag.
			t.tagFailed(id, err)
		default:
			// Exited between the identity check and the task walk: there is
			// nothing left to upgrade either.
			info.preDaemon = false
			t.exitedUntagged(id, errTaskGone)
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

// upgradeReconciledStart replaces a pre-daemon sentinel adoption with the
// real attribution its replayed start event carries: reconcile runs before
// the since-replay is drained, so a container born in a stream gap is
// adopted as StepOrdinalPreDaemon moments before its true start event —
// with the correct event-time ordinal — arrives. Without the upgrade the
// replay is discarded and the container reports as "started before
// cargowall" for the rest of the run.
func (t *Tracker) upgradeReconciledStart(info *containerInfo, id string, timeNano int64) {
	ordinal := t.tagger.OrdinalAt(time.Unix(0, timeNano))
	t.mu.Lock()
	info.preDaemon = false
	if ordinal == 0 {
		t.mu.Unlock()
		return // genuinely pre-step: the sentinel was right
	}
	info.birthOrdinal = ordinal
	if info.effectiveOrdinal == events.StepOrdinalPreDaemon {
		// Keep a real exec re-tag if one already happened.
		info.effectiveOrdinal = ordinal
	}
	pid := info.initPID
	t.mu.Unlock()

	// Identity was verified at adoption; the PID has not changed since.
	if held, err := t.tagger.TagContainerProcess(pid, ordinal); held == 0 {
		if err != nil {
			t.tagFailed(id, err)
		} else {
			t.exitedUntagged(id, errTaskGone)
		}
		return
	}
	t.tagged.Add(1)
	t.logger.Info("Container attribution upgraded from replayed start event",
		"container", shortID(id), "step_ordinal", ordinal)
	t.logAttribution(events.AuditEvent{
		EventType:       events.EventContainerAttribution,
		ContainerID:     shortID(id),
		ContainerOrigin: true,
		AttributionKind: "start",
		StepOrdinal:     ordinal,
		PID:             uint32(pid),
	})
}

func (t *Tracker) handleExecStart(ctx context.Context, containerID, execID string, timeNano int64) {
	pid, execID, err := t.resolveExecPid(ctx, containerID, execID)
	if err != nil {
		if errors.Is(err, errExecAlreadySeen) {
			// Replayed exec_start after a stream reconnect (docker's `since`
			// is inclusive): handled once already. A second pass would
			// re-inspect, double-count execTagged, skew the latency
			// percentiles with an event minutes old, and re-tag a PID that
			// may since have been recycled.
			return
		}
		if errors.Is(err, errExecExited) {
			t.exitedBeforeTag.Add(1)
			t.logExecExited(containerID, execID, pid, err)
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
		gone, derr := t.exitedFirst(ctx, err, t.execRunning(execID))
		if gone {
			// A one-off exec (a post step's docker exec) finished before
			// this check.
			t.exitedBeforeTag.Add(1)
			t.logExecExited(containerID, execID, pid, err)
			return
		}
		if ctx.Err() == nil { // shutting down mid-check is not a finding
			t.identityRejected.Add(1)
			t.warnIdentity("Exec identity check failed; not tagging", containerID, err, derr)
		}
		return
	}
	t.pidsVisible.Store(true)

	if held, err := t.tagger.TagContainerProcess(pid, ordinal); held == 0 {
		if err != nil {
			t.tagFailed(containerID, err)
		} else {
			t.exitedBeforeTag.Add(1)
			t.logExecExited(containerID, execID, pid, errTaskGone)
		}
		return
	}
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

// errExecExited marks an exec the daemon reports as already finished: its
// pid may since belong to another process, even one in the same container,
// so it is never checked or tagged.
var errExecExited = errors.New("exec already exited")

// errTaskGone means a task passed its identity check but had exited, or was
// exiting, by the task walk that would have tagged it: nothing was tagged.
var errTaskGone = errors.New("task gone by the task walk")

// errExecAlreadySeen means the exec was handled on a previous delivery — a
// reconnect replay, not a failure; handleExecStart returns without counting
// or logging it as a skip.
var errExecAlreadySeen = errors.New("exec already handled")

// resolveExecPid turns an exec event into the exec leader's host PID and
// the exec's id, which the event may not carry. The execID attribute is the
// fast path; daemons that omit it fall back to diffing the container's live
// ExecIDs against what we've already handled.
// Both paths honour the seenExecs idempotency guard — the replay after a
// stream reconnect arrives on whichever path the daemon supports.
// The error exists for the Debug log: an unresolvable exec is expected
// degradation (exec already exited), but WHICH failure occurred must be
// diagnosable from a debug run.
func (t *Tracker) resolveExecPid(ctx context.Context, containerID, execID string) (int, string, error) {
	ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
	defer cancel()

	if execID != "" {
		if t.markExecSeen(containerID, execID) {
			return 0, "", errExecAlreadySeen
		}
		pid, err := t.inspectExecPid(ictx, execID)
		return pid, execID, err
	}

	cinsp, err := t.client.inspectContainer(ictx, containerID)
	if err != nil {
		return 0, "", fmt.Errorf("container inspect for exec fallback: %w", err)
	}
	sawSeen := false
	for _, id := range cinsp.ExecIDs {
		if t.markExecSeen(containerID, id) {
			sawSeen = true
			continue
		}
		if pid, err := t.inspectExecPid(ictx, id); err == nil {
			return pid, id, nil
		}
	}
	if sawSeen {
		// Every live exec was already handled — the signature of a replayed
		// event after a stream reconnect, so the guard must hold on this
		// path exactly as on the execID fast path. (Approximation: an
		// unseen exec that failed inspection alongside a seen one is also
		// classified as replay; it would have been unattributable anyway.)
		return 0, "", errExecAlreadySeen
	}
	return 0, "", fmt.Errorf("no execID attribute and no unseen running exec among %d", len(cinsp.ExecIDs))
}

// exitPolls and exitPollInterval bound how long exitedFirst asks the
// daemon: dockerd learns of an exit from containerd some milliseconds after
// the kernel reaps the task, and reports it running until then.
const (
	exitPolls        = 10
	exitPollInterval = 20 * time.Millisecond
)

// exitedFirst reports whether a failed identity check is a task that
// exited before it could be checked. Only a gone task can be (see
// taskGone). Once any identity check has passed, this /proc sees the
// daemon's pids, so a missing one has exited. Until then the daemon's pids
// may be in another pid namespace, where every check fails this way, so the
// daemon is asked, within a bound, until it reports the task stopped. A
// task it still reports running, or cannot report at all, keeps the
// warning; when asking failed, the error is returned for it. handleStart
// asks on the event stream, so the bound is also how long a daemon whose
// pids are out of sight holds each container start.
func (t *Tracker) exitedFirst(ctx context.Context, err error, running func(context.Context) (bool, error)) (bool, error) {
	if !taskGone(err) {
		return false, nil
	}
	if t.pidsVisible.Load() {
		return true, nil
	}
	for i := 1; ; i++ {
		ictx, cancel := context.WithTimeout(ctx, unaryTimeout)
		up, derr := running(ictx)
		cancel()
		if derr != nil {
			return false, derr
		}
		if !up {
			return true, nil
		}
		if i == exitPolls {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(exitPollInterval):
		}
	}
}

// containerRunning and execRunning are exitedFirst's question to the
// daemon.
func (t *Tracker) containerRunning(id string) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		insp, err := t.client.inspectContainer(ctx, id)
		return insp.State.Running, err
	}
}

func (t *Tracker) execRunning(execID string) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		insp, err := t.client.inspectExec(ctx, execID)
		return insp.Running, err
	}
}

// logExecExited records an exec that finished before it could be tagged.
// Whatever its leader left running in the background stays untagged, in
// the container's tier, as it always has; a one-off exec leaves nothing.
func (t *Tracker) logExecExited(containerID, execID string, pid int, err error) {
	t.logger.Debug("Exec exited before it could be tagged; anything it left running stays in the container's tier",
		"container", shortID(containerID), "exec", shortID(execID), "pid", pid, "error", err)
}

// exitedUntagged counts and logs a container whose task exited before it
// could be tagged: an exit, not a finding.
func (t *Tracker) exitedUntagged(containerID string, err error) {
	t.exitedBeforeTag.Add(1)
	t.logger.Debug("Container exited before it could be tagged", "container", shortID(containerID), "error", err)
}

// tagFailed counts and logs a task that passed its identity check but could
// not be tagged: a failed task walk, or a step map that refused the write
// (full, say). Its traffic stays in the container's tier.
func (t *Tracker) tagFailed(containerID string, err error) {
	t.tagSkipped.Add(1)
	t.logger.Warn("Could not tag container task; its traffic stays in the container tier",
		"container", shortID(containerID), "error", err)
}

// warnIdentity logs a failed identity check, with the daemon's error when
// asking it whether the task had exited failed.
func (t *Tracker) warnIdentity(msg, containerID string, err, daemonErr error) {
	args := []any{"container", shortID(containerID), "error", err}
	if daemonErr != nil {
		args = append(args, "daemon_error", daemonErr)
	}
	t.logger.Warn(msg, args...)
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
// stepCmdline retry in pkg/steps). An exec that never got a pid keeps
// reading 0 and falls out as unattributable — the stricter tier, by
// design. One that started and has already finished reads its pid with
// Running false, and is errExecExited. The retry window is small against
// any real exec workload and is included in the reported tag latency.
func (t *Tracker) inspectExecPid(ctx context.Context, execID string) (int, error) {
	for i := 0; ; i++ {
		insp, err := t.client.inspectExec(ctx, execID)
		if err != nil {
			return 0, fmt.Errorf("exec inspect %s: %w", shortID(execID), err)
		}
		if insp.Pid != 0 {
			if !insp.Running {
				return 0, fmt.Errorf("exec %s: %w", shortID(execID), errExecExited)
			}
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
	// Same reason, same shape: a lingering absence count would leak (the
	// sweep loop iterates t.containers, which this id is leaving), and —
	// worse — docker ids survive stop+start, so a re-adopted id carrying a
	// stale count of 1 would be swept on its first absence, defeating the
	// two-pass guard for exactly that container.
	delete(t.missingCounts, id)
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
