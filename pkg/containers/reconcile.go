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

// Reconciliation: the diff between what the tracker believes and what the
// daemon reports, run at the top of every event-stream session. Adoption of
// unknown running containers, re-adoption of new incarnations behind a kept
// container id, and the two-pass stale sweep all live here.

package containers

import (
	"context"
	"sync"
)

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
	// Absence must be seen on TWO consecutive passes before the sweep
	// fires: a settling daemon can answer /containers/json with a partial
	// list, and a single partial answer must not wipe live containers
	// (live-restore containers never re-emit a start event, so a wrong
	// sweep is permanent). The empty-list guard below is the degenerate
	// case of the same distrust.
	t.mu.Lock()
	var stale []string
	for id := range t.containers {
		if live[id] {
			delete(t.missingCounts, id)
			continue
		}
		t.missingCounts[id]++
		if t.missingCounts[id] >= 2 {
			stale = append(stale, id)
			delete(t.missingCounts, id)
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
		t.logger.Info("Container removed during reconciliation (absent from two consecutive lists)",
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
