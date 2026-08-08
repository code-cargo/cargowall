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

package containers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/origin"
)

// The tracker is asynchronous (stream goroutine + unary inspects), so every
// observable effect is polled rather than awaited on a channel.
const (
	waitFor = 3 * time.Second
	tick    = 10 * time.Millisecond
)

type tagCall struct {
	pid     int
	ordinal uint32
}

// fakeTagger records TagContainerProcess calls and serves a settable
// OrdinalAt result; both are called from the tracker's stream goroutine.
type fakeTagger struct {
	mu      sync.Mutex
	calls   []tagCall
	ordinal uint32
}

func (f *fakeTagger) TagContainerProcess(pid int, ordinal uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, tagCall{pid: pid, ordinal: ordinal})
}

func (f *fakeTagger) OrdinalAt(time.Time) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ordinal
}

func (f *fakeTagger) setOrdinal(o uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ordinal = o
}

func (f *fakeTagger) tagCalls() []tagCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// recordingSink captures audit events. Consume runs under the audit
// logger's mutex and must not block, so it only appends.
type recordingSink struct {
	mu     sync.Mutex
	events []events.AuditEvent
}

func (s *recordingSink) Consume(ev events.AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *recordingSink) attributions() []events.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []events.AuditEvent
	for _, ev := range s.events {
		if ev.EventType == events.EventContainerAttribution {
			out = append(out, ev)
		}
	}
	return out
}

// fakeDaemon serves the four Docker Engine endpoints the tracker consumes,
// over a unix socket. Events pushed via push stream to the connected
// client; the stream handler unblocks on request-context done so tracker
// Close (which cancels the client request) never hangs on a live stream.
type fakeDaemon struct {
	sock string

	mu         sync.Mutex
	containers map[string]containerInspect
	execs      map[string]execInspect
	// execPidDelay[id] > 0 makes the next N exec inspects report Pid 0 —
	// the shape dockerd serves between emitting exec_start and recording
	// the pid from containerd (the publish race the tracker retries over).
	execPidDelay map[string]int
	list         []containerSummary

	eventCh chan dockerEvent
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{
		containers:   make(map[string]containerInspect),
		execs:        make(map[string]execInspect),
		execPidDelay: make(map[string]int),
		eventCh:      make(chan dockerEvent, 16),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "OK")
	})
	mux.HandleFunc("/events", d.serveEvents)
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		_ = json.NewEncoder(w).Encode(d.list)
	})
	mux.HandleFunc("/containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		insp, ok := d.containers[r.PathValue("id")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(insp)
	})
	mux.HandleFunc("/exec/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		id := r.PathValue("id")
		insp, ok := d.execs[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if d.execPidDelay[id] > 0 {
			d.execPidDelay[id]--
			insp.Pid = 0
			insp.Running = false
		}
		_ = json.NewEncoder(w).Encode(insp)
	})
	d.sock = startUnixServer(t, mux)
	return d
}

func (d *fakeDaemon) serveEvents(w http.ResponseWriter, r *http.Request) {
	// Flush the header immediately: the tracker's events() blocks until the
	// response arrives, and reconciliation only runs after that.
	w.WriteHeader(http.StatusOK)
	fl := w.(http.Flusher)
	fl.Flush()
	enc := json.NewEncoder(w)
	for {
		select {
		case ev := <-d.eventCh:
			_ = enc.Encode(ev)
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (d *fakeDaemon) setContainer(insp containerInspect) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.containers[insp.ID] = insp
}

func (d *fakeDaemon) updateContainer(id string, fn func(*containerInspect)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	insp := d.containers[id]
	fn(&insp)
	d.containers[id] = insp
}

func (d *fakeDaemon) setExec(id string, insp execInspect) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.execs[id] = insp
}

func (d *fakeDaemon) setExecPidDelay(id string, inspects int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.execPidDelay[id] = inspects
}

func (d *fakeDaemon) setList(list ...containerSummary) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.list = list
}

// push queues one event for the stream; the channel is buffered well past
// what any test sends, so push never blocks the test goroutine.
func (d *fakeDaemon) push(ev dockerEvent) { d.eventCh <- ev }

func startEvent(id string, nano int64) dockerEvent {
	ev := dockerEvent{Type: "container", Action: "start", TimeNano: nano}
	ev.Actor.ID = id
	return ev
}

func execStartEvent(containerID, execID string, nano int64) dockerEvent {
	// Real daemons suffix the command ("exec_start: sh -c ..."), so the
	// tracker matches on the prefix — mirror that shape here.
	ev := dockerEvent{Type: "container", Action: "exec_start: sh -c true", TimeNano: nano}
	ev.Actor.ID = containerID
	if execID != "" {
		ev.Actor.Attributes = map[string]string{"execID": execID}
	}
	return ev
}

func dieEvent(id string, nano int64) dockerEvent {
	ev := dockerEvent{Type: "container", Action: "die", TimeNano: nano}
	ev.Actor.ID = id
	return ev
}

// makeInspect builds the minimal inspect payload handleStart consumes.
func makeInspect(id string, pid int, ip string, privileged bool) containerInspect {
	var insp containerInspect
	insp.ID = id
	insp.State.Pid = pid
	insp.State.Running = true
	insp.HostConfig.Privileged = privileged
	insp.NetworkSettings.IPAddress = ip
	return insp
}

type fixture struct {
	daemon     *fakeDaemon
	tagger     *fakeTagger
	sink       *recordingSink
	tracker    *Tracker
	procRoot   string
	cgroupRoot string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{
		daemon:     newFakeDaemon(t),
		tagger:     &fakeTagger{},
		sink:       &recordingSink{},
		procRoot:   t.TempDir(),
		cgroupRoot: t.TempDir(),
	}
}

// start runs the real Start against the fake daemon. Close is registered
// before the daemon's cleanup runs (LIFO), so the stream client disconnects
// first and the events handler unblocks via its request context.
func (f *fixture) start(t *testing.T) {
	t.Helper()
	auditLogger, err := events.NewAuditLogger("", false)
	require.NoError(t, err)
	auditLogger.AddSink(f.sink)
	tr, err := Start(context.Background(), Options{
		Socket:     f.daemon.sock,
		ProcRoot:   f.procRoot,
		CgroupRoot: f.cgroupRoot,
	}, f.tagger, nil, auditLogger, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	f.tracker = tr
	t.Cleanup(tr.Close)
}

// addContainer wires a runnable container into the daemon and the fake
// proc/cgroup trees so the identity check passes.
func (f *fixture) addContainer(t *testing.T, id string, pid int, ip string, privileged bool) {
	t.Helper()
	writeProcEntry(t, f.procRoot, pid, cgroupV2Line(id)+"\n", "app")
	mkScopeDir(t, f.cgroupRoot, id)
	f.daemon.setContainer(makeInspect(id, pid, ip, privileged))
}

// waitAttribution polls for the attribution audit event of the given kind
// for the given container. Handlers tag before they log, so once the event
// is visible every tagger call it implies has already been recorded.
func (f *fixture) waitAttribution(t *testing.T, kind, containerID string) events.AuditEvent {
	t.Helper()
	var got events.AuditEvent
	require.Eventually(t, func() bool {
		for _, ev := range f.sink.attributions() {
			if ev.AttributionKind == kind && ev.ContainerID == shortID(containerID) {
				got = ev
				return true
			}
		}
		return false
	}, waitFor, tick, "no %q attribution for %s", kind, shortID(containerID))
	return got
}

func TestStartFailsWithoutDaemon(t *testing.T) {
	// No socket means no daemon: the caller must get an error to degrade
	// on, never a tracker that spins.
	_, err := Start(context.Background(), Options{
		Socket: filepath.Join(t.TempDir(), "none.sock"),
	}, &fakeTagger{}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.ErrorContains(t, err, "docker daemon unreachable")
}

func TestStartEventTagsAndIndexes(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("a", 64)
	f.addContainer(t, id, 4242, "172.17.0.2", false)
	f.tagger.setOrdinal(7)
	f.start(t)

	// A non-container event must be skipped without disturbing the stream.
	f.daemon.push(dockerEvent{Type: "network", Action: "connect"})
	f.daemon.push(startEvent(id, time.Now().UnixNano()))

	ev := f.waitAttribution(t, "start", id)
	assert.Equal(t, events.EventContainerAttribution, ev.EventType)
	assert.Equal(t, id[:12], ev.ContainerID)
	assert.True(t, ev.ContainerOrigin)
	assert.Equal(t, uint32(7), ev.StepOrdinal)
	assert.Equal(t, uint32(4242), ev.PID)
	assert.GreaterOrEqual(t, ev.TagLatencyMS, 0.0)
	assert.False(t, ev.Privileged)

	assert.Equal(t, []tagCall{{pid: 4242, ordinal: 7}}, f.tagger.tagCalls())

	// The IP index is what DNS client attribution consults.
	ord, short, ok := f.tracker.LookupClient(&net.UDPAddr{IP: net.ParseIP("172.17.0.2"), Port: 33333})
	require.True(t, ok)
	assert.Equal(t, uint32(7), ord)
	assert.Equal(t, id[:12], short)
}

func TestReconcileTagsPreDaemon(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("b", 64)
	f.addContainer(t, id, 5150, "172.17.0.3", false)
	// In the list before any event flows = running before the tracker:
	// mirrors seedExisting's pre-daemon semantics.
	f.daemon.setList(containerSummary{ID: id})
	f.start(t)

	ev := f.waitAttribution(t, "reconcile", id)
	assert.Equal(t, events.StepOrdinalPreDaemon, ev.StepOrdinal)
	assert.Zero(t, ev.TagLatencyMS, "reconcile has no docker-event timestamp to measure from")
	assert.Equal(t, []tagCall{{pid: 5150, ordinal: events.StepOrdinalPreDaemon}}, f.tagger.tagCalls())
}

func TestExecStartRetagsEffectiveOrdinal(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("e", 64)
	f.addContainer(t, id, 4242, "172.17.0.4", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	execID := strings.Repeat("f", 64)
	writeProcEntry(t, f.procRoot, 4343, cgroupV2Line(id)+"\n", "sh")
	f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4343, ContainerID: id})
	// The exec belongs to the step active at exec time, never the
	// container's birth step.
	f.tagger.setOrdinal(9)
	f.daemon.push(execStartEvent(id, execID, time.Now().UnixNano()))

	ev := f.waitAttribution(t, "exec", id)
	assert.Equal(t, uint32(9), ev.StepOrdinal)
	assert.Equal(t, uint32(4343), ev.PID)
	assert.Contains(t, f.tagger.tagCalls(), tagCall{pid: 4343, ordinal: 9})

	// DNS attribution follows the newest exec: effectiveOrdinal moved on.
	ord, _, ok := f.tracker.LookupClient(&net.UDPAddr{IP: net.ParseIP("172.17.0.4"), Port: 1})
	require.True(t, ok)
	assert.Equal(t, uint32(9), ord)
}

// Pins the fix for the CI failure on PR #109: dockerd emits exec_start
// BEFORE it records the exec pid from containerd, so the first inspect(s)
// read Pid 0 for a live exec. The tracker must retry through that window
// instead of dropping attribution.
func TestExecStartRetriesUntilDockerdPublishesPid(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("9", 64)
	f.addContainer(t, id, 4242, "172.17.0.30", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	execID := strings.Repeat("d", 64)
	writeProcEntry(t, f.procRoot, 4646, cgroupV2Line(id)+"\n", "sh")
	f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4646, ContainerID: id})
	f.daemon.setExecPidDelay(execID, 2)
	f.tagger.setOrdinal(9)
	f.daemon.push(execStartEvent(id, execID, time.Now().UnixNano()))

	ev := f.waitAttribution(t, "exec", id)
	assert.Equal(t, uint32(9), ev.StepOrdinal)
	assert.Equal(t, uint32(4646), ev.PID)
	// Two Pid-0 inspects at 50ms apart put the measured latency at or above
	// the retry interval — the honest cost of the publish race.
	assert.GreaterOrEqual(t, ev.TagLatencyMS, 50.0)
	assert.Contains(t, f.tagger.tagCalls(), tagCall{pid: 4646, ordinal: 9})
}

func TestExecStartWithoutExecIDFallsBackToDiff(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("1", 64)
	f.addContainer(t, id, 4242, "172.17.0.5", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	// Daemons that omit Actor.Attributes["execID"] force the fallback:
	// diff the container's live ExecIDs against what was already handled.
	execID := strings.Repeat("2", 64)
	writeProcEntry(t, f.procRoot, 4444, cgroupV2Line(id)+"\n", "sh")
	f.daemon.setExec(execID, execInspect{ID: execID, Running: true, Pid: 4444, ContainerID: id})
	f.daemon.updateContainer(id, func(c *containerInspect) { c.ExecIDs = []string{execID} })
	f.tagger.setOrdinal(11)
	f.daemon.push(execStartEvent(id, "", time.Now().UnixNano()))

	ev := f.waitAttribution(t, "exec", id)
	assert.Equal(t, uint32(4444), ev.PID)
	assert.Contains(t, f.tagger.tagCalls(), tagCall{pid: 4444, ordinal: 11})
}

func TestDieRemovesIPIndex(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("3", 64)
	f.addContainer(t, id, 4242, "172.17.0.6", false)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)

	addr := &net.TCPAddr{IP: net.ParseIP("172.17.0.6"), Port: 1}
	_, _, ok := f.tracker.LookupClient(addr)
	require.True(t, ok)

	f.daemon.push(dieEvent(id, time.Now().UnixNano()))
	require.Eventually(t, func() bool {
		_, _, ok := f.tracker.LookupClient(addr)
		return !ok
	}, waitFor, tick, "dead container must leave the IP index")
}

func TestIdentityMismatchSkipsTagging(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("4", 64)
	otherID := strings.Repeat("5", 64)
	// The daemon reports pid 4242, but /proc shows that pid in another
	// container's cgroup — the recycled-PID shape the identity check
	// exists to catch.
	writeProcEntry(t, f.procRoot, 4242, cgroupV2Line(otherID)+"\n", "app")
	mkScopeDir(t, f.cgroupRoot, id)
	f.daemon.setContainer(makeInspect(id, 4242, "172.17.0.7", false))
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))

	// The attribution event still lands (the audit stream stays complete)
	// but no tag may reach the unrelated process, and the marker reports
	// the TAGGING outcome — ordinal 0, so "identity-rejected, would have
	// been step 7" can never read as "tagged with step 7".
	ev := f.waitAttribution(t, "start", id)
	assert.Zero(t, ev.StepOrdinal)
	assert.Empty(t, f.tagger.tagCalls())

	// DNS attribution is orthogonal: the container's address (from inspect)
	// still resolves to the event-time ordinal — the identity check guards
	// PID tagging, not IP identity.
	ord, _, ok := f.tracker.LookupClient(&net.TCPAddr{IP: net.ParseIP("172.17.0.7"), Port: 1})
	require.True(t, ok)
	assert.Equal(t, uint32(7), ord)
}

func TestOrdinalZeroSkipsTagging(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("6", 64)
	f.addContainer(t, id, 4242, "172.17.0.8", false)
	// Default ordinal 0 = started before any step boundary: stays untagged
	// so its traffic classifies to the container-unattributed tier.
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))

	ev := f.waitAttribution(t, "start", id)
	assert.Zero(t, ev.StepOrdinal)
	assert.Empty(t, f.tagger.tagCalls())
}

func TestPrivilegedContainerFlagged(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("7", 64)
	f.addContainer(t, id, 4242, "172.17.0.9", true)
	f.tagger.setOrdinal(7)
	f.start(t)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))

	assert.True(t, f.waitAttribution(t, "start", id).Privileged)
}

func TestLookupClientNonIPAddr(t *testing.T) {
	tr := &Tracker{byIP: make(map[netip.Addr]*containerInfo)}
	_, _, ok := tr.LookupClient(&net.UnixAddr{Name: "x", Net: "unix"})
	assert.False(t, ok)
}

// --- Enrich (white-box: no daemon, fake origin store) ---

type lookupCall struct {
	v6      bool
	dstPort uint16
	proto   uint8
	srcPort uint16
}

// fakeOrigin implements originLookup with canned records; it captures call
// arguments so tests can assert the protocol-block port rewrite.
type fakeOrigin struct {
	recs  []origin.Record
	calls []lookupCall
}

func (f *fakeOrigin) LookupV4(_ uint32, dstPort uint16, proto uint8, srcPort uint16) []origin.Record {
	f.calls = append(f.calls, lookupCall{dstPort: dstPort, proto: proto, srcPort: srcPort})
	// Enrich filters the returned slice in place; hand out a copy like the
	// real store does.
	return slices.Clone(f.recs)
}

func (f *fakeOrigin) LookupV6(_ [16]byte, dstPort uint16, proto uint8, srcPort uint16) []origin.Record {
	f.calls = append(f.calls, lookupCall{v6: true, dstPort: dstPort, proto: proto, srcPort: srcPort})
	return slices.Clone(f.recs)
}

func (f *fakeOrigin) Records() uint64 { return uint64(len(f.recs)) }

// enrichTracker builds a Tracker with only the fields Enrich touches —
// enrichment must stay testable without a daemon or kernel maps.
func enrichTracker(procRoot string, obs originLookup) *Tracker {
	return &Tracker{
		observer: obs,
		opts:     Options{ProcRoot: procRoot},
		byIP:     make(map[netip.Addr]*containerInfo),
		byCgroup: make(map[uint64]*containerInfo),
	}
}

// blockedV4Event is the plain TCP-block shape: SrcPort nonzero keeps it out
// of the protocol-block branch.
func blockedV4Event(ts uint64) *events.BpfBlockedEvent {
	return &events.BpfBlockedEvent{
		IpVersion: 4,
		IpProto:   6,
		SrcIp:     0x0A000001,
		DstIp:     0x8C527203,
		SrcPort:   40000,
		DstPort:   443,
		Timestamp: ts,
	}
}

func TestEnrichNilObserverNoOp(t *testing.T) {
	// A Tracker without an observer (origin.Start failed) must leave the
	// event untouched; the typed-nil case is guarded at Start.
	tr := &Tracker{}
	audit := events.AuditEvent{}
	tr.Enrich(&audit, blockedV4Event(200))
	assert.Equal(t, events.AuditEvent{}, audit)
}

func TestEnrichClassification(t *testing.T) {
	fullID := strings.Repeat("a", 64)
	otherFullID := strings.Repeat("b", 64)
	info := &containerInfo{id: fullID}
	other := &containerInfo{id: otherFullID}
	containerIP := netip.MustParseAddr("172.17.0.2")

	tests := []struct {
		name        string
		recs        []origin.Record
		byCgroup    map[uint64]*containerInfo
		byIP        map[netip.Addr]*containerInfo
		wantOrdinal uint32
		wantOrigin  bool
		wantID      string
		wantPID     uint32
		wantProcess string
	}{
		{
			name:        "tagged record classified via cgroup id",
			recs:        []origin.Record{{CgroupID: 42, StepOrdinal: 7, PID: 4242, Timestamp: 100}},
			byCgroup:    map[uint64]*containerInfo{42: info},
			wantOrdinal: 7, wantOrigin: true, wantID: fullID[:12],
			wantPID: 4242, wantProcess: "curl",
		},
		{
			// Start→tag window: the socket carried no ordinal, so only the
			// container tier may be claimed — never a step.
			name:       "untagged record classified via source IP",
			recs:       []origin.Record{{SrcIP: containerIP, Timestamp: 100}},
			byIP:       map[netip.Addr]*containerInfo{containerIP: info},
			wantOrigin: true, wantID: fullID[:12],
		},
		{
			name: "agreeing duplicates enrich fully",
			recs: []origin.Record{
				{Cookie: 1, CgroupID: 42, StepOrdinal: 7, PID: 4242, Timestamp: 100},
				{Cookie: 2, CgroupID: 42, StepOrdinal: 7, PID: 4242, Timestamp: 90},
			},
			byCgroup:    map[uint64]*containerInfo{42: info},
			wantOrdinal: 7, wantOrigin: true, wantID: fullID[:12],
			wantPID: 4242, wantProcess: "curl",
		},
		{
			// Disagreeing candidates: a step claim would be a guess, but
			// every candidate being a container still supports the (stricter)
			// container tier.
			name: "disagreeing all-container candidates claim container only",
			recs: []origin.Record{
				{CgroupID: 42, StepOrdinal: 7, Timestamp: 100},
				{CgroupID: 43, StepOrdinal: 8, Timestamp: 90},
			},
			byCgroup:   map[uint64]*containerInfo{42: info, 43: other},
			wantOrigin: true,
		},
		{
			name: "disagreeing candidates with one unclassified claim nothing",
			recs: []origin.Record{
				{CgroupID: 42, StepOrdinal: 7, Timestamp: 100},
				{CgroupID: 99, StepOrdinal: 8, Timestamp: 90},
			},
			byCgroup: map[uint64]*containerInfo{42: info},
		},
		{
			// The cgroup hook runs before TC on the same packet: a record
			// newer than the event cannot explain it.
			name:     "record postdating the event is filtered",
			recs:     []origin.Record{{CgroupID: 42, StepOrdinal: 7, Timestamp: 300}},
			byCgroup: map[uint64]*containerInfo{42: info},
		},
		{
			name: "postdated candidate dropped, remaining one wins",
			recs: []origin.Record{
				{CgroupID: 43, StepOrdinal: 9, Timestamp: 300},
				{CgroupID: 42, StepOrdinal: 7, Timestamp: 100},
			},
			byCgroup:    map[uint64]*containerInfo{42: info, 43: other},
			wantOrdinal: 7, wantOrigin: true, wantID: fullID[:12],
		},
		{
			// map_sock_pid-eviction shape: the origin record still knows the
			// socket, but a host flow must not claim the container tier.
			name:        "host record copies identity without container origin",
			recs:        []origin.Record{{StepOrdinal: 5, PID: 4242, Timestamp: 100}},
			wantOrdinal: 5, wantPID: 4242, wantProcess: "curl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procRoot := t.TempDir()
			writeProcEntry(t, procRoot, 4242, cgroupV2Line(fullID)+"\n", "curl")
			tr := enrichTracker(procRoot, &fakeOrigin{recs: tt.recs})
			if tt.byCgroup != nil {
				tr.byCgroup = tt.byCgroup
			}
			if tt.byIP != nil {
				tr.byIP = tt.byIP
			}

			audit := events.AuditEvent{}
			tr.Enrich(&audit, blockedV4Event(200))
			assert.Equal(t, tt.wantOrdinal, audit.StepOrdinal)
			assert.Equal(t, tt.wantOrigin, audit.ContainerOrigin)
			assert.Equal(t, tt.wantID, audit.ContainerID)
			assert.Equal(t, tt.wantPID, audit.PID)
			assert.Equal(t, tt.wantProcess, audit.Process)
		})
	}
}

func TestEnrichLookupKeying(t *testing.T) {
	fo := &fakeOrigin{}
	tr := enrichTracker(t.TempDir(), fo)

	tr.Enrich(&events.AuditEvent{}, blockedV4Event(200))
	require.Len(t, fo.calls, 1)
	assert.Equal(t, lookupCall{dstPort: 443, proto: 6, srcPort: 40000}, fo.calls[0])

	// Protocol-block events carry the protocol number in dst_port; origin
	// records for non-TCP/UDP flows carry ports 0, so the lookup must be
	// keyed with zeros or it could never match.
	ev := &events.BpfBlockedEvent{IpVersion: 4, IpProto: 47, DstIp: 1, DstPort: 47, Timestamp: 200}
	require.True(t, ev.IsProtocolBlock())
	tr.Enrich(&events.AuditEvent{}, ev)
	require.Len(t, fo.calls, 2)
	assert.Equal(t, lookupCall{dstPort: 0, proto: 47, srcPort: 0}, fo.calls[1])

	// v6 events must key the v6 store, not truncate into v4 space.
	ev6 := &events.BpfBlockedEvent{IpVersion: 6, IpProto: 6, SrcPort: 40000, DstPort: 443, Timestamp: 200}
	tr.Enrich(&events.AuditEvent{}, ev6)
	require.Len(t, fo.calls, 3)
	assert.True(t, fo.calls[2].v6)
}
