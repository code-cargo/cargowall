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
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBridgeDevice(t *testing.T) {
	id := "0123456789abcdef0123"
	for _, tc := range []struct {
		name string
		nw   networkInspect
		want string
	}{
		{"named", networkInspect{ID: id, Options: map[string]string{bridgeNameOption: "mybr0"}}, "mybr0"},
		{"default unnamed", networkInspect{ID: id, Options: map[string]string{defaultBridgeOption: "true"}}, "docker0"},
		{"user-defined", networkInspect{ID: id}, "br-0123456789ab"},
		{"no id", networkInspect{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, bridgeDevice(tc.nw))
		})
	}
}

// bridgeRecorder records what OnBridge and OnBridgeGone are called with,
// in order.
type bridgeRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *bridgeRecorder) up(dev string) { r.record("up " + dev) }

func (r *bridgeRecorder) gone(dev string) { r.record("gone " + dev) }

func (r *bridgeRecorder) record(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *bridgeRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// awaitCalls waits for the recorder to have seen want after the first n
// calls, and returns how many it has seen then.
func (r *bridgeRecorder) awaitCalls(t *testing.T, n int, want ...string) int {
	t.Helper()
	require.Eventually(t, func() bool {
		got := r.got()
		return len(got) >= n+len(want) && slices.Equal(got[n:n+len(want)], want)
	}, waitFor, tick, "want %q after call %d, got %q", want, n, r.got())
	return n + len(want)
}

// startBridgeTracker starts a tracker on d with only the bridge callbacks
// set (nil for neither).
func startBridgeTracker(t *testing.T, d *fakeDaemon, r *bridgeRecorder) {
	t.Helper()
	opts := Options{Socket: d.sock, ProcRoot: t.TempDir(), CgroupRoot: t.TempDir()}
	if r != nil {
		opts.OnBridge, opts.OnBridgeGone = r.up, r.gone
	}
	tr, err := Start(context.Background(), opts, &fakeTagger{}, nil, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(tr.Close)
}

func networkDestroyEvent(name string) dockerEvent {
	ev := dockerEvent{Type: "network", Action: "destroy"}
	ev.Actor.ID = "netid-" + name
	ev.Actor.Attributes = map[string]string{"name": name}
	return ev
}

// Every bridge network's device is reported, from the session's list and
// as created, and reported gone when its network is destroyed. Other
// drivers' networks never are.
func TestBridges_ListedCreatedDestroyed(t *testing.T) {
	d := newFakeDaemon(t)
	d.setNetwork("bridge", "bridge", "172.17.0.0/16")
	d.mu.Lock()
	nw := d.networks["bridge"]
	nw.Options = map[string]string{bridgeNameOption: "docker0", defaultBridgeOption: "true"}
	d.networks["bridge"] = nw
	d.mu.Unlock()
	d.setNetwork("lan", "macvlan", "192.168.1.0/24")
	r := &bridgeRecorder{}
	startBridgeTracker(t, d, r)
	n := r.awaitCalls(t, 0, "up docker0")

	d.setNetwork("appnet", "bridge", "172.18.0.0/16")
	d.push(networkCreateEvent("appnet"))
	n = r.awaitCalls(t, n, "up br-netid-appnet")

	d.push(networkCreateEvent("lan"))
	d.push(networkDestroyEvent("lan"))
	d.push(networkDestroyEvent("appnet"))
	n = r.awaitCalls(t, n, "gone br-netid-appnet")
	require.Len(t, r.got(), n, "a macvlan network is no bridge")
}

// A session's list is the whole set of bridges: one destroyed in the gap
// before it is reported gone, unless a listed network now uses its device,
// and every listed one is reported again.
func TestBridges_SessionListReplacesTheSet(t *testing.T) {
	d := newFakeDaemon(t)
	d.setNetwork("appnet", "bridge", "172.18.0.0/16")
	d.setNetwork("named", "bridge", "172.19.0.0/16")
	d.mu.Lock()
	nw := d.networks["named"]
	nw.Options = map[string]string{bridgeNameOption: "ci-br"}
	d.networks["named"] = nw
	d.mu.Unlock()
	r := &bridgeRecorder{}
	startBridgeTracker(t, d, r)
	require.Eventually(t, func() bool { return len(r.got()) == 2 }, waitFor, tick)
	require.ElementsMatch(t, []string{"up br-netid-appnet", "up ci-br"}, r.got())

	// In the gap: appnet goes, and named is recreated under a new id,
	// behind the same device.
	d.mu.Lock()
	delete(d.networks, "appnet")
	nw = d.networks["named"]
	nw.ID = "netid-named-2"
	d.networks["named"] = nw
	d.mu.Unlock()
	d.endStream()
	r.awaitCalls(t, 2, "gone br-netid-appnet", "up ci-br")

	// The recreated network's destroy, under its new id, reports it gone.
	destroy := networkDestroyEvent("named")
	destroy.Actor.ID = "netid-named-2"
	d.push(destroy)
	r.awaitCalls(t, 4, "gone ci-br")
}

// With no bridge callback and no carve-out, networks cost the daemon
// nothing: none is listed or inspected.
func TestBridges_NoneAskedNoneInspected(t *testing.T) {
	d := newFakeDaemon(t)
	d.setNetwork("appnet", "bridge", "172.18.0.0/16")
	startBridgeTracker(t, d, nil)
	d.push(networkCreateEvent("appnet"))
	d.push(networkDestroyEvent("appnet"))
	require.Never(t, func() bool { return d.networkInspectCount() > 0 }, 300*time.Millisecond, tick)
}
