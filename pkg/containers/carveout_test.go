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

// Tests for the caller side of the bridge-subnet carve-out: which subnets
// reach AllowLocalSubnet (bridge-driver only), and which outcomes are
// remembered. pkg/origin owns the policy for a prefix that does arrive; a
// mistake here instead exempts a non-bridge network from the cgroup hook,
// or retries a refusal forever. The docker-event fixture lives in
// tracker_test.go.

package containers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/origin"
)

// carveRecorder is an AllowLocalSubnet that records every prefix it is
// handed and answers with the error queued for it, if any.
type carveRecorder struct {
	mu    sync.Mutex
	calls []netip.Prefix
	errs  map[netip.Prefix]error
}

func (r *carveRecorder) allow(p netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, p)
	return r.errs[p]
}

func (r *carveRecorder) failNext(p netip.Prefix, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errs == nil {
		r.errs = make(map[netip.Prefix]error)
	}
	r.errs[p] = err
}

func (r *carveRecorder) carved() []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]netip.Prefix(nil), r.calls...)
}

// newCarveTracker builds a Tracker with only what the carve-out touches.
// Start would also run reconcile, which clears the driver cache
// concurrently and would make the cache assertions racy.
func newCarveTracker(d *fakeDaemon, r *carveRecorder) *Tracker {
	return &Tracker{
		client:      newDockerClient(d.sock),
		logger:      slog.New(slog.DiscardHandler),
		opts:        Options{AllowLocalSubnet: r.allow},
		seenSubnets: make(map[string]bool),
		netDrivers:  make(map[string]bool),
	}
}

func networkCreateEvent(name string) dockerEvent {
	ev := dockerEvent{Type: "network", Action: "create"}
	ev.Actor.ID = "netid-" + name
	ev.Actor.Attributes = map[string]string{"name": name}
	return ev
}

func TestCarvePrefix_BridgeSubnetCarvedOnce(t *testing.T) {
	d := newFakeDaemon(t)
	d.setNetwork("appnet", "bridge", "172.18.0.0/16")
	r := &carveRecorder{}
	tr := newCarveTracker(d, r)
	ctx := context.Background()

	// An unmasked prefix, as a container's address/len produces.
	tr.carvePrefix(ctx, "appnet", netip.MustParsePrefix("172.18.0.5/16"))
	tr.carvePrefix(ctx, "appnet", netip.MustParsePrefix("172.18.0.9/16"))

	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16")}, r.carved())
	require.Equal(t, 1, d.networkInspectCount(), "the driver is resolved once")
}

// "" is the legacy top-level inspect fields: it must be resolved to the
// literal "bridge" network and its driver verified, not assumed.
func TestCarvePrefix_DefaultNetworkDriverIsVerified(t *testing.T) {
	d := newFakeDaemon(t)
	d.setNetwork("bridge", "macvlan", "192.168.1.0/24")
	r := &carveRecorder{}
	tr := newCarveTracker(d, r)

	tr.carvePrefix(context.Background(), "", netip.MustParsePrefix("192.168.1.0/24"))
	require.Empty(t, r.carved(), "a non-bridge default network stays adjudicated")
	require.Equal(t, 1, d.networkInspectCount())
}

func TestCarvePrefix_NonBridgeNetworkNeverCarved(t *testing.T) {
	for _, driver := range []string{"macvlan", "ipvlan", "overlay", "host"} {
		t.Run(driver, func(t *testing.T) {
			d := newFakeDaemon(t)
			d.setNetwork("lan", driver, "192.168.1.0/24")
			r := &carveRecorder{}
			tr := newCarveTracker(d, r)
			ctx := context.Background()

			tr.carvePrefix(ctx, "lan", netip.MustParsePrefix("192.168.1.0/24"))
			tr.carvePrefix(ctx, "lan", netip.MustParsePrefix("192.168.1.0/24"))
			require.Empty(t, r.carved())
			require.Equal(t, 1, d.networkInspectCount(), "the non-bridge verdict is cached")

			// The verdict belongs to the network, not the prefix: the same
			// subnet later seen on a bridge network is evaluated afresh.
			d.setNetwork("br", "bridge", "192.168.1.0/24")
			tr.carvePrefix(ctx, "br", netip.MustParsePrefix("192.168.1.0/24"))
			require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, r.carved())
		})
	}
}

// An inspect failure is transient: nothing is carved and nothing cached,
// so the next container on that network tries again.
func TestCarvePrefix_InspectFailureRetries(t *testing.T) {
	d := newFakeDaemon(t)
	r := &carveRecorder{}
	tr := newCarveTracker(d, r)
	ctx := context.Background()
	prefix := netip.MustParsePrefix("172.18.0.0/16")

	tr.carvePrefix(ctx, "appnet", prefix) // 404: the network is not there yet
	require.Empty(t, r.carved())

	d.setNetwork("appnet", "bridge", "172.18.0.0/16")
	tr.carvePrefix(ctx, "appnet", prefix)
	require.Equal(t, []netip.Prefix{prefix}, r.carved())
	require.Equal(t, 2, d.networkInspectCount())
}

// A policy refusal is a decision and is remembered; any other failure is
// transient and retried.
func TestCarvePrefix_RefusalRememberedFailureRetried(t *testing.T) {
	d := newFakeDaemon(t)
	d.setNetwork("refused", "bridge", "10.8.0.0/16")
	d.setNetwork("flaky", "bridge", "172.19.0.0/16")
	r := &carveRecorder{}
	refused := netip.MustParsePrefix("10.8.0.0/16")
	flaky := netip.MustParsePrefix("172.19.0.0/16")
	r.failNext(refused, fmt.Errorf("%w: contains host interface address", origin.ErrLocalNetworkRefused))
	r.failNext(flaky, errors.New("interface enumeration: transient"))
	tr := newCarveTracker(d, r)
	ctx := context.Background()

	tr.carvePrefix(ctx, "refused", refused)
	tr.carvePrefix(ctx, "refused", refused)
	tr.carvePrefix(ctx, "flaky", flaky)
	tr.carvePrefix(ctx, "flaky", flaky)

	require.Equal(t, []netip.Prefix{refused, flaky, flaky}, r.carved(),
		"the refusal is asked once; the transient failure is asked again")
}

func TestHandleNetworkCreate(t *testing.T) {
	t.Run("bridge carves every subnet and primes the cache", func(t *testing.T) {
		d := newFakeDaemon(t)
		d.setNetwork("appnet", "bridge", "172.18.0.0/16", "fd00:18::/64", "not-a-prefix")
		r := &carveRecorder{}
		tr := newCarveTracker(d, r)
		ctx := context.Background()

		tr.handleNetworkCreate(ctx, networkCreateEvent("appnet"))
		require.Equal(t, []netip.Prefix{
			netip.MustParsePrefix("172.18.0.0/16"),
			netip.MustParsePrefix("fd00:18::/64"),
		}, r.carved())

		// A container's own discovery of a new subnet on the same network
		// reuses the cached driver.
		tr.carvePrefix(ctx, "appnet", netip.MustParsePrefix("172.20.0.0/16"))
		require.Equal(t, 1, d.networkInspectCount())
	})
	t.Run("non-bridge carves nothing", func(t *testing.T) {
		d := newFakeDaemon(t)
		d.setNetwork("lan", "macvlan", "192.168.1.0/24")
		r := &carveRecorder{}
		tr := newCarveTracker(d, r)

		tr.handleNetworkCreate(context.Background(), networkCreateEvent("lan"))
		require.Empty(t, r.carved())
	})
	t.Run("inspect failure carves nothing", func(t *testing.T) {
		d := newFakeDaemon(t)
		r := &carveRecorder{}
		tr := newCarveTracker(d, r)

		tr.handleNetworkCreate(context.Background(), networkCreateEvent("gone"))
		require.Empty(t, r.carved())
	})
}

// Through the real event stream: a create carves, and a destroy evicts the
// driver cache, so a same-name network recreated with another driver —
// whose create cargowall never saw — is resolved afresh when a container
// turns up on it, never read as the dead network's "bridge".
func TestNetworkEventsCarveAndEvict(t *testing.T) {
	f := newFixture(t)
	r := &carveRecorder{}
	f.allowLocal = r.allow
	f.daemon.setNetwork("appnet", "bridge", "172.18.0.0/16")
	f.tagger.setOrdinal(7)
	f.start(t)

	f.daemon.push(networkCreateEvent("appnet"))
	require.Eventually(t, func() bool { return len(r.carved()) == 1 }, waitFor, tick)

	destroy := dockerEvent{Type: "network", Action: "destroy"}
	destroy.Actor.ID = "netid-appnet"
	destroy.Actor.Attributes = map[string]string{"name": "appnet"}
	f.daemon.push(destroy)
	f.daemon.setNetwork("appnet", "macvlan", "192.168.50.0/24")

	id := strings.Repeat("d", 64)
	f.addContainer(t, id, 4242, "", false)
	f.daemon.updateContainer(id, func(insp *containerInspect) {
		insp.NetworkSettings.Networks = inspectNetworks{
			"appnet": {IPAddress: "192.168.50.7", IPPrefixLen: 24},
		}
	})
	f.daemon.push(startEvent(id, 1_000))
	// handleStart carves before it tags and logs, so once the attribution
	// is visible the carve decision for this container has been made.
	f.waitAttribution(t, "start", id)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16")}, r.carved(),
		"the recreated macvlan network's subnet must stay adjudicated")
}

func TestDiscoverBridgeSubnets(t *testing.T) {
	d := newFakeDaemon(t)
	d.setNetwork("bridge", "bridge", "172.17.0.0/16")
	d.setNetwork("appnet", "bridge", "172.18.0.5/16", "fd00:18::/64")
	d.setNetwork("dup", "bridge", "172.18.0.0/16")
	d.setNetwork("lan", "macvlan", "192.168.1.0/24")
	d.setNetwork("bad", "bridge", "not-a-prefix")
	d.setNetwork("host", "host")

	got, err := DiscoverBridgeSubnets(context.Background(), d.sock)
	require.NoError(t, err)
	require.ElementsMatch(t, []netip.Prefix{
		netip.MustParsePrefix("172.17.0.0/16"),
		netip.MustParsePrefix("172.18.0.0/16"),
		netip.MustParsePrefix("fd00:18::/64"),
	}, got, "bridge-driver subnets only, masked and deduplicated")
}

func TestDiscoverBridgeSubnets_DaemonUnreachable(t *testing.T) {
	_, err := DiscoverBridgeSubnets(context.Background(), filepath.Join(t.TempDir(), "none.sock"))
	require.ErrorContains(t, err, "docker daemon unreachable")
}
