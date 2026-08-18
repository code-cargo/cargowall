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

// Tests for the network-event side of the tracker: `network
// connect`/`disconnect` address refresh. The docker-event fixture lives in
// tracker_test.go.

package containers

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// networkChangeEvent is a docker `network connect`/`disconnect` event: the
// actor is the NETWORK, the container rides in the attributes.
func networkChangeEvent(action, networkName, containerID string) dockerEvent {
	ev := dockerEvent{Type: "network", Action: action}
	ev.Actor.ID = "netid-" + networkName
	ev.Actor.Attributes = map[string]string{"name": networkName, "container": containerID}
	return ev
}

// inspectNetworks is the anonymous struct type containerInspect uses for
// per-network settings, aliased for readable test literals.
type inspectNetworks = map[string]struct {
	IPAddress           string `json:"IPAddress"`
	IPPrefixLen         int    `json:"IPPrefixLen"`
	GlobalIPv6Address   string `json:"GlobalIPv6Address"`
	GlobalIPv6PrefixLen int    `json:"GlobalIPv6PrefixLen"`
}

func lookupIP(tr *Tracker, ip string) (string, bool) {
	_, id, ok := tr.LookupClient(&net.UDPAddr{IP: net.ParseIP(ip), Port: 5353})
	return id, ok
}

// docker network connect on a running container: the gained address must
// start attributing to it — without the refresh, DNS queries from that
// address would stay unattributed for the container's lifetime.
func TestNetworkConnectIndexesGainedAddress(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("a", 64)
	f.addContainer(t, id, 4242, "172.17.0.2", false)
	f.tagger.setOrdinal(7)
	f.start(t)

	f.daemon.push(startEvent(id, 1_000))
	f.waitAttribution(t, "start", id)
	_, ok := lookupIP(f.tracker, "172.18.0.3")
	require.False(t, ok, "address not held yet")

	f.daemon.updateContainer(id, func(insp *containerInspect) {
		insp.NetworkSettings.Networks = inspectNetworks{
			"mynet": {IPAddress: "172.18.0.3", IPPrefixLen: 24},
		}
	})
	f.daemon.push(networkChangeEvent("connect", "mynet", id))

	require.Eventually(t, func() bool {
		got, ok := lookupIP(f.tracker, "172.18.0.3")
		return ok && got == shortID(id)
	}, waitFor, tick, "gained address must attribute to the container")
	got, ok := lookupIP(f.tracker, "172.17.0.2")
	require.True(t, ok, "original address survives the refresh")
	require.Equal(t, shortID(id), got)
}

// docker network disconnect: the released address must leave the index
// BEFORE docker IPAM can hand it to another container — a stale mapping
// stamps the next holder's traffic with the wrong identity.
func TestNetworkDisconnectReleasesAddress(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("b", 64)
	f.addContainer(t, id, 4242, "172.17.0.2", false)
	f.daemon.updateContainer(id, func(insp *containerInspect) {
		insp.NetworkSettings.Networks = inspectNetworks{
			"mynet": {IPAddress: "172.18.0.3", IPPrefixLen: 24},
		}
	})
	f.tagger.setOrdinal(7)
	f.start(t)

	f.daemon.push(startEvent(id, 1_000))
	f.waitAttribution(t, "start", id)
	_, ok := lookupIP(f.tracker, "172.18.0.3")
	require.True(t, ok, "address indexed at start")

	f.daemon.updateContainer(id, func(insp *containerInspect) {
		insp.NetworkSettings.Networks = nil
	})
	f.daemon.push(networkChangeEvent("disconnect", "mynet", id))

	require.Eventually(t, func() bool {
		_, ok := lookupIP(f.tracker, "172.18.0.3")
		return !ok
	}, waitFor, tick, "released address must not stay mapped to its old holder")
	got, ok := lookupIP(f.tracker, "172.17.0.2")
	require.True(t, ok, "the addresses still held stay indexed")
	require.Equal(t, shortID(id), got)
}

// An empty inspect after a CONNECT is a racy teardown artifact, not truth:
// a connect cannot leave the container with fewer addresses, so the
// refresh must keep the existing index rather than adopt the empty set.
func TestNetworkConnectIgnoresEmptyInspect(t *testing.T) {
	f := newFixture(t)
	id := strings.Repeat("c", 64)
	f.addContainer(t, id, 4242, "172.17.0.2", false)
	f.tagger.setOrdinal(7)
	f.start(t)

	f.daemon.push(startEvent(id, 1_000))
	f.waitAttribution(t, "start", id)

	f.daemon.updateContainer(id, func(insp *containerInspect) {
		insp.NetworkSettings.IPAddress = ""
		insp.NetworkSettings.Networks = nil
	})
	f.daemon.push(networkChangeEvent("connect", "mynet", id))

	// The handler runs async within milliseconds in this harness (see the
	// Eventually in the connect test); Never here proves the guard rather
	// than a race won.
	require.Never(t, func() bool {
		_, ok := lookupIP(f.tracker, "172.17.0.2")
		return !ok
	}, 500*time.Millisecond, tick, "an empty connect-inspect must not drop held addresses")
}
