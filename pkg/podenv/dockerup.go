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

package podenv

// Whether the daemon is up yet: on some hosts (Blacksmith's) the Docker
// socket accepts connections seconds before dockerd answers on it, and
// before it has made a bridge.

import (
	"net"
	"time"

	"github.com/code-cargo/cargowall/pkg/network"
)

// interfaces lists the network interfaces: net.Interfaces, or a test's
// stand-in for them.
var interfaces = net.Interfaces

// How long the daemon is given to answer GET /_ping. With bridges to show
// for it, or bridges that could not be listed, 2s, as every other request
// startup makes of it. With none, a daemon may still be up, its default
// bridge renamed (daemon.json's "bridge"), or none made yet (--bridge=none,
// Podman's socket), so it is asked too, but briefly: one that is up answers
// /_ping from memory in milliseconds, even on a busy host, which 300ms
// leaves two orders of magnitude of headroom, while a socket that accepts
// and does not answer, as Blacksmith's does for seconds before its daemon
// starts, costs startup only that. Asking starts nothing that would not
// start anyway: the tracker connects to the socket once it starts.
const (
	pingWithBridges    = 2 * time.Second
	pingWithoutBridges = 300 * time.Millisecond
)

// probeUp reads whether the daemon is up: the bridges it has made in our
// network namespace (Bridges, or BridgesErr when they could not be
// listed), and, where there is a socket, whether it answers GET /_ping in
// time (pingWithBridges, pingWithoutBridges). One that has already
// answered, its GET /info or the request servingPid made, is not asked
// again.
func (d *Dockerd) probeUp(socket string) {
	if ifaces, err := interfaces(); err != nil {
		d.BridgesErr = err
		d.note("its bridges", err)
	} else {
		for _, ifi := range ifaces {
			if network.DockerBridge(ifi.Name) {
				d.Bridges = append(d.Bridges, ifi.Name)
			}
		}
	}
	if d.Kind == DockerdAbsent {
		return
	}
	if d.pid != 0 || (d.info != nil && d.infoErr == nil) {
		d.Answers = true
		return
	}
	within := pingWithBridges
	if d.BridgesErr == nil && len(d.Bridges) == 0 {
		within = pingWithoutBridges
	}
	if err := dockerGetWithin(socket, "/_ping", nil, within); err != nil {
		d.note("its answer", err)
		return
	}
	d.Answers = true
}

// None reports that there is no Docker here: no socket, and no bridge,
// listed. Bridges that could not be listed are not none.
func (d Dockerd) None() bool {
	return d.Kind == DockerdAbsent && d.BridgesErr == nil && len(d.Bridges) == 0
}

// Pending reports that Docker is still to come up: there is a socket, but
// the daemon did not answer in time. Its containers, its bridges' subnets
// and its daemon's config are then the daemon's to show once it answers,
// not cargowall's to wait for at startup.
func (d Dockerd) Pending() bool { return d.Kind != DockerdAbsent && !d.Answers }

// Unreachable reports Docker's bridges, or bridges that could not be
// listed, with no socket to ask about them: a daemon cargowall cannot talk
// to, such as another container's whose socket is not shared, with
// containers already on them possibly.
func (d Dockerd) Unreachable() bool {
	return d.Kind == DockerdAbsent && (len(d.Bridges) > 0 || d.BridgesErr != nil)
}
