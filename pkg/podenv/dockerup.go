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

	"github.com/code-cargo/cargowall/pkg/network"
)

// interfaces lists the network interfaces: net.Interfaces, or a test's
// stand-in for them.
var interfaces = net.Interfaces

// probeUp reads whether the daemon is up: the bridges it has made in our
// network namespace (Bridges), and, only where there are some to show for
// it and a socket, whether it answers. One that has already answered, its
// GET /info or the request servingPid made, is not asked again; any other
// is asked GET /_ping once, within 2s. A host with a socket and no bridge
// is not asked at all: no container can have run there yet, so nothing
// waits on the answer, and a socket that accepts but does not answer would
// cost the whole timeout.
func (d *Dockerd) probeUp(socket string) {
	if ifaces, err := interfaces(); err != nil {
		d.note("its bridges", err)
	} else {
		for _, ifi := range ifaces {
			if network.DockerBridge(ifi.Name) {
				d.Bridges = append(d.Bridges, ifi.Name)
			}
		}
	}
	if d.Kind == DockerdAbsent || len(d.Bridges) == 0 {
		return
	}
	if d.pid != 0 || (d.info != nil && d.infoErr == nil) {
		d.Answers = true
		return
	}
	if err := dockerGet(socket, "/_ping", nil); err != nil {
		d.note("its answer", err)
		return
	}
	d.Answers = true
}

// None reports that there is no Docker here: no socket, and no bridge.
func (d Dockerd) None() bool { return d.Kind == DockerdAbsent && len(d.Bridges) == 0 }

// Pending reports that Docker is still to come up: there is a socket, but
// no bridge yet, or a daemon that did not answer. Its containers, its
// bridges' subnets and its daemon's config are then the daemon's to show
// once it answers, not cargowall's to wait for at startup.
func (d Dockerd) Pending() bool { return d.Kind != DockerdAbsent && !d.Answers }

// Unreachable reports Docker's bridges with no socket to ask about them:
// a daemon cargowall cannot talk to, such as another container's whose
// socket is not shared, with containers already on them possibly.
func (d Dockerd) Unreachable() bool { return d.Kind == DockerdAbsent && len(d.Bridges) > 0 }
