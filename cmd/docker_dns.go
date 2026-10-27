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

package cmd

import (
	"log/slog"

	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// dockerSocket is where both the environment probe and container tracking
// find the daemon.
const dockerSocket = "/var/run/docker.sock"

// dockerDNS owns --docker-dns-interception: the proxy's listener on the
// docker bridge, and pointing the daemon's containers at it. The bridge
// listener and the PREROUTING redirect (network.SetupDNSRedirect) work for
// any daemon whose bridge is in our netns. Rewriting daemon.json and
// restarting the daemon only work for one that runs here: a dind sidecar
// reads its own daemon.json and no service manager of ours manages it, so
// for a foreign daemon both are skipped and the redirect alone catches its
// containers' DNS.
type dockerDNS struct {
	bridgeIP string // "" when there is no docker bridge: the feature is idle
	restart  bool   // the daemon is ours and daemon.json was rewritten: restart applies it
	logger   *slog.Logger
}

// startDockerDNS adds the bridge listener and, only for a daemon proven
// local, rewrites daemon.json: a foreign or unidentified one is left alone,
// and the redirect covers its containers. The returned undo restores
// daemon.json; the caller defers it. It is registered before the rewrite,
// so a signal landing mid-write still has one, and restoring a file that
// was never written is safe.
func startDockerDNS(dnsServer *dns.Server, dockerd podenv.Dockerd, teardowns *teardownList,
	logger *slog.Logger,
) (*dockerDNS, func()) {
	d := &dockerDNS{logger: logger}
	bridgeIP, err := network.GetDockerBridgeIP()
	if err != nil {
		logger.Debug("Docker bridge not found, container DNS filtering unavailable", "error", err)
		return d, func() {}
	}
	d.bridgeIP = bridgeIP
	// Marked container-serving so queries arriving there attribute via the
	// container-IP lookup, never the host-netns sockdiag path.
	dnsServer.AddContainerListenAddr(bridgeIP + ":53")
	logger.Info("Docker DNS interception enabled", "docker_bridge", bridgeIP)

	if dockerd.Kind != podenv.DockerdLocal {
		logger.Info("Docker daemon not proven local; leaving its config alone, container DNS is redirected at the bridge",
			"dockerd", dockerd.Kind.String(), "reason", dockerd.Reason)
		return d, func() {}
	}
	undo := teardowns.add(func() {
		if err := network.RestoreDockerDNS(logger); err != nil {
			logger.Warn("Failed to restore Docker DNS", "error", err)
		}
	})
	if err := network.ConfigureDockerDNS(bridgeIP, logger); err != nil {
		logger.Warn("Failed to configure Docker DNS", "error", err)
		return d, undo
	}
	d.restart = true
	return d, undo
}

// restartDaemon applies the daemon.json rewrite: Docker's SIGHUP handler
// does not reload DNS settings, so only a full restart does. Nil-safe.
func (d *dockerDNS) restartDaemon() {
	if d == nil || !d.restart {
		return
	}
	if err := network.RestartDockerDaemon(d.logger); err != nil {
		d.logger.Warn("Failed to restart Docker daemon for DNS config", "error", err)
	}
}
