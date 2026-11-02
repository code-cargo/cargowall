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
	"net"

	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// dockerSocket is where both the environment probe and container tracking
// find the daemon.
const dockerSocket = "/var/run/docker.sock"

// dockerDNS owns --docker-dns-interception: the proxy's listener on the
// docker bridge, and pointing the daemon's containers at it. The bridge
// listener and the redirect's prerouting chain (network.DNSRedirect) work
// for any daemon whose bridge is in our netns. Rewriting daemon.json and
// restarting the daemon only work for one that runs here: a dind sidecar
// reads its own daemon.json and no service manager of ours manages it, so
// for a foreign daemon both are skipped and the redirect alone catches its
// containers' DNS.
//
// The bridge listener binds over UDP and TCP both or neither, and only once
// it holds is anything sent to it: when it does not, the daemon is not
// restarted onto it (restartDaemon), and the redirect drops container DNS at
// the bridge rather than sending it there (redirectSpec). Either would hand
// the queries to whatever holds the address instead, or to nothing.
type dockerDNS struct {
	bridgeIP string // "" when there is no docker bridge: the feature is idle
	// proxy holds the bridge listener, and once it is ready says whether it
	// bound (dns.Server.BindError).
	proxy interface{ BindError(addr string) error }
	// restart restarts the daemon, which applies the daemon.json rewrite; nil
	// when the daemon is not ours or daemon.json was not rewritten.
	restart func(*slog.Logger) error
	undo    func() // restores daemon.json
	logger  *slog.Logger
}

// startDockerDNS adds the bridge listener and, only for a daemon proven
// local, rewrites daemon.json: a foreign or unidentified one is left alone,
// and the redirect covers its containers. The returned undo restores
// daemon.json; the caller defers it. It is registered before the rewrite,
// so a signal landing mid-write still has one: the second-signal path runs
// it on another goroutine, and pkg/network serializes the two, so it either
// undoes a finished rewrite or stops one from starting. Restoring a file
// that was never written leaves it alone.
func startDockerDNS(dnsServer *dns.Server, dockerd podenv.Dockerd, teardowns *teardownList,
	logger *slog.Logger,
) (*dockerDNS, func()) {
	d := &dockerDNS{proxy: dnsServer, logger: logger}
	bridgeIP, err := network.GetDockerBridgeIP()
	if err != nil {
		logger.Debug("Docker bridge not found, container DNS filtering unavailable", "error", err)
		return d, func() {}
	}
	d.bridgeIP = bridgeIP
	// Marked container-serving so queries arriving there attribute via the
	// container-IP lookup, never the host-netns sockdiag path.
	dnsServer.AddContainerListenAddr(d.listenAddr())
	logger.Info("Docker DNS interception enabled", "docker_bridge", bridgeIP)

	if dockerd.Kind != podenv.DockerdLocal {
		logger.Info("Docker daemon not proven local; leaving its config alone, container DNS is redirected at the bridge",
			"dockerd", dockerd.Kind.String(), "reason", dockerd.Reason)
		return d, func() {}
	}
	d.undo = teardowns.add(func() {
		if err := network.RestoreDockerDNS(logger); err != nil {
			logger.Warn("Failed to restore Docker DNS", "error", err)
		}
	})
	if err := network.ConfigureDockerDNS(bridgeIP, logger); err != nil {
		logger.Warn("Failed to configure Docker DNS", "error", err)
		return d, d.undo
	}
	d.restart = network.RestartDockerDaemon
	return d, d.undo
}

// listenAddr is the proxy's listener on the docker bridge.
func (d *dockerDNS) listenAddr() string { return net.JoinHostPort(d.bridgeIP, "53") }

// bridge is the docker bridge's IP, "" when there is none. Nil-safe: nil is
// the feature off.
func (d *dockerDNS) bridge() string {
	if d == nil {
		return ""
	}
	return d.bridgeIP
}

// listenerErr is why the proxy is not listening on the docker bridge, nil
// when it is or there is no bridge. Valid once the proxy is ready.
// Nil-safe.
func (d *dockerDNS) listenerErr() error {
	if d.bridge() == "" {
		return nil
	}
	return d.proxy.BindError(d.listenAddr())
}

// restartDaemon applies the daemon.json rewrite: Docker's SIGHUP handler
// does not reload DNS settings, so only a full restart does. Without the
// bridge listener it undoes the rewrite instead, and the daemon keeps the
// DNS it has. Nil-safe.
func (d *dockerDNS) restartDaemon() {
	if d == nil || d.restart == nil {
		return
	}
	if err := d.listenerErr(); err != nil {
		d.logger.Warn("Not restarting the Docker daemon onto the bridge listener, which the proxy could not bind; "+
			"daemon.json is restored, and its containers keep the DNS they have", "addr", d.listenAddr(), "error", err)
		d.undo()
		return
	}
	if err := d.restart(d.logger); err != nil {
		d.logger.Warn("Failed to restart Docker daemon for DNS config", "error", err)
	}
}
