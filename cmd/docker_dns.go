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
// The listener binds over UDP and TCP both or neither, and nothing is
// pointed at it until it is known to hold, once the proxy is ready
// (useListener): one that does not is another process's address, or no
// one's, and daemon.json or the bridge DNAT would hand container DNS to it.
type dockerDNS struct {
	bridgeIP string         // "" when there is no docker bridge: the feature is idle
	dockerd  podenv.Dockerd // the daemon behind the socket: whether daemon.json is ours
	// proxy holds the bridge listener, and once it is ready says whether it
	// bound (dns.Server.BindError).
	proxy interface{ BindError(addr string) error }
	// configure rewrites daemon.json to point the daemon's containers at the
	// listener, and restore undoes it: network.ConfigureDockerDNS and
	// RestoreDockerDNS, which a test stands in for.
	configure func(dnsIP string, logger *slog.Logger) error
	restore   func(logger *slog.Logger) error
	restart   bool // daemon.json was rewritten: the daemon restart applies it
	logger    *slog.Logger
}

// startDockerDNS adds the bridge listener, before the proxy starts. Nothing
// is pointed at it yet (useListener).
func startDockerDNS(dnsServer *dns.Server, dockerd podenv.Dockerd, logger *slog.Logger) *dockerDNS {
	d := &dockerDNS{
		dockerd: dockerd, proxy: dnsServer,
		configure: network.ConfigureDockerDNS, restore: network.RestoreDockerDNS, logger: logger,
	}
	bridgeIP, err := network.GetDockerBridgeIP()
	if err != nil {
		logger.Debug("Docker bridge not found, container DNS filtering unavailable", "error", err)
		return d
	}
	d.bridgeIP = bridgeIP
	// Marked container-serving so queries arriving there attribute via the
	// container-IP lookup, never the host-netns sockdiag path.
	dnsServer.AddContainerListenAddr(d.listenAddr())
	return d
}

// useListener puts the bridge listener to use once the proxy is ready, or
// warns that the proxy could not bind it, which with the redirect on is a
// lost dns-redirect posture too (startDNSRedirect). Only for a daemon proven
// local, and only onto a bound listener, is daemon.json rewritten: a foreign
// or unidentified daemon is left alone, and the redirect, when on, covers
// its containers. The returned undo restores daemon.json; the caller defers
// it. It is registered before the rewrite, so a signal landing mid-write
// still has one: the second-signal path runs it on another goroutine, and
// pkg/network serializes the two, so it either undoes a finished rewrite or
// stops one from starting. Nil-safe.
func (d *dockerDNS) useListener(teardowns *teardownList, redirect bool) func() {
	if d.bridge() == "" {
		return func() {}
	}
	local := d.dockerd.Kind == podenv.DockerdLocal
	if err := d.listenerErr(); err != nil {
		d.logger.Warn(unboundListener(local, redirect), "addr", d.listenAddr(), "error", err)
		return func() {}
	}
	d.logger.Info("Docker DNS interception enabled", "docker_bridge", d.bridgeIP)
	if !local {
		msg := "Docker daemon not proven local; leaving its config alone, container DNS is redirected at the bridge"
		if !redirect {
			msg = "Docker daemon not proven local; leaving its config alone, so its containers reach the proxy " +
				"only by naming the bridge listener"
		}
		d.logger.Info(msg, "dockerd", d.dockerd.Kind.String(), "reason", d.dockerd.Reason)
		return func() {}
	}
	undo := teardowns.add(func() {
		if err := d.restore(d.logger); err != nil {
			d.logger.Warn("Failed to restore Docker DNS", "error", err)
		}
	})
	if err := d.configure(d.bridgeIP, d.logger); err != nil {
		d.logger.Warn("Failed to configure Docker DNS", "error", err)
		return undo
	}
	d.restart = true
	return undo
}

// unboundListener is useListener's warning for a bridge listener the proxy
// could not bind: what containers resolve through instead, which turns on
// whether daemon.json was the proxy's to rewrite and whether the redirect is
// on.
func unboundListener(local, redirect bool) string {
	msg := "Docker DNS interception unavailable: the proxy could not listen on the docker bridge"
	if local {
		msg += ", so daemon.json is left alone"
	}
	msg += "; containers resolve as their daemon configures them, around the proxy"
	if redirect {
		msg += ", which the DNS redirect does not cover either (a lost dns-redirect posture)"
	}
	return msg
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

// listeningIP is the docker bridge's IP when the proxy holds its listener
// there, "" otherwise: the address container DNS may be sent to and allowed
// at. Valid once the proxy is ready. Nil-safe.
func (d *dockerDNS) listeningIP() string {
	if d.listenerErr() != nil {
		return ""
	}
	return d.bridge()
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
