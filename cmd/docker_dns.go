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
	"net/netip"

	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// dockerSocket is where both the environment probe and container tracking
// find the daemon.
const dockerSocket = "/var/run/docker.sock"

// dockerDNS owns --docker-dns-interception: the proxy's listeners for
// container DNS, on addresses cargowall adds to lo (network.ContainerDNSIPv4
// and ContainerDNSIPv6), and pointing the daemon's containers at them. The
// listeners and the redirect's prerouting chain (network.DNSRedirect), which
// sends DNS arriving on any docker bridge to them, work for any daemon whose
// bridges are in our netns, and for one whose bridges come up only after
// cargowall: the addresses don't depend on a bridge. Rewriting daemon.json
// and restarting the daemon only work for one that runs here: a dind sidecar
// reads its own daemon.json and no service manager of ours manages it, so
// for a foreign daemon both are skipped and the redirect alone catches its
// containers' DNS.
//
// Each address is added (network.OwnedAddrs) only once the proxy holds its
// primary listener, so a second cargowall in the netns, which never gets
// that far, never touches the first's. One something else already holds is
// not added, and its listener does not bind. Each listener binds over UDP
// and TCP both or neither, and nothing is pointed at one that did not
// (useListener, startDNSRedirect): container DNS would go to whatever holds
// the address instead, or to nothing.
type dockerDNS struct {
	dockerd podenv.Dockerd // the daemon behind the socket: whether daemon.json is ours
	// proxy holds the listeners, and once it is ready says whether each
	// bound (dns.Server.BindError).
	proxy interface{ BindError(addr string) error }
	// configure rewrites daemon.json to point the daemon's containers at the
	// listener, restore undoes it, and recover undoes only one a previous run
	// left: network.ConfigureDockerDNS, RestoreDockerDNS and
	// RecoverDockerDNS, which a test stands in for.
	configure func(dnsIP string, logger *slog.Logger) error
	restore   func(logger *slog.Logger) error
	recover   func(logger *slog.Logger) (bool, error)
	restart   bool // daemon.json changed: the daemon restart applies it
	logger    *slog.Logger
}

// containerListenAddr is the proxy's listener for container DNS at addr.
func containerListenAddr(addr netip.Addr) string { return netip.AddrPortFrom(addr, 53).String() }

// startDockerDNS adds the container listeners, before the proxy starts, with
// their addresses to be added to lo once it holds its primary (see
// dockerDNS), unless --docker-dns-interception is off: then it returns nil.
// An address equal to the proxy's upstream is refused, as is one another
// interface or route holds. Nothing is pointed at the listeners yet
// (useListener). The returned undo removes the addresses; the caller defers
// it. It is registered before anything is added, so a forced shutdown that
// lands mid-add still has one: pkg/network serializes the two, so it either
// removes what was added or stops an add from starting.
func startDockerDNS(cmd *StartCmd, dnsServer *dns.Server, dockerd podenv.Dockerd, teardowns *teardownList,
	logger *slog.Logger,
) (*dockerDNS, func()) {
	if !cmd.DockerDNSInterception {
		return nil, func() {}
	}
	d := &dockerDNS{
		dockerd: dockerd, proxy: dnsServer, configure: network.ConfigureDockerDNS,
		restore: network.RestoreDockerDNS, recover: network.RecoverDockerDNS, logger: logger,
	}
	upstream, _ := netip.ParseAddrPort(cmd.DNSUpstream)
	owned := network.NewOwnedAddrs(upstream.Addr().Unmap(), logger)
	undo := teardowns.add(func() {
		if err := owned.Remove(); err != nil {
			logger.Warn("Failed to remove the container DNS addresses from lo", "error", err)
		}
	})
	for _, addr := range []netip.Addr{network.ContainerDNSIPv4, network.ContainerDNSIPv6} {
		// Marked container-serving so queries arriving there attribute via
		// the container-IP lookup, never the host-netns sockdiag path.
		dnsServer.AddContainerListenAddr(containerListenAddr(addr))
		dnsServer.PrepareListenAddr(containerListenAddr(addr), func() error { return owned.Add(addr) })
	}
	return d, undo
}

// useListener puts the IPv4 container listener to use once the proxy is
// ready, or warns that the proxy could not bind it, which with the redirect
// requested is a lost dns-redirect posture too (startDNSRedirect). Only for
// a daemon proven local, and only onto a bound listener, is daemon.json
// rewritten, to point containers at it: a foreign or unidentified daemon is
// left alone, and whether the redirect sends its containers' DNS to the
// listener is the redirect's to say once it is in place ("DNS redirect
// installed"). daemon.json takes one address, and the redirect sends IPv6
// container DNS to the IPv6 listener. The returned undo restores
// daemon.json; the caller defers it. It is registered before the rewrite,
// so a signal landing mid-write still has one: the second-signal path runs
// it on another goroutine, and pkg/network serializes the two, so it either
// undoes a finished rewrite or stops one from starting. Nil-safe.
func (d *dockerDNS) useListener(teardowns *teardownList, redirect bool) func() {
	if d == nil {
		return func() {}
	}
	local := d.dockerd.Kind == podenv.DockerdLocal
	listen := containerListenAddr(network.ContainerDNSIPv4)
	if err := d.listenerErr(network.ContainerDNSIPv4); err != nil {
		d.logger.Warn(unboundListener(local, local && d.recoverLeftover(), redirect), "addr", listen, "error", err)
		return func() {}
	}
	d.logger.Info("Docker DNS interception enabled", "listen", listen,
		"listen_ipv6", containerListenAddr(network.ContainerDNSIPv6), "ipv6_bound", d.listeningIPv6() != "")
	if !local {
		d.logger.Info("Docker daemon not proven local; leaving its config alone, so its containers reach the proxy "+
			"only through the DNS redirect or by naming its listener", "dockerd", d.dockerd.Kind.String(), "reason", d.dockerd.Reason)
		return func() {}
	}
	undo := teardowns.add(func() {
		if err := d.restore(d.logger); err != nil {
			d.logger.Warn("Failed to restore Docker DNS", "error", err)
		}
	})
	if err := d.configure(d.listeningIP(), d.logger); err != nil {
		d.logger.Warn("Failed to configure Docker DNS", "error", err)
		return undo
	}
	d.restart = true
	return undo
}

// recoverLeftover undoes the daemon.json rewrite a run that did not shut
// down cleanly left, for a local daemon this run will not point at its
// listener, and reports whether there was one. Such a rewrite points the
// daemon's containers at an address the proxy does not listen on, so the
// daemon restart is due to apply the original (restartDaemon). A rewrite
// onto a bound listener undoes a leftover on its way
// (network.ConfigureDockerDNS).
func (d *dockerDNS) recoverLeftover() bool {
	recovered, err := d.recover(d.logger)
	if err != nil {
		d.logger.Warn("Failed to undo the daemon.json rewrite a previous run left", "error", err)
	}
	if recovered {
		d.restart = true
	}
	return recovered
}

// unboundListener is useListener's warning for an IPv4 container listener
// the proxy could not bind: what containers resolve through instead, which
// turns on whether daemon.json was the proxy's to rewrite, whether a
// previous run's rewrite of it was undone, and whether the redirect is
// requested.
func unboundListener(local, restored, redirect bool) string {
	msg := "Docker DNS interception unavailable: the proxy could not listen on its container DNS address"
	switch {
	case restored:
		msg += ", so daemon.json is not pointed at it, and the rewrite a previous run left there is undone"
	case local:
		msg += ", so daemon.json is left alone"
	}
	msg += "; containers resolve as their daemon configures them, around the proxy"
	if redirect {
		msg += ", which the DNS redirect does not cover either (a lost dns-redirect posture)"
	}
	return msg
}

// listenerErr is why the proxy is not listening for container DNS at addr,
// nil when it is or the feature is off. Valid once the proxy is ready.
// Nil-safe.
func (d *dockerDNS) listenerErr(addr netip.Addr) error {
	if d == nil {
		return nil
	}
	return d.proxy.BindError(containerListenAddr(addr))
}

// listening is addr when the proxy holds its container listener there, ""
// otherwise. Nil-safe.
func (d *dockerDNS) listening(addr netip.Addr) string {
	if d == nil || d.listenerErr(addr) != nil {
		return ""
	}
	return addr.String()
}

// listeningIP and listeningIPv6 are the container listeners' addresses the
// proxy holds, "" for one it does not: the addresses container DNS may be
// sent to and allowed at, and so the redirect's (startDNSRedirect). Without
// one the bridges get no rule for its family: a DNAT would hand container
// DNS to whatever holds the address, and a drop would block DNS under an
// auditing policy, which promises to block nothing, while under an
// enforcing one the loss already refuses startup. Valid once the proxy is
// ready. Nil-safe.
func (d *dockerDNS) listeningIP() string { return d.listening(network.ContainerDNSIPv4) }

func (d *dockerDNS) listeningIPv6() string { return d.listening(network.ContainerDNSIPv6) }

// serving reports whether the proxy holds a container listener, whose
// queries the container lookup attributes. Nil-safe.
func (d *dockerDNS) serving() bool { return d.listeningIP() != "" || d.listeningIPv6() != "" }

// dnsInfraIPs are the addresses port-53 traffic must always reach, which
// startup allows at TC: the proxy's 127.0.0.1, its upstream, and the
// container listeners daemon.json and the redirect send container DNS to,
// those the proxy holds (listeningIP, listeningIPv6): port 53 at one it does
// not is another process's, or no one's. Load-bearing under
// --container-egress=enforce, where container resolution otherwise meets
// EPERM.
func dnsInfraIPs(upstream string, containerDNS *dockerDNS) []string {
	ips := []string{"127.0.0.1"}
	if host, _, err := net.SplitHostPort(upstream); err == nil {
		ips = append(ips, host)
	}
	for _, ip := range []string{containerDNS.listeningIP(), containerDNS.listeningIPv6()} {
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
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
