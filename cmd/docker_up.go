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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/code-cargo/cargowall/pkg/containers"
	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// dockerFile carries, for a Docker that was still to come up at startup,
// whether and when it answered, from `cargowall start` to `cargowall
// summary`.
var dockerFile = "/tmp/cargowall-docker"

// dockerRecord is dockerFile's content.
type dockerRecord struct {
	Answered bool    `json:"answered"`
	AfterS   float64 `json:"after_s,omitempty"` // seconds after startup
}

// dockerUp is what startup makes of Docker's state (podenv.Dockerd), and,
// for a Docker still to come up (Pending), its arrival. On some hosts
// (Blacksmith's) the socket accepts connections seconds before dockerd
// answers on it, and before it has made a bridge. Nothing waits for it:
// a daemon that has not answered has started no container cargowall could
// ask about, so nothing needs carving before the cgroup hook adjudicates
// (a docker0 already up is carved from its address), and the container DNS
// addresses and the redirect's DNAT on docker0 and br-* cover bridges made
// later. What does wait for the daemon, container tracking and the
// carve-outs it makes, starts when it answers, and is logged then.
//
// daemon.json is left alone for such a daemon, now and when it answers:
// it may be reading it already, restarting it once it has answered would
// kill the job's service containers, and the redirect's DNAT sends its
// containers' DNS to the proxy without either.
type dockerUp struct {
	dockerd      podenv.Dockerd
	attribution  bool // --container-egress is on
	interception bool // --docker-dns-interception is on, with DNS tracking
	redirect     bool // --dns-redirect is on, with DNS tracking
	start        time.Time
	logger       *slog.Logger
	// dnsLine says where a pending daemon's containers' DNS goes, read at
	// startup (containerDNS), and dnsAround whether that is, or may be,
	// around the proxy.
	dnsLine   string
	dnsAround bool

	mu      sync.Mutex
	arrived bool
	closed  bool               // torn down: an arrival after it is not one
	stop    context.CancelFunc // the watcher's, when no tracker watches
}

// newDockerUp logs the runtime environment and what startup makes of
// Docker's state in it: one Info line for a host with no Docker, or for one
// still to come up, saying what starts when it answers.
func newDockerUp(shape podenv.Shape, cmd *StartCmd, logger *slog.Logger) *dockerUp {
	logger.Info("Runtime environment", shape.LogArgs()...)
	u := &dockerUp{
		dockerd:      shape.Dockerd,
		attribution:  cmd.ContainerEgress != ContainerEgressOff,
		interception: cmd.DockerDNSInterception && !cmd.DisableDNSTracking,
		redirect:     cmd.DNSRedirect && !cmd.DisableDNSTracking,
		start:        time.Now(),
		logger:       logger,
	}
	switch {
	case u.dockerd.None():
		logger.Info("No Docker on this host: no Docker socket and no Docker bridge")
	case u.dockerd.Pending():
		if u.interception {
			u.dnsLine, u.dnsAround = u.containerDNS()
		}
		logger.Info(u.pendingLine())
		u.record(dockerRecord{})
	}
	return u
}

// pendingLine is the startup line for a Docker still to come up.
func (u *dockerUp) pendingLine() string {
	parts := []string{"Docker socket present, daemon not answering yet"}
	switch {
	case u.dockerd.BridgesErr != nil:
		parts[0] += ", and its bridges could not be listed (" + u.dockerd.BridgesErr.Error() + ")"
	case len(u.dockerd.Bridges) > 0:
		parts[0] += " though its bridges are up"
	}
	if u.attribution {
		parts = append(parts, "container attribution and bridge carve-outs start when it does")
	}
	if u.interception {
		parts = append(parts, u.dnsLine)
	}
	return strings.Join(parts, "; ")
}

// daemonDNSServers reads daemon.json's "dns": network.DockerDNSServers, or
// a test's stand-in.
var daemonDNSServers = network.DockerDNSServers

// containerDNS is where a Docker still to come up has its containers' DNS
// go, and whether that is, or may be, around the proxy. With the redirect
// it goes to the proxy whatever daemon.json says. Without it, daemon.json,
// left alone, decides, as the daemon read it when it started: a previous
// run's rewrite left in it points its containers at the IPv4 container
// listener. A daemon whose daemon.json is not ours, or one that cannot be
// read, cannot be said to.
func (u *dockerUp) containerDNS() (string, bool) {
	if u.redirect {
		return fmt.Sprintf("its containers' DNS goes to %s and %s by the DNS redirect, and daemon.json is left alone",
			network.ContainerDNSIPv4, network.ContainerDNSIPv6), false
	}
	if u.dockerd.Kind != podenv.DockerdLocal {
		return "its daemon.json is not ours to read or rewrite, so without --dns-redirect its containers' DNS goes " +
			"around the proxy", true
	}
	servers, err := daemonDNSServers()
	switch {
	case err != nil:
		return "daemon.json is left alone and could not be read (" + err.Error() + "), so whether its containers' " +
			"DNS reaches the proxy without --dns-redirect is not known", true
	case slices.Contains(servers, network.ContainerDNSIPv4.String()):
		return fmt.Sprintf("daemon.json is left alone, and already points its containers at %s, so their DNS "+
			"reaches the proxy", network.ContainerDNSIPv4), false
	}
	return "daemon.json is left alone, so without --dns-redirect its containers' DNS goes around the proxy", true
}

// track starts container attribution's userspace half (startUserspace),
// whose tracker reports when a Docker still to come up answers (connected).
// Without one, a watcher of its own does, so the arrival is logged and
// recorded either way.
func (u *dockerUp) track(ctx context.Context, a *containerAttribution, dnsServer *dns.Server, containerDNS bool,
	auditLogger *events.AuditLogger,
) {
	if a.startUserspace(ctx, dnsServer, containerDNS, auditLogger, u) || !u.dockerd.Pending() {
		return
	}
	wctx, cancel := context.WithCancel(ctx)
	u.mu.Lock()
	u.stop = cancel
	u.mu.Unlock()
	go func() {
		if containers.WaitAnswer(wctx, dockerSocket) == nil {
			u.answered(false, nil)
		}
	}()
}

// connected is the tracker's Options.OnConnect: its first connect to a
// Docker still to come up is that Docker's arrival.
func (u *dockerUp) connected(first bool, carved []netip.Prefix) {
	if first && u.dockerd.Pending() {
		u.answered(true, carved)
	}
}

// answered logs and records the arrival of a Docker still to come up,
// once: when it answered, whether container attribution went on, the bridge
// subnets that carved, and where its containers' DNS goes.
func (u *dockerUp) answered(tracked bool, carved []netip.Prefix) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.arrived || u.closed {
		return
	}
	u.arrived = true
	after := time.Since(u.start)
	parts := []string{fmt.Sprintf("Docker answered %s after cargowall started", after.Round(100*time.Millisecond))}
	args := []any{"after_s", after.Seconds()}
	if tracked {
		parts = append(parts, "container attribution on")
		args = append(args, "carved", carved)
	}
	if u.interception {
		parts = append(parts, u.dnsLine)
	}
	if u.interception && u.dnsAround {
		u.logger.Warn(strings.Join(parts, "; "), args...)
	} else {
		u.logger.Info(strings.Join(parts, "; "), args...)
	}
	u.record(dockerRecord{Answered: true, AfterS: after.Seconds()})
}

// close stops the watcher, and says at teardown that a Docker still to come
// up never did: with no bridge of its at startup no container of its can
// have run, so nothing went untracked; with its bridges up, or bridges that
// could not be listed, containers on them may have, untracked.
func (u *dockerUp) close() {
	if u == nil || !u.dockerd.Pending() {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	if u.stop != nil {
		u.stop()
	}
	switch {
	case u.arrived:
	case len(u.dockerd.Bridges) > 0:
		u.logger.Warn("Docker never answered, though its bridges were up at startup: containers on them went untracked",
			"bridges", u.dockerd.Bridges)
	case u.dockerd.BridgesErr != nil:
		u.logger.Warn("Docker never answered, and its bridges could not be listed at startup: containers on any "+
			"went untracked", "error", u.dockerd.BridgesErr)
	default:
		u.logger.Info("Docker never answered while cargowall ran, and had made no bridge: no container of its can " +
			"have run, so none went untracked")
	}
}

// record writes rec to dockerFile, warning on failure: the summary's line
// about Docker is the only thing that reads it.
func (u *dockerUp) record(rec dockerRecord) {
	data, err := json.Marshal(rec)
	if err == nil {
		err = writeSentinel(dockerFile, data)
	}
	if err != nil {
		u.logger.Warn("Failed to write Docker state file", "path", dockerFile, "error", err)
	}
}

// readDockerRecord returns the record of a Docker that was still to come up
// at startup, and whether there is one.
func readDockerRecord() (dockerRecord, bool) {
	sf, ok := readStateFile(dockerFile)
	if !ok {
		return dockerRecord{}, false
	}
	var rec dockerRecord
	if err := json.Unmarshal(sf.data, &rec); err != nil {
		return dockerRecord{}, false
	}
	return rec, true
}

// dockerLine is the summary's neutral line about a Docker that was still to
// come up at startup, "" for none.
func dockerLine() string {
	rec, ok := readDockerRecord()
	switch {
	case !ok:
		return ""
	case !rec.Answered:
		return "Docker: the daemon never answered while CargoWall ran; no containers observed."
	}
	return fmt.Sprintf("Docker: the daemon answered %.0fs after CargoWall started.", rec.AfterS)
}
