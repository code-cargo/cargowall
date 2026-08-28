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
	"errors"
	"log/slog"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/containers"
	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/origin"
	"github.com/code-cargo/cargowall/pkg/steps"
)

// containerAttribution owns the two-phase startup of the container
// attribution subsystem and the root-cgroup egress hook (issue #106). The
// split is forced by daemon boot order, and this type is the one place that
// order is encoded:
//
//   - Kernel half (newContainerAttribution): the origin observer and the
//     enricher shell must exist BEFORE the event reader starts, so no
//     verdict event misses the join store.
//   - Userspace half (startUserspace): docker-events tracking must start
//     AFTER the dockerd restart, so its event subscription isn't severed
//     and containers running across the restart aren't misfiled as
//     pre-daemon.
//
// Every method is nil-receiver safe: a nil *containerAttribution IS the
// disabled feature, so startCargoWall wires the subsystem unconditionally
// instead of threading flag checks through the boot sequence. All failures
// are warn-only, which stays correct under --cgroup-enforce only because TC
// egress remains attached: losing this subsystem degrades enforcement to
// TC-only, it never leaves traffic unpoliced.
type containerAttribution struct {
	stepTracker *steps.Tracker
	mode        origin.Mode      // target posture, applied by enableMode after gating
	observer    *origin.Observer // nil when the observer failed to load/attach
	enricher    *containers.Enricher
	tracker     *containers.Tracker // nil until startUserspace succeeds
	logger      *slog.Logger
}

// resolveMode maps the flags onto the hook's posture. Container attribution
// off means the hook isn't running at all; on, it defaults to shadow
// (compute verdicts, report would-blocks, block nothing) so the blast radius
// of the surfaces this hook newly sees is measured before anyone relies on
// it. Enforcement is opt-in.
func resolveMode(containerAttribution, cgroupEnforce bool) origin.Mode {
	switch {
	case !containerAttribution:
		return origin.ModeObserve
	case cgroupEnforce:
		return origin.ModeEnforce
	default:
		return origin.ModeShadow
	}
}

// newContainerAttribution is the kernel-half phase. Returns nil (feature
// off) when disabled or when step attribution isn't live: without step tags
// the observer's ordinals would always be zero, and the step-map shrink for
// disabled attribution makes container tagging meaningless anyway.
func newContainerAttribution(enabled bool, mode origin.Mode, stepTracker *steps.Tracker, tcObjs *bpf.TcBpfObjects, logger *slog.Logger) *containerAttribution {
	if !enabled {
		return nil
	}
	if stepTracker == nil {
		if mode == origin.ModeEnforce {
			// Never drop a requested enforcement posture silently: the
			// operator believes pre-NAT/loopback/bridge egress is policed.
			logger.Warn("Container attribution disabled and --cgroup-enforce DROPPED " +
				"(requires active step attribution) — egress policing falls back to post-NAT TC only")
		} else {
			logger.Warn("Container attribution disabled (requires active step attribution)")
		}
		return nil
	}
	a := &containerAttribution{
		stepTracker: stepTracker,
		mode:        mode,
		enricher:    &containers.Enricher{},
		logger:      logger,
	}
	obs, err := origin.Start(tcObjs, logger)
	if err != nil {
		// Warn-only, and still correct under phase 3b: TC egress remains
		// attached and enforcing, so losing this hook degrades enforcement
		// to TC-only (plus the loss of container attribution) rather than
		// leaving traffic unpoliced. That is precisely why TC stays.
		// target_mode makes a dropped --cgroup-enforce request visible.
		logger.Warn("Container egress hook disabled — enforcement falls back to TC egress only",
			"target_mode", mode.String(), "error", err)
	} else {
		a.observer = obs
		logger.Info("Container egress hook attached", "target_mode", mode.String())
	}
	return a
}

// wireVerdicts routes the cgroup hook's verdicts into the shared
// post-verdict pipeline in pkg/events — the same one TC events flow
// through, so a denial from either hook gets hostname resolution,
// late-allow reconciliation, notifications, and an audit record. Container
// identity is attached as decoration; it is not the owner of the outcome,
// because most cgroup verdicts are host processes with no container at all.
// The sink only ever sees Blocks and shadow would-blocks: enforce-mode
// would-blocks (audit posture) are TC's to report and never leave
// origin.insert — one reporter per packet.
func (a *containerAttribution) wireVerdicts(configMgr *config.Manager, notificationTracker *events.NotificationTracker,
	auditLogger *events.AuditLogger, fw events.FirewallUpdater,
) {
	if a == nil || a.observer == nil {
		return
	}
	enricher := a.enricher
	a.observer.SetVerdictSink(func(rec origin.Record) {
		events.ReportVerdict(events.VerdictRecord{
			SrcIP:       rec.SrcIP.String(),
			DstIP:       rec.DstIP.String(),
			SrcPort:     rec.SrcPort,
			DstPort:     rec.DstPort,
			Proto:       rec.Proto,
			PID:         rec.PID,
			StepOrdinal: rec.StepOrdinal,
			Dropped:     rec.Verdict == origin.VerdictBlock,
			// Mid-stream comes from the BPF flag, which applies the same
			// guard as tc_egress's EVENT_FLAG_MIDSTREAM (ACK set, no
			// SYN/RST). Re-deriving it as "TCP and not SYN" would re-include
			// the kernel RST / SYN-ACK replies that guard exists to exclude.
			MidStream: rec.Midstream,
			// Degraded rides through: a saturated reporting pipeline delivers
			// blocks on a bounded path (audit record only) rather than losing
			// them — see origin.Record.Degraded.
			Degraded: rec.Degraded,
			Decorate: func(audit *events.AuditEvent) {
				enricher.DecorateVerdict(audit, rec)
			},
		}, configMgr, notificationTracker, auditLogger, fw, a.logger)
	})
}

// enableMode raises the cgroup hook to its configured posture. MUST be
// called only after the allowlist, DNS/infra auto-allows, and
// existing-connection gating are programmed — the same attach-before-program
// guard that makes cmd/start.go attach TC last.
func (a *containerAttribution) enableMode() {
	if a == nil || a.observer == nil || a.mode == origin.ModeObserve {
		return
	}
	if err := a.observer.SetMode(a.mode); err != nil {
		// Failure leaves the hook in observe: no enforcement from it, TC
		// still enforcing. Degraded, never fail-open — and the dropped
		// target posture is named so a lost --cgroup-enforce is visible.
		a.logger.Warn("Container egress hook stays in observe mode",
			"target_mode", a.mode.String(), "error", err)
	}
}

// allowLocalNetwork is a nil-safe pass-through to the observer's
// AllowLocalNetwork: the carve-out policy (width cap, host-address
// locality, bridge-device exemption, fail-closed enumeration) lives ON the
// map write in pkg/origin — a permanent workload-influenced exemption must
// not depend on which caller reached it. With no observer there is nothing
// adjudicating, so there is nothing to carve.
func (a *containerAttribution) allowLocalNetwork(prefix netip.Prefix) error {
	if a == nil || a.observer == nil {
		return nil
	}
	return a.observer.AllowLocalNetwork(prefix)
}

// ensureLoopbackAllowed appends the userspace half of the loopback
// carve-out pair. TC egress is attached to one interface and has never
// seen `lo`, so loopback was never subject to the allowlist — but the
// cgroup hook fires on it, and without this every local-only flow (the
// runner's own services, test listeners, the DNS proxy's DNAT'd
// 127.0.0.1:53) would meet default-deny. The BPF hook also carves
// loopback out directly; this half makes the allowance visible in the
// rendered policy rather than hidden in bytecode. On the facade, not in
// startCargoWall: the type exists so boot doesn't thread feature checks,
// and a nil receiver — attribution off, or step attribution dead — is
// exactly the case where the hook never adjudicates and no allowance is
// needed. MUST run before UpdateAllowlistTC programs the maps. (It no longer
// has to follow the config load: auto-allows are journalled and re-applied
// across loads, issue #119.)
func (a *containerAttribution) ensureLoopbackAllowed(configMgr *config.Manager) {
	if a == nil {
		return
	}
	configMgr.EnsureInfraAllowed([]string{"127.0.0.0/8", "::1/128"}, nil, config.AutoAddedTypeLoopback)
}

// preallowLocalNetworks carves out the local-only networks that exist
// BEFORE the mode is raised: the default docker bridge (host config), and
// the bridge subnets of containers that predate cargowall — docker-event
// tracking starts only after the dockerd restart, and service containers or
// compose stacks must not lose bridge-local traffic to enforce-mode EPERM
// (or pollute shadow telemetry with false would-blocks) in that window.
func (a *containerAttribution) preallowLocalNetworks(ctx context.Context) {
	if a == nil || a.observer == nil || a.mode == origin.ModeObserve {
		return
	}
	if subnet, err := network.GetDockerBridgeSubnet(); err == nil {
		if prefix, perr := netip.ParsePrefix(subnet); perr == nil {
			if aerr := a.allowLocalNetwork(prefix); aerr != nil && !errors.Is(aerr, origin.ErrLocalNetworkRefused) {
				a.logger.Warn("Default bridge carve-out failed", "subnet", subnet, "error", aerr)
			}
		}
	} else {
		// Warn, not Debug: under shadow/enforce this carve-out is what keeps
		// published ports and default-bridge container traffic alive.
		a.logger.Warn("Docker bridge subnet not discovered; default-bridge traffic stays adjudicated",
			"error", err)
	}
	subnets, err := containers.DiscoverBridgeSubnets(ctx, "")
	if err != nil {
		a.logger.Warn("Cannot pre-scan bridge subnets; pre-existing user-defined bridges stay adjudicated until tracking starts",
			"error", err)
		return
	}
	for _, prefix := range subnets {
		// Refusals are the policy's decision and already logged by the
		// write; transient failures are warned and left for the tracker's
		// discovery paths to retry.
		if err := a.allowLocalNetwork(prefix); err != nil && !errors.Is(err, origin.ErrLocalNetworkRefused) {
			a.logger.Warn("Bridge subnet carve-out failed; tracking will retry", "subnet", prefix.String(), "error", err)
		}
	}
}

// enricherArg is what ProcessBlockedEvents receives. Nil (from a nil
// receiver) means enrichment is off; the shell itself no-ops until
// startUserspace binds the live tracker.
func (a *containerAttribution) enricherArg() events.ContainerEnricher {
	if a == nil {
		return nil
	}
	return a.enricher
}

// observerProgram exposes the observer for BPF runtime-stats logging; nil
// when the observer isn't running.
func (a *containerAttribution) observerProgram() *ebpf.Program {
	if a == nil || a.observer == nil {
		return nil
	}
	return a.observer.Program()
}

// startUserspace is the late phase: docker-events tracking, tagging, DNS
// client attribution (only meaningful when the bridge listener exists), and
// bridge-subnet discovery (allowLocalSubnet, may be nil).
func (a *containerAttribution) startUserspace(ctx context.Context, dnsServer *dns.Server, dockerBridgeIP string, auditLogger *events.AuditLogger, allowLocalSubnet func(prefix netip.Prefix) error) {
	if a == nil {
		return
	}
	ctr, err := containers.Start(ctx, containers.Options{AllowLocalSubnet: allowLocalSubnet}, a.stepTracker, a.observer, auditLogger, a.logger)
	if err != nil {
		a.logger.Warn("Container attribution disabled", "error", err)
		return
	}
	a.tracker = ctr
	a.enricher.Bind(ctr)
	if dnsServer != nil && dockerBridgeIP != "" {
		dnsServer.SetContainerLookup(ctr.LookupClient)
	}
	a.logger.Info("Container attribution enabled")
}

// Close stops the tracker before the observer: the tracker's shutdown
// telemetry summary reads the observer's record counter.
func (a *containerAttribution) Close() {
	if a == nil {
		return
	}
	if a.tracker != nil {
		a.tracker.Close()
	}
	if a.observer != nil {
		a.observer.Close()
	}
}
