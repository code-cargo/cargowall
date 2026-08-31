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

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/containers"
	"github.com/code-cargo/cargowall/pkg/dns"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/origin"
)

// l7Feature owns the L7 (TLS SNI / HTTP Host / QUIC) enforcement lifecycle:
// the oracle, its DNS registrar, the late-allow seam, and the mode gate.
// Destination-identity enforcement is its own concern — it deliberately does
// not hang off containerAttribution, which owns docker tracking and the cgroup
// attach order. A nil *l7Feature is not a usable value: callers hold one only
// when the feature is on, and guard explicitly.
type l7Feature struct {
	oracle *origin.L7
	// cm answers "did this name forward-resolve to this IP" for the scope
	// writes the L4 paths drive; see dns.RegisterL7Identity.
	cm *config.Manager
	// targetMode is the posture raise() applies once the scope maps have
	// warmed, mirroring how the origin mode is raised after the allowlist.
	targetMode uint8
	logger     *slog.Logger
}

// startL7 constructs and starts the oracle, and hands the DNS proxy the
// registrar so resolved IPs are L7-scoped. It runs EARLY — the mode gate stays
// off until raise(), so startup resolutions scope their destinations before any
// flow is adjudicated. Returns nil when --tls-sni is off, or when the cgroup
// hook it rides is not running.
func startL7(cmd *StartCmd, obs *origin.Observer, enricher *containers.Enricher,
	configMgr *config.Manager, dnsServer *dns.Server, auditLogger *events.AuditLogger,
	notificationTracker *events.NotificationTracker, logger *slog.Logger,
) *l7Feature {
	if cmd.TLSSNI == TLSSNIOff {
		return nil
	}
	if obs == nil {
		// The RUNTIME downgrade (attribution disabled, observer load/attach
		// failure), as loud as a dropped --container-egress=enforce: the operator asked
		// for SNI pinning, and without it the shared-edge hole stays open with
		// nothing else in the logs saying so.
		logger.Warn("--tls-sni requested but the cgroup egress hook is not running — " +
			"L7 SNI enforcement is OFF and shared-edge IPs stay L4-only")
		return nil
	}

	// The policy's second tier is bound to the live proxy, so the set the
	// oracle consults is the same one the query gate uses and stays current as
	// chains are learned.
	var derived func(name string) ([]config.Port, bool)
	if dnsServer != nil {
		derived = dnsServer.DerivedAllowPorts
	}

	oracle, err := obs.EnableL7(origin.L7Options{
		Matcher: config.NewL7Policy(configMgr, derived),
		PinIP:   cmd.TLSSNI == TLSSNIEnforcePinned,
		Sink:    l7Sink(obs, enricher, configMgr, auditLogger, notificationTracker, logger),
	})
	if err != nil {
		logger.Warn("L7 SNI enforcement disabled", "error", err)
		return nil
	}

	f := &l7Feature{oracle: oracle, cm: configMgr, targetMode: origin.L7ModeObserve, logger: logger}
	if cmd.TLSSNI == TLSSNIEnforce || cmd.TLSSNI == TLSSNIEnforcePinned {
		f.targetMode = origin.L7ModeEnforce
	}
	if dnsServer != nil {
		// Install the registrar only. Repairing what the proxy resolved before
		// this point is NOT done here: the proxy keeps resolving while the
		// firewall is still nil, so any snapshot taken now would miss that
		// window. ApplyRulesToTrackedHostnames — run after SetFirewall and
		// before raise() — replays both allow tiers in one pass.
		dnsServer.SetL7Registrar(oracle)
	}
	logger.Info("L7 SNI enforcement prepared",
		"target_mode", l7ModeName(f.targetMode), "pin_ip", cmd.TLSSNI == TLSSNIEnforcePinned)
	return f
}

// raise lifts the L7 mode gate to its target posture. Called from the boot
// sequence after the allowlist and scope maps have warmed. Deliberately NOT
// conditioned on the cgroup hook reaching its own posture: the two gates are
// separate map keys and the kernel's L7 drop never consults ORIGIN_MODE, so
// coupling them only meant an origin SetMode failure silently took L7 —
// observe mode included — off entirely.
func (f *l7Feature) raise() {
	if err := f.oracle.SetMode(f.targetMode); err != nil {
		f.logger.Warn("L7 stays off", "target_mode", l7ModeName(f.targetMode), "error", err)
		return
	}
	f.logger.Info("L7 SNI enforcement active", "mode", l7ModeName(f.targetMode))
}

// registrar is what the L4 paths take alongside the firewall so a /32 they
// open is scoped in the same reconciliation. Passed explicitly; nil when L7 is
// off, so a caller cannot silently drop it by handing over the raw firewall.
func (f *l7Feature) registrar() events.L7LateRegistrar {
	return l7LateRegistrar{l7: f.oracle, cm: f.cm, logger: f.logger}
}

// l7Sink adapts denied oracle outcomes onto the shared reporting helper. Only
// denials are reported: an l7_blocked when the flow was dropped, or an
// l7_would_block when observe mode or audit posture passed it. Admitted flows
// produce no per-flow record — the kernel stats already count them. The punt's
// socket cookie resolves to pid/step through the same join origin records use,
// so an L7 denial carries the identical attribution as its sibling L4 outcomes.
func l7Sink(obs *origin.Observer, enricher *containers.Enricher, configMgr *config.Manager,
	auditLogger *events.AuditLogger, notificationTracker *events.NotificationTracker,
	logger *slog.Logger,
) func(origin.L7Outcome) {
	return func(o origin.L7Outcome) {
		// Admitted flows produce no record — except one the per-IP binding
		// WOULD have denied, which is the measurement deciding whether pinning
		// is safe to turn on.
		if o.Allowed && !o.WouldNarrow {
			return
		}
		pid, ordinal := obs.ResolveCookie(o.Cookie)
		events.ReportL7(events.L7Record{
			SrcIP:       o.SrcIP.String(),
			DstIP:       o.DstIP.String(),
			DstPort:     o.DstPort,
			Proto:       o.IPProto,
			PID:         pid,
			StepOrdinal: ordinal,
			Name:        o.Name,
			L7Protocol:  o.Protocol.String(),
			Reason:      string(o.Reason),
			// A would-narrow passed the packet whatever the posture, so it
			// reports as telemetry, never as a drop that happened.
			Enforced: o.Enforce && !o.WouldNarrow,
			Decorate: func(audit *events.AuditEvent) {
				enricher.DecorateVerdict(audit, origin.Record{
					Cookie:   o.Cookie,
					CgroupID: o.CgroupID,
					SrcIP:    o.SrcIP,
				})
			},
		}, configMgr, auditLogger, notificationTracker, logger)
	}
}

// l7LateRegistrar routes the L4 paths' scope writes through the one seam the
// DNS allow path uses, keeping the scope-bit vocabulary in pkg/dns. The l7
// field is the oracle behind dns.L7Registrar (widened from *origin.L7 so tests
// can record what this seam registers).
type l7LateRegistrar struct {
	l7     dns.L7Registrar
	cm     *config.Manager
	logger *slog.Logger
}

func (r l7LateRegistrar) RegisterLateAllow(hostname string, ip net.IP, allowPorts []config.Port) {
	dns.RegisterL7Identity(r.l7, r.cm, hostname, ip, allowPorts, r.logger)
}

func l7ModeName(mode uint8) string {
	switch mode {
	case origin.L7ModeEnforce:
		return "enforce"
	case origin.L7ModeObserve:
		return "observe"
	default:
		return "off"
	}
}
