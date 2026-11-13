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
	postures   *postureLedger
	// dns is the proxy, whose step tier the registrar carries while step
	// rules are on (stepLateRegistrar); nil without one.
	dns    *dns.Server
	logger *slog.Logger
}

// startL7 constructs and starts the oracle, and hands the DNS proxy the
// registrar so resolved IPs are L7-scoped. It runs EARLY — the mode gate stays
// off until raise(), so startup resolutions scope their destinations before any
// flow is adjudicated. Returns nil when --tls-sni is off, or when an observe
// posture could not start. A non-nil error means a requested enforce posture
// was lost and startup must fail: without it the shared-edge hole stays open.
func startL7(cmd *StartCmd, obs *origin.Observer, enricher *containers.Enricher,
	configMgr *config.Manager, dnsServer *dns.Server, auditLogger *events.AuditLogger,
	notificationTracker *events.NotificationTracker, p *postureLedger, logger *slog.Logger,
) (*l7Feature, error) {
	if cmd.TLSSNI == TLSSNIOff {
		return nil, nil
	}
	if obs == nil {
		// Under enforce this is unreachable in practice — the enforce rungs
		// require --container-egress=enforce, whose loss already failed
		// startup — but the ledger decides either way. Why the hook is down
		// is the container-egress row's to say.
		return nil, p.lose(postureTLSSNI, "the cgroup egress hook it rides is not running")
	}

	oracle, err := obs.EnableL7(origin.L7Options{
		Matcher: l7Policy(configMgr, dnsServer),
		PinIP:   cmd.TLSSNI == TLSSNIEnforcePinned,
		Sink:    l7Sink(obs, enricher, configMgr, auditLogger, notificationTracker, logger),
	})
	if err != nil {
		return nil, p.lose(postureTLSSNI, p.errReason(err))
	}

	f := &l7Feature{oracle: oracle, cm: configMgr, targetMode: origin.L7ModeObserve, postures: p, dns: dnsServer, logger: logger}
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
	return f, nil
}

// l7Policy is the oracle's name authority. Its second tier is bound to the
// live proxy, so the set the oracle consults is the same one the query gate
// uses and stays current as chains are learned; so is its step tier, by the
// step policy a flow's punt names.
func l7Policy(configMgr *config.Manager, dnsServer *dns.Server) config.L7Policy {
	if dnsServer == nil {
		return config.NewL7Policy(configMgr, nil)
	}
	return config.NewL7Policy(configMgr, dnsServer.DerivedAllowPorts).WithSteps(dnsServer.StepAllowPorts)
}

// raise lifts the L7 mode gate to its target posture. Called from the boot
// sequence after the allowlist and scope maps have warmed. Deliberately NOT
// conditioned on the cgroup hook reaching its own posture: the two gates are
// separate map keys and the kernel's L7 drop never consults ORIGIN_MODE, so
// coupling them only meant an origin SetMode failure silently took L7 —
// observe mode included — off entirely. A non-nil error means an enforce
// posture was lost and startup must fail.
func (f *l7Feature) raise() error {
	if err := f.oracle.SetMode(f.targetMode); err != nil {
		return f.postures.lose(postureTLSSNI, "mode gate could not be raised: "+f.postures.errReason(err))
	}
	f.logger.Info("L7 SNI enforcement active", "mode", l7ModeName(f.targetMode))
	return nil
}

// registrar is what the L4 paths take alongside the firewall so a /32 they
// open is scoped in the same reconciliation. Passed explicitly; nil when L7 is
// off, so a caller cannot silently drop it by handing over the raw firewall.
// With step rules on, settled by now, it carries the proxy's step tier for
// the event pipeline's late-allow (events.StepLateAllower).
func (f *l7Feature) registrar() events.L7LateRegistrar {
	r := l7LateRegistrar{l7: f.oracle, cm: f.cm, logger: f.logger}
	if f.dns != nil && f.cm.HasStepRules() {
		return stepLateRegistrar{l7LateRegistrar: r, steps: f.dns}
	}
	return r
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

// stepLateRegistrar is l7LateRegistrar with the proxy's step tier.
type stepLateRegistrar struct {
	l7LateRegistrar
	steps *dns.Server
}

func (r stepLateRegistrar) LateAllowStep(ordinal uint32, hostname string, ip net.IP, port uint16, proto uint8) (bool, string) {
	return r.steps.LateAllowStep(ordinal, hostname, ip, port, proto)
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
