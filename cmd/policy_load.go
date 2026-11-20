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
	"fmt"
	"log/slog"
	"net"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
)

// loadStartupPolicy loads the run's policy from its source: CI mode (the
// CodeCargo API, env vars or a config file), the LoadPolicy hook, or a config
// file. Then, whichever source it was, it allows the DNS infrastructure on
// port 53 (allowDNSInfra).
//
// It returns whether the CodeCargo API policy loaded, the hook's state
// machine client, and the hook's cleanup, which the caller runs at shutdown
// (it may be set even when err is).
func loadStartupPolicy(ctx context.Context, cmd *StartCmd, hooks *StartHooks, configMgr *config.Manager,
	auditLogger *events.AuditLogger, dockerBridgeIP string, logger *slog.Logger,
) (apiPolicyLoaded bool, smClient events.StateMachineClient, cleanup func(), err error) {
	switch {
	case cmd.CIMode() != CIModeNone:
		apiPolicyLoaded = loadCIConfig(ctx, cmd, configMgr, auditLogger, logger)
	case hooks != nil && hooks.LoadPolicy != nil:
		// Extension hook: load policy from external source (e.g., NATS state machine)
		policy, client, hookCleanup, hookErr := hooks.LoadPolicy(ctx, cmd)
		if hookErr != nil {
			return false, nil, hookCleanup, fmt.Errorf("failed to load policy via hook: %w", hookErr)
		}
		if policy != nil {
			if loadErr := configMgr.LoadConfigFromCargoWall(policy); loadErr != nil {
				return false, nil, hookCleanup, fmt.Errorf("failed to load CargoWall config: %w", loadErr)
			}
			// LoadConfigFromCargoWall mapped the policy's mode onto the
			// manager's posture; re-sync the logger's event labeling.
			if auditLogger != nil {
				auditLogger.SetAuditMode(configMgr.IsAuditMode())
			}
		}
		smClient, cleanup = client, hookCleanup
	default:
		// Load from file (original behavior)
		if loadErr := configMgr.LoadConfig(cmd.Config); loadErr != nil {
			logger.Error("Failed to load config", "error", loadErr, "path", cmd.Config)
			// Continue with default deny-all policy
		}
	}

	allowDNSInfra(configMgr, cmd.DNSUpstream, dockerBridgeIP)
	return apiPolicyLoaded, smClient, cleanup, nil
}

// allowDNSInfra allows port-53 traffic to the DNS proxy's own address, its
// upstream and the Docker bridge listener. It runs after every policy source:
// the proxy forwards every query to the upstream, so under default deny a
// policy without a rule for it would leave the job unable to resolve
// anything. It is a no-op while no config has loaded.
func allowDNSInfra(configMgr *config.Manager, upstream, dockerBridgeIP string) {
	ips := []string{"127.0.0.1"}
	if host, _, err := net.SplitHostPort(upstream); err == nil {
		ips = append(ips, host)
	}
	if dockerBridgeIP != "" {
		ips = append(ips, dockerBridgeIP)
	}
	configMgr.EnsureDNSAllowed(ips)
}
