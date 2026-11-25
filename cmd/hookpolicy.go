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

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
)

// loadHookPolicy loads the policy an extension hook supplies (the SaaS
// sidecar's state machine), as LoadConfigFromCargoWall reads a CodeCargo
// policy on every path: a search domain it refuses is dropped, and the rest
// of the policy loads. It returns the hook's state-machine client and its
// cleanup, which the caller defers; on an error it has run the cleanup
// itself.
func loadHookPolicy(ctx context.Context, cmd *StartCmd, hooks *StartHooks, configMgr *config.Manager,
	auditLogger *events.AuditLogger,
) (events.StateMachineClient, func(), error) {
	policy, smClient, cleanup, err := hooks.LoadPolicy(ctx, cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load policy via hook: %w", err)
	}
	if policy == nil {
		return smClient, cleanup, nil
	}
	if err := configMgr.LoadConfigFromCargoWall(policy); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, fmt.Errorf("failed to load CargoWall config: %w", err)
	}
	// LoadConfigFromCargoWall mapped the policy's mode onto the manager's
	// posture; re-sync the logger's event labeling.
	if auditLogger != nil {
		auditLogger.SetAuditMode(configMgr.IsAuditMode())
	}
	return smClient, cleanup, nil
}
