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
	"strings"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/lockdown"
)

// The lockdown's flag is a bool; these are its values in the posture
// record, spelled as the flag takes them.
const (
	sudoLockdownOn  = "true"
	sudoLockdownOff = "false"
)

// policySudoLockdown applies the policy's sudo lockdown settings, which
// override the flags. It runs once the policy has loaded and before the
// postures are registered, since the ledger reads the request off cmd.
func policySudoLockdown(cmd *StartCmd, sl *config.SudoLockdownSettings) {
	if sl == nil {
		return
	}
	cmd.SudoLockdown = sl.Enabled
	cmd.SudoAllowCommands = strings.Join(sl.AllowCommands, ",")
}

// parseSudoAllowCommands splits a comma-separated list of command paths,
// stripping arguments (anything after the first whitespace) and skipping
// non-absolute paths. Returns the cleaned list of command paths.
func parseSudoAllowCommands(input string, logger *slog.Logger) []string {
	if input == "" {
		return nil
	}
	var cmds []string
	for _, c := range strings.Split(input, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Sudoers commands must be absolute paths with no arguments.
		// Strip arguments (anything after the first whitespace) and warn.
		if fields := strings.Fields(c); len(fields) > 1 {
			logger.Warn("Stripping arguments from sudo allow command (sudoers requires bare paths)",
				"original", c, "path", fields[0])
			c = fields[0]
		}
		if !strings.HasPrefix(c, "/") {
			logger.Warn("Skipping non-absolute sudo allow command", "command", c)
			continue
		}
		cmds = append(cmds, c)
	}
	return cmds
}

// sudoLockdownConfig builds the lockdown's config from the flags, which the
// policy may have overridden (policySudoLockdown).
func sudoLockdownConfig(cmd *StartCmd, logger *slog.Logger) *lockdown.SudoLockdownConfig {
	return &lockdown.SudoLockdownConfig{
		AllowCommands: parseSudoAllowCommands(cmd.SudoAllowCommands, logger),
		Username:      "", // Auto-detect
	}
}

// enableLockdown is lockdown.EnableSudoLockdown, a var so tests can fail it.
var enableLockdown = lockdown.EnableSudoLockdown

// enableSudoLockdown applies the lockdown. The caller registers the undo
// against the same config BEFORE calling this, so a signal landing mid-write
// can never strand the runner with a restricted sudoers file.
//
// A lockdown that returns an error has undone itself, so the job would run
// with the runner's sudo unchanged: it could not be applied, a verification
// saw sudo still run an unlisted command as root, or the runner's worker runs
// as root, beyond any lockdown. That is the posture lost, and the error
// returned fails startup under an enforcing policy. What the posture promises
// is the lockdown's own guarantee: sudo, for the job's user, runs only the
// allowlist, checked against a command it does not name. The docker socket
// and whatever an allowlisted command itself grants are outside it. What the
// lockdown only warns about (a verification that could not complete, sudo
// reading another policy source, the sudoers.d-only fallback) leaves it in
// place and loses nothing.
func enableSudoLockdown(cfg *lockdown.SudoLockdownConfig, postures *postureLedger, logger *slog.Logger) error {
	if err := enableLockdown(cfg, logger); err != nil {
		return postures.lose(postureSudoLockdown, postures.errReason(err))
	}
	return nil
}
