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

package lockdown

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strings"
)

const (
	sudoersDir  = "/etc/sudoers.d"
	sudoersFile = "/etc/sudoers.d/cargowall-lockdown"
)

// SudoLockdownConfig configures the sudo lockdown behavior
type SudoLockdownConfig struct {
	// AllowCommands is a list of command paths to whitelist via NOPASSWD
	AllowCommands []string
	// Username is the user to configure sudoers for (auto-detected if empty)
	Username string
}

// sudoersUnsafeChars are characters that could be used for sudoers injection.
const sudoersUnsafeChars = " ,#\n\r\t`;&!()\\|"

// validateSudoersInput checks that a username and command paths do not contain
// characters that could alter sudoers semantics.
func validateSudoersInput(username string, cmds []string) error {
	if strings.ContainsAny(username, sudoersUnsafeChars) {
		return fmt.Errorf("sudoers username %q contains unsafe characters", username)
	}
	for _, c := range cmds {
		if strings.ContainsAny(c, sudoersUnsafeChars) {
			return fmt.Errorf("sudoers command %q contains unsafe characters", c)
		}
	}
	return nil
}

// EnableSudoLockdown configures sudoers to restrict what commands can be run with sudo
// and removes the target user from the docker group.
func EnableSudoLockdown(cfg *SudoLockdownConfig, logger *slog.Logger) error {
	logger.Info("Enabling sudo lockdown")

	// Determine the target username
	username := cfg.Username
	if username == "" {
		// Try to detect the current non-root user
		currentUser, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to get current user: %w", err)
		}
		if currentUser.Uid == "0" {
			// We're root, try common CI usernames
			for _, u := range []string{"runner", "github", "ci"} {
				if _, err := user.Lookup(u); err == nil {
					username = u
					break
				}
			}
		} else {
			username = currentUser.Username
		}
	}

	if username == "" {
		return fmt.Errorf("could not determine target username for sudo lockdown")
	}

	logger.Debug("Target user for sudo lockdown", "username", username)

	// Remove user from docker group to prevent docker-based firewall bypass
	if out, err := exec.Command("gpasswd", "-d", username, "docker").CombinedOutput(); err != nil {
		logger.Warn("Failed to remove user from docker group (user may not be in group)", "error", err, "output", strings.TrimSpace(string(out)))
	} else {
		logger.Info("Removed user from docker group", "username", username)
	}

	// Build the sudoers configuration
	sudoersContent, err := buildSudoersConfig(cfg, username)
	if err != nil {
		return fmt.Errorf("failed to build sudoers config: %w", err)
	}

	// Ensure sudoers.d directory exists
	if err := os.MkdirAll(sudoersDir, 0o755); err != nil {
		return fmt.Errorf("failed to create sudoers.d directory: %w", err)
	}

	// Write to a temp file first, then validate with visudo before installing
	tmpFile := sudoersFile + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(sudoersContent), 0o440); err != nil {
		return fmt.Errorf("failed to write temp sudoers file: %w", err)
	}

	if out, err := exec.Command("visudo", "-cf", tmpFile).CombinedOutput(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("visudo validation failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	if err := os.Rename(tmpFile, sudoersFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to install sudoers file: %w", err)
	}

	logger.Info("Sudo lockdown enabled",
		"sudoers_file", sudoersFile,
		"allow_commands", cfg.AllowCommands,
		"username", username)

	return nil
}

// DisableSudoLockdown removes the sudoers lockdown configuration and restores
// the user to the docker group.
func DisableSudoLockdown(cfg *SudoLockdownConfig, logger *slog.Logger) error {
	logger.Info("Disabling sudo lockdown")

	// Remove sudoers file
	if err := os.Remove(sudoersFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Warn("Failed to remove sudoers file", "error", err)
	}

	// Determine the target username for docker group restore
	username := cfg.Username
	if username == "" {
		currentUser, err := user.Current()
		if err == nil {
			if currentUser.Uid == "0" {
				for _, u := range []string{"runner", "github", "ci"} {
					if _, err := user.Lookup(u); err == nil {
						username = u
						break
					}
				}
			} else {
				username = currentUser.Username
			}
		}
	}

	// Re-add user to docker group
	if username != "" {
		if out, err := exec.Command("gpasswd", "-a", username, "docker").CombinedOutput(); err != nil {
			logger.Warn("Failed to re-add user to docker group", "error", err, "output", strings.TrimSpace(string(out)))
		} else {
			logger.Info("Restored user to docker group", "username", username)
		}
	}

	logger.Info("Sudo lockdown disabled")
	return nil
}

// buildSudoersConfig generates the sudoers configuration content.
// The lockdown relies on restricting NOPASSWD to a specific set of commands
// and removing the user from the docker group. Note: sudoers negation (!ALL)
// is intentionally not used because it does not reliably override grants from
// other sudoers files and gives a false sense of security.
func buildSudoersConfig(cfg *SudoLockdownConfig, username string) (string, error) {
	// Merge user commands + always-allowed /usr/bin/kill
	cmds := slices.Clone(cfg.AllowCommands)
	cmds = append(cmds, "/usr/bin/kill")

	if err := validateSudoersInput(username, cmds); err != nil {
		return "", err
	}

	content := fmt.Sprintf(`# CargoWall sudo lockdown configuration
# This file restricts sudo access to prevent firewall bypass
# Generated by cargowall - DO NOT EDIT

# Allowed commands (lockdown relies on restricting NOPASSWD commands
# and removing the user from the docker group)
%s ALL=(ALL) NOPASSWD: %s
`, username, strings.Join(cmds, ", "))

	return content, nil
}
