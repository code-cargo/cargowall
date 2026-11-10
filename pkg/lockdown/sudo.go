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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
)

const (
	sudoersDir  = "/etc/sudoers.d"
	sudoersFile = "/etc/sudoers.d/zz-cargowall-lockdown"
	// stateFile uses a dotfile name — sudo's #includedir/@includedir processing
	// ignores files containing '.' so this cannot interfere with sudoers parsing.
	stateFile      = "/etc/sudoers.d/.cargowall-lockdown-state"
	disabledSuffix = ".cargowall-disabled"
)

var sudoGrantingGroups = []string{"sudo", "admin", "wheel"}

// SudoLockdownConfig configures the sudo lockdown behavior
type SudoLockdownConfig struct {
	// AllowCommands is a list of command paths to whitelist via NOPASSWD
	AllowCommands []string
	// Username is the user to configure sudoers for (auto-detected if empty)
	Username string
}

// lockdownState records changes made during EnableSudoLockdown so they can be
// reversed by DisableSudoLockdown.
type lockdownState struct {
	Username      string   `json:"username"`
	RemovedGroups []string `json:"removedGroups"`
	DisabledFiles []string `json:"disabledFiles"`
	DockerRemoved bool     `json:"dockerRemoved"`
	// SudoersBlock is whether the lockdown rules were also appended to
	// /etc/sudoers, for a file that does not read sudoers.d last.
	SudoersBlock bool `json:"sudoersBlock,omitempty"`
}

const sudoersUnsafeChars = " ,#\n\r\t`;&!()\\|*?[]"

// validateSudoersInput checks that a username and command paths do not contain
// characters that could alter sudoers semantics.
func validateSudoersInput(username string, cmds []string) error {
	if username == "" {
		return fmt.Errorf("sudoers username must not be empty")
	}
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

// resolveUsername determines the target username from config or auto-detection.
// When cfgUsername is set it is returned directly. Otherwise the current user
// is used, falling back to common CI usernames when running as root.
func resolveUsername(cfgUsername string) (string, error) {
	if cfgUsername != "" {
		return cfgUsername, nil
	}
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}
	if currentUser.Uid != "0" {
		return currentUser.Username, nil
	}
	// Running as root — try common CI usernames
	for _, u := range []string{"runner", "github", "ci"} {
		if _, err := user.Lookup(u); err == nil {
			return u, nil
		}
	}
	return "", fmt.Errorf("could not determine target username for sudo lockdown")
}

// lookupUserGIDs returns the set of group IDs the user belongs to.
func lookupUserGIDs(username string) (map[string]bool, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(gids))
	for _, gid := range gids {
		set[gid] = true
	}
	return set, nil
}

// removeFromSudoGroups removes the user from sudo-granting groups and returns
// the list of groups the user was actually removed from. Returns an error if
// any group removal fails. Groups that don't exist or that the user is not a
// member of are skipped (checked via os/user, not gpasswd output parsing).
func removeFromSudoGroups(username string, logger *slog.Logger) ([]string, error) {
	userGIDs, gidErr := lookupUserGIDs(username)
	if gidErr != nil {
		// Fail closed: attempt removal from all groups rather than skipping
		logger.Warn("Failed to look up user groups, attempting removal from all sudo-granting groups",
			"username", username, "error", gidErr)
	}

	var removed []string
	var failures []string
	for _, group := range sudoGrantingGroups {
		grp, err := user.LookupGroup(group)
		if err != nil {
			logger.Debug("Group does not exist, skipping",
				"username", username, "group", group)
			continue
		}
		if userGIDs != nil && !userGIDs[grp.Gid] {
			logger.Debug("User not in group, skipping",
				"username", username, "group", group)
			continue
		}
		out, err := exec.Command("gpasswd", "-d", username, group).CombinedOutput()
		if err != nil {
			logger.Warn("Failed to remove user from group",
				"username", username, "group", group,
				"error", err, "output", strings.TrimSpace(string(out)))
			failures = append(failures, group)
			continue
		}
		logger.Info("Removed user from group", "username", username, "group", group)
		removed = append(removed, group)
	}
	if len(failures) > 0 {
		return removed, fmt.Errorf("failed to remove user from groups: %v", failures)
	}
	return removed, nil
}

// restoreToGroups re-adds the user to the given groups. Returns true if all
// groups were restored successfully (or the list was empty).
func restoreToGroups(username string, groups []string, logger *slog.Logger) bool {
	allOk := true
	for _, group := range groups {
		out, err := exec.Command("gpasswd", "-a", username, group).CombinedOutput()
		if err != nil {
			logger.Warn("Failed to re-add user to group",
				"username", username, "group", group,
				"error", err, "output", strings.TrimSpace(string(out)))
			allOk = false
			continue
		}
		logger.Info("Restored user to group", "username", username, "group", group)
	}
	return allOk
}

// rollbackState tracks accumulated system changes during EnableSudoLockdown
// so they can be undone if the operation fails at any point.
type rollbackState struct {
	lockdownState
	logger *slog.Logger
}

func (r *rollbackState) rollback() {
	os.Remove(sudoersFile)
	// Unconditional: the block is found by its markers, and a run that
	// crashed after appending it never recorded that it did.
	if _, err := removeSudoersBlock(mainSudoers); err != nil {
		r.logger.Warn("Failed to remove the lockdown block from sudoers during rollback",
			"path", mainSudoers, "error", err)
	}
	restoreDisabledSudoersFiles(r.DisabledFiles, r.logger)
	if r.Username != "" {
		restoreToGroups(r.Username, r.RemovedGroups, r.logger)
		if r.DockerRemoved {
			if out, err := exec.Command("gpasswd", "-a", r.Username, "docker").CombinedOutput(); err != nil {
				r.logger.Warn("Failed to restore docker group during rollback",
					"error", err, "output", strings.TrimSpace(string(out)))
			}
		}
	}
}

// saveLockdownState atomically writes the lockdown state to disk.
func saveLockdownState(state *lockdownState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal lockdown state: %w", err)
	}
	tmp := stateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("failed to write lockdown state: %w", err)
	}
	if err := os.Rename(tmp, stateFile); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to install lockdown state: %w", err)
	}
	return nil
}

// loadLockdownState reads the lockdown state from disk. Returns nil if no
// state file exists.
func loadLockdownState() (*lockdownState, error) {
	data, err := os.ReadFile(stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read lockdown state: %w", err)
	}
	var state lockdownState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse lockdown state: %w", err)
	}
	return &state, nil
}

func removeLockdownState() {
	os.Remove(stateFile)
}

// recoverLockdownState attempts to reconstruct a lockdownState by scanning
// the filesystem for evidence of a previous lockdown run. Used as a fallback
// when the state file exists but is corrupted. main is the sudoers file a
// lockdown block may have been appended to.
func recoverLockdownState(dir, main, username string, logger *slog.Logger) *lockdownState {
	recovered := &lockdownState{Username: username}

	if data, err := os.ReadFile(main); err == nil {
		if _, found, _ := withoutBlock(string(data)); found {
			recovered.SudoersBlock = true
			logger.Info("Recovered the lockdown block in sudoers", "path", main)
		}
	}

	// Recover disabled files by scanning for *.cargowall-disabled files.
	recovered.DisabledFiles = findDisabledSudoersFiles(dir, logger)
	if len(recovered.DisabledFiles) > 0 {
		logger.Info("Recovered disabled sudoers files from filesystem scan",
			"count", len(recovered.DisabledFiles), "files", recovered.DisabledFiles)
	}

	// Recover removed groups: any sudo-granting group the user is NOT
	// currently a member of is assumed to have been removed by a previous
	// lockdown. Over-restoring via gpasswd -a is idempotent and safe.
	userGIDs, err := lookupUserGIDs(username)
	if err != nil {
		// Cannot determine membership — assume all were removed (fail-closed).
		logger.Warn("Cannot look up user groups for state recovery, assuming all sudo groups removed",
			"username", username, "error", err)
		recovered.RemovedGroups = append(recovered.RemovedGroups, sudoGrantingGroups...)
	} else {
		for _, group := range sudoGrantingGroups {
			grp, lookupErr := user.LookupGroup(group)
			if lookupErr != nil {
				continue // group does not exist on this system
			}
			if !userGIDs[grp.Gid] {
				recovered.RemovedGroups = append(recovered.RemovedGroups, group)
			}
		}
	}
	if len(recovered.RemovedGroups) > 0 {
		logger.Info("Inferred previously removed sudo groups",
			"groups", recovered.RemovedGroups)
	}

	// Docker group: if user is not a member, assume we removed them.
	if userGIDs != nil {
		if grp, lookupErr := user.LookupGroup("docker"); lookupErr == nil && !userGIDs[grp.Gid] {
			recovered.DockerRemoved = true
			logger.Info("Inferred docker group was previously removed")
		}
	}

	return recovered
}

// EnableSudoLockdown configures sudoers to restrict what commands can be run
// with sudo, removes the target user from sudo-granting and docker groups,
// and disables competing sudoers.d files. It then checks, as a job step,
// that sudo refuses a command the allowlist does not name, and undoes it
// all with an error when sudo does not.
func EnableSudoLockdown(cfg *SudoLockdownConfig, logger *slog.Logger) error {
	logger.Info("Enabling sudo lockdown")

	username, err := resolveUsername(cfg.Username)
	if err != nil {
		return err
	}
	logger.Debug("Target user for sudo lockdown", "username", username)

	// Clean up stale state from a previous run that was not shut down cleanly
	prev, prevErr := loadLockdownState()
	if prevErr != nil {
		logger.Warn("Lockdown state file is corrupted, attempting best-effort recovery",
			"error", prevErr, "state_file", stateFile)
		prev = recoverLockdownState(sudoersDir, mainSudoers, username, logger)
	}
	if prev != nil {
		logger.Warn("Found stale lockdown state from previous run, cleaning up first")
		stale := &rollbackState{lockdownState: *prev, logger: logger}
		stale.rollback()
		removeLockdownState()
	}

	// Remove any scratch files a crashed run left beside /etc/sudoers.
	cleanStaleSudoersTemps(filepath.Dir(mainSudoers), logger)

	// Set up deferred rollback — disabled on success. Every error path after
	// this point automatically undoes all system modifications.
	rb := &rollbackState{
		lockdownState: lockdownState{Username: username},
		logger:        logger,
	}
	success := false
	defer func() {
		if !success {
			rb.rollback()
			// The state is saved before verification, so a failed
			// verification's rollback removes it too.
			removeLockdownState()
		}
	}()

	// The groups as a process started before the lockdown holds them, which
	// removing the user from a group below does not change. Both the competing
	// %group scan and the verification need them as a running step has them.
	preGIDs, preErr := lookupUserGIDs(username)
	if preErr != nil {
		logger.Warn("Failed to look up user groups before lockdown; %group grant detection is fail-closed",
			"username", username, "error", preErr)
	}

	// Remove user from sudo-granting groups, for logins after the lockdown;
	// the rules below are what hold against processes already running.
	rb.RemovedGroups, err = removeFromSudoGroups(username, logger)
	if err != nil {
		return fmt.Errorf("sudo lockdown incomplete, group removal failed: %w", err)
	}

	// Remove user from the docker group. Like the sudo groups, this reaches
	// only logins after the lockdown: running job steps keep the docker
	// socket, which warnDockerAccess reports.
	if out, err := exec.Command("gpasswd", "-d", username, "docker").CombinedOutput(); err != nil {
		logger.Warn("Failed to remove user from docker group (user may not be in group)", "error", err, "output", strings.TrimSpace(string(out)))
	} else {
		logger.Info("Removed user from docker group for later logins; running job steps keep it", "username", username)
		rb.DockerRemoved = true
	}

	// Build the sudoers configuration
	sudoersContent, err := buildSudoersConfig(cfg, username)
	if err != nil {
		return fmt.Errorf("failed to build sudoers config: %w", err)
	}
	rules := lockdownRules(username, cfg.AllowCommands)

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

	// The same rules go at the end of /etc/sudoers, where sudo reads them
	// after every sudoers.d file and every include: that is what holds the
	// lockdown, whatever a competing file contains or how it is spelled. The
	// sudoers.d file above is a duplicate, read earlier on a distro whose
	// /etc/sudoers includes the directory, and never read on an image whose
	// does not — except where /etc/sudoers cannot be replaced, when it is the
	// fallback (applySudoersBlock says so).
	rb.SudoersBlock, err = applySudoersBlock(mainSudoers, sudoersDir, rules, logger)
	if err != nil {
		return fmt.Errorf("sudo lockdown incomplete, %s could not be amended with the lockdown rules: %w", mainSudoers, err)
	}

	// Disable competing sudoers.d files that grant this user access, matched
	// against the groups from before the removal above. With the rules
	// appended, this is for the job summary only and cannot fail the
	// lockdown; in the fallback it is load-bearing.
	rb.DisabledFiles, err = disableCompetingSudoersFiles(sudoersDir, username, preGIDs, !rb.SudoersBlock, logger)
	if err != nil {
		return fmt.Errorf("sudo lockdown incomplete, competing grants remain active: %w", err)
	}

	// Validate the overall sudoers configuration after all modifications, and
	// roll back if sudo would not parse it. visudo only warns about an alias a
	// disabled file left undefined, so that does not stop the lockdown;
	// nothing relies on it, since the appended rules are read last regardless.
	if out, err := exec.Command("visudo", "-c").CombinedOutput(); err != nil {
		logger.Warn("Overall sudoers validation failed after modifications, rolling back",
			"error", err, "output", strings.TrimSpace(string(out)))
		return fmt.Errorf("sudoers validation failed after lockdown modifications: %w", err)
	}

	// Save state first, so a forced teardown during the verification below
	// restores the groups too, not only the sudoers files. A failed
	// verification's rollback removes the state (the deferred cleanup).
	//
	// A crash before this point leaves no state file. The appended block and
	// the disabled sudoers.d files are still found and undone by scan (by
	// their markers and their suffix), but the removed groups are restored
	// only from state, so they stay removed. Accepted: it matters only on a
	// reused runner, where teardown work is kept proportionate.
	if err := saveLockdownState(&rb.lockdownState); err != nil {
		logger.Warn("Failed to save lockdown state, rolling back", "error", err)
		return fmt.Errorf("sudo lockdown aborted, state could not be persisted: %w", err)
	}

	// Ask sudo, as a job step, whether the lockdown holds, and report the
	// docker access it leaves, which fails nothing.
	if view, err := lookupJobView(username, preGIDs); err != nil {
		logger.Warn("Cannot verify sudo lockdown, leaving it in place: a job step's credentials are unknown", "username", username, "error", err)
	} else if err := verifyLockdown(view, cfg.AllowCommands, logger); err != nil {
		return err
	} else {
		warnDockerAccess(view, logger)
	}

	success = true
	logger.Info("Sudo lockdown enabled",
		"sudoers_file", sudoersFile,
		"allow_commands", cfg.AllowCommands,
		"username", username,
		"removed_groups", rb.RemovedGroups,
		"disabled_files", rb.DisabledFiles,
		"sudoers_block", rb.SudoersBlock)

	return nil
}

// DisableSudoLockdown removes the sudoers lockdown configuration, restores
// disabled sudoers.d files, and re-adds the user to removed groups.
func DisableSudoLockdown(cfg *SudoLockdownConfig, logger *slog.Logger) error {
	logger.Info("Disabling sudo lockdown")

	// Load state to know what to restore
	state, err := loadLockdownState()
	if err != nil {
		logger.Warn("Failed to load lockdown state, falling back to best-effort cleanup", "error", err)
	}

	// Remove lockdown sudoers file first so that a crash during the
	// remaining restore steps leaves the user with their original grants
	// (safe direction) rather than both lockdown + original grants active.
	if err := os.Remove(sudoersFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Warn("Failed to remove sudoers file", "error", err)
	}

	// The block goes next, for the same reason. Removed by its markers
	// whatever the state says, which a crash may have left without it.
	restoreFailed := false
	if removed, err := removeSudoersBlock(mainSudoers); err != nil {
		logger.Warn("Failed to remove the lockdown block from sudoers", "path", mainSudoers, "error", err)
		restoreFailed = true
	} else if removed {
		logger.Info("Removed the lockdown block from sudoers", "path", mainSudoers)
	}

	// Restore disabled sudoers.d files
	if state != nil {
		if !restoreDisabledSudoersFiles(state.DisabledFiles, logger) {
			restoreFailed = true
		}
	} else {
		// State is unavailable — scan for orphaned *.cargowall-disabled files
		// so they don't remain disabled indefinitely.
		if orphaned := findDisabledSudoersFiles(sudoersDir, logger); len(orphaned) > 0 {
			logger.Warn("Found orphaned disabled sudoers files without state, restoring",
				"files", orphaned)
			if !restoreDisabledSudoersFiles(orphaned, logger) {
				restoreFailed = true
			}
		}
	}

	// Determine username for group restoration
	username := ""
	if state != nil {
		username = state.Username
	}
	if username == "" {
		resolvedUsername, resolveErr := resolveUsername(cfg.Username)
		if resolveErr != nil {
			logger.Warn("Failed to resolve username for group/docker restoration, keeping state for manual recovery",
				"error", resolveErr)
			restoreFailed = true
		} else {
			username = resolvedUsername
		}
	}

	// Re-add to sudo-granting groups
	if state != nil && username != "" {
		if !restoreToGroups(username, state.RemovedGroups, logger) {
			restoreFailed = true
		}
	}

	// Re-add user to docker group only if state confirms we removed them
	if username != "" && state != nil && state.DockerRemoved {
		if out, err := exec.Command("gpasswd", "-a", username, "docker").CombinedOutput(); err != nil {
			logger.Warn("Failed to re-add user to docker group", "error", err, "output", strings.TrimSpace(string(out)))
			restoreFailed = true
		} else {
			logger.Info("Restored user to docker group", "username", username)
		}
	}

	// Only remove state file if all restores succeeded; keep it for manual
	// recovery otherwise.
	if restoreFailed {
		logger.Warn("Some changes could not be restored; keeping state file for manual recovery",
			"state_file", stateFile)
	} else {
		removeLockdownState()
	}

	cleanStaleSudoersTemps(filepath.Dir(mainSudoers), logger)

	logger.Info("Sudo lockdown disabled")
	if restoreFailed {
		return fmt.Errorf("sudo lockdown disable incomplete: some changes could not be restored; see state file %s", stateFile)
	}
	return nil
}

// buildSudoersConfig generates the sudoers configuration content: a header
// and lockdownRules.
func buildSudoersConfig(cfg *SudoLockdownConfig, username string) (string, error) {
	cmds := slices.Clone(cfg.AllowCommands)

	if err := validateSudoersInput(username, cmds); err != nil {
		return "", err
	}

	header := fmt.Sprintf(`# CargoWall sudo lockdown configuration
# This file restricts sudo access to prevent firewall bypass
# Generated by cargowall - DO NOT EDIT
#
# The first rule denies the user every command, and the allowlist follows.
# Sudoers is last-match-wins, so they hold against any grant read before
# them, a group's included, whatever groups a running process kept.
# Competing sudoers.d files are disabled as well (renamed to *%s), and the
# user is removed from sudo-granting groups for later logins.
`, disabledSuffix)

	return header + "\n" + lockdownRules(username, cmds), nil
}

// lockdownRules are the lockdown's sudoers rules: everything denied to the
// user, then the allowlist allowed without a password. The deny holds for
// any command the allowlist does not name, as the last rule to match it,
// against every grant read before it. The caller has validated both.
func lockdownRules(username string, cmds []string) string {
	rules := username + " ALL=(ALL:ALL) !ALL\n"
	if len(cmds) > 0 {
		rules += fmt.Sprintf("%s ALL=(ALL) NOPASSWD: %s\n", username, strings.Join(cmds, ", "))
	}
	return rules
}
