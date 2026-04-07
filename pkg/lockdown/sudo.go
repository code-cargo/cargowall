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

// disableCompetingSudoersFiles scans /etc/sudoers.d/ for files that grant
// sudo access to the given username — whether via a direct user entry,
// User_Alias membership, or a matching %group grant — and renames them to
// *.cargowall-disabled. Returns the list of original file paths that were
// disabled and an error if any matching file could not be disabled (lockdown
// may be incomplete).
func disableCompetingSudoersFiles(dir, username string, logger *slog.Logger) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read sudoers.d directory: %w", err)
	}

	// Resolve user's group memberships once for all file checks.
	userGIDs, gidErr := lookupUserGIDs(username)
	if gidErr != nil {
		logger.Warn("Failed to look up user groups for sudoers scan, group detection disabled",
			"username", username, "error", gidErr)
	}

	// Collect User_Alias names containing the target user across all files
	// so we can detect cross-file alias-based grants (alias defined in one
	// file, grant using that alias in another).
	aliases := collectUserAliases(dir, username)

	var disabled []string
	var renameFailed []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip our own files and already-disabled files
		if name == filepath.Base(sudoersFile) ||
			name == filepath.Base(stateFile) ||
			strings.HasSuffix(name, ".tmp") ||
			strings.HasSuffix(name, disabledSuffix) {
			continue
		}

		path := filepath.Join(dir, name)
		grants, readErr := sudoersFileGrantsUser(path, username, userGIDs, aliases)
		if readErr != nil {
			logger.Warn("Cannot read sudoers file, treating as potential grant",
				"path", path, "error", readErr)
			renameFailed = append(renameFailed, path)
			continue
		}
		if !grants {
			continue
		}

		disabledPath := path + disabledSuffix
		// Use Link+Remove instead of Rename to atomically fail if the
		// disabled target already exists (Link returns EEXIST).
		if err := os.Link(path, disabledPath); err != nil {
			if errors.Is(err, os.ErrExist) {
				logger.Warn("Disabled target already exists, cannot safely disable sudoers file",
					"path", path, "disabledPath", disabledPath)
			} else {
				logger.Warn("Failed to disable sudoers file",
					"path", path, "error", err)
			}
			renameFailed = append(renameFailed, path)
			continue
		}
		if err := os.Remove(path); err != nil {
			logger.Warn("Failed to remove original after linking disabled copy, cleaning up",
				"path", path, "error", err)
			os.Remove(disabledPath)
			renameFailed = append(renameFailed, path)
			continue
		}
		logger.Info("Disabled competing sudoers file", "path", path)
		disabled = append(disabled, path)
	}

	// Verification re-scan: catch any files that appeared during the disable
	// pass (narrows the TOCTOU window to microseconds).
	if len(renameFailed) == 0 {
		recheck, _ := os.ReadDir(dir)
		for _, entry := range recheck {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if name == filepath.Base(sudoersFile) ||
				name == filepath.Base(stateFile) ||
				strings.HasSuffix(name, ".tmp") ||
				strings.HasSuffix(name, disabledSuffix) {
				continue
			}
			path := filepath.Join(dir, name)
			if grants, _ := sudoersFileGrantsUser(path, username, userGIDs, aliases); grants {
				logger.Warn("New sudoers file appeared during lockdown scan",
					"path", path)
				renameFailed = append(renameFailed, path)
			}
		}
	}

	if len(renameFailed) > 0 {
		return disabled, fmt.Errorf("failed to disable competing sudoers files: %v", renameFailed)
	}
	return disabled, nil
}

// sudoersFileGrantsUser returns true if the file contains a non-comment line
// that either:
//   - starts with the username followed by whitespace (direct grant),
//   - contains the username in a User_Alias definition (indirect grant via alias),
//   - starts with a name present in aliases (cross-file alias grant), or
//   - contains a %group grant where the user is a member of that group.
//
// aliases is the set of User_Alias names (collected across all sudoers.d files)
// that include the target username; it may be nil when cross-file detection is
// not needed.
//
// Returns an error if the file cannot be read or contains #include directives
// that cannot be inspected, so the caller can fail closed.
func sudoersFileGrantsUser(path, username string, userGIDs map[string]bool, aliases map[string]bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("failed to read sudoers file %s: %w", path, err)
	}
	directPrefix := username + " "
	directPrefixTab := username + "\t"
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// #include/#includedir and @include/@includedir are sudoers directives,
		// NOT comments. Modern sudo (1.9.1+) uses the @ form.
		if isIncludeDirective(trimmed) {
			return false, fmt.Errorf("sudoers file %s contains include directive that cannot be inspected", path)
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Defaults !authenticate disables password prompts for all users,
		// effectively granting passwordless sudo to anyone with a grant.
		if strings.HasPrefix(trimmed, "Defaults") && strings.Contains(trimmed, "!authenticate") {
			return false, fmt.Errorf("sudoers file %s contains 'Defaults !authenticate' which bypasses password requirements", path)
		}
		if strings.HasPrefix(trimmed, directPrefix) || strings.HasPrefix(trimmed, directPrefixTab) {
			return true, nil
		}
		// Detect ALL as user specifier — grants every user on the system.
		if fields := strings.Fields(trimmed); len(fields) > 0 && fields[0] == "ALL" {
			return true, nil
		}
		if strings.HasPrefix(trimmed, "User_Alias ") {
			if userAliasContains(trimmed, username) {
				return true, nil
			}
		}
		// Check if line uses a known User_Alias name as a grant (cross-file).
		if len(aliases) > 0 {
			if fields := strings.Fields(trimmed); len(fields) > 0 && aliases[fields[0]] {
				return true, nil
			}
		}
		// Detect %group grants where the user is a member.
		// When userGIDs is nil (lookup failed), treat any %group line as a
		// potential grant (fail-closed) rather than skipping.
		if strings.HasPrefix(trimmed, "%") {
			if userGIDs == nil {
				return true, nil
			}
			groupName := strings.Fields(trimmed)[0][1:]
			if grp, err := user.LookupGroup(groupName); err == nil && userGIDs[grp.Gid] {
				return true, nil
			}
		}
	}
	return false, nil
}

// isIncludeDirective returns true if the line is a sudoers #include,
// #includedir, @include, or @includedir directive. Requires the keyword
// to be followed by a space (and a path), or to be the entire line.
func isIncludeDirective(line string) bool {
	for _, prefix := range []string{"#include ", "#includedir ", "@include ", "@includedir "} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	switch line {
	case "#include", "#includedir", "@include", "@includedir":
		return true
	}
	return false
}

// userAliasContains checks whether a User_Alias line includes the given
// username as a member. Format: "User_Alias NAME = user1, user2, ..."
// Strips trailing inline comments (# ...) before parsing.
// Note: sudoers line continuations (\) are not handled; this is rare for
// User_Alias definitions in practice.
func userAliasContains(line, username string) bool {
	_, after, found := strings.Cut(line, "=")
	if !found {
		return false
	}
	// Strip trailing inline comment
	if idx := strings.Index(after, "#"); idx >= 0 {
		after = after[:idx]
	}
	for _, member := range strings.Split(after, ",") {
		if strings.TrimSpace(member) == username {
			return true
		}
	}
	return false
}

// userAliasName extracts the alias name from a User_Alias line.
// Format: "User_Alias NAME = user1, user2, ..."
func userAliasName(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return ""
	}
	return fields[1]
}

// collectUserAliases scans sudoers files in dir for User_Alias definitions
// that include the given username and returns the set of alias names. This
// enables cross-file detection: an alias defined in one file and used as a
// grant in another.
func collectUserAliases(dir, username string) map[string]bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	aliases := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == filepath.Base(sudoersFile) ||
			name == filepath.Base(stateFile) ||
			strings.HasSuffix(name, ".tmp") ||
			strings.HasSuffix(name, disabledSuffix) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "User_Alias ") && userAliasContains(trimmed, username) {
				if alias := userAliasName(trimmed); alias != "" {
					aliases[alias] = true
				}
			}
		}
	}
	return aliases
}

// restoreDisabledSudoersFiles renames *.cargowall-disabled files back to their
// original paths. Skips files where the original already exists to avoid
// clobbering entries recreated while lockdown was active. Returns true if all
// files were restored successfully (or the list was empty).
func restoreDisabledSudoersFiles(files []string, logger *slog.Logger) bool {
	allOk := true
	for _, original := range files {
		disabledPath := original + disabledSuffix
		if _, err := os.Stat(original); err == nil {
			logger.Warn("Sudoers file already exists at original path, skipping restore",
				"original", original)
			allOk = false
			continue
		}
		if err := os.Rename(disabledPath, original); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				logger.Warn("Failed to restore sudoers file",
					"original", original, "error", err)
				allOk = false
			}
			continue
		}
		logger.Info("Restored sudoers file", "path", original)
	}
	return allOk
}

// findDisabledSudoersFiles scans the sudoers.d directory for files ending in
// disabledSuffix and returns their original paths (with the suffix stripped).
// Used as a fallback when the state file is unavailable.
func findDisabledSudoersFiles(dir string, logger *slog.Logger) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Warn("Failed to scan sudoers.d for orphaned disabled files", "error", err)
		return nil
	}
	var originals []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, disabledSuffix) {
			original := filepath.Join(dir, strings.TrimSuffix(name, disabledSuffix))
			originals = append(originals, original)
		}
	}
	return originals
}

// rollbackState tracks accumulated system changes during EnableSudoLockdown
// so they can be undone if the operation fails at any point.
type rollbackState struct {
	lockdownState
	logger *slog.Logger
}

func (r *rollbackState) rollback() {
	os.Remove(sudoersFile)
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
// when the state file exists but is corrupted.
func recoverLockdownState(dir, username string, logger *slog.Logger) *lockdownState {
	recovered := &lockdownState{Username: username}

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
// and disables competing sudoers.d files.
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
		prev = recoverLockdownState(sudoersDir, username, logger)
	}
	if prev != nil {
		logger.Warn("Found stale lockdown state from previous run, cleaning up first")
		stale := &rollbackState{lockdownState: *prev, logger: logger}
		stale.rollback()
		removeLockdownState()
	}

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
		}
	}()

	// Remove user from sudo-granting groups to neutralize group-based grants
	rb.RemovedGroups, err = removeFromSudoGroups(username, logger)
	if err != nil {
		return fmt.Errorf("sudo lockdown incomplete, group removal failed: %w", err)
	}

	// Disable competing sudoers.d files that grant this user access
	rb.DisabledFiles, err = disableCompetingSudoersFiles(sudoersDir, username, logger)
	if err != nil {
		return fmt.Errorf("sudo lockdown incomplete, competing grants remain active: %w", err)
	}

	// Remove user from docker group to prevent docker-based firewall bypass
	if out, err := exec.Command("gpasswd", "-d", username, "docker").CombinedOutput(); err != nil {
		logger.Warn("Failed to remove user from docker group (user may not be in group)", "error", err, "output", strings.TrimSpace(string(out)))
	} else {
		logger.Info("Removed user from docker group", "username", username)
		rb.DockerRemoved = true
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

	// Validate the overall sudoers configuration after all modifications.
	// If disabling files broke alias/Defaults dependencies, roll back.
	if out, err := exec.Command("visudo", "-c").CombinedOutput(); err != nil {
		logger.Warn("Overall sudoers validation failed after modifications, rolling back",
			"error", err, "output", strings.TrimSpace(string(out)))
		return fmt.Errorf("sudoers validation failed after lockdown modifications: %w", err)
	}

	// Save state so DisableSudoLockdown can reverse all changes
	if err := saveLockdownState(&rb.lockdownState); err != nil {
		logger.Warn("Failed to save lockdown state, rolling back", "error", err)
		return fmt.Errorf("sudo lockdown aborted, state could not be persisted: %w", err)
	}

	success = true
	logger.Info("Sudo lockdown enabled",
		"sudoers_file", sudoersFile,
		"allow_commands", cfg.AllowCommands,
		"username", username,
		"removed_groups", rb.RemovedGroups,
		"disabled_files", rb.DisabledFiles)

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

	// Restore disabled sudoers.d files
	restoreFailed := false
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

	logger.Info("Sudo lockdown disabled")
	if restoreFailed {
		return fmt.Errorf("sudo lockdown disable incomplete: some changes could not be restored; see state file %s", stateFile)
	}
	return nil
}

// buildSudoersConfig generates the sudoers configuration content.
// The lockdown relies on restricting NOPASSWD to a specific set of commands,
// removing the user from sudo-granting groups, and disabling competing
// sudoers.d files. Sudoers negation (!ALL) is intentionally not used because
// it does not reliably override grants from other sudoers files.
func buildSudoersConfig(cfg *SudoLockdownConfig, username string) (string, error) {
	cmds := slices.Clone(cfg.AllowCommands)

	if err := validateSudoersInput(username, cmds); err != nil {
		return "", err
	}

	header := fmt.Sprintf(`# CargoWall sudo lockdown configuration
# This file restricts sudo access to prevent firewall bypass
# Generated by cargowall - DO NOT EDIT
#
# Effective only when combined with disabling competing sudoers.d files
# (renamed to *%s) and removing the user from sudo-granting groups.
`, disabledSuffix)

	if len(cmds) == 0 {
		return header, nil
	}

	content := header + fmt.Sprintf("\n%s ALL=(ALL) NOPASSWD: %s\n",
		username, strings.Join(cmds, ", "))

	return content, nil
}
