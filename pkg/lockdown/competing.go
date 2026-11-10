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

// Competing sudoers.d grants: finding the files that could let the user sudo
// past the lockdown, disabling them, and restoring them afterwards. A file
// sudo reads after the lockdown rules is disabled if it holds any rule line;
// one read before them is judged by parsing a rule's user list, since
// deny-first overrides it whatever it says.

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// ownSudoersEntry reports whether a sudoers.d entry is one of ours or a
// scratch file, which the competing-file scan skips.
func ownSudoersEntry(name string) bool {
	return name == filepath.Base(sudoersFile) ||
		name == filepath.Base(stateFile) ||
		strings.HasSuffix(name, ".tmp") ||
		strings.HasSuffix(name, disabledSuffix) ||
		strings.HasPrefix(name, sudoersTempPrefix)
}

// sudoReadsSudoersD reports whether sudo reads a file of this name from an
// includedir: it skips a name containing '.' or ending in '~'.
func sudoReadsSudoersD(name string) bool {
	return !strings.Contains(name, ".") && !strings.HasSuffix(name, "~")
}

// readAfterLockdown reports whether sudo reads a sudoers.d file of this name
// after the lockdown file. sudo reads the directory in sorted (byte) order,
// and sudoers is last-match-wins, so only a file read after the lockdown
// rules can override them.
func readAfterLockdown(name string) bool {
	return sudoReadsSudoersD(name) && name > filepath.Base(sudoersFile)
}

// disableCompetingSudoersFiles scans /etc/sudoers.d/ for files that could
// grant the user sudo and renames them to *.cargowall-disabled, returning the
// files it disabled.
//
// loadBearing says whether the lockdown depends on this scan. It does not
// when the rules are appended as the last lines of /etc/sudoers: those hold
// whatever a sudoers.d file says, so the scan is for the job summary, and a
// file it cannot inspect or cannot disable is a Warn, never a failed
// lockdown. It does in the fallback where /etc/sudoers cannot be replaced
// and the lockdown rests on its own sudoers.d file: there a file the scan
// cannot inspect is disabled as if it competed (fail-closed), and a file it
// cannot disable fails the lockdown.
//
// A file sudo reads AFTER the lockdown file can override that file's
// deny-first rules, so any such file holding a rule line at all — a user
// specification in any spelling, or an include that pulls in later-read
// lines — counts, without trusting a parser to attribute it to the user. A
// file read before the lockdown file is overridden by it whatever it says,
// so there the parser decides.
//
// userGIDs is the user's group memberships as a running job holds them, from
// before the lockdown removed any. A nil map (the lookup failed) makes any
// %group a potential grant, fail-closed.
func disableCompetingSudoersFiles(dir, username string, userGIDs map[string]bool, loadBearing bool, logger *slog.Logger) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !loadBearing {
			logger.Warn("Cannot scan sudoers.d for competing grants; reporting only, the appended rules hold",
				"dir", dir, "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read sudoers.d directory: %w", err)
	}

	// Collect User_Alias names containing the target user across all files
	// so we can detect cross-file alias-based grants (alias defined in one
	// file, grant using that alias in another).
	aliases := collectUserAliases(dir, username)

	var disabled, failed []string
	// unsettled records a file the scan could not settle: a failure of the
	// lockdown when the scan is load-bearing, a Warn when it is not.
	unsettled := func(path, msg string, args ...any) {
		args = append([]any{"path", path}, args...)
		if !loadBearing {
			logger.Warn(msg+"; reporting only, the appended rules hold", args...)
			return
		}
		logger.Warn(msg, args...)
		failed = append(failed, path)
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || ownSudoersEntry(entry.Name()) {
			continue
		}
		name := entry.Name()
		path := filepath.Join(dir, name)
		seen[name] = true
		competes, reason, readErr := sudoersFileCompetes(path, name, username, userGIDs, aliases)
		if readErr != nil {
			if !loadBearing {
				unsettled(path, "Cannot inspect sudoers file", "error", readErr)
				continue
			}
			// The lockdown rests on this scan: what it cannot inspect is
			// disabled as if it competed.
			competes, reason = true, "cannot be inspected: "+readErr.Error()
		}
		if !competes {
			continue
		}
		if err := disableSudoersFile(path); err != nil {
			unsettled(path, "Failed to disable competing sudoers file", "error", err)
			continue
		}
		logger.Info("Disabled competing sudoers file", "path", path, "reason", reason)
		disabled = append(disabled, path)
	}

	// Verification re-scan: catch any files that appeared during the disable
	// pass (narrows the TOCTOU window to microseconds). Only names the first
	// pass did not see: one it already settled, or reported, is not new.
	if len(failed) == 0 {
		recheck, _ := os.ReadDir(dir)
		for _, entry := range recheck {
			if entry.IsDir() || ownSudoersEntry(entry.Name()) || seen[entry.Name()] {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			competes, _, err := sudoersFileCompetes(path, entry.Name(), username, userGIDs, aliases)
			if competes || (err != nil && loadBearing) {
				unsettled(path, "New sudoers file appeared during lockdown scan")
			}
		}
	}

	if len(failed) > 0 {
		return disabled, fmt.Errorf("failed to disable competing sudoers files: %v", failed)
	}
	return disabled, nil
}

// disableSudoersFile renames path to path+disabledSuffix. It links then
// removes rather than renaming, so it fails (EEXIST) instead of overwriting a
// disabled copy that already exists.
func disableSudoersFile(path string) error {
	disabledPath := path + disabledSuffix
	if err := os.Link(path, disabledPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("a disabled copy %s already exists: %w", disabledPath, err)
		}
		return err
	}
	if err := os.Remove(path); err != nil {
		os.Remove(disabledPath)
		return fmt.Errorf("remove the original after linking its disabled copy: %w", err)
	}
	return nil
}

// sudoersFileGrantsUser returns true if the file contains a sudoers rule
// whose user list grants the target user. A rule's user list is the
// comma-separated list of users that opens the line (`alice, runner ALL=…`);
// the user matches when a non-negated element names them — by name, by
// `#uid`, by a `%group` or `%#gid` they are in, by `ALL`, or by a User_Alias
// — and no later element negates them, as sudoers resolves the list
// last-match-wins. A User_Alias definition that includes them counts too.
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
	uid := ""
	if u, err := user.Lookup(username); err == nil {
		uid = u.Uid
	}
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
		// Defaults !authenticate disables password prompts for all users,
		// effectively granting passwordless sudo to anyone with a grant.
		if isDefaultsLine(trimmed) && strings.Contains(trimmed, "!authenticate") {
			return false, fmt.Errorf("sudoers file %s contains 'Defaults !authenticate' which bypasses password requirements", path)
		}
		if isAliasDefinition(trimmed, "User_Alias") {
			if userAliasContains(trimmed, username) {
				return true, nil
			}
			continue
		}
		// Other definition and default lines are never a user grant; skipping
		// them keeps their leading word out of the user-list parse below.
		if isNonGrantLine(trimmed) {
			continue
		}
		// A comment, unless it is a user named by uid ("#1001 …"): '#' and a
		// digit is a user specifier, not a comment.
		if strings.HasPrefix(trimmed, "#") && !(len(trimmed) >= 2 && trimmed[1] >= '0' && trimmed[1] <= '9') {
			continue
		}
		if userListGrants(grantUserList(trimmed), username, uid, userGIDs, aliases) {
			return true, nil
		}
	}
	return false, nil
}

// hasSudoersKeyword reports whether a line opens with keyword as a whole
// word: followed by the end of the line or one of seps. A bare prefix test
// would read "Defaultsx, runner ALL=…" — a rule for users named Defaultsx and
// runner — as a Defaults line.
func hasSudoersKeyword(line, keyword, seps string) bool {
	rest, ok := strings.CutPrefix(line, keyword)
	return ok && (rest == "" || strings.ContainsRune(seps, rune(rest[0])))
}

// isDefaultsLine reports whether a line is a Defaults entry: the keyword
// alone or bound to a user (':'), host ('@'), command ('!') or runas ('>')
// list.
func isDefaultsLine(trimmed string) bool {
	return hasSudoersKeyword(trimmed, "Defaults", " \t:@!>")
}

// isAliasDefinition reports whether a line defines an alias of the given
// kind ("User_Alias", "Host_Alias", …). Only whitespace may follow the
// keyword; anything else is not a definition and is treated as a rule.
func isAliasDefinition(trimmed, kind string) bool {
	return hasSudoersKeyword(trimmed, kind, " \t")
}

// isNonGrantLine reports whether a line is a sudoers definition or default
// whose leading word is not a user list: a Defaults line, or an alias
// definition other than User_Alias (which the caller handles).
//
// Ignoring every Defaults line is safe under deny-first: a Defaults entry
// sets options, and none can re-open a command the lockdown's !ALL denies.
func isNonGrantLine(trimmed string) bool {
	if isDefaultsLine(trimmed) {
		return true
	}
	for _, kind := range []string{"Host_Alias", "Cmnd_Alias", "Runas_Alias"} {
		if isAliasDefinition(trimmed, kind) {
			return true
		}
	}
	return false
}

// grantUserList is the comma-separated user list that opens a sudoers rule
// line, before the whitespace that begins the host spec. A '!' negation may
// be separated from its user by whitespace ("alice, ! bob, runner"), so a
// space after a dangling '!' stays inside the element rather than ending the
// list. So "alice , runner ALL=(ALL) ..." yields ["alice", "runner"] and
// "alice, ! bob, runner ALL=..." yields ["alice", "!bob", "runner"]. This is
// defense in depth for files read before the lockdown rules and for
// reporting; a file read after them is disabled structurally, parser or not.
func grantUserList(line string) []string {
	var items []string
	var b strings.Builder
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" {
			items = append(items, s)
		}
		b.Reset()
	}
	i, n := 0, len(line)
	for i < n {
		switch c := line[i]; {
		case c == ',':
			flush()
			i++
		case c == ' ' || c == '\t':
			j := i
			for j < n && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			cur := strings.TrimSpace(b.String())
			switch {
			case cur == "" || strings.HasSuffix(cur, "!"):
				i = j // leading space, or a space after a dangling '!'
			case j < n && line[j] == ',':
				i = j // space before a comma: still the same list
			default:
				flush() // the host spec begins
				return items
			}
		default:
			b.WriteByte(c)
			i++
		}
	}
	flush()
	return items
}

// userListGrants resolves whether a rule's user list grants the user, as
// sudoers does: an element may be negated with '!', and the last element to
// name the user wins. An unknown uid or a %group with no group information
// counts as naming the user (fail-closed).
func userListGrants(items []string, username, uid string, userGIDs, aliases map[string]bool) bool {
	granted := false
	for _, item := range items {
		neg := false
		for strings.HasPrefix(item, "!") {
			neg = !neg
			item = strings.TrimLeft(item[1:], " \t")
		}
		if item == "" {
			continue
		}
		if userListItemNames(normalizeUserItem(item), username, uid, userGIDs, aliases) {
			granted = !neg
		}
	}
	return granted
}

// normalizeUserItem removes a user element's sudoers quoting: a backslash
// escapes the next character, and a name may be double-quoted.
func normalizeUserItem(item string) string {
	if strings.Contains(item, `\`) {
		var b strings.Builder
		for i := 0; i < len(item); i++ {
			if item[i] == '\\' && i+1 < len(item) {
				i++
			}
			b.WriteByte(item[i])
		}
		item = b.String()
	}
	if len(item) >= 2 && item[0] == '"' && item[len(item)-1] == '"' {
		item = item[1 : len(item)-1]
	}
	return item
}

// userListItemNames reports whether one user-list element names the target
// user: ALL, the username, a known User_Alias, a "#uid", a "%group" /
// "%#gid" the user belongs to, or a "+netgroup" (which it cannot resolve, so
// it counts, fail-closed).
func userListItemNames(item, username, uid string, userGIDs, aliases map[string]bool) bool {
	switch {
	case item == "ALL", item == username, aliases[item]:
		return true
	}
	if strings.HasPrefix(item, "+") {
		return true // a netgroup, membership unknowable here: fail closed
	}
	if id, ok := strings.CutPrefix(item, "#"); ok {
		// A user by uid; an unknown target uid counts as a match.
		return uid == "" || id == uid
	}
	grp, byGroup := strings.CutPrefix(item, "%")
	if !byGroup {
		return false
	}
	if userGIDs == nil {
		return true // group membership unknown: fail closed
	}
	if gid, byID := strings.CutPrefix(grp, "#"); byID {
		return userGIDs[gid]
	}
	g, err := user.LookupGroup(grp)
	return err == nil && userGIDs[g.Gid]
}

// sudoersFileCompetes reports whether a sudoers.d file could grant the user
// sudo past the lockdown, and a short reason. A file sudo reads after the
// lockdown file is judged structurally — it competes if it holds any rule
// line at all — because a grant there, in any spelling, overrides the
// deny-first rules; a parser miss there would be a hole. A file read before
// the lockdown rules is overridden by them, so the parser decides and a miss
// cannot matter.
func sudoersFileCompetes(path, name, username string, userGIDs, aliases map[string]bool) (bool, string, error) {
	if readAfterLockdown(name) {
		has, err := fileHasEffectiveRule(path)
		if err != nil {
			return false, "", err
		}
		if has {
			return true, "read after the lockdown rules", nil
		}
		return false, "", nil
	}
	grants, err := sudoersFileGrantsUser(path, username, userGIDs, aliases)
	if err != nil {
		return false, "", err
	}
	return grants, "grants the user", nil
}

// fileHasEffectiveRule reports whether a sudoers file holds a line sudo would
// act on: a user specification (in any spelling) or an include directive.
// Blank lines, comments, Defaults and alias definitions are inert on their
// own. An unreadable file is an error, so the caller fails closed.
func fileHasEffectiveRule(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("failed to read sudoers file %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if isIncludeDirective(trimmed) {
			return true, nil // pulls in lines read after the lockdown rules
		}
		// A '#' and a digit is a user named by uid, not a comment.
		if strings.HasPrefix(trimmed, "#") && !(len(trimmed) >= 2 && trimmed[1] >= '0' && trimmed[1] <= '9') {
			continue
		}
		if isNonGrantLine(trimmed) || isAliasDefinition(trimmed, "User_Alias") {
			continue
		}
		return true, nil // a user specification
	}
	return false, nil
}

// isIncludeDirective returns true if the line is a sudoers #include,
// #includedir, @include, or @includedir directive. The keyword may be
// followed by whitespace, by the end of the line, or — as sudo-rs accepts —
// by the path with no separator ("#include/etc/x"). This is used only for
// reporting now that the appended block, not the read order of sudoers.d,
// holds the lockdown; erring toward "directive" only disables an inert file,
// the safe direction. A non-directive "#..." (a comment, a #uid) is handled
// by the caller.
func isIncludeDirective(line string) bool {
	for _, kw := range []string{"#includedir", "@includedir", "#include", "@include"} {
		if rest, ok := strings.CutPrefix(line, kw); ok {
			if rest == "" || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '/' {
				return true
			}
		}
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
			if isAliasDefinition(trimmed, "User_Alias") && userAliasContains(trimmed, username) {
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
