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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSudoersFileGrantsUser_groupByID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sudoers")
	gids := map[string]bool{"27": true}
	for content, want := range map[string]bool{
		"%#27 ALL=(ALL:ALL) NOPASSWD:ALL\n":        true,
		"%#28 ALL=(ALL:ALL) NOPASSWD:ALL\n":        false,
		"%#28, %#27 ALL=(ALL:ALL) NOPASSWD:ALL\n":  true,  // gid in a comma list
		"%#27,%#28 ALL=(ALL:ALL) NOPASSWD:ALL\n":   true,  // no space after the comma
		"%#28,%#29 ALL=(ALL:ALL) NOPASSWD:ALL\n":   false, // neither gid is the user's
		"alice, %#27 ALL=(ALL:ALL) NOPASSWD:ALL\n": true,  // mixed name + gid
		"%#28, alice ALL=(ALL:ALL) NOPASSWD:ALL\n": false, // neither names runner
		"ALL, !%#27 ALL=(ALL:ALL) NOPASSWD:ALL\n":  false, // the group negated out of ALL
	} {
		writeFile(t, path, content)
		if got, err := sudoersFileGrantsUser(path, "runner", gids, nil); err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", content, got, err, want)
		}
	}
}

// TestSudoersFileGrantsUser_userList: the user list that opens a rule is
// comma-separated, so a grant naming the target anywhere in it must be
// detected — the shape a plain "line starts with the username" check misses.
func TestSudoersFileGrantsUser_userList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sudoers")
	cases := []struct {
		content  string
		username string
		want     bool
	}{
		{"alice, runner ALL=(ALL) NOPASSWD: /bin/cat\n", "runner", true},
		{"runner, alice ALL=(ALL) NOPASSWD: /bin/cat\n", "runner", true},
		{"alice , runner ALL=(ALL) NOPASSWD: /bin/cat\n", "runner", true},
		{"alice,runner ALL=(ALL) NOPASSWD: /bin/cat\n", "runner", true},
		{"alice, bob ALL=(ALL) NOPASSWD: /bin/cat\n", "runner", false},
		{"ALL, !runner ALL=(ALL) NOPASSWD:ALL\n", "runner", false},        // excluded from ALL
		{"!runner, ALL ALL=(ALL) NOPASSWD:ALL\n", "runner", true},         // re-added after
		{"#999, #0 ALL=(ALL:ALL) NOPASSWD:ALL\n", "root", true},           // uid in a comma list
		{"#999, #1001 ALL=(ALL:ALL) NOPASSWD:ALL\n", "root", false},       // neither is 0
		{`"runner" ALL=(ALL) NOPASSWD: /bin/cat` + "\n", "runner", true},  // quoted name
		{"alice, ! bob, runner ALL=(ALL) NOPASSWD:ALL\n", "runner", true}, // space after '!'
		{`ru\nner ALL=(ALL) NOPASSWD: /bin/cat` + "\n", "runner", true},   // backslash escape
		{"alice, !runner ALL=(ALL) NOPASSWD:ALL\n", "runner", false},      // negated only
		{"+net, runner ALL=(ALL) NOPASSWD:ALL\n", "runner", true},         // runner beside a netgroup
		{"+net ALL=(ALL) NOPASSWD:ALL\n", "runner", true},                 // netgroup: unknowable, fail-closed
	}
	for _, tt := range cases {
		writeFile(t, path, tt.content)
		if got, err := sudoersFileGrantsUser(path, tt.username, nil, nil); err != nil || got != tt.want {
			t.Errorf("%q (%s): got %v, %v; want %v", tt.content, tt.username, got, err, tt.want)
		}
	}
}

// TestSudoersFileCompetes: a file read after the lockdown rules is judged
// structurally — any rule line in any spelling, or an include, disables it,
// even one granting another user — while a file read before them is judged
// by parsing, where a miss is harmless because deny-first overrides it.
func TestSudoersFileCompetes(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		// Read after zz-cargowall-lockdown (structural).
		{"zzz-list", `"runner" ALL=(ALL) NOPASSWD: /bin/cat` + "\n", true},
		{"zzz-other", "someoneelse ALL=(ALL) NOPASSWD:ALL\n", true}, // another user, still disabled
		{"zzz-uid", "#1234 ALL=(ALL) NOPASSWD:ALL\n", true},
		{"zzz-include", "@includedir /etc/sudoers.extra\n", true},
		{"zzz-tab-include", "#include\t/etc/grant\n", true},   // a tab separator
		{"zzz-nosep-include", "#include/etc/grant\n", true},   // no separator (sudo-rs)
		{"zzz-tab-includedir", "#includedir\t/etc/x\n", true}, // includedir with a tab
		{"zzz-notes", "# just a comment\n\n# END\n", false},
		{"zzz-hash-tab", "#\ta tab comment\n", false}, // '#' + whitespace is a comment
		{"zzz-defaults", "Defaults:runner !requiretty\nUser_Alias FOO = a, b\n", false},
		{"zzz-defaults-forms", "Defaults\tenv_reset\nDefaults@host x\nDefaults!/bin/ls noexec\nDefaults>root x\nDefaults\n" +
			"Host_Alias H = h\nCmnd_Alias C = /bin/ls\nRunas_Alias R = root\n", false},
		{"zzz-defaultsx", "Defaultsx, runner ALL=(ALL) NOPASSWD:ALL\n", true},     // a rule, not a Defaults line
		{"zzz-user-aliasx", "User_Aliasx, runner ALL=(ALL) NOPASSWD:ALL\n", true}, // a rule, not an alias
		{"zzz-dotted.bak", "someoneelse ALL=(ALL) NOPASSWD:ALL\n", false},         // sudo ignores dotted names
		// Read before zz-cargowall-lockdown (parser; deny-first overrides).
		{"00-other", "someoneelse ALL=(ALL) NOPASSWD:ALL\n", false},
		{"00-runner", "runner ALL=(ALL) NOPASSWD:ALL\n", true},
		{"00-defaultsx", "Defaultsx, runner ALL=(ALL) NOPASSWD:ALL\n", true}, // parsed as a user list
	}
	for _, tt := range cases {
		path := filepath.Join(dir, tt.name)
		writeFile(t, path, tt.content)
		got, reason, err := sudoersFileCompetes(path, tt.name, "runner", nil, nil)
		if err != nil || got != tt.want {
			t.Errorf("%s %q: got %v (%s), %v; want %v", tt.name, tt.content, got, reason, err, tt.want)
		}
		if got && reason == "" {
			t.Errorf("%s: a competing file has no reason", tt.name)
		}
		os.Remove(path)
	}
}

// TestReadAfterLockdown pins sudo's own read order: bytewise strcmp,
// case-sensitive, C locale, skipping a name with '.' or ending in '~'.
func TestReadAfterLockdown(t *testing.T) {
	for name, want := range map[string]bool{
		"zz-cargowall-lockdown": false, // the lockdown file itself
		"zz-team":               true,
		"zzz":                   true,
		"zzz-team":              true,
		"zz0-local":             true,
		"zz_cargowall":          true,  // '_' (0x5F) sorts after '-' (0x2D)
		"ZZ-after":              false, // uppercase sorts before lowercase
		"ZZZ-team":              false, // would sort after if case were folded
		"00-base":               false,
		"README":                false,
		"zzz-team.bak":          false, // dotted: sudo ignores it
		"zzz-team~":             false, // backup: sudo ignores it
	} {
		if got := readAfterLockdown(name); got != want {
			t.Errorf("readAfterLockdown(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestSudoersFileGrantsUser_aliasInList: a User_Alias used anywhere in the
// user list, not only as the whole list, grants its members.
func TestSudoersFileGrantsUser_aliasInList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sudoers")
	aliases := map[string]bool{"ADMINS": true}
	for content, want := range map[string]bool{
		"ADMINS, alice ALL=(ALL) NOPASSWD:ALL\n": true,
		"alice, ADMINS ALL=(ALL) NOPASSWD:ALL\n": true,
		"alice, bob ALL=(ALL) NOPASSWD:ALL\n":    false,
	} {
		writeFile(t, path, content)
		if got, err := sudoersFileGrantsUser(path, "runner", nil, aliases); err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", content, got, err, want)
		}
	}
}

func TestSudoersFileGrantsUser(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		username string
		want     bool
		wantErr  bool
	}{
		{
			name:     "direct grant matches",
			content:  "runner ALL=(ALL) NOPASSWD:ALL\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "grant with tab separator",
			content:  "runner\tALL=(ALL) NOPASSWD:ALL\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "comment line ignored",
			content:  "# runner ALL=(ALL) NOPASSWD:ALL\n",
			username: "runner",
			want:     false,
		},
		{
			name:     "different user no match",
			content:  "admin ALL=(ALL) NOPASSWD:ALL\n",
			username: "runner",
			want:     false,
		},
		{
			name:     "group grant matches when GIDs unknown (fail-closed)",
			content:  "%sudo ALL=(ALL:ALL) ALL\n",
			username: "runner",
			want:     true, // nil GIDs = any %group is a potential grant
		},
		{
			name:     "empty file",
			content:  "",
			username: "runner",
			want:     false,
		},
		{
			name:     "username as substring does not match",
			content:  "runner2 ALL=(ALL) ALL\n",
			username: "runner",
			want:     false,
		},
		{
			name: "match among multiple lines",
			content: `# Defaults
Defaults env_reset
runner ALL=(ALL) NOPASSWD:ALL
`,
			username: "runner",
			want:     true,
		},
		{
			name:     "User_Alias with target user matches",
			content:  "User_Alias RUNNERS = runner, admin\nRUNNERS ALL=(ALL) ALL\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "User_Alias without target user does not match",
			content:  "User_Alias ADMINS = admin, root\nADMINS ALL=(ALL) ALL\n",
			username: "runner",
			want:     false,
		},
		{
			name:     "User_Alias single user",
			content:  "User_Alias CI = runner\nCI ALL=(ALL) NOPASSWD:ALL\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "User_Alias with inline comment",
			content:  "User_Alias CI = runner # CI user\nCI ALL=(ALL) ALL\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "hash include directive returns error",
			content:  "#include /etc/sudoers.d/extra\n",
			username: "runner",
			wantErr:  true,
		},
		{
			name:     "hash includedir directive returns error",
			content:  "#includedir /etc/sudoers.d/extra.d\n",
			username: "runner",
			wantErr:  true,
		},
		{
			name:     "at-include directive returns error",
			content:  "@include /etc/sudoers.d/extra\n",
			username: "runner",
			wantErr:  true,
		},
		{
			name:     "at-includedir directive returns error",
			content:  "@includedir /etc/sudoers.d/extra.d\n",
			username: "runner",
			wantErr:  true,
		},
		{
			name:     "Defaults !authenticate returns error",
			content:  "Defaults !authenticate\n",
			username: "runner",
			wantErr:  true,
		},
		{
			name:     "Defaults with authenticate negation in context returns error",
			content:  "Defaults:runner !authenticate\n",
			username: "runner",
			wantErr:  true,
		},
		{
			name:     "group grant matches when GIDs nil (fail-closed)",
			content:  "%ops ALL=(ALL) ALL\n",
			username: "runner",
			want:     true, // nil GIDs = treat any %group as potential grant
		},
		{
			name:     "ALL user specifier grants all users",
			content:  "ALL ALL=(ALL) NOPASSWD: ALL\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "ALL user specifier with specific commands",
			content:  "ALL ALL=(ALL) NOPASSWD: /usr/bin/apt\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "ALL user specifier with tab separator",
			content:  "ALL\tALL=(ALL) ALL\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "ALL in comment line is ignored",
			content:  "# ALL ALL=(ALL) ALL\n",
			username: "runner",
			want:     false,
		},
		{
			name:     "hash-includes non-directive treated as comment",
			content:  "#includes_discussion\nrunner ALL=(ALL) ALL\n",
			username: "runner",
			want:     true,
		},
		{
			name:     "grant by uid matches",
			content:  "#0 ALL=(ALL) NOPASSWD:ALL\n",
			username: "root",
			want:     true,
		},
		{
			name:     "grant by uid in a user list matches",
			content:  "#4242,#0 ALL=(ALL) NOPASSWD:ALL\n",
			username: "root",
			want:     true,
		},
		{
			name:     "grant by another uid no match",
			content:  "#4242 ALL=(ALL) NOPASSWD:ALL\n",
			username: "root",
			want:     false,
		},
		{
			name:     "grant by uid for an unknown user matches (fail-closed)",
			content:  "#4242 ALL=(ALL) NOPASSWD:ALL\n",
			username: "no-such-user-cargowall",
			want:     true,
		},
		{
			name:     "hash-includes non-directive alone is harmless",
			content:  "#includes_discussion\n",
			username: "runner",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sudoers")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := sudoersFileGrantsUser(path, tt.username, nil, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("sudoersFileGrantsUser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSudoersFileGrantsUser_unreadableFile(t *testing.T) {
	_, err := sudoersFileGrantsUser("/nonexistent/path", "runner", nil, nil)
	if err == nil {
		t.Fatal("expected error for unreadable file, got nil")
	}
}

func TestDisableCompetingSudoersFiles(t *testing.T) {
	dir := t.TempDir()
	logger := discardLogger()

	// Create files that grant the user access
	writeFile(t, filepath.Join(dir, "90-runner"), "runner ALL=(ALL) NOPASSWD:ALL\n")
	writeFile(t, filepath.Join(dir, "50-cloud-init"), "# cloud-init defaults\nDefaults env_reset\n")
	writeFile(t, filepath.Join(dir, "91-other"), "otheruser ALL=(ALL) ALL\n")

	disabled, err := disableCompetingSudoersFiles(dir, "runner", map[string]bool{"27": true}, true, logger)
	if err != nil {
		t.Fatal(err)
	}

	if len(disabled) != 1 {
		t.Fatalf("expected 1 disabled file, got %d: %v", len(disabled), disabled)
	}
	if filepath.Base(disabled[0]) != "90-runner" {
		t.Errorf("expected 90-runner to be disabled, got %s", disabled[0])
	}

	// Verify the file was renamed
	if _, err := os.Stat(filepath.Join(dir, "90-runner")); !os.IsNotExist(err) {
		t.Error("original file should not exist after disable")
	}
	if _, err := os.Stat(filepath.Join(dir, "90-runner"+disabledSuffix)); err != nil {
		t.Error("disabled file should exist")
	}

	// Non-matching files should be untouched
	if _, err := os.Stat(filepath.Join(dir, "50-cloud-init")); err != nil {
		t.Error("non-matching file should be untouched")
	}
	if _, err := os.Stat(filepath.Join(dir, "91-other")); err != nil {
		t.Error("other user file should be untouched")
	}
}

func TestDisableCompetingSudoersFiles_skipsOwnFiles(t *testing.T) {
	dir := t.TempDir()
	logger := discardLogger()

	// Create our own files — they should never be disabled
	writeFile(t, filepath.Join(dir, filepath.Base(sudoersFile)), "runner ALL=(ALL) NOPASSWD: /usr/sbin/iptables\n")
	writeFile(t, filepath.Join(dir, filepath.Base(stateFile)), `{"username":"runner"}`)

	disabled, err := disableCompetingSudoersFiles(dir, "runner", map[string]bool{"27": true}, true, logger)
	if err != nil {
		t.Fatal(err)
	}
	if len(disabled) != 0 {
		t.Errorf("expected 0 disabled files, got %d: %v", len(disabled), disabled)
	}
}

func TestRestoreDisabledSudoersFiles(t *testing.T) {
	dir := t.TempDir()
	logger := discardLogger()

	original := filepath.Join(dir, "90-runner")
	disabledPath := original + disabledSuffix
	writeFile(t, disabledPath, "runner ALL=(ALL) NOPASSWD:ALL\n")

	if ok := restoreDisabledSudoersFiles([]string{original}, logger); !ok {
		t.Error("restoreDisabledSudoersFiles should return true on success")
	}

	if _, err := os.Stat(original); err != nil {
		t.Error("original file should be restored")
	}
	if _, err := os.Stat(disabledPath); !os.IsNotExist(err) {
		t.Error("disabled file should not exist after restore")
	}
}

func TestRestoreDisabledSudoersFiles_toleratesMissing(t *testing.T) {
	logger := discardLogger()
	// Should not panic or error on missing files; missing disabled file is tolerated
	if ok := restoreDisabledSudoersFiles([]string{"/nonexistent/file"}, logger); !ok {
		t.Error("restoreDisabledSudoersFiles should return true for missing files (tolerated)")
	}
}

func TestUserAliasContains(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		username string
		want     bool
	}{
		{
			name:     "exact match",
			line:     "User_Alias CI = runner",
			username: "runner",
			want:     true,
		},
		{
			name:     "among multiple members",
			line:     "User_Alias RUNNERS = admin, runner, ci",
			username: "runner",
			want:     true,
		},
		{
			name:     "not present",
			line:     "User_Alias ADMINS = admin, root",
			username: "runner",
			want:     false,
		},
		{
			name:     "substring does not match",
			line:     "User_Alias CI = runner2, runner3",
			username: "runner",
			want:     false,
		},
		{
			name:     "no equals sign",
			line:     "User_Alias BROKEN",
			username: "runner",
			want:     false,
		},
		{
			name:     "empty after equals",
			line:     "User_Alias EMPTY = ",
			username: "runner",
			want:     false,
		},
		{
			name:     "inline comment stripped",
			line:     "User_Alias CI = runner # the CI user",
			username: "runner",
			want:     true,
		},
		{
			name:     "inline comment hides member",
			line:     "User_Alias CI = admin # runner",
			username: "runner",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := userAliasContains(tt.line, tt.username); got != tt.want {
				t.Errorf("userAliasContains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSudoersFileGrantsUser_crossFileAlias(t *testing.T) {
	// A file containing only "RUNNERS ALL=(ALL) ALL" should be detected as a
	// grant when we know (from another file) that RUNNERS is a User_Alias
	// containing our target user.
	path := filepath.Join(t.TempDir(), "sudoers")
	writeFile(t, path, "RUNNERS ALL=(ALL) ALL\n")

	// Without aliases — should NOT match
	got, err := sudoersFileGrantsUser(path, "runner", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("should not match without aliases")
	}

	// With aliases — should match
	aliases := map[string]bool{"RUNNERS": true}
	got, err = sudoersFileGrantsUser(path, "runner", nil, aliases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("should match when RUNNERS is a known alias for the user")
	}
}

func TestCollectUserAliases(t *testing.T) {
	dir := t.TempDir()

	// File with alias containing target user
	writeFile(t, filepath.Join(dir, "10-aliases"), "User_Alias RUNNERS = runner, admin\n")
	// File with alias NOT containing target user
	writeFile(t, filepath.Join(dir, "20-other"), "User_Alias ADMINS = admin, root\n")
	// File with grant using the alias
	writeFile(t, filepath.Join(dir, "30-grant"), "RUNNERS ALL=(ALL) ALL\n")

	aliases := collectUserAliases(dir, "runner")
	if !aliases["RUNNERS"] {
		t.Error("expected RUNNERS in aliases")
	}
	if aliases["ADMINS"] {
		t.Error("ADMINS should not be in aliases (runner is not a member)")
	}
}

func TestCollectUserAliases_skipsOwnFiles(t *testing.T) {
	dir := t.TempDir()

	// Our own files should be skipped even if they match
	writeFile(t, filepath.Join(dir, filepath.Base(sudoersFile)), "User_Alias CI = runner\n")
	writeFile(t, filepath.Join(dir, filepath.Base(stateFile)), "User_Alias CI = runner\n")
	writeFile(t, filepath.Join(dir, "test.tmp"), "User_Alias CI = runner\n")
	writeFile(t, filepath.Join(dir, "test"+disabledSuffix), "User_Alias CI = runner\n")

	aliases := collectUserAliases(dir, "runner")
	if len(aliases) != 0 {
		t.Errorf("expected no aliases from own files, got %v", aliases)
	}
}

func TestUserAliasName(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"User_Alias RUNNERS = runner, admin", "RUNNERS"},
		{"User_Alias CI = runner", "CI"},
		{"User_Alias BROKEN", ""},
		{"User_Alias", ""},
	}
	for _, tt := range tests {
		if got := userAliasName(tt.line); got != tt.want {
			t.Errorf("userAliasName(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestDisableCompetingSudoersFiles_crossFileAlias(t *testing.T) {
	dir := t.TempDir()
	logger := discardLogger()

	// Alias defined in one file, grant using it in another
	writeFile(t, filepath.Join(dir, "10-aliases"), "User_Alias RUNNERS = runner, admin\n")
	writeFile(t, filepath.Join(dir, "20-grant"), "RUNNERS ALL=(ALL) ALL\n")
	// Unrelated file
	writeFile(t, filepath.Join(dir, "30-other"), "otheruser ALL=(ALL) ALL\n")

	disabled, err := disableCompetingSudoersFiles(dir, "runner", map[string]bool{"27": true}, true, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Both the alias file and the grant file should be disabled
	if len(disabled) != 2 {
		t.Fatalf("expected 2 disabled files, got %d: %v", len(disabled), disabled)
	}

	// Verify the files were renamed
	if _, err := os.Stat(filepath.Join(dir, "10-aliases")); !os.IsNotExist(err) {
		t.Error("alias file should be disabled")
	}
	if _, err := os.Stat(filepath.Join(dir, "20-grant")); !os.IsNotExist(err) {
		t.Error("grant file should be disabled")
	}
	// Unrelated file untouched
	if _, err := os.Stat(filepath.Join(dir, "30-other")); err != nil {
		t.Error("unrelated file should be untouched")
	}
}

func TestFindDisabledSudoersFiles(t *testing.T) {
	dir := t.TempDir()
	logger := discardLogger()

	writeFile(t, filepath.Join(dir, "90-runner"+disabledSuffix), "runner ALL=(ALL) ALL\n")
	writeFile(t, filepath.Join(dir, "50-other"+disabledSuffix), "other ALL=(ALL) ALL\n")
	writeFile(t, filepath.Join(dir, "normal-file"), "something\n")

	found := findDisabledSudoersFiles(dir, logger)
	if len(found) != 2 {
		t.Fatalf("expected 2 disabled files, got %d: %v", len(found), found)
	}
}

func TestFindDisabledSudoersFiles_emptyDir(t *testing.T) {
	dir := t.TempDir()
	logger := discardLogger()

	found := findDisabledSudoersFiles(dir, logger)
	if len(found) != 0 {
		t.Errorf("expected 0 disabled files, got %d", len(found))
	}
}

func TestIsIncludeDirective(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"#include /etc/sudoers.d/extra", true},
		{"#includedir /etc/sudoers.d", true},
		{"@include /etc/sudoers.d/extra", true},
		{"@includedir /etc/sudoers.d", true},
		{"#include", true},
		{"#includedir", true},
		{"@include", true},
		{"@includedir", true},
		{"#include\t/etc/grant", true},        // a tab separator (both sudos)
		{"#includedir\t/etc/sudoers.d", true}, // includedir with a tab
		{"#include/etc/grant", true},          // no separator (sudo-rs)
		{"@include/etc/grant", true},
		{"#includedir/etc/sudoers.d", true},
		{"#includes_discussion", false},
		{"#including_notes", false},
		{"@including_stuff", false},
		{"@includedir_extra", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			if got := isIncludeDirective(tt.line); got != tt.want {
				t.Errorf("isIncludeDirective(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// TestDisableCompetingSudoersFiles_uninspectable: an early-sorting file the
// scan can't inspect (a nested include) never fails the lockdown when the
// rules are appended — the scan is for the summary, so it's a Warn and the
// file is left alone. In the fallback, where the lockdown rests on the scan,
// the file is disabled as if it competed.
func TestDisableCompetingSudoersFiles_uninspectable(t *testing.T) {
	const nest = "@include /etc/sudoers.extra\n"

	t.Run("appended", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "aaa-nest"), nest)
		logger, buf := captureLog()
		disabled, err := disableCompetingSudoersFiles(dir, "runner", map[string]bool{"27": true}, false, logger)
		if err != nil || len(disabled) != 0 {
			t.Fatalf("disableCompetingSudoersFiles = %v, %v; want nothing disabled, nil", disabled, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "aaa-nest")); err != nil {
			t.Errorf("the uninspectable file was touched: %v", err)
		}
		if !strings.Contains(buf.String(), "reporting only") {
			t.Errorf("no reporting-only Warn: %s", buf.String())
		}
	})

	t.Run("fallback", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "aaa-nest"), nest)
		disabled, err := disableCompetingSudoersFiles(dir, "runner", map[string]bool{"27": true}, true, discardLogger())
		if err != nil || len(disabled) != 1 {
			t.Fatalf("disableCompetingSudoersFiles = %v, %v; want it disabled, nil", disabled, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "aaa-nest"+disabledSuffix)); err != nil {
			t.Errorf("the uninspectable file was not disabled: %v", err)
		}
	})
}

// TestDisableCompetingSudoersFiles_cannotDisable: a competing file that
// can't be disabled (a disabled copy already exists) is a Warn when the rules
// are appended, and fails the lockdown in the fallback.
func TestDisableCompetingSudoersFiles_cannotDisable(t *testing.T) {
	setup := func(t *testing.T) string {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "90-runner"), "runner ALL=(ALL) NOPASSWD:ALL\n")
		writeFile(t, filepath.Join(dir, "90-runner"+disabledSuffix), "stale\n")
		return dir
	}
	if _, err := disableCompetingSudoersFiles(setup(t), "runner", nil, false, discardLogger()); err != nil {
		t.Errorf("appended: err = %v, want nil (reporting only)", err)
	}
	if _, err := disableCompetingSudoersFiles(setup(t), "runner", nil, true, discardLogger()); err == nil {
		t.Error("fallback: want an error, the lockdown rests on this scan")
	}
}

// TestDisableCompetingSudoersFiles_recheck: a file the first pass judged not
// to compete, which gains a grant before the re-scan, is caught there — a
// failure when the scan is load-bearing, a Warn when the rules are appended.
// A file the first pass already reported is not reported again.
func TestDisableCompetingSudoersFiles_recheck(t *testing.T) {
	run := func(t *testing.T, loadBearing bool) (string, error) {
		dir := t.TempDir()
		notes := filepath.Join(dir, "50-notes")
		writeFile(t, notes, "# nothing here\n")
		prev := scanPassDone
		scanPassDone = func() { writeFile(t, notes, "runner ALL=(ALL) NOPASSWD:ALL\n") }
		t.Cleanup(func() { scanPassDone = prev })
		logger, buf := captureLog()
		_, err := disableCompetingSudoersFiles(dir, "runner", nil, loadBearing, logger)
		return buf.String(), err
	}
	if _, err := run(t, true); err == nil {
		t.Error("load-bearing: a file that changed to a grant during the pass did not fail the scan")
	}
	if out, err := run(t, false); err != nil || !strings.Contains(out, "appeared or changed") {
		t.Errorf("appended: err=%v, want nil and a Warn; log: %s", err, out)
	}

	// Reported once, not twice: a file that cannot be disabled is reported by
	// the first pass and skipped by the re-scan.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "90-runner"), "runner ALL=(ALL) NOPASSWD:ALL\n")
	writeFile(t, filepath.Join(dir, "90-runner"+disabledSuffix), "stale\n")
	logger, buf := captureLog()
	if _, err := disableCompetingSudoersFiles(dir, "runner", nil, false, logger); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Errorf("the undisableable file was reported %d times, want once: %s", n, buf.String())
	}
}
