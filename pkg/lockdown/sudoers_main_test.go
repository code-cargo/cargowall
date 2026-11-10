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
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ubuntuSudoers is the shape Debian and Ubuntu ship: the includedir last.
const ubuntuSudoers = `Defaults	env_reset
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root	ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
`

// arcSudoers is the actions-runner image's whole /etc/sudoers: a group
// grant and no include.
const arcSudoers = "%sudo   ALL=(ALL:ALL) NOPASSWD:ALL\n"

const testRules = "runner ALL=(ALL:ALL) !ALL\nrunner ALL=(ALL) NOPASSWD: /usr/sbin/iptables\n"

func TestWithoutBlock(t *testing.T) {
	block := lockdownBlock(testRules, false)
	tests := []struct {
		name    string
		content string
		want    string
		found   bool
		wantErr bool
	}{
		{name: "no block", content: arcSudoers, want: arcSudoers},
		{name: "block at the end", content: arcSudoers + block, want: arcSudoers, found: true},
		{name: "block between lines", content: "a\n" + block + "b\n", want: "a\nb\n", found: true},
		// An added-newline block at the end has that newline taken back...
		{name: "added-newline block at end", content: "a\n" + lockdownBlock(testRules, true), want: "a", found: true},
		// ...but one with content after it must keep the separator, or "head"
		// and "tail" would join.
		{name: "added-newline block mid-file", content: "head\n" + lockdownBlock(testRules, true) + "tail\n", want: "head\ntail\n", found: true},
		{name: "begin without end", content: arcSudoers + blockBegin + "\n" + testRules, wantErr: true},
		{name: "end without begin", content: arcSudoers + blockEnd + "\n", wantErr: true},
		{name: "second begin", content: blockBegin + "\n" + block, wantErr: true},
		// A second whole pair, or a stray marker after the pair, is not ours to
		// guess about: refuse, so a stale block's allowlist can't survive.
		{name: "two pairs", content: arcSudoers + block + "x\n" + block, wantErr: true},
		{name: "a pair then a stray end", content: arcSudoers + block + blockEnd + "\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found, err := withoutBlock(tt.content)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want || found != tt.found {
				t.Errorf("withoutBlock = %q, %v; want %q, %v", got, found, tt.want, tt.found)
			}
		})
	}
}

func TestWithBlock(t *testing.T) {
	// A base without a trailing newline: a newline is added and recorded in
	// the begin marker.
	got, err := withBlock("%sudo ALL=(ALL) ALL", testRules)
	if err != nil {
		t.Fatal(err)
	}
	if want := "%sudo ALL=(ALL) ALL\n" + lockdownBlock(testRules, true); got != want {
		t.Errorf("a file without a trailing newline: got %q, want %q", got, want)
	}

	again, err := withBlock(got, testRules)
	if err != nil {
		t.Fatal(err)
	}
	if again != got {
		t.Errorf("not idempotent:\n%q\n%q", got, again)
	}

	other := "runner ALL=(ALL:ALL) !ALL\n"
	replaced, err := withBlock(got, other)
	if err != nil {
		t.Fatal(err)
	}
	if want := "%sudo ALL=(ALL) ALL\n" + lockdownBlock(other, true); replaced != want {
		t.Errorf("a previous block is not replaced: got %q, want %q", replaced, want)
	}

	// A base that already ends with a newline: none is added.
	withNL, err := withBlock("%sudo ALL=(ALL) ALL\n", testRules)
	if err != nil {
		t.Fatal(err)
	}
	if want := "%sudo ALL=(ALL) ALL\n" + lockdownBlock(testRules, false); withNL != want {
		t.Errorf("a file with a trailing newline: got %q, want %q", withNL, want)
	}
}

// stubVisudo stands in for visudo for the test, returning err and counting
// calls.
func stubVisudo(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	prev := visudoCheckFile
	visudoCheckFile = func(string) error {
		calls++
		return err
	}
	t.Cleanup(func() { visudoCheckFile = prev })
	return &calls
}

func writeSudoers(t *testing.T, content string) string {
	t.Helper()
	main := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(main, []byte(content), 0o440); err != nil {
		t.Fatal(err)
	}
	return main
}

func readString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestAppendSudoersBlock_noFinalNewline: a sudoers file that does not end
// with a newline is restored byte for byte, including the absence of that
// newline.
func TestAppendSudoersBlock_noFinalNewline(t *testing.T) {
	stubVisudo(t, nil)
	const noNL = "%sudo   ALL=(ALL:ALL) NOPASSWD:ALL" // no trailing newline
	main := writeSudoers(t, noNL)

	appended, err := appendSudoersBlock(main, testRules)
	if err != nil || !appended {
		t.Fatalf("appendSudoersBlock = %v, %v", appended, err)
	}
	if got, want := readString(t, main), noNL+"\n"+lockdownBlock(testRules, true); got != want {
		t.Errorf("content: got %q, want %q", got, want)
	}
	if removed, err := removeSudoersBlock(main); err != nil || !removed {
		t.Fatalf("removeSudoersBlock = %v, %v", removed, err)
	}
	if got := readString(t, main); got != noNL {
		t.Errorf("not restored byte for byte: got %q, want %q", got, noNL)
	}
}

func TestAppendSudoersBlock_arcShape(t *testing.T) {
	calls := stubVisudo(t, nil)
	main := writeSudoers(t, arcSudoers)

	appended, err := appendSudoersBlock(main, testRules)
	if err != nil {
		t.Fatal(err)
	}
	if !appended {
		t.Fatal("a sudoers without the include gets no block")
	}
	if got, want := readString(t, main), arcSudoers+lockdownBlock(testRules, false); got != want {
		t.Errorf("content: got %q, want %q", got, want)
	}
	if fi, err := os.Stat(main); err != nil || fi.Mode().Perm() != 0o440 {
		t.Errorf("mode not kept: %v %v", fi.Mode(), err)
	}
	if *calls != 1 {
		t.Errorf("visudo calls = %d, want 1", *calls)
	}

	removed, err := removeSudoersBlock(main)
	if err != nil || !removed {
		t.Fatalf("removeSudoersBlock = %v, %v", removed, err)
	}
	if got := readString(t, main); got != arcSudoers {
		t.Errorf("not restored byte for byte: got %q", got)
	}
	removed, err = removeSudoersBlock(main)
	if err != nil || removed {
		t.Errorf("a second removal = %v, %v; want false, nil", removed, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(main)); len(entries) != 1 {
		t.Errorf("left files behind: %v", entries)
	}
}

// TestAppendSudoersBlock_includedirShape: a distro /etc/sudoers that ends
// with the includedir is still appended to — the block is always the last
// lines read, whatever sudoers.d holds — and is restored byte for byte.
func TestAppendSudoersBlock_includedirShape(t *testing.T) {
	stubVisudo(t, nil)
	main := writeSudoers(t, ubuntuSudoers)

	appended, err := appendSudoersBlock(main, testRules)
	if err != nil || !appended {
		t.Fatalf("appendSudoersBlock = %v, %v; want true, nil", appended, err)
	}
	if got, want := readString(t, main), ubuntuSudoers+lockdownBlock(testRules, false); got != want {
		t.Errorf("content: got %q, want %q", got, want)
	}
	if removed, err := removeSudoersBlock(main); err != nil || !removed {
		t.Fatalf("removeSudoersBlock = %v, %v", removed, err)
	}
	if got := readString(t, main); got != ubuntuSudoers {
		t.Errorf("not restored byte for byte: got %q", got)
	}
}

// TestAppendSudoersBlock_replacesStaleBlock: a block a crashed run left is
// replaced in place, so its allowlist never outlives that run.
func TestAppendSudoersBlock_replacesStaleBlock(t *testing.T) {
	stubVisudo(t, nil)
	stale := lockdownRules("runner", []string{"/bin/old"})
	main := writeSudoers(t, ubuntuSudoers+lockdownBlock(stale, false))

	appended, err := appendSudoersBlock(main, testRules)
	if err != nil || !appended {
		t.Fatalf("appendSudoersBlock = %v, %v; want true, nil", appended, err)
	}
	if got, want := readString(t, main), ubuntuSudoers+lockdownBlock(testRules, false); got != want {
		t.Errorf("stale block not replaced: got %q, want %q", got, want)
	}
}

func TestAppendSudoersBlock_visudoRejects(t *testing.T) {
	stubVisudo(t, errors.New("syntax error"))
	main := writeSudoers(t, arcSudoers)

	if _, err := appendSudoersBlock(main, testRules); err == nil {
		t.Fatal("expected an error")
	}
	if got := readString(t, main); got != arcSudoers {
		t.Errorf("a rejected edit reached the file: %q", got)
	}
	if entries, _ := os.ReadDir(filepath.Dir(main)); len(entries) != 1 {
		t.Errorf("left files behind: %v", entries)
	}
}

func TestAppendSudoersBlock_missingFile(t *testing.T) {
	calls := stubVisudo(t, nil)
	main := filepath.Join(t.TempDir(), "sudoers")
	appended, err := appendSudoersBlock(main, testRules)
	if err != nil || appended {
		t.Fatalf("appendSudoersBlock = %v, %v; want false, nil", appended, err)
	}
	if removed, err := removeSudoersBlock(main); err != nil || removed {
		t.Errorf("removeSudoersBlock = %v, %v; want false, nil", removed, err)
	}
	if *calls != 0 {
		t.Errorf("visudo calls = %d, want 0", *calls)
	}
}

func TestAppendSudoersBlock_brokenMarkers(t *testing.T) {
	stubVisudo(t, nil)
	broken := arcSudoers + blockBegin + "\n" + testRules
	main := writeSudoers(t, broken)
	if _, err := appendSudoersBlock(main, testRules); err == nil {
		t.Error("appendSudoersBlock: expected an error for a block without its end")
	}
	if _, err := removeSudoersBlock(main); err == nil {
		t.Error("removeSudoersBlock: expected an error for a block without its end")
	}
	if got := readString(t, main); got != broken {
		t.Errorf("a file with broken markers was changed: %q", got)
	}
}

func TestReplaceSudoers_refusesSymlink(t *testing.T) {
	stubVisudo(t, nil)
	target := writeSudoers(t, arcSudoers)
	link := filepath.Join(t.TempDir(), "sudoers")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := replaceSudoers(link, "x\n"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("replaceSudoers through a symlink: %v", err)
	}
	if got := readString(t, target); got != arcSudoers {
		t.Errorf("symlink target changed: %q", got)
	}
}

// TestReplaceSudoers_keepsOwner: an edit preserves a non-root owner, which
// needs root to set up (and to chown the result back).
func TestReplaceSudoers_keepsOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own a file as another user")
	}
	stubVisudo(t, nil)
	main := writeSudoers(t, arcSudoers)
	if err := os.Chown(main, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := replaceSudoers(main, "runner ALL=(ALL:ALL) !ALL\n"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(main)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != 65534 || st.Gid != 65534 {
		t.Errorf("owner not preserved: uid=%d gid=%d, want 65534/65534", st.Uid, st.Gid)
	}
}

// stubRename makes replaceSudoers' rename fail with err, the way a
// bind-mounted /etc/sudoers (EBUSY) or a read-only one (EROFS) does.
func stubRename(t *testing.T, err error) {
	t.Helper()
	prev := renameFile
	renameFile = func(oldpath, newpath string) error {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	t.Cleanup(func() { renameFile = prev })
}

// TestReplaceSudoers_notReplaceable: a rename that fails the way a mount
// point does is errSudoersNotReplaceable, the file is left untouched, and no
// temp file is left behind.
func TestReplaceSudoers_notReplaceable(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EBUSY, syscall.EROFS} {
		t.Run(errno.Error(), func(t *testing.T) {
			stubVisudo(t, nil)
			stubRename(t, errno)
			main := writeSudoers(t, arcSudoers)
			err := replaceSudoers(main, "x\n")
			if !errors.Is(err, errSudoersNotReplaceable) || !errors.Is(err, errno) {
				t.Fatalf("replaceSudoers = %v, want errSudoersNotReplaceable wrapping %v", err, errno)
			}
			if got := readString(t, main); got != arcSudoers {
				t.Errorf("file changed: %q", got)
			}
			if entries, _ := os.ReadDir(filepath.Dir(main)); len(entries) != 1 {
				t.Errorf("left files behind: %v", entries)
			}
		})
	}
}

// TestReplaceSudoers_otherRenameError: a rename failure that is not a mount
// point or a read-only filesystem is an ordinary error, not the fallback.
func TestReplaceSudoers_otherRenameError(t *testing.T) {
	stubVisudo(t, nil)
	stubRename(t, syscall.EIO)
	main := writeSudoers(t, arcSudoers)
	if err := replaceSudoers(main, "x\n"); err == nil || errors.Is(err, errSudoersNotReplaceable) {
		t.Errorf("replaceSudoers = %v, want an error that is not errSudoersNotReplaceable", err)
	}
}

// captureLog is a logger whose output the test can read.
func captureLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// noSudoRsFile points sudoRsSudoers at an absent path for the test, so the
// host's own /etc/sudoers-rs, if any, cannot decide the result.
func noSudoRsFile(t *testing.T) {
	t.Helper()
	prev := sudoRsSudoers
	sudoRsSudoers = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { sudoRsSudoers = prev })
}

// TestApplySudoersBlock_fallsBackWhenNotReplaceable: an /etc/sudoers that
// cannot be replaced, and that ends by including sudoers.d, does not fail
// the lockdown; it falls back to the sudoers.d file with a Warn naming the
// weaker guarantee.
func TestApplySudoersBlock_fallsBackWhenNotReplaceable(t *testing.T) {
	noSudoRsFile(t)
	stubVisudo(t, nil)
	stubRename(t, syscall.EBUSY)
	main := writeSudoers(t, ubuntuSudoers)
	logger, buf := captureLog()

	appended, err := applySudoersBlock(main, "/etc/sudoers.d", testRules, logger)
	if err != nil || appended {
		t.Fatalf("applySudoersBlock = %v, %v; want false, nil (the fallback)", appended, err)
	}
	if got := readString(t, main); got != ubuntuSudoers {
		t.Errorf("file changed: %q", got)
	}
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "falling back to the sudoers.d file") {
		t.Errorf("no Warn naming the fallback: %s", out)
	}
}

// TestApplySudoersBlock_fallbackRefusesWithSudoRsFile: sudo-rs reads its
// own file in preference to /etc/sudoers, and nothing checks that file, so
// the fallback is refused while it exists.
func TestApplySudoersBlock_fallbackRefusesWithSudoRsFile(t *testing.T) {
	prev := sudoRsSudoers
	t.Cleanup(func() { sudoRsSudoers = prev })
	stubVisudo(t, nil)
	stubRename(t, syscall.EBUSY)
	sudoRsSudoers = writeSudoers(t, "root ALL=(ALL) ALL\n")
	_, err := applySudoersBlock(writeSudoers(t, ubuntuSudoers), "/etc/sudoers.d", testRules, discardLogger())
	if err == nil || !strings.Contains(err.Error(), "sudo-rs reads") {
		t.Errorf("applySudoersBlock with /etc/sudoers-rs present = %v, want a refusal naming sudo-rs's file", err)
	}
}

// TestApplySudoersBlock_refusesFallbackThatDoesNotHold: where /etc/sudoers
// cannot be replaced and the sudoers.d file would not be read last — a grant
// after the includedir, or no includedir at all (the ARC image) — the
// lockdown fails with that reason rather than reporting a fallback that does
// not hold.
func TestApplySudoersBlock_refusesFallbackThatDoesNotHold(t *testing.T) {
	for name, content := range map[string]string{
		"grant after the includedir": ubuntuSudoers + "runner ALL=(ALL) NOPASSWD: /bin/cat\n",
		"arc image, no includedir":   arcSudoers,
		"empty":                      "",
	} {
		t.Run(name, func(t *testing.T) {
			noSudoRsFile(t)
			stubVisudo(t, nil)
			stubRename(t, syscall.EBUSY)
			main := writeSudoers(t, content)
			_, err := applySudoersBlock(main, "/etc/sudoers.d", testRules, discardLogger())
			if err == nil || !errors.Is(err, errSudoersNotReplaceable) || !strings.Contains(err.Error(), "does not hold") {
				t.Errorf("applySudoersBlock = %v, want a not-replaceable error saying the fallback does not hold", err)
			}
			if got := readString(t, main); got != content {
				t.Errorf("file changed: %q", got)
			}
		})
	}
}

// TestApplySudoersBlock_otherErrorFails: any other failure to amend
// /etc/sudoers fails the lockdown rather than falling back silently.
func TestApplySudoersBlock_otherErrorFails(t *testing.T) {
	stubVisudo(t, errors.New("syntax error"))
	main := writeSudoers(t, arcSudoers)
	logger, _ := captureLog()
	if _, err := applySudoersBlock(main, "/etc/sudoers.d", testRules, logger); err == nil {
		t.Error("applySudoersBlock: expected an error")
	}
}

// TestSudoersEndsWithIncludedir: the fallback holds only where classic sudo
// and sudo-rs both read /etc/sudoers as ending with an include of sudoers.d.
// One row per spelling measured against both parsers: every spelling either
// one reads differently — a comment, a dropped line, a rule after it, an
// include of another path — must be refused.
func TestSudoersEndsWithIncludedir(t *testing.T) {
	const d = "/etc/sudoers.d"
	for _, tt := range []struct {
		name, content string
		want          bool
	}{
		// Both parsers read these as ending with an include of sudoers.d.
		{"ubuntu default", ubuntuSudoers, true},
		{"hash spelling", "#includedir /etc/sudoers.d\n", true},
		{"a tab separator", "@includedir\t/etc/sudoers.d\n", true},
		{"a trailing slash", "@includedir /etc/sudoers.d/\n", true},
		{"quoted with a trailing slash", "@includedir \"/etc/sudoers.d/\"\n", true},
		{"hash, quoted", "#includedir \"/etc/sudoers.d\"\n", true},
		{"trailing spaces", "@includedir /etc/sudoers.d   \n", true},
		{"comments and blanks after", "@includedir /etc/sudoers.d\n# note\n#\tnote\n#\n\n   \n#x note\n", true},

		// Read differently by one parser or both: refused.
		{"no includedir (arc image)", arcSudoers, false},
		{"empty", "", false},
		{"no separator, @", "@includedir/etc/sudoers.d\n", false},   // classic: a syntax error
		{"no separator, #", "#includedir/etc/sudoers.d\n", false},   // classic: a comment
		{"leading blanks", "  #includedir /etc/sudoers.d\n", false}, // classic: a comment
		{"leading tab", "\t@includedir /etc/sudoers.d\n", false},
		{"a #-1 rule after", "@includedir /etc/sudoers.d\n#-1, runner ALL=(ALL) ALL\n", false}, // classic: a user id
		{"a #- line after", "@includedir /etc/sudoers.d\n#-x note\n", false},
		{"a #uid rule after", "@includedir /etc/sudoers.d\n#4242 ALL=(ALL) ALL\n", false},
		{"a tab include after", "@includedir /etc/sudoers.d\n#include\t/etc/extra\n", false},
		{"a no-separator include after", "@includedir /etc/sudoers.d\n#include/etc/extra\n", false},
		{"unterminated quote", "@includedir \"/etc/sudoers.d\n", false},
		{"trailing quote only", "@includedir /etc/sudoers.d\"\n", false},
		{"an empty quoted string first", "@includedir \"\"/etc/sudoers.d\n", false},
		{"a trailing NBSP", "@includedir /etc/sudoers.d\u00a0\n", false},
		{"a continuation into it", "Defaults env_reset \\\n@includedir /etc/sudoers.d\n", false},
		{"a rule continued into it", "runner ALL=(ALL) NOPASSWD: /usr/bin/cat \\\n@includedir /etc/sudoers.d\n", false},
		{"a continuation with trailing blanks", "Defaults env_reset \\  \n@includedir /etc/sudoers.d\n", false},
		{"a continuation with a trailing tab", "Defaults env_reset \\\t\n@includedir /etc/sudoers.d\n", false},
		{"a continuation with a trailing CR", "Defaults env_reset \\\r\n@includedir /etc/sudoers.d\n", false},
		{"a last comment continued with a trailing blank", "@includedir /etc/sudoers.d\n# note \\ \n", false},
		{"CRLF", "@includedir /etc/sudoers.d\r\n", false}, // sudo-rs drops it
		{"no final newline", "@includedir /etc/sudoers.d", false},
		{"a vertical tab", "@includedir /etc/sudoers.d\v\n", false},
		{"a trailing comment", "@includedir /etc/sudoers.d # note\n", false},
		{"a second word", "@includedir /etc/sudoers.d extra\n", false},
		{"a relative path", "@includedir sudoers.d\n", false},
		{"a single-file include", "#include /etc/sudoers.d\n", false},
		{"another directory", "@includedir /etc/sudoers.local\n", false},
		{"a rule after", "@includedir /etc/sudoers.d\nrunner ALL=(ALL) ALL\n", false},
		{"Defaults after", "@includedir /etc/sudoers.d\nDefaults !lecture\n", false},
		{"a second includedir after", "@includedir /etc/sudoers.d\n@includedir /etc/sudoers.x\n", false},
		{"a comment continued into a rule", "@includedir /etc/sudoers.d\n# note \\\nrunner ALL=(ALL) ALL\n", false},
		{"a CR-only line after", "@includedir /etc/sudoers.d\n\r\n", false},
		{"a last comment ending in a backslash", "@includedir /etc/sudoers.d\n# note \\\n", false},
		{"a path that only starts with it", "@includedir /etc/sudoers.d.local\n", false},
		{"a subdirectory of it", "@includedir /etc/sudoers.d/sub\n", false},
	} {
		if _, got := sudoersEndsWithIncludedir(tt.content, d); got != tt.want {
			t.Errorf("%s: sudoersEndsWithIncludedir(%q) = %v, want %v", tt.name, tt.content, got, tt.want)
		}
	}
}

// TestApplySudoersBlock_logs: the log says what holds the lockdown — an Info
// that the rules are the last lines of sudoers, or, with an /etc/sudoers-rs
// present, a Warn that sudo-rs may not read them.
func TestApplySudoersBlock_logs(t *testing.T) {
	prev := sudoRsSudoers
	t.Cleanup(func() { sudoRsSudoers = prev })

	stubVisudo(t, nil)
	sudoRsSudoers = filepath.Join(t.TempDir(), "absent")
	logger, buf := captureLog()
	if appended, err := applySudoersBlock(writeSudoers(t, arcSudoers), "/etc/sudoers.d", testRules, logger); err != nil || !appended {
		t.Fatalf("applySudoersBlock = %v, %v", appended, err)
	}
	if out := buf.String(); !strings.Contains(out, "level=INFO") || !strings.Contains(out, "as the last lines of sudoers") {
		t.Errorf("no Info that the rules are the last lines: %s", out)
	}

	sudoRsSudoers = writeSudoers(t, "root ALL=(ALL) ALL\n")
	logger, buf = captureLog()
	if appended, err := applySudoersBlock(writeSudoers(t, arcSudoers), "/etc/sudoers.d", testRules, logger); err != nil || !appended {
		t.Fatalf("applySudoersBlock = %v, %v", appended, err)
	}
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "sudo-rs") || strings.Contains(out, "level=INFO") {
		t.Errorf("with /etc/sudoers-rs present, want a Warn and no Info: %s", out)
	}
}

// TestSudoersEndsWithIncludedir_reasons: a refused fallback says why in terms
// of what went wrong, not just that the last line isn't the include — a
// continued or unterminated include line looks like one.
func TestSudoersEndsWithIncludedir_reasons(t *testing.T) {
	const d = "/etc/sudoers.d"
	for content, want := range map[string]string{
		"":                           "nothing includes",
		arcSudoers:                   "not an include of",
		"@includedir /etc/sudoers.d": "no final newline",
		"Defaults x \\  \n@includedir /etc/sudoers.d\n": "ends in a backslash",
	} {
		why, ok := sudoersEndsWithIncludedir(content, d)
		if ok || !strings.Contains(why, want) {
			t.Errorf("sudoersEndsWithIncludedir(%q) = %q, %v; want a refusal saying %q", content, why, ok, want)
		}
	}
	if why, ok := sudoersEndsWithIncludedir(ubuntuSudoers, d); !ok || why != "" {
		t.Errorf("the ubuntu default = %q, %v; want \"\", true", why, ok)
	}
}
