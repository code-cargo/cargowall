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

// The lockdown's rules hold because sudo reads them last: sudoers is
// last-match-wins, so a grant read after them would still match. They are
// appended as the last lines of /etc/sudoers, between markers, on every
// shape — a distro file that ends by including sudoers.d as well as an image
// that wrote the file from scratch to grant a group. sudoers expands an
// include where it stands, so those lines are read after every sudoers.d file
// and every nested include, whatever they hold. They are removed again when
// the lockdown ends, and nothing else in the file is touched. Where
// /etc/sudoers cannot be replaced (a bind-mounted file), the lockdown falls
// back to its sudoers.d file, a weaker guarantee that the log names.

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	mainSudoers = "/etc/sudoers"
	blockBegin  = "# BEGIN cargowall sudo lockdown (removed when the lockdown ends)"
	// blockBeginAddedNL marks a block we had to separate from the file with a
	// newline the file did not end with. Removing such a block also takes
	// that newline back, so a file with no final newline is restored exactly.
	blockBeginAddedNL = "# BEGIN cargowall sudo lockdown (added a preceding newline; removed when the lockdown ends)"
	blockEnd          = "# END cargowall sudo lockdown"
	// sudoersTempPrefix names the scratch files replaceSudoers creates beside
	// a sudoers file. The leading dot keeps sudo from reading one (sudo skips
	// a name containing '.'); a crash's leftover is cleaned on the next
	// enable and on disable.
	sudoersTempPrefix = ".sudoers.cargowall-"
)

// isBeginMarker reports whether a block-stripped line is a begin marker, and
// whether it is the variant that added a preceding newline.
func isBeginMarker(line string) (addedNL, ok bool) {
	switch line {
	case blockBegin:
		return false, true
	case blockBeginAddedNL:
		return true, true
	}
	return false, false
}

// sudoRsSudoers is the file sudo-rs reads in preference to /etc/sudoers when
// it exists. A var so tests can point it at a scratch file.
var sudoRsSudoers = "/etc/sudoers-rs"

// renameFile swaps a validated temp file over a sudoers file. A var so tests
// can make the rename fail the way a bind-mounted file does.
var renameFile = os.Rename

// errSudoersNotReplaceable is a sudoers file that cannot be replaced by
// rename: a bind-mounted file (a Kubernetes ConfigMap subPath, a file a
// container runtime binds in) is a mount point, and rename onto it fails with
// EBUSY; a read-only filesystem fails with EROFS. It is never written in
// place instead: such a mount is usually read-only anyway, and a torn write
// would break sudo for everyone.
var errSudoersNotReplaceable = errors.New("sudoers file cannot be replaced")

// notReplaceable reports whether err is a rename or create failure that
// means the file cannot be replaced at all, rather than a transient error.
func notReplaceable(err error) bool {
	return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EROFS)
}

// visudoCheckFile validates a candidate sudoers file, includes and all. A
// var so tests can stand in for visudo, which needs root.
var visudoCheckFile = func(path string) error {
	if out, err := exec.Command("visudo", "-cf", path).CombinedOutput(); err != nil {
		return fmt.Errorf("visudo rejected %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// lockdownBlock is rules wrapped in the markers withoutBlock finds, with the
// begin marker saying whether a preceding newline was added.
func lockdownBlock(rules string, addedNL bool) string {
	begin := blockBegin
	if addedNL {
		begin = blockBeginAddedNL
	}
	return begin + "\n" + strings.TrimRight(rules, "\n") + "\n" + blockEnd + "\n"
}

// withoutBlock is content with the lockdown block cut out, marker lines
// included, and whether there was one. When the block's begin marker says it
// added a preceding newline, that newline is taken back too, so a file with
// no final newline is restored byte for byte.
//
// Exactly one marker pair is ours: withBlock strips the old block before it
// appends a new one, and every edit is an atomic replace, so cargowall never
// leaves two. Any other marker — a begin without its end, an end without its
// begin, or a second pair anywhere in the file — means the file was edited by
// someone else, and is an error that leaves it untouched: guessing which
// lines are ours could delete rules that are not, or leave a stale block's
// allowlist live after the lockdown ends.
func withoutBlock(content string) (string, bool, error) {
	lines := strings.SplitAfter(content, "\n")
	begin, end := -1, -1
	addedNL := false
	for i, line := range lines {
		l := strings.TrimRight(line, "\n")
		if a, ok := isBeginMarker(l); ok {
			if begin >= 0 {
				return "", false, errors.New("sudoers holds more than one lockdown block")
			}
			begin, addedNL = i, a
		} else if l == blockEnd {
			switch {
			case begin < 0:
				return "", false, errors.New("sudoers holds a lockdown block end without its beginning")
			case end >= 0:
				return "", false, errors.New("sudoers holds more than one lockdown block")
			}
			end = i
		}
	}
	switch {
	case begin < 0:
		return content, false, nil
	case end < 0:
		return "", false, errors.New("sudoers holds a lockdown block without its end")
	}
	before := strings.Join(lines[:begin], "")
	after := strings.Join(lines[end+1:], "")
	// The added newline is the one that separated the file's own last line
	// from the block. Only take it back when the block ended the file;
	// otherwise what follows it needs the separator.
	if addedNL && after == "" {
		before = strings.TrimSuffix(before, "\n")
	}
	return before + after, true, nil
}

// withBlock is content with the lockdown block at its end, replacing one a
// previous run left. A base that does not end with a newline gets one before
// the block, recorded in the begin marker so withoutBlock restores it.
func withBlock(content, rules string) (string, error) {
	base, _, err := withoutBlock(content)
	if err != nil {
		return "", err
	}
	addedNL := base != "" && !strings.HasSuffix(base, "\n")
	if addedNL {
		base += "\n"
	}
	return base + lockdownBlock(rules, addedNL), nil
}

// appendSudoersBlock appends the lockdown rules as the last lines of main,
// and reports whether it did. Those lines are read after every rule in main
// and after every file it includes, wherever they appear and however they
// are spelled, since sudoers is last-match-wins and expands an include where
// it stands. So the lockdown holds whatever a sudoers.d file contains,
// without the reader having to tell a grant from an inert line there. A block
// a previous run left is replaced, so its allowlist never outlives that run.
// A missing main file is no sudo to lock down here: nothing is appended, and
// the step verification is the backstop.
func appendSudoersBlock(main, rules string) (bool, error) {
	data, err := os.ReadFile(main)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", main, err)
	}
	next, err := withBlock(string(data), rules)
	if err != nil {
		return false, err
	}
	if err := replaceSudoers(main, next); err != nil {
		return false, err
	}
	return true, nil
}

// removeSudoersBlock takes the lockdown block back out of main, leaving the
// rest as it is, and reports whether there was one. Idempotent: a file
// without a block is left alone.
func removeSudoersBlock(main string) (bool, error) {
	data, err := os.ReadFile(main)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", main, err)
	}
	next, found, err := withoutBlock(string(data))
	if err != nil || !found {
		return false, err
	}
	if err := replaceSudoers(main, next); err != nil {
		return false, err
	}
	return true, nil
}

// replaceSudoers swaps main's content for content atomically: a temporary
// file beside it, with main's mode and owner, validated, then renamed over
// it. A file sudo refuses to parse would take sudo away from everyone, so
// nothing invalid is ever put in its place. A symlink is refused rather
// than replaced by a file. The temporary file has a unique name, so a
// concurrent edit of the same file (a forced teardown's Disable racing an
// Enable) can never rename one edit's unvalidated file over the real one.
func replaceSudoers(main, content string) error {
	fi, err := os.Lstat(main)
	if err != nil {
		return fmt.Errorf("stat %s: %w", main, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", main)
	}
	f, err := os.CreateTemp(filepath.Dir(main), sudoersTempPrefix+"*")
	if err != nil {
		if notReplaceable(err) {
			return fmt.Errorf("%w: create a temp file beside %s: %w", errSudoersNotReplaceable, main, err)
		}
		return fmt.Errorf("create a temp file beside %s: %w", main, err)
	}
	tmp := f.Name()
	_, err = f.WriteString(content)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && err == nil {
		err = os.Lchown(tmp, int(st.Uid), int(st.Gid))
	}
	if err == nil {
		err = visudoCheckFile(tmp)
	}
	if err == nil {
		if err = renameFile(tmp, main); err != nil && notReplaceable(err) {
			os.Remove(tmp)
			return fmt.Errorf("%w: replace %s: %w", errSudoersNotReplaceable, main, err)
		}
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", main, err)
	}
	return nil
}

// applySudoersBlock appends the lockdown rules to main and says in the log
// what holds the lockdown. The appended lines are the guarantee. Where main
// cannot be replaced (a bind mount, a read-only file), it falls back to the
// sudoers.d file in dir alone — but only where that holds: main, still
// readable, must end by including dir in a spelling both classic sudo and
// sudo-rs read that way (sudoersEndsWithIncludedir), and sudo-rs must not be
// reading a file of its own instead. Then competing-file disabling (which
// keeps later sudoers.d files from overriding it) and the step verification
// carry the lockdown, and a Warn names the weaker guarantee. Otherwise the
// lockdown's rules would not be read last, so it fails with that reason. Any
// other error is returned and fails the lockdown.
func applySudoersBlock(main, dir, rules string, logger *slog.Logger) (bool, error) {
	appended, err := appendSudoersBlock(main, rules)
	switch {
	case errors.Is(err, errSudoersNotReplaceable):
		if fileExists(sudoRsSudoers) {
			return false, fmt.Errorf("%w, and the fallback to %s does not hold: sudo-rs reads %s in preference to %s, and nothing checks it",
				err, dir, sudoRsSudoers, main)
		}
		data, rerr := os.ReadFile(main)
		if rerr != nil {
			return false, fmt.Errorf("%w, and it cannot be read to check the fallback: %w", err, rerr)
		}
		if last, ok := sudoersEndsWithIncludedir(string(data), dir); !ok {
			return false, fmt.Errorf("%w, and the fallback to %s does not hold: %s", err, dir, notLastReason(main, dir, last))
		}
		logger.Warn("Cannot append the lockdown rules to sudoers, which cannot be replaced; "+
			"falling back to the sudoers.d file alone, which sudoers includes last; "+
			"competing-file disabling and the step verification carry the lockdown",
			"path", main, "error", err)
		return false, nil
	case err != nil:
		return false, err
	case !appended:
		logger.Warn("No sudoers file to append the lockdown rules to; relying on the sudoers.d file and the step verification", "path", main)
	case fileExists(sudoRsSudoers):
		logger.Warn("Appended the lockdown rules to sudoers, but sudo-rs reads its own file in preference to it, "+
			"so they may not be read there; the step verification is the backstop",
			"path", main, "sudo_rs_file", sudoRsSudoers)
	default:
		logger.Info("Appended the lockdown rules as the last lines of sudoers", "path", main)
	}
	return appended, nil
}

// sudoersEndsWithIncludedir reports whether both classic sudo and sudo-rs,
// reading content as a whole sudoers file, read nothing in it after an
// include of dir: its last line either of them acts on is that include. It
// returns that last line too, for the reason when it does not hold.
//
// This is the check the sudoers.d fallback rests on, so it accepts only the
// intersection of the two parsers, on bytes: a spelling one of them reads
// differently — as a comment, a dropped line, a rule, or an include of
// another path — is refused, which only costs the fallback, the safe
// direction. It is deliberately separate from the competing-file scan's
// lenient isIncludeDirective, which errs the other way. Measured against sudo
// 1.9.15p5, 1.9.17p2 and sudo-rs 0.2.13:
//   - the include is strictIncludedirOf: no leading blanks, the keyword and a
//     separator, the path, and a real newline;
//   - the line before it must not end in a backslash, which would continue
//     a rule into it;
//   - after it, only lines both parsers skip (skippedByBoth).
func sudoersEndsWithIncludedir(content, dir string) (string, bool) {
	lines := strings.Split(content, "\n") // lines[i] for i < len-1 ended in '\n'
	inc := len(lines) - 1
	for inc >= 0 && skippedByBoth(lines[inc]) {
		inc--
	}
	if inc < 0 {
		return "", false
	}
	line := lines[inc]
	newline := inc < len(lines)-1 // sudo-rs needs a real '\n' after the path
	if !newline || !strictIncludedirOf(line, dir) {
		return line, false
	}
	if inc > 0 && strings.HasSuffix(lines[inc-1], `\`) {
		return line, false
	}
	return line, true
}

// skippedByBoth reports whether both parsers skip a line, so that a line
// after the include does not matter: empty, only spaces and tabs, or a '#'
// comment both read as one — '#' alone or followed by a byte that is not a
// digit, not '-' (classic sudo reads "#-1" as a user id) and that does not
// begin "include". A line ending in a backslash is never skipped: it
// continues into the next.
func skippedByBoth(line string) bool {
	if strings.HasSuffix(line, `\`) {
		return false
	}
	t := strings.TrimLeft(line, " \t")
	if t == "" {
		return true
	}
	rest, ok := strings.CutPrefix(t, "#")
	if !ok {
		return false
	}
	if rest == "" {
		return true
	}
	if c := rest[0]; (c >= '0' && c <= '9') || c == '-' {
		return false
	}
	return !strings.HasPrefix(rest, "include")
}

// strictIncludedirOf reports whether line is, to both parsers, an includedir
// of dir: "#includedir" or "@includedir" at the very start of the line; one
// or more spaces or tabs; the path, either a run of printable ASCII other
// than space, '"' and '\', or one balanced pair of double quotes around such
// characters; then only spaces and tabs. The path must be dir, with or
// without a trailing slash. A Unicode space, a '\r', a vertical tab, an
// unbalanced quote or a trailing comment all refuse it.
func strictIncludedirOf(line, dir string) bool {
	var rest string
	switch {
	case strings.HasPrefix(line, "#includedir"):
		rest = line[len("#includedir"):]
	case strings.HasPrefix(line, "@includedir"):
		rest = line[len("@includedir"):]
	default:
		return false
	}
	after := strings.TrimLeft(rest, " \t")
	if len(after) == len(rest) {
		return false // no separator: only sudo-rs reads that as an include
	}
	var path string
	if q, ok := strings.CutPrefix(after, `"`); ok {
		end := strings.IndexByte(q, '"')
		if end < 0 {
			return false
		}
		path, after = q[:end], q[end+1:]
		for i := 0; i < len(path); i++ {
			if c := path[i]; c < 0x20 || c > 0x7e || c == '\\' {
				return false
			}
		}
	} else {
		n := 0
		for n < len(after) && after[n] > 0x20 && after[n] < 0x7f && after[n] != '"' && after[n] != '\\' {
			n++
		}
		path, after = after[:n], after[n:]
	}
	if strings.Trim(after, " \t") != "" {
		return false
	}
	return path == dir || path == dir+"/"
}

// notLastReason says why the sudoers.d fallback would not hold.
func notLastReason(main, dir, last string) string {
	if last == "" {
		return fmt.Sprintf("%s holds no rule or include, so %s is never read", main, dir)
	}
	if len(last) > 120 {
		last = strings.ToValidUTF8(last[:120], "") + "…"
	}
	return fmt.Sprintf("the last line sudo reads in %s is %q, not an include of %s, so the lockdown's file there is not read last", main, last, dir)
}

// fileExists reports whether path names an existing file.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// cleanStaleSudoersTemps removes scratch files a crashed run left beside the
// sudoers files in dir. They are inert — sudo does not read a dotted name —
// but tidied so they do not accumulate. Best-effort.
func cleanStaleSudoersTemps(dir string, logger *slog.Logger) {
	matches, err := filepath.Glob(filepath.Join(dir, sudoersTempPrefix+"*"))
	if err != nil {
		return
	}
	for _, m := range matches {
		if err := os.Remove(m); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.Debug("Could not remove a stale sudoers temp file", "path", m, "error", err)
		}
	}
}
