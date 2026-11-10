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

// The lockdown's rules hold only where sudo reads them last: sudoers is
// last-match-wins, so a grant read after them still matches. The lockdown
// file in sudoers.d is read last when /etc/sudoers ends by including that
// directory, as Debian and Ubuntu ship it. An image whose /etc/sudoers does
// not, such as one that wrote the file from scratch to grant a group, never
// reads the lockdown file at all, or reads lines after it; there the same
// rules are appended to /etc/sudoers itself, between markers, and removed
// again when the lockdown ends. Nothing else in the file is touched.

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
		err = os.Rename(tmp, main)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", main, err)
	}
	return nil
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
