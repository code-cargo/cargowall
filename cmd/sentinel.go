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

// State files `cargowall start` shares with the processes that read them:
// the action's wait loop and post step, `cargowall wait-ready`, and
// `cargowall summary`. They sit at fixed paths in world-writable /tmp, so
// writes are atomic renames and reads are defensive. The failure
// sentinel's format lives here whole, writer and readers together.
package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// maxSentinelReasonBytes bounds a reason written into a state file: the text
// can carry an eBPF verifier dump or an attacker-influenced API body, and it
// is echoed verbatim into CI logs by the consumer.
const maxSentinelReasonBytes = 4096

// sanitizeReason bounds a reason and strips control characters (including
// newlines) so it can never start a log line at the consumer.
func sanitizeReason(s string) string {
	truncated := false
	if len(s) > maxSentinelReasonBytes {
		s = s[:maxSentinelReasonBytes]
		truncated = true
	}
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if truncated {
		s += "... (truncated)"
	}
	return s
}

// writeSentinel atomically publishes a state file: the content is written to
// a private temp file in the same directory and renamed into place. These
// files are written as root into world-writable /tmp, and rename replaces
// whatever occupies the path — an attacker-planted symlink or plain file —
// without ever following it. Atomic publication also means a concurrent
// poller (the action's wait loop, `cargowall wait-ready`) can never observe
// a partially-written file.
func writeSentinel(path string, content []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename has succeeded
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	// CreateTemp uses 0600; the readers (action wait loop, summary step) may
	// be unprivileged.
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// stateFile is a defensively-read state file: content plus mtime.
type stateFile struct {
	data    []byte
	modTime time.Time
}

// readStateFile reads a cargowall state file from world-writable /tmp
// defensively: symlinks and non-regular files are ignored (Lstat +
// O_NOFOLLOW) and the read is bounded.
func readStateFile(path string) (stateFile, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return stateFile{}, false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return stateFile{}, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 8192))
	if err != nil {
		return stateFile{}, false
	}
	return stateFile{data: data, modTime: fi.ModTime()}, true
}

// writeFailureSentinel publishes the failure sentinel: the writer's pid on
// the first line (so a reader can tell THIS run's sentinel from a previous
// run's leftover by comparing against the pidfile, which mtime alone cannot
// do after a SIGKILL), then, when startup failed on a refused posture, a
// `refused=<posture>` line naming it (see exitRefused), then a bounded,
// control-character-stripped reason — unsanitized text here reaches CI
// logs, where an embedded newline plus a `::`-prefixed line is a
// workflow-command injection. The refusal rides here rather than in a file
// of its own: the action reads this file to decide anyway, so a refusal
// cannot be lost to a second write that failed.
func writeFailureSentinel(path, reason, refused string) error {
	head := fmt.Sprintf("pid=%d\n", os.Getpid())
	if refused != "" {
		head += "refused=" + refused + "\n"
	}
	return writeSentinel(path, []byte(head+sanitizeReason(reason)+"\n"))
}

// publishStartupFailure writes the failure sentinel for a startup that
// returned err, naming refused, the posture whose loss it was, if any.
func publishStartupFailure(path string, err error, refused string, logger *slog.Logger) {
	if werr := writeFailureSentinel(path, "cargowall startup failed: "+err.Error(), refused); werr != nil {
		logger.Warn("Failed to write failure sentinel", "path", path, "error", werr)
	}
}

// sentinelPid extracts the `pid=N` stamp from a sentinel's first line.
func sentinelPid(data []byte) (int, bool) {
	first, _, _ := strings.Cut(string(data), "\n")
	rest, ok := strings.CutPrefix(strings.TrimSpace(first), "pid=")
	if !ok {
		return 0, false
	}
	pid, err := strconv.Atoi(rest)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// sentinelReason renders a sentinel's human-readable reason for CI logs:
// the pid stamp and any refused= line are dropped, control characters are
// stripped (the file is world-writable, and an embedded newline plus a `::`
// prefix is a workflow command injection), and the result is bounded and
// never empty.
func sentinelReason(data []byte) string {
	body := string(data)
	if first, rest, found := strings.Cut(body, "\n"); found && strings.HasPrefix(strings.TrimSpace(first), "pid=") {
		body = rest
		if line, after, found := strings.Cut(body, "\n"); found && strings.HasPrefix(line, "refused=") {
			body = after
		}
	}
	reason := sanitizeReason(strings.TrimSpace(body))
	if reason == "" {
		return "(no reason recorded)"
	}
	return reason
}
