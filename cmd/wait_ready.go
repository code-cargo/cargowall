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
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// WaitReadyCmd blocks until cargowall writes its ready sentinel, fails fast
// if the failure sentinel appears instead, or gives up when the timeout
// elapses. Used by shell-driven CI scripts to gate the build step on the
// firewall being attached and the policy loaded.
type WaitReadyCmd struct {
	ReadyFile string `help:"Path to the ready sentinel file" default:"/tmp/cargowall-ready" env:"CARGOWALL_READY_FILE"`
	// FailureFile shares its default and env var with `cargowall start`, so
	// an --api-failure-mode=fail abort surfaces here as an immediate error
	// carrying the abort reason instead of a generic timeout.
	FailureFile string `help:"Path to the failure sentinel file; when it appears, exit immediately with the reason it contains" default:"/tmp/cargowall-failed" env:"CARGOWALL_FAILURE_FILE"`
	// Pidfile shares its env var with `cargowall start` and anchors the
	// failure sentinel's staleness check to the run itself (see
	// failureSentinelAnchor) instead of this reader's clock.
	Pidfile  string        `help:"Path to the cargowall pidfile; used to distinguish this run's failure sentinel from a previous run's leftover" default:"" env:"CARGOWALL_PIDFILE"`
	Timeout  time.Duration `help:"How long to wait before giving up" default:"30s"`
	Interval time.Duration `help:"Polling interval" default:"100ms"`
}

func (c *WaitReadyCmd) Run() error {
	return waitForReady(c.ReadyFile, c.FailureFile, c.Pidfile, c.Timeout, c.Interval)
}

// staleSlack absorbs scheduling jitter around the staleness anchor: a
// sentinel may legitimately carry an mtime a moment before the anchor
// (pidfile write vs. sentinel write ordering, coarse filesystem timestamps).
const staleSlack = 2 * time.Second

// waitForReady polls until the ready sentinel exists, the failure sentinel
// exists (returning its content as the error), or the timeout fires.
// Extracted so tests can drive it without going through kong.
func waitForReady(path, failurePath, pidfilePath string, timeout, interval time.Duration) error {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		run := readRunIdentity(pidfilePath, start)

		if data, ok := readStateFile(path); ok && run.owns(data) {
			return nil
		}
		if failurePath != "" {
			if data, ok := readStateFile(failurePath); ok && run.owns(data) {
				return fmt.Errorf("cargowall reported startup failure: %s", sentinelReason(data.data))
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s", timeout, path)
		}
		time.Sleep(interval)
	}
}

// runIdentity is what this reader knows about the cargowall run it is
// waiting on: the pid from the pidfile when available, and the time a
// trustworthy sentinel must postdate.
type runIdentity struct {
	pid    int
	hasPid bool
	anchor time.Time
}

// readRunIdentity resolves the current run's identity. Preferred: the
// pidfile — `cargowall start` writes it at process entry and stamps the same
// pid into every sentinel, so an exact pid match identifies THIS run's
// sentinel with no timing assumptions at all (mtime alone cannot: a
// SIGKILLed run leaves a pidfile whose own sentinel is necessarily newer).
// Its mtime is the fallback anchor for sentinels written by an older binary
// that doesn't stamp a pid; with no pidfile at all, this reader's start time
// is the last resort, safe only for the tight `start & ; wait-ready` shape.
// Re-read every poll so a pidfile appearing mid-wait upgrades the identity.
func readRunIdentity(pidfilePath string, waitStart time.Time) runIdentity {
	id := runIdentity{anchor: waitStart}
	if pidfilePath == "" {
		return id
	}
	fi, err := os.Lstat(pidfilePath)
	if err != nil || !fi.Mode().IsRegular() {
		return id
	}
	pid, perr := readPidfile(pidfilePath)
	if perr != nil || !processAlive(pid) {
		// A pidfile whose process is gone is a SIGKILLed run's leftover.
		// Trusting it as an anchor would legitimize that same run's
		// leftover sentinel (necessarily newer than its own pidfile) and
		// abort a healthy job with the previous run's reason. Fall back to
		// the reader's clock, which correctly rejects both.
		return id
	}
	id.anchor = fi.ModTime()
	id.pid, id.hasPid = pid, true
	return id
}

// processAlive reports whether pid exists. EPERM counts as alive: cargowall
// runs as root and wait-ready often does not.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// owns reports whether a state file was written by this run. An explicit
// `pid=N` stamp is authoritative in both directions; otherwise fall back to
// the mtime anchor.
func (r runIdentity) owns(data stateFile) bool {
	if pid, ok := sentinelPid(data.data); ok && r.hasPid {
		return pid == r.pid
	}
	return !data.modTime.Before(r.anchor.Add(-staleSlack))
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
// the pid stamp is dropped, control characters are stripped (the file is
// world-writable, and an embedded newline plus a `::` prefix is a workflow
// command injection), and the result is bounded and never empty.
func sentinelReason(data []byte) string {
	body := string(data)
	if first, rest, found := strings.Cut(body, "\n"); found && strings.HasPrefix(strings.TrimSpace(first), "pid=") {
		body = rest
	}
	reason := sanitizeReason(strings.TrimSpace(body))
	if reason == "" {
		return "(no reason recorded)"
	}
	return reason
}
