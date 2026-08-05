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
		_, err := os.Stat(path)
		if err == nil {
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if failurePath != "" {
			anchor := failureSentinelAnchor(pidfilePath, start)
			if reason, ok := readFailureSentinel(failurePath, anchor); ok {
				return fmt.Errorf("cargowall reported startup failure: %s", reason)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s", timeout, path)
		}
		time.Sleep(interval)
	}
}

// failureSentinelAnchor returns the time a trustworthy failure sentinel must
// postdate. Preferred anchor: the pidfile's mtime — `cargowall start` writes
// it at process entry and the sentinel strictly after, so "sentinel newer
// than pidfile" identifies THIS run's sentinel no matter how long the
// launcher dawdled between starting cargowall and running wait-ready.
// Without a pidfile (not configured, or start hasn't written it yet) fall
// back to this reader's own start time, which is only safe for the tight
// `start & ; wait-ready` launch shape. Re-evaluated every poll so the
// pidfile appearing mid-wait upgrades the anchor.
func failureSentinelAnchor(pidfilePath string, waitStart time.Time) time.Time {
	if pidfilePath != "" {
		if fi, err := os.Lstat(pidfilePath); err == nil && fi.Mode().IsRegular() {
			return fi.ModTime()
		}
	}
	return waitStart
}

// readFailureSentinel returns the failure reason and true when a trustworthy
// sentinel exists. The path lives in world-writable /tmp, so it is read
// defensively: symlinks and non-regular files are ignored (Lstat +
// O_NOFOLLOW), sentinels older than the anchor (modulo staleSlack) are
// treated as another run's leftovers, and the reason quoted into CI logs is
// bounded.
func readFailureSentinel(path string, anchor time.Time) (string, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.ModTime().Before(anchor.Add(-staleSlack)) {
		return "", false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}
