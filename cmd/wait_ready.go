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
	FailureFile string        `help:"Path to the failure sentinel file; when it appears, exit immediately with the reason it contains" default:"/tmp/cargowall-failed" env:"CARGOWALL_FAILURE_FILE"`
	Timeout     time.Duration `help:"How long to wait before giving up" default:"30s"`
	Interval    time.Duration `help:"Polling interval" default:"100ms"`
}

func (c *WaitReadyCmd) Run() error {
	return waitForReady(c.ReadyFile, c.FailureFile, c.Timeout, c.Interval)
}

// staleSlack is how far before waitForReady's own start a failure sentinel's
// mtime may lie and still be trusted. In every launch flow (`start &` then
// wait-ready) the sentinel is written seconds after both processes begin, so
// a small slack only covers scheduling jitter — anything older is a leftover
// from a previous run that `cargowall start` hasn't cleaned up yet, and
// failing fast on it would abort a healthy run. The ready file is deliberately
// NOT mtime-guarded: launchers already clear stale ready files before
// starting, and standalone users may legitimately run wait-ready long after
// startup completed.
const staleSlack = 2 * time.Second

// waitForReady polls until the ready sentinel exists, the failure sentinel
// exists (returning its content as the error), or the timeout fires.
// Extracted so tests can drive it without going through kong.
func waitForReady(path, failurePath string, timeout, interval time.Duration) error {
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
			if reason, ok := readFailureSentinel(failurePath, start); ok {
				return fmt.Errorf("cargowall reported startup failure: %s", reason)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s", timeout, path)
		}
		time.Sleep(interval)
	}
}

// readFailureSentinel returns the failure reason and true when a trustworthy
// sentinel exists. The path lives in world-writable /tmp, so it is read
// defensively: symlinks and non-regular files are ignored (Lstat +
// O_NOFOLLOW), sentinels older than this process (modulo staleSlack) are
// treated as another run's leftovers, and the reason quoted into CI logs is
// bounded.
func readFailureSentinel(path string, waitStart time.Time) (string, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.ModTime().Before(waitStart.Add(-staleSlack)) {
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
