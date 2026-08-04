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
	"os"
	"strings"
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

// waitForReady polls until the ready sentinel exists, the failure sentinel
// exists (returning its content as the error), or the timeout fires.
// Extracted so tests can drive it without going through kong.
func waitForReady(path, failurePath string, timeout, interval time.Duration) error {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for {
		_, err := os.Stat(path)
		if err == nil {
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if failurePath != "" {
			if reason, rerr := os.ReadFile(failurePath); rerr == nil {
				return fmt.Errorf("cargowall reported startup failure: %s", strings.TrimSpace(string(reason)))
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s", timeout, path)
		}
		time.Sleep(interval)
	}
}
