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
	"strconv"
	"strings"
	"syscall"
	"time"
)

// StopCmd reads a pidfile written by `cargowall start --pidfile X`, sends
// SIGTERM to that process, and waits for it to exit (so subsequent CI
// teardown steps can rely on iptables/Docker DNS having been restored).
type StopCmd struct {
	Pidfile string        `help:"Path to the pidfile written by 'cargowall start --pidfile X'" required:"" env:"CARGOWALL_PIDFILE"`
	Timeout time.Duration `help:"How long to wait for the process to exit after SIGTERM" default:"15s"`
	Remove  bool          `help:"Remove the pidfile after a successful stop" default:"true"`
}

func (c *StopCmd) Run() error {
	pid, err := readPidfile(c.Pidfile)
	if err != nil {
		return err
	}
	return stopProcess(pid, c.Timeout, c.Pidfile, c.Remove)
}

// readPidfile reads and parses a pidfile. Returns ErrNotExist wrapped if
// the file is missing so callers can distinguish "already stopped" from
// other errors.
func readPidfile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read pidfile %s: %w", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid in %s: %q", path, string(data))
	}
	return pid, nil
}

// stopProcess sends SIGTERM and polls until the process exits or the
// timeout fires. Removes the pidfile on success when remove is true.
func stopProcess(pid int, timeout time.Duration, pidfile string, remove bool) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	cleanup := func() {
		if remove {
			_ = os.Remove(pidfile)
		}
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		// ESRCH means the process is already gone — treat that as success.
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone) {
			cleanup()
			return nil
		}
		return fmt.Errorf("send SIGTERM to %d: %w", pid, err)
	}

	deadline := time.Now().Add(timeout)
	for {
		// Signal 0 probes whether the process exists without delivering anything.
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			cleanup()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("process %d did not exit within %s", pid, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
