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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWritePidfile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pid")

	if err := writePidfile(path, 4242); err != nil {
		t.Fatalf("writePidfile: %v", err)
	}
	got, err := readPidfile(path)
	if err != nil {
		t.Fatalf("readPidfile: %v", err)
	}
	if got != 4242 {
		t.Fatalf("got pid %d, want 4242", got)
	}
}

// O_NOFOLLOW is the *only* defense against the symlink-clobber attack
// (a previous job on a shared self-hosted runner planting /tmp/cargowall.pid
// as a symlink to /etc/hostname or similar). Pin the behavior so a future
// refactor can't quietly drop the flag and leave the security gap open.
func TestWritePidfile_RefusesToFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "innocent-file")
	pidfile := filepath.Join(dir, "pidfile")

	original := []byte("important contents\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, pidfile); err != nil {
		t.Fatal(err)
	}

	err := writePidfile(pidfile, 9999)
	if err == nil {
		t.Fatal("writePidfile should fail when the path is a symlink, got nil")
	}
	if !strings.Contains(err.Error(), "too many levels of symbolic links") &&
		!strings.Contains(err.Error(), "ELOOP") {
		// On Linux, O_NOFOLLOW on a symlink returns ELOOP. Accept either the
		// raw constant name or the message text the kernel produces.
		t.Logf("note: error was %v (still a refusal, just unexpected wording)", err)
	}

	// The critical property: the symlink target must be unmodified.
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read symlink target: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("symlink target was clobbered: got %q, want %q", string(got), string(original))
	}
}

func TestReadPidfile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pid")
	if err := os.WriteFile(path, []byte("12345\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pid, err := readPidfile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 12345 {
		t.Fatalf("got pid %d, want 12345", pid)
	}
}

func TestReadPidfile_Missing(t *testing.T) {
	if _, err := readPidfile("/nonexistent/pidfile"); err == nil {
		t.Fatal("expected error reading missing pidfile, got nil")
	}
}

func TestReadPidfile_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pid")
	if err := os.WriteFile(path, []byte("not-a-number"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := readPidfile(path); err == nil {
		t.Fatal("expected error parsing non-numeric pidfile, got nil")
	}
}

func TestStopProcess_AlreadyExited(t *testing.T) {
	// Pick a pid we're sure is not running.
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")
	if err := os.WriteFile(pidfile, []byte("999999"), 0o644); err != nil {
		t.Fatal(err)
	}

	// stopProcess should treat ESRCH as success and remove the pidfile.
	if err := stopProcess(999999, time.Second, pidfile, true); err != nil {
		t.Fatalf("expected nil error for already-gone pid, got %v", err)
	}
	if _, err := os.Stat(pidfile); !os.IsNotExist(err) {
		t.Fatalf("expected pidfile to be removed, stat err=%v", err)
	}
}

func TestStopProcess_RealChild(t *testing.T) {
	// Spawn a sleep we control. SIGTERM should reap it.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("could not spawn helper process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")
	if err := os.WriteFile(pidfile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		t.Fatal(err)
	}

	// Reap in the background so the process actually disappears (otherwise it
	// stays a zombie and Signal(0) keeps reporting it as alive).
	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()

	if err := stopProcess(cmd.Process.Pid, 5*time.Second, pidfile, true); err != nil {
		t.Fatalf("stopProcess returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("helper process did not exit after SIGTERM")
	}
}
