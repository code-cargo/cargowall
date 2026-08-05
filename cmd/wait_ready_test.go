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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWaitForReady_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ready")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := waitForReady(path, "", "", 100*time.Millisecond, 10*time.Millisecond); err != nil {
		t.Fatalf("expected nil error when sentinel already exists, got %v", err)
	}
}

func TestWaitForReady_AppearsBeforeTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ready")

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = os.WriteFile(path, nil, 0o644)
	}()

	if err := waitForReady(path, "", "", 500*time.Millisecond, 10*time.Millisecond); err != nil {
		t.Fatalf("expected sentinel to appear before timeout, got %v", err)
	}
}

func TestWaitForReady_TimesOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "never-appears")

	err := waitForReady(path, "", "", 50*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestWaitForReady_FailureSentinelFailsFast(t *testing.T) {
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "never-appears")
	failurePath := filepath.Join(dir, "failed")
	if err := os.WriteFile(failurePath, []byte("policy fetch from https://api failed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err := waitForReady(readyPath, failurePath, "", 5*time.Second, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected failure-sentinel error, got nil")
	}
	if !strings.Contains(err.Error(), "policy fetch from https://api failed") {
		t.Fatalf("error must carry the sentinel's reason, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected fail-fast, waited %v", elapsed)
	}
}

// A failure sentinel left behind by a PREVIOUS run must not abort this one:
// wait-ready runs as a separate process and can poll before `cargowall
// start` reaches its stale-file cleanup, so the reader itself ignores
// sentinels older than its own start.
func TestWaitForReady_StaleFailureSentinelIgnored(t *testing.T) {
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	failurePath := filepath.Join(dir, "failed")
	if err := os.WriteFile(failurePath, []byte("previous run's reason\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(failurePath, old, old); err != nil {
		t.Fatal(err)
	}

	err := waitForReady(readyPath, failurePath, "", 100*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("stale sentinel must be ignored (timeout expected), got %v", err)
	}
}

// A symlink planted at the failure-sentinel path in world-writable /tmp must
// be ignored, not followed — following would quote an attacker-chosen file's
// contents into the CI log.
func TestWaitForReady_SymlinkFailureSentinelIgnored(t *testing.T) {
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("root-only-contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	failurePath := filepath.Join(dir, "failed")
	if err := os.Symlink(target, failurePath); err != nil {
		t.Fatal(err)
	}

	err := waitForReady(readyPath, failurePath, "", 100*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "root-only-contents") {
		t.Fatalf("symlink target must not be read: %v", err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("symlink sentinel must be ignored (timeout expected), got %v", err)
	}
}

// The ready sentinel wins when both exist — a completed startup must not be
// reported as failed because a concurrent watcher raced the state files.
func TestWaitForReady_ReadyWinsOverFailure(t *testing.T) {
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	failurePath := filepath.Join(dir, "failed")
	for _, p := range []string{readyPath, failurePath} {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := waitForReady(readyPath, failurePath, "", 100*time.Millisecond, 10*time.Millisecond); err != nil {
		t.Fatalf("expected ready sentinel to win, got %v", err)
	}
}

// With a LIVE pidfile anchor, a sentinel written before wait-ready started
// is trusted when its pid stamp matches — the launcher may do arbitrary work
// between `cargowall start` and `wait-ready`, and the reader's own clock must
// not discard a genuine failure.
func TestWaitForReady_PidfileAnchorTrustsOlderSentinel(t *testing.T) {
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	pidPath := filepath.Join(dir, "pid")
	failurePath := filepath.Join(dir, "failed")

	// This test process stands in for a live cargowall run.
	livePid := os.Getpid()
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(livePid)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pidTime := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(pidPath, pidTime, pidTime); err != nil {
		t.Fatal(err)
	}
	sentinel := fmt.Sprintf("pid=%d\npolicy lockdown reason\n", livePid)
	if err := os.WriteFile(failurePath, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}
	sentinelTime := time.Now().Add(-5 * time.Minute)
	if err := os.Chtimes(failurePath, sentinelTime, sentinelTime); err != nil {
		t.Fatal(err)
	}

	err := waitForReady(readyPath, failurePath, pidPath, 5*time.Second, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected failure-sentinel error")
	}
	if !strings.Contains(err.Error(), "policy lockdown reason") {
		t.Fatalf("a live run's own sentinel must be trusted, got %v", err)
	}
}

// A DEAD pidfile is a SIGKILLed run's leftover: trusting it as an anchor
// would legitimize that same run's leftover sentinel (necessarily newer than
// its own pidfile) and abort a healthy job with the previous run's reason.
func TestWaitForReady_DeadPidfileDoesNotLegitimizeStaleSentinel(t *testing.T) {
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	pidPath := filepath.Join(dir, "pid")
	failurePath := filepath.Join(dir, "failed")

	// A pid that cannot be running (max_pid+1 style sentinel value).
	if err := os.WriteFile(pidPath, []byte("4194304\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pidTime := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(pidPath, pidTime, pidTime); err != nil {
		t.Fatal(err)
	}
	// The dead run's sentinel: newer than its pidfile, older than this wait.
	if err := os.WriteFile(failurePath, []byte("pid=4194304\nprevious run's reason\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sentinelTime := time.Now().Add(-59 * time.Minute)
	if err := os.Chtimes(failurePath, sentinelTime, sentinelTime); err != nil {
		t.Fatal(err)
	}

	err := waitForReady(readyPath, failurePath, pidPath, 100*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("a dead run's pidfile+sentinel pair must be rejected, got %v", err)
	}
}

// A sentinel OLDER than this run's pidfile is a previous run's leftover and
// must be ignored even though it exists.
func TestWaitForReady_PidfileAnchorRejectsPreviousRunSentinel(t *testing.T) {
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	pidPath := filepath.Join(dir, "pid")
	failurePath := filepath.Join(dir, "failed")

	// A leftover sentinel stamped with a DIFFERENT pid than this run's.
	if err := os.WriteFile(failurePath, []byte("pid=4194304\nstale reason from last job\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(failurePath, old, old); err != nil {
		t.Fatal(err)
	}
	// This run's pidfile is live and fresh.
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := waitForReady(readyPath, failurePath, pidPath, 50*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("previous run's sentinel must be ignored (timeout expected), got %v", err)
	}
}
