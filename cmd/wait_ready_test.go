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
	"path/filepath"
	"testing"
	"time"
)

func TestWaitForReady_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ready")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := waitForReady(path, 100*time.Millisecond, 10*time.Millisecond); err != nil {
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

	if err := waitForReady(path, 500*time.Millisecond, 10*time.Millisecond); err != nil {
		t.Fatalf("expected sentinel to appear before timeout, got %v", err)
	}
}

func TestWaitForReady_TimesOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "never-appears")

	err := waitForReady(path, 50*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
