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

import (
	"os"
	"os/user"
	"strings"
	"testing"
)

// lookupOrSkip is a user every Debian or Ubuntu host has, or a skip.
func lookupOrSkip(t *testing.T, name string) *user.User {
	t.Helper()
	u, err := user.Lookup(name)
	if err != nil {
		t.Skipf("no %s user here: %v", name, err)
	}
	return u
}

// The lockdown takes the sudo of the user the runner's job steps run as:
// the Runner.Worker's owner, whatever the account is called, ahead of
// SUDO_USER and every guess. A configured user is taken as given.
func TestResolveTarget_workerOwner(t *testing.T) {
	nobody := lookupOrSkip(t, "nobody")
	root := t.TempDir()
	fakeProc(t, root, "40", "Runner.Worker", status(nobody.Uid, "65534"), "")
	fakeProc(t, root, "41", "Runner.Worker", status(nobody.Uid, "65534"), "")
	fakeProc(t, root, "42", "bash", status("0", "0"), "") // not a worker

	if got, err := resolveTarget("", root, "someoneelse"); err != nil || got != "nobody" {
		t.Errorf("resolveTarget = %q, %v; want the worker's owner, nobody", got, err)
	}
	if got, err := resolveTarget("alice", root, ""); err != nil || got != "alice" {
		t.Errorf("a configured user = %q, %v; want alice", got, err)
	}
}

// A worker running as root has steps with root and no use for sudo, so no
// lockdown holds against them: an error, not a lockdown of another account
// that would verify and report applied.
func TestResolveTarget_rootWorker(t *testing.T) {
	nobody := lookupOrSkip(t, "nobody")
	root := t.TempDir()
	fakeProc(t, root, "40", "Runner.Worker", status("0", "0"), "")
	fakeProc(t, root, "41", "Runner.Worker", status(nobody.Uid, "65534"), "")
	for _, sudoUser := range []string{"", "nobody", "root"} {
		_, err := resolveTarget("", root, sudoUser)
		if err == nil || !strings.Contains(err.Error(), "runs as root") {
			t.Errorf("SUDO_USER=%q: err = %v; want a root worker refused", sudoUser, err)
		}
	}
}

// Workers of several users are picked between by SUDO_USER only, and only
// for a user one of them runs as.
func TestResolveTarget_severalWorkers(t *testing.T) {
	nobody := lookupOrSkip(t, "nobody")
	daemon := lookupOrSkip(t, "daemon")
	lookupOrSkip(t, "bin")
	root := t.TempDir()
	fakeProc(t, root, "40", "Runner.Worker", status(nobody.Uid, "65534"), "")
	fakeProc(t, root, "41", "Runner.Worker", status(daemon.Uid, "1"), "")

	if got, err := resolveTarget("", root, "daemon"); err != nil || got != "daemon" {
		t.Errorf("SUDO_USER=daemon: %q, %v; want daemon", got, err)
	}
	for _, sudoUser := range []string{"", "bin", "no-such-user-here"} {
		if got, err := resolveTarget("", root, sudoUser); err == nil || !strings.Contains(err.Error(), "several users") {
			t.Errorf("SUDO_USER=%q: %q, %v; want several workers refused", sudoUser, got, err)
		}
	}
}

// A worker whose uid names no user cannot be locked down by name.
func TestResolveTarget_workerWithoutUser(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, "40", "Runner.Worker", status("3999999", "3999999"), "")
	if _, err := user.LookupId("3999999"); err == nil {
		t.Skip("uid 3999999 names a user here")
	}
	if got, err := resolveTarget("", root, "nobody"); err == nil || !strings.Contains(err.Error(), "names no user") {
		t.Errorf("resolveTarget = %q, %v; want an unnamed uid refused", got, err)
	}
}

// With no worker visible, the user who ran cargowall through sudo is next;
// root there says nothing about the job, so the guesses follow.
func TestResolveTarget_noWorker(t *testing.T) {
	lookupOrSkip(t, "nobody")
	root := t.TempDir()
	if got, err := resolveTarget("", root, "nobody"); err != nil || got != "nobody" {
		t.Errorf("SUDO_USER=nobody: %q, %v; want nobody", got, err)
	}
	if os.Getuid() == 0 {
		return // the guesses as root depend on the host's accounts
	}
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, sudoUser := range []string{"", "root"} {
		if got, err := resolveTarget("", root, sudoUser); err != nil || got != cur.Username {
			t.Errorf("SUDO_USER=%q: %q, %v; want the current user %s", sudoUser, got, err, cur.Username)
		}
	}
}

// A host has sudo when cargowall's PATH finds one, or when any of the
// places sudo is installed holds one, a dangling link included: either way a
// job step may run it.
func TestHasSudo(t *testing.T) {
	dir := t.TempDir()
	old := sudoPaths
	t.Cleanup(func() { sudoPaths = old })
	t.Setenv("PATH", dir)
	sudoPaths = []string{dir + "/elsewhere/sudo", dir + "/link/sudo"}
	if hasSudo() {
		t.Fatal("hasSudo with no sudo on PATH or at any install path")
	}

	writeFile(t, dir+"/sudo", "#!/bin/sh\n")
	if err := os.Chmod(dir+"/sudo", 0o755); err != nil {
		t.Fatal(err)
	}
	if !hasSudo() {
		t.Error("a sudo on PATH was missed")
	}
	if err := os.Remove(dir + "/sudo"); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(dir+"/link", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir+"/gone", dir+"/link/sudo"); err != nil {
		t.Fatal(err)
	}
	if !hasSudo() {
		t.Error("a sudo at an install path, off PATH, was missed")
	}
}
