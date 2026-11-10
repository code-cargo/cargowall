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

// asRoot is the current user when cargowall runs as root, as it does.
var asRoot = &user.User{Uid: "0", Username: "root"}

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
// SUDO_USER and every guess. A configured user must be that owner.
func TestResolveTarget_workerOwner(t *testing.T) {
	nobody := lookupOrSkip(t, "nobody")
	root := t.TempDir()
	fakeProc(t, root, "40", "Runner.Worker", status(nobody.Uid, "65534"), "")
	fakeProc(t, root, "41", "Runner.Worker", status(nobody.Uid, "65534"), "")
	fakeProc(t, root, "42", "bash", status("0", "0"), "") // not a worker

	if got, err := resolveTarget("", root, "someoneelse", asRoot, nil); err != nil || got != "nobody" {
		t.Errorf("resolveTarget = %q, %v; want the worker's owner, nobody", got, err)
	}
	alice := &user.User{Uid: "4242", Username: "alice"}
	if got, err := resolveTarget("", root, "daemon", alice, []string{"daemon"}); err != nil || got != "nobody" {
		t.Errorf("resolveTarget = %q, %v; want the worker's owner ahead of every fallback", got, err)
	}
	if got, err := resolveTarget("nobody", root, "daemon", asRoot, nil); err != nil || got != "nobody" {
		t.Errorf("a configured user who is the owner = %q, %v; want nobody", got, err)
	}
	lookupOrSkip(t, "daemon")
	if got, err := resolveTarget("daemon", root, "", asRoot, nil); err == nil || !strings.Contains(err.Error(), "is not the user") {
		t.Errorf("a configured user who is not the owner = %q, %v; want refused", got, err)
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
	if _, err := resolveTarget("alice", root, "", asRoot, nil); err == nil || !strings.Contains(err.Error(), "runs as root") {
		t.Errorf("a configured user with a root worker: err = %v; want refused", err)
	}
	for _, sudoUser := range []string{"", "nobody", "root"} {
		_, err := resolveTarget("", root, sudoUser, asRoot, nil)
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

	if got, err := resolveTarget("", root, "daemon", asRoot, nil); err != nil || got != "daemon" {
		t.Errorf("SUDO_USER=daemon: %q, %v; want daemon", got, err)
	}
	if got, err := resolveTarget("nobody", root, "daemon", asRoot, nil); err != nil || got != "nobody" {
		t.Errorf("a configured owner over SUDO_USER: %q, %v; want nobody", got, err)
	}
	for _, sudoUser := range []string{"", "bin", "no-such-user-here"} {
		if got, err := resolveTarget("", root, sudoUser, asRoot, nil); err == nil || !strings.Contains(err.Error(), "several users") {
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
	if got, err := resolveTarget("", root, "nobody", asRoot, nil); err == nil || !strings.Contains(err.Error(), "/etc/passwd does not name") {
		t.Errorf("resolveTarget = %q, %v; want an unnamed uid refused", got, err)
	}
}

// With no worker visible, a configured user is the target, then a non-root
// current user. Otherwise a runner account and the user who ran cargowall
// through sudo are the candidates: either alone, or both when they agree, is
// the target, and both differing is refused, since either could be the
// job's and locking the other would report a lockdown applied. Root as
// SUDO_USER names nobody.
func TestResolveTarget_noWorker(t *testing.T) {
	lookupOrSkip(t, "nobody")
	lookupOrSkip(t, "daemon")
	root := t.TempDir()
	alice := &user.User{Uid: "4242", Username: "alice"}
	for _, tc := range []struct {
		name     string
		cfg      string
		sudoUser string
		current  *user.User
		guesses  []string
		want     string
	}{
		{"a configured user", "bin", "daemon", asRoot, []string{"nobody"}, "bin"},
		{"a non-root current user", "", "daemon", alice, []string{"nobody"}, "alice"},
		{"a runner account alone", "", "", asRoot, []string{"no-such-user-here", "nobody"}, "nobody"},
		{"a runner account and SUDO_USER root", "", "root", asRoot, []string{"nobody"}, "nobody"},
		{"a runner account that is SUDO_USER", "", "nobody", asRoot, []string{"nobody"}, "nobody"},
		{"a runner account and a different SUDO_USER", "", "daemon", asRoot, []string{"nobody"}, ""},
		{"SUDO_USER when no runner account exists", "", "daemon", asRoot, []string{"no-such-user-here"}, "daemon"},
		{"SUDO_USER root names nothing", "", "root", asRoot, []string{"no-such-user-here"}, ""},
		{"nothing at all", "", "", asRoot, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveTarget(tc.cfg, root, tc.sudoUser, tc.current, tc.guesses)
			if tc.want == "" {
				if err == nil {
					t.Errorf("resolveTarget = %q; want no target", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("resolveTarget = %q, %v; want %s", got, err, tc.want)
			}
		})
	}
}

// A host has sudo when any name sudo is installed under is in a standard
// directory, on cargowall's PATH or on a Runner.Worker's PATH, a dangling
// link included: a job step may run it. With none, a sudo policy file left
// behind is reported.
func TestHasSudo(t *testing.T) {
	dir := t.TempDir()
	oldDirs, oldPolicies := sudoDirs, sudoPolicies
	t.Cleanup(func() { sudoDirs, sudoPolicies = oldDirs, oldPolicies })
	sudoDirs = []string{dir + "/std"}
	sudoPolicies = []string{dir + "/etc/sudoers"}
	t.Setenv("PATH", dir+"/path:relative/bin")
	proc := dir + "/proc"
	fakeProc(t, proc, "40", "Runner.Worker", status("1001", "1001"), "HOME=/home/runner\x00PATH="+dir+"/job")
	fakeProc(t, proc, "41", "bash", status("1001", "1001"), "PATH="+dir+"/notworker")
	for _, d := range []string{"std", "path", "job", "notworker", "etc"} {
		if err := os.MkdirAll(dir+"/"+d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	check := func(want bool, wantPolicy, why string) {
		t.Helper()
		found, policy := hasSudo(proc)
		if found != want || policy != wantPolicy {
			t.Errorf("%s: hasSudo = %v, %q; want %v, %q", why, found, policy, want, wantPolicy)
		}
	}
	place := func(path string) func() {
		t.Helper()
		if err := os.Symlink(dir+"/gone", path); err != nil {
			t.Fatal(err)
		}
		return func() { os.Remove(path) }
	}

	t.Chdir(dir)
	if err := os.MkdirAll(dir+"/relative/bin", 0o755); err != nil {
		t.Fatal(err)
	}
	place(dir + "/relative/bin/sudo")
	check(false, "", "nothing anywhere but a relative PATH entry, which names nothing fixed")
	undo := place(dir + "/notworker/sudo")
	check(false, "", "a sudo only on a process that is not the worker")
	undo()

	for _, tc := range []struct{ path, why string }{
		{dir + "/std/sudo.ws", "classic sudo under its own name in a standard dir"},
		{dir + "/std/sudoedit", "sudoedit in a standard dir"},
		{dir + "/path/sudo-rs", "sudo-rs on cargowall's PATH"},
		{dir + "/job/sudo", "a sudo only on the worker's PATH"},
	} {
		undo := place(tc.path)
		check(true, "", tc.why)
		undo()
	}

	writeFile(t, dir+"/etc/sudoers", "root ALL=(ALL) ALL\n")
	check(false, dir+"/etc/sudoers", "a policy left behind by a removed sudo")
}

// The visudo cargowall runs and the sudo whose answer it trusts come only
// from cargowall's PATH and the fixed directories, never a worker's PATH,
// which is the job's; and only as an executable that cargowall's user owns
// and nobody else can write, in a directory likewise, links resolved.
// sudoedit never probes.
func TestToolBinaries(t *testing.T) {
	dir := t.TempDir()
	old := sudoDirs
	t.Cleanup(func() { sudoDirs = old })
	sudoDirs = []string{dir + "/a", dir + "/b", dir + "/open"}
	t.Setenv("PATH", dir+"/path")
	for _, d := range []string{"a", "b", "path", "job", "open"} {
		if err := os.MkdirAll(dir+"/"+d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir+"/open", 0o777); err != nil {
		t.Fatal(err)
	}
	exe := func(path string, mode os.FileMode) {
		t.Helper()
		writeFile(t, path, "#!/bin/sh\n")
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	if p, err := visudoBinary(); err == nil {
		t.Errorf("visudoBinary = %q with none anywhere", p)
	}
	writeFile(t, dir+"/a/visudo", "not executable\n")
	exe(dir+"/open/visudo", 0o755) // in a directory anyone can write
	exe(dir+"/path/visudo", 0o775) // group-writable
	exe(dir+"/b/visudo-rs", 0o755)
	if p, err := visudoBinary(); err != nil || p != dir+"/b/visudo-rs" {
		t.Errorf("visudoBinary = %q, %v; want sudo-rs's visudo-rs, past a non-executable, a group-writable and an exposed visudo", p, err)
	}

	proc := t.TempDir()
	fakeProc(t, proc, "40", "Runner.Worker", status("1001", "1001"), "PATH="+dir+"/job")
	exe(dir+"/job/sudo", 0o755)
	if found, _ := hasSudo(proc); !found {
		t.Error("hasSudo missed a sudo on the worker's PATH")
	}
	if p := sudoBinary(); p != "" {
		t.Errorf("sudoBinary = %q; a sudo only on the worker's PATH must never be the one probed with", p)
	}
	exe(dir+"/a/sudoedit", 0o755)
	if err := os.Symlink(dir+"/gone", dir+"/a/sudo"); err != nil {
		t.Fatal(err)
	}
	if p := sudoBinary(); p != "" {
		t.Errorf("sudoBinary = %q; want neither sudoedit nor a dangling link", p)
	}
	exe(dir+"/b/sudo-rs.real", 0o755)
	if err := os.Symlink(dir+"/b/sudo-rs.real", dir+"/path/sudo-rs"); err != nil {
		t.Fatal(err)
	}
	if p := sudoBinary(); p != dir+"/b/sudo-rs.real" {
		t.Errorf("sudoBinary = %q; want the link on PATH resolved to its target", p)
	}
}
