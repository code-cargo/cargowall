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
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code-cargo/cargowall/pkg/procfs"
)

// fakeProc writes a /proc/<pid> with the given comm, status and environ.
func fakeProc(t *testing.T, root, pid, comm, status, environ string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "comm"), comm+"\n")
	writeFile(t, filepath.Join(dir, "status"), status)
	writeFile(t, filepath.Join(dir, "environ"), environ)
}

func status(uid, groups string) string {
	return "Name:\tRunner.Worker\nUid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\nGid:\t1001\t1001\t1001\t1001\nGroups:\t" + groups + " \n"
}

func TestParseStatusCreds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	writeFile(t, path, status("1001", "27 100 123 1001"))
	uid, groups, ok := parseStatusCreds(path)
	if !ok || uid != 1001 || !slices.Equal(groups, []uint32{27, 100, 123, 1001}) {
		t.Errorf("parseStatusCreds = %d, %v, %v", uid, groups, ok)
	}

	writeFile(t, path, "Name:\tx\nGroups:\t\n")
	if _, _, ok := parseStatusCreds(path); ok {
		t.Error("a status without Uid parsed")
	}
	writeFile(t, path, "Uid:\t1001\t1001\t1001\t1001\nGroups:\t27 x\n")
	if _, _, ok := parseStatusCreds(path); ok {
		t.Error("a status with a malformed group parsed")
	}
}

func TestWorkerView(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, "100", "Runner.Worker", status("1001", "27 100 1001"),
		"PATH=/bin\x00DOCKER_HOST=unix:///run/user/docker.sock\x00DOCKER_HOST=tcp://shadowed:2375\x00")
	fakeProc(t, root, "101", "Runner.Worker", status("1001", "123 1001"), "DOCKER_HOST=tcp://localhost:2375\x00")
	fakeProc(t, root, "200", "Runner.Worker", status("1002", "4 1002"), "DOCKER_HOST=tcp://other:2375\x00")
	fakeProc(t, root, "300", "bash", status("1001", "999"), "")
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	groups, hosts, found := workerView(root, 1001)
	if !found {
		t.Fatal("no worker found")
	}
	slices.Sort(groups)
	if want := []uint32{27, 100, 123, 1001}; !slices.Equal(groups, want) {
		t.Errorf("groups = %v, want %v (the user's workers joined, nothing else)", groups, want)
	}
	slices.Sort(hosts)
	if want := []string{"tcp://localhost:2375", "unix:///run/user/docker.sock"}; !slices.Equal(hosts, want) {
		t.Errorf("docker hosts = %v, want %v", hosts, want)
	}

	if _, _, found := workerView(root, 4242); found {
		t.Error("found a worker for a user that runs none")
	}
}

func TestSudoProbe(t *testing.T) {
	first := sudoProbe(nil)
	if first == nil {
		t.Skip("none of the probe commands exist here")
	}
	for _, p := range sudoProbes {
		if fileExists(p[0]) {
			if !slices.Equal(first, p) {
				t.Errorf("sudoProbe(nil) = %v, want %v, the first that exists", first, p)
			}
			break
		}
	}

	// Allowing the first probe moves the check to one the allowlist does
	// not name, by path or as the same file (/bin is /usr/bin on merged-usr
	// systems).
	next := sudoProbe([]string{first[0]})
	if next == nil {
		t.Skip("only one probe command exists here")
	}
	a, err := os.Stat(first[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(next[0])
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(a, b) {
		t.Errorf("sudoProbe chose %v, the allowed %s", next, first[0])
	}

	all := make([]string, 0, len(sudoProbes))
	for _, p := range sudoProbes {
		all = append(all, p[0])
	}
	if p := sudoProbe(all); p != nil {
		t.Errorf("sudoProbe with every probe allowed = %v, want nil", p)
	}
}

// TestRunAs runs probes as another user, with a supplementary group distinct
// from the primary gid — which setting credentials needs root for. It is what
// proves runAs applies Credential.Groups: a probe without it would not see
// gid 4242.
func TestRunAs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run as another user")
	}
	v := &jobView{uid: 65534, gid: 65534, groups: []uint32{65534, 4242}}
	if code, out, err := v.runAs("/bin/sh", "-c", `id -u; id -G`); err != nil || code != 0 {
		t.Fatalf("runAs: %d, %q, %v", code, out, err)
	} else if !strings.Contains(out, "65534") || !strings.Contains(out, "4242") {
		t.Errorf("runAs did not apply uid 65534 and the supplementary gid 4242: %q", out)
	}
	dir := t.TempDir() // root's, mode 0700
	if code, _, err := v.runAs("/usr/bin/test", "-w", dir); err != nil || code == 0 {
		t.Errorf("runAs wrote where uid 65534 cannot: %d, %v", code, err)
	}
}

// TestRunAs_execFailure: a command that cannot be started is an error
// (nothing ran), not a zero exit.
func TestRunAs_execFailure(t *testing.T) {
	v := selfView(t)
	if code, _, err := v.runAs("/does/not/exist"); err == nil || code != -1 {
		t.Errorf("a missing binary: code=%d err=%v, want -1 and an error", code, err)
	}
}

// selfView is a jobView for the test process's own user, so runAs needs no
// privilege: it runs as who it already is.
func selfView(t *testing.T) *jobView {
	t.Helper()
	gids, err := syscall.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	groups := make([]uint32, len(gids))
	for i, g := range gids {
		groups[i] = uint32(g)
	}
	return &jobView{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), groups: groups}
}

// writeExec writes an executable shell script and returns its path.
func writeExec(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRunAs_classifies checks the three outcomes runAs must tell apart: a
// clean exit (status, no error), a command killed by a signal, and a
// timeout.
func TestRunAs_classifies(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runAs sets process credentials, which needs root")
	}
	v := selfView(t)
	dir := t.TempDir()

	if code, out, err := v.runAs(writeExec(t, dir, "ok", "echo hello; exit 3")); err != nil || code != 3 || !strings.Contains(out, "hello") {
		t.Errorf("clean exit: code=%d out=%q err=%v, want 3, hello, nil", code, out, err)
	}
	if code, _, err := v.runAs(writeExec(t, dir, "sig", "kill -TERM $$")); err == nil || code != -1 {
		t.Errorf("a signal: code=%d err=%v, want -1 and an error", code, err)
	}

	old := probeTimeout
	probeTimeout = 200 * time.Millisecond
	defer func() { probeTimeout = old }()
	if code, _, err := v.runAs(writeExec(t, dir, "slow", "sleep 5")); err == nil || code != -1 {
		t.Errorf("a timeout: code=%d err=%v, want -1 and an error", code, err)
	}
}

// fakeSudo puts a stand-in `sudo` first on PATH; verifyLockdown finds it
// with exec.LookPath.
func fakeSudo(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	writeExec(t, dir, "sudo", body)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestVerifyLockdown_outcomes exercises the decisive branches: a sudo that
// runs the probe (escalation), one that refuses it (held), and one that
// never completes (unverifiable, left in place).
func TestVerifyLockdown_outcomes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("verifyLockdown runs the probe with process credentials, which needs root")
	}
	v := selfView(t)

	fakeSudo(t, "exit 0")
	if err := verifyLockdown(v, nil, discardLogger()); !errors.Is(err, errLockdownIneffective) {
		t.Errorf("sudo running the probe: err=%v, want errLockdownIneffective", err)
	}

	fakeSudo(t, "echo nope >&2; exit 1")
	if err := verifyLockdown(v, nil, discardLogger()); err != nil {
		t.Errorf("sudo refusing the probe: err=%v, want nil", err)
	}

	old := probeTimeout
	probeTimeout = 200 * time.Millisecond
	defer func() { probeTimeout = old }()
	fakeSudo(t, "sleep 5")
	if err := verifyLockdown(v, nil, discardLogger()); err != nil {
		t.Errorf("a sudo that hangs: err=%v, want nil (left in place)", err)
	}
}

// TestLookupJobView_fallbackUsesPreGIDs: with no Runner.Worker of the user's
// own, the view falls back to the groups captured before the lockdown.
func TestLookupJobView_fallbackUsesPreGIDs(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	view, err := lookupJobView(u.Username, map[string]bool{"4242": true})
	if err != nil {
		t.Fatal(err)
	}
	if view.from == procfs.RunnerWorkerComm {
		t.Skip("a Runner.Worker of this user is running; the fallback isn't taken")
	}
	if !slices.Contains(view.groups, 4242) {
		t.Errorf("fallback groups %v do not include the pre-lockdown gid 4242", view.groups)
	}
}

// TestLookupJobView_unknownGroups: with no Runner.Worker and no pre-lockdown
// groups (the lookup failed), a step's groups are unknown, so the view is an
// error rather than a probe with the primary gid alone, which could report a
// lockdown verified that it never tested.
func TestLookupJobView_unknownGroups(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	view, err := lookupJobView(u.Username, nil)
	if err == nil && view.from == procfs.RunnerWorkerComm {
		t.Skip("a Runner.Worker of this user is running; the fallback isn't taken")
	}
	if err == nil {
		t.Errorf("lookupJobView with no worker and nil preGIDs = %+v, want an error", view)
	}
}

// TestVerifyLockdown_allowlistControl: with an allowlist, "Verified" also
// needs sudo to permit an allowlisted command (sudo -n -l, nothing run). A
// deny that holds while the allowlist does not apply is a Warn instead.
func TestVerifyLockdown_allowlistControl(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("verifyLockdown runs the probe with process credentials, which needs root")
	}
	v := selfView(t)
	allow := []string{"/usr/bin/id"}

	// Refuses the probe (args "-n -- ..."), permits the -l check ("-n -l ...").
	fakeSudo(t, `[ "$2" = "-l" ] && exit 0; exit 1`)
	logger, buf := captureLog()
	if err := verifyLockdown(v, allow, logger); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "Verified sudo lockdown") || !strings.Contains(out, "allowlist_checked=/usr/bin/id") {
		t.Errorf("allowlist applies: want Verified with the command checked: %s", out)
	}

	// Refuses everything: the deny holds but the allowlist does not apply.
	fakeSudo(t, "exit 1")
	logger, buf = captureLog()
	if err := verifyLockdown(v, allow, logger); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); strings.Contains(out, "Verified sudo lockdown") || !strings.Contains(out, "sudo -l did not confirm") {
		t.Errorf("allowlist refused: want a Warn and no Verified: %s", out)
	}

	// The -l check itself never completes (here, a timeout): unverified, a
	// Warn that the allowlist could not be checked, never "Verified".
	old := probeTimeout
	probeTimeout = 200 * time.Millisecond
	defer func() { probeTimeout = old }()
	fakeSudo(t, `[ "$2" = "-l" ] && sleep 5; exit 1`)
	logger, buf = captureLog()
	if err := verifyLockdown(v, allow, logger); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); strings.Contains(out, "Verified sudo lockdown") || !strings.Contains(out, "could not be checked") {
		t.Errorf("-l check failed to run: want a Warn and no Verified: %s", out)
	}
	probeTimeout = old

	// No allowlisted command exists to ask about: the control is skipped and
	// the deny alone is verified.
	fakeSudo(t, "exit 1")
	logger, buf = captureLog()
	if err := verifyLockdown(v, []string{"/no/such/cmd"}, logger); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "Verified sudo lockdown") || !strings.Contains(out, `allowlist_checked=""`) {
		t.Errorf("no allowlisted command exists: want Verified with nothing checked: %s", out)
	}
}

// TestAllowlistProbe: the positive check asks about the first allowlisted
// command that exists as a regular file, skipping one that doesn't — asking
// sudo -l about a missing command would fail and read as the allowlist not
// applying.
func TestAllowlistProbe(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct {
		allow []string
		want  string
	}{
		{[]string{"/no/such/cmd", "/usr/bin/id"}, "/usr/bin/id"},
		{[]string{dir, "/usr/bin/id"}, "/usr/bin/id"}, // a directory is not a command
		{[]string{"/no/such/cmd"}, ""},
		{nil, ""},
	} {
		if got := allowlistProbe(tt.allow); got != tt.want {
			t.Errorf("allowlistProbe(%v) = %q, want %q", tt.allow, got, tt.want)
		}
	}
}
