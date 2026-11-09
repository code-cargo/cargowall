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
	"path/filepath"
	"slices"
	"testing"
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestRunAs runs probes as another user, which setting credentials needs
// root for.
func TestRunAs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run as another user")
	}
	v := &jobView{uid: 65534, gid: 65534, groups: []uint32{65534}}
	if code, err := v.runAs("/bin/sh", "-c", `[ "$(id -u)" = 65534 ] && [ "$(id -G)" = 65534 ] && [ "$PATH" != "" ]`); err != nil || code != 0 {
		t.Errorf("runAs did not run as uid 65534 with only its groups: %d, %v", code, err)
	}
	dir := t.TempDir() // root's, mode 0700
	if code, err := v.runAs("/usr/bin/test", "-w", dir); err != nil || code == 0 {
		t.Errorf("runAs wrote where uid 65534 cannot: %d, %v", code, err)
	}
}
