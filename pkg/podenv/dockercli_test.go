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

package podenv

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/procfs"
)

// /proc/<pid>/environ is NUL-separated KEY=value, values free to hold "=",
// and a key set twice reads as its first value, as getenv reads it.
func TestParseEnviron(t *testing.T) {
	env := parseEnviron([]byte("HOME=/home/runner\x00DOCKER_HOST=tcp://a:2376\x00X=a=b\x00\x00junk\x00DOCKER_HOST=unix://\x00"))
	want := map[string]string{"HOME": "/home/runner", "DOCKER_HOST": "tcp://a:2376", "X": "a=b"}
	if len(env) != len(want) {
		t.Fatalf("parseEnviron = %v, want %v", env, want)
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("parseEnviron[%q] = %q, want %q", k, env[k], v)
		}
	}
}

// startedBySudo finds the nearest sudo through the processes between, and
// reads the environment sudo was given, unless the runner's worker comes
// first: a sudo above it started the runner, not us. Copies of sh named
// sudo and Runner.Worker stand in for both.
func TestStartedBySudo(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	data, err := os.ReadFile(sh)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	standIn := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sudo, sudoRs, worker := standIn("sudo"), standIn("sudo-rs"), standIn(procfs.RunnerWorkerComm)
	// start runs script under the stand-in top, with DOCKER_HOST and env in
	// its environment, and returns the sleep at the bottom of the chain.
	// The trailing commands keep each shell from exec'ing the next in its
	// place.
	start := func(top, script string, env ...string) int {
		cmd := exec.Command(top, "-c", script+"; :")
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "DOCKER_HOST=tcp://dind:2375"}, env...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		pid := cmd.Process.Pid
		for i := 0; i < 250; i++ {
			kids, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
			if f := strings.Fields(string(kids)); len(f) > 0 {
				pid, _ = strconv.Atoi(f[0])
				continue
			}
			if procfs.Comm(pid) == "sleep" {
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				return pid
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("no sleep at the bottom of %q", script)
		return 0
	}

	env, err := startedBySudo(start(sudo, "sleep 60"), "1001")
	if err != nil || env["DOCKER_HOST"] != "tcp://dind:2375" {
		t.Errorf("under sudo: got %v, %v; want the stand-in sudo's environment", env, err)
	}
	env, err = startedBySudo(start(sudoRs, "sleep 60"), "1001")
	if err != nil || env["DOCKER_HOST"] != "tcp://dind:2375" {
		t.Errorf("under sudo-rs by its own name: got %v, %v; want its environment", env, err)
	}
	// A worker carrying our SUDO_UID was started under the runner's sudo,
	// from which we inherited ours: our own environment is the job's.
	underRunnerSudo := start(sudo, worker+" -c 'sleep 60; :'", "SUDO_UID=1001")
	env, err = startedBySudo(underRunnerSudo, "1001")
	if err != nil || env != nil {
		t.Errorf("under a worker a sudo started: got %v, %v; want our own environment (nil)", env, err)
	}
	// A worker without it: a sudo between gave us ours and exec'd us in its
	// place, leaving our environment its scrubbed one.
	if _, err := startedBySudo(underRunnerSudo, "1002"); err == nil {
		t.Errorf("under a worker with another SUDO_UID: want an error")
	}
	if _, err := startedBySudo(start(worker, "sleep 60"), "1001"); err == nil {
		t.Errorf("under a worker with no SUDO_UID: want an error")
	}
	// Init has no parent, and is not sudo.
	if _, err := startedBySudo(1, "1001"); err == nil {
		t.Errorf("startedBySudo(1): want an error, from no sudo among its parents")
	}
}

func TestDockerHostElsewhere(t *testing.T) {
	const sock = "/var/run/docker.sock"
	for in, want := range map[string]bool{
		"unix:///var/run/docker.sock":       false,
		"unix:///var/run//docker.sock":      false,
		"unix://":                           false, // the CLI's default socket
		"unix:///run/user/1000/docker.sock": true,
		"tcp://localhost:2376":              true,
		"ssh://builder@remote.example.com":  true,
	} {
		if got := dockerHostElsewhere(in, sock); got != want {
			t.Errorf("dockerHostElsewhere(%q) = %v, want %v", in, got, want)
		}
	}

	// Another spelling of the same socket, as /var/run is of /run.
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "run", "docker.sock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../run", filepath.Join(root, "var", "run")); err != nil {
		t.Fatal(err)
	}
	probed := filepath.Join(root, "run", "docker.sock")
	if dockerHostElsewhere("unix://"+filepath.Join(root, "var", "run", "docker.sock"), probed) {
		t.Errorf("symlinked spelling of the socket: want the same daemon")
	}
	if !dockerHostElsewhere("unix://"+filepath.Join(root, "var", "run", "other.sock"), probed) {
		t.Errorf("a socket that does not exist is not the probed one")
	}
	// Before the daemon has made its socket, the spellings still match.
	notYet := filepath.Join(root, "run", "later.sock")
	if dockerHostElsewhere("unix://"+filepath.Join(root, "var", "run", "later.sock"), notYet) {
		t.Errorf("symlinked spelling of a socket not yet made: want the same daemon")
	}
}

// The CLI's daemon comes from DOCKER_HOST, else the context DOCKER_CONTEXT
// or the config's currentContext names, through the context's stored
// endpoint, as the docker CLI resolves it.
func TestDockerCLIHost(t *testing.T) {
	dir := t.TempDir()
	context := func(name, host string) {
		sum := sha256.Sum256([]byte(name))
		meta := filepath.Join(dir, "contexts", "meta", hex.EncodeToString(sum[:]))
		if err := os.MkdirAll(meta, 0o755); err != nil {
			t.Fatal(err)
		}
		data := `{"Name":"` + name + `","Metadata":{},"Endpoints":{"docker":{"Host":"` + host + `","SkipTLSVerify":false}}}`
		if err := os.WriteFile(filepath.Join(meta, "meta.json"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	config := func(data string) {
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	context("remote", "tcp://builder:2376")
	env := func(kv ...string) func(string) string {
		m := map[string]string{"DOCKER_CONFIG": dir}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	check := func(name string, getenv func(string) string, wantHost string, wantErr bool) {
		t.Helper()
		host, setting, err := dockerCLIHost(getenv, "")
		if (err != nil) != wantErr || host != wantHost {
			t.Errorf("%s: got %q (%s), %v; want %q, error %v", name, host, setting, err, wantHost, wantErr)
		}
	}
	check("no config at all", env(), "", false)
	check("DOCKER_HOST", env("DOCKER_HOST", "tcp://a:2375", "DOCKER_CONTEXT", "remote"), "tcp://a:2375", false)
	check("DOCKER_CONTEXT", env("DOCKER_CONTEXT", "remote"), "tcp://builder:2376", false)
	check("DOCKER_CONTEXT naming the default", env("DOCKER_CONTEXT", "default"), "", false)
	check("DOCKER_CONTEXT naming no stored context", env("DOCKER_CONTEXT", "gone"), "", true)
	config(`{"auths":{},"currentContext":"remote"}`)
	check("the config's currentContext", env(), "tcp://builder:2376", false)
	check("DOCKER_CONTEXT over the config", env("DOCKER_CONTEXT", "default"), "", false)
	config(`{"auths":{}}`)
	check("a config with no current context", env(), "", false)
	// As the CLI reads it: an empty config is none, and one it cannot
	// parse is ignored for the default context.
	config(``)
	check("an empty config", env(), "", false)
	config(`{not json`)
	check("a config the CLI cannot parse either", env(), "", false)
	home := func(k string) string { return map[string]string{"HOME": filepath.Dir(dir)}[k] }
	check("a HOME with no .docker", home, "", false)

	// A FIFO where a config file should be is refused, not waited on.
	fifo := func(path string) {
		t.Helper()
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	unblocked := func(name string, getenv func(string) string) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			check(name, getenv, "", true)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the probe waits on the FIFO", name)
		}
	}
	fifo(filepath.Join(dir, "config.json"))
	unblocked("a FIFO for the config", env())
	sum := sha256.Sum256([]byte("remote"))
	meta := filepath.Join(dir, "contexts", "meta", hex.EncodeToString(sum[:]), "meta.json")
	fifo(meta)
	unblocked("a FIFO for the context's meta.json", env("DOCKER_CONTEXT", "remote"))
	for _, path := range []string{filepath.Join(dir, "config.json"), meta} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	context("remote", "tcp://builder:2376")

	// Without HOME the CLI reads its user's passwd entry's home: under
	// sudo, the job user's (SUDO_UID), not ours.
	passwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(passwd, ".docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(passwd, ".docker")
	context("remote", "tcp://builder:2376")
	config(`{"currentContext":"remote"}`)
	saved := passwdHome
	passwdHome = func(uid string) string {
		if uid == "1001" {
			return passwd
		}
		return ""
	}
	t.Cleanup(func() { passwdHome = saved })
	noHome := func(string) string { return "" }
	if host, _, err := dockerCLIHost(noHome, "1001"); err != nil || host != "tcp://builder:2376" {
		t.Errorf("no HOME, under sudo: got %q, %v; want the job user's context", host, err)
	}
	if host, _, err := dockerCLIHost(noHome, ""); err != nil || host != "" {
		t.Errorf("no HOME, our own user with no config: got %q, %v; want the default", host, err)
	}
}
