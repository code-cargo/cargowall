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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// /proc/<pid>/environ is NUL-separated KEY=value, values free to hold "=".
func TestParseEnviron(t *testing.T) {
	env := parseEnviron([]byte("HOME=/home/runner\x00DOCKER_HOST=tcp://a:2376\x00X=a=b\x00\x00junk\x00"))
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

// sudoEnv finds the nearest sudo through the processes between, and reads
// the environment sudo was given. Here a shell named sudo stands in for
// it, with a child of its own.
func TestSudoEnv(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	data, err := os.ReadFile(sh)
	if err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(t.TempDir(), "sudo")
	if err := os.WriteFile(fake, data, 0o755); err != nil {
		t.Fatal(err)
	}
	// The trailing command keeps the shell from exec'ing sleep in its place.
	cmd := exec.Command(fake, "-c", "sleep 60; :")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "DOCKER_HOST=tcp://dind:2375"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	var child int
	for i := 0; i < 250 && child == 0; i++ {
		kids, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", cmd.Process.Pid, cmd.Process.Pid))
		if f := strings.Fields(string(kids)); len(f) > 0 {
			child, _ = strconv.Atoi(f[0])
		} else {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if child == 0 {
		t.Fatal("the stand-in sudo started no child")
	}
	env, err := sudoEnv(child)
	if err != nil {
		t.Fatal(err)
	}
	if got := env["DOCKER_HOST"]; got != "tcp://dind:2375" {
		t.Errorf("sudoEnv(child of sudo)[DOCKER_HOST] = %q, want the stand-in's", got)
	}
	// Init has no parent, and is not sudo.
	if _, err := sudoEnv(1); err == nil {
		t.Errorf("sudoEnv(1): want an error, from no sudo among its parents")
	}
}

// /proc/<pid>/stat names the process in parentheses, a name that may hold
// spaces and parentheses of its own, then its state and parent.
func TestParseStat(t *testing.T) {
	for in, want := range map[string]struct {
		comm string
		ppid int
	}{
		"4242 (sudo) S 4100 4242 4100 0 -1":        {"sudo", 4100},
		"4243 (a b) (c)) R 1 4243 4243 0 -1":       {"a b) (c)", 1},
		"1 (systemd) S 0 1 1 0 -1 4194560 75 7 0 ": {"systemd", 0},
	} {
		comm, ppid, err := parseStat([]byte(in))
		if err != nil || comm != want.comm || ppid != want.ppid {
			t.Errorf("parseStat(%q) = %q, %d, %v; want %q, %d", in, comm, ppid, err, want.comm, want.ppid)
		}
	}
	for _, in := range []string{"", "4242 sudo S 1", "4242 (sudo)", "4242 (sudo) S x"} {
		if _, _, err := parseStat([]byte(in)); err == nil {
			t.Errorf("parseStat(%q): want an error", in)
		}
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
		host, setting, err := dockerCLIHost(getenv)
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

	// Without HOME the CLI reads the passwd entry's home, as here.
	passwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(passwd, ".docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(passwd, ".docker")
	context("remote", "tcp://builder:2376")
	config(`{"currentContext":"remote"}`)
	saved := passwdHome
	passwdHome = func() string { return passwd }
	t.Cleanup(func() { passwdHome = saved })
	check("no HOME: the passwd home's config", func(string) string { return "" }, "tcp://builder:2376", false)
}
