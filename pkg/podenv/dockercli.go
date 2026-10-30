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

// Which daemon the job's docker CLI uses, read as the CLI reads it: from
// the job's environment and the docker config that names.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// defaultDockerHost is the docker CLI's default socket, which an empty
// unix:// address means too.
const defaultDockerHost = "/var/run/docker.sock"

// dockerEnv is the environment the job's docker CLI runs in, which says
// which daemon it uses: under sudo, the one sudo was given, the job's,
// since a plain sudo strips DOCKER_HOST and hands us root's HOME;
// otherwise ours. Under sudo our own says nothing of the job's, so a sudo
// that cannot be read leaves the daemon unidentified (sudoEnv).
func dockerEnv() (func(string) string, error) {
	if os.Getenv("SUDO_UID") == "" {
		return os.Getenv, nil
	}
	env, err := sudoEnv(os.Getppid())
	if err != nil {
		return nil, fmt.Errorf("started under sudo, whose environment, the job's, cannot be read: %w", err)
	}
	return func(k string) string { return env[k] }, nil
}

// maxSudoDepth is how many processes up sudoEnv looks for sudo.
const maxSudoDepth = 16

// sudoEnv reads the environment of the nearest process named sudo from
// pid up, through any shell sudo ran in between. There is none to find
// for a process started detached (by setsid, or in the background of a
// shell that has since exited), which init has adopted.
func sudoEnv(pid int) (map[string]string, error) {
	for i := 0; i < maxSudoDepth && pid > 0; i++ {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return nil, err
		}
		comm, ppid, err := parseStat(stat)
		if err != nil {
			return nil, fmt.Errorf("/proc/%d/stat: %w", pid, err)
		}
		if comm == "sudo" {
			data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
			if err != nil {
				return nil, err
			}
			return parseEnviron(data), nil
		}
		pid = ppid
	}
	return nil, errors.New("no sudo among cargowall's parents")
}

// parseStat reads a process's name and parent from its /proc/<pid>/stat:
// "pid (comm) state ppid ...", where comm may hold spaces and parentheses.
func parseStat(stat []byte) (comm string, ppid int, err error) {
	open, end := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if open < 0 || end < open {
		return "", 0, errors.New("no process name")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 2 {
		return "", 0, errors.New("no parent")
	}
	ppid, err = strconv.Atoi(fields[1])
	return string(stat[open+1 : end]), ppid, err
}

// parseEnviron parses a /proc/<pid>/environ: NUL-separated KEY=value.
func parseEnviron(data []byte) map[string]string {
	env := make(map[string]string)
	for _, kv := range bytes.Split(data, []byte{0}) {
		if k, v, ok := strings.Cut(string(kv), "="); ok && k != "" {
			env[k] = v
		}
	}
	return env
}

// passwdHome is the current user's home directory from the passwd
// database, or "".
var passwdHome = func() string {
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// dockerCLIHost is the daemon address the docker CLI would use in the
// environment getenv reads, resolved as the CLI resolves it: DOCKER_HOST;
// else the context DOCKER_CONTEXT names, else the config file's current
// context, through that context's stored endpoint. setting says which; ""
// is the default context, the default socket. A context that cannot be
// read is an error, as it is to the CLI.
func dockerCLIHost(getenv func(string) string) (host, setting string, err error) {
	if h := getenv("DOCKER_HOST"); h != "" {
		return h, "DOCKER_HOST", nil
	}
	dir := getenv("DOCKER_CONFIG")
	if dir == "" {
		// The CLI falls back on the user's passwd entry without HOME.
		home := getenv("HOME")
		if home == "" {
			home = passwdHome()
		}
		if home != "" {
			dir = filepath.Join(home, ".docker")
		}
	}
	name, setting := getenv("DOCKER_CONTEXT"), "DOCKER_CONTEXT"
	if name == "" && dir != "" {
		config := filepath.Join(dir, "config.json")
		data, err := os.ReadFile(config)
		if errors.Is(err, fs.ErrNotExist) {
			return "", "", nil
		}
		if err != nil {
			return "", "", err
		}
		// As the CLI reads it: an empty file is no config, and one it
		// cannot parse is warned about and then ignored, for the default
		// context.
		var cfg struct {
			CurrentContext string `json:"currentContext"`
		}
		if len(bytes.TrimSpace(data)) == 0 || json.Unmarshal(data, &cfg) != nil {
			return "", "", nil
		}
		name, setting = cfg.CurrentContext, config+"'s currentContext"
	}
	if name == "" || name == "default" {
		return "", "", nil
	}
	setting = fmt.Sprintf("docker context %q (from %s)", name, setting)
	if dir == "" {
		return "", "", fmt.Errorf("%s: no docker config directory", setting)
	}
	sum := sha256.Sum256([]byte(name))
	data, err := os.ReadFile(filepath.Join(dir, "contexts", "meta", hex.EncodeToString(sum[:]), "meta.json"))
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", setting, err)
	}
	var meta struct {
		Endpoints map[string]struct{ Host string }
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", "", fmt.Errorf("%s: %w", setting, err)
	}
	if host = meta.Endpoints["docker"].Host; host == "" {
		return "", "", fmt.Errorf("%s names no docker endpoint", setting)
	}
	return host, setting, nil
}

// dockerHostElsewhere reports whether a docker daemon address names a
// daemon other than the one on socket. Two spellings of one socket are the
// same daemon: /var/run is a symlink to /run on most distributions. They
// are compared with their directories' symlinks resolved, so the spellings
// match before the daemon has made its socket too.
func dockerHostElsewhere(host, socket string) bool {
	p, ok := strings.CutPrefix(host, "unix://")
	if !ok {
		return true
	}
	if p == "" {
		p = defaultDockerHost
	}
	if resolveDir(p) == resolveDir(socket) {
		return false
	}
	if a, err := os.Stat(p); err == nil {
		if b, err := os.Stat(socket); err == nil && os.SameFile(a, b) {
			return false
		}
	}
	return true
}

// resolveDir is path with the symlinks in its directory resolved, or just
// cleaned when that directory cannot be resolved.
func resolveDir(path string) string {
	path = filepath.Clean(path)
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		return filepath.Join(dir, filepath.Base(path))
	}
	return path
}
