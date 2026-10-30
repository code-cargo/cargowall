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
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/procfs"
)

// defaultDockerHost is the docker CLI's default socket, which an empty
// unix:// address means too.
const defaultDockerHost = "/var/run/docker.sock"

// dockerEnv is the environment the job's docker CLI runs in, which says
// which daemon it uses, and the user it runs as, whose passwd entry gives
// the CLI a home without HOME. Under the sudo that started us, the
// environment sudo was given and SUDO_UID, the job's, since a plain sudo
// strips DOCKER_HOST and hands us root's HOME; otherwise ours, and "" for
// our own user. Under sudo our own environment says nothing of the job's,
// so a sudo that cannot be found or read leaves the daemon unidentified
// (startedBySudo).
func dockerEnv() (getenv func(string) string, uid string, err error) {
	uid = os.Getenv("SUDO_UID")
	if uid == "" {
		return os.Getenv, "", nil
	}
	env, err := startedBySudo(os.Getppid(), uid, os.Getenv("SUDO_COMMAND"))
	if err != nil {
		return nil, "", fmt.Errorf("started under sudo, whose environment, the job's, cannot be read: %w", err)
	}
	if env == nil {
		return os.Getenv, "", nil
	}
	return func(k string) string { return env[k] }, uid, nil
}

// sudoComms are the names sudo runs under: its own, and sudo-rs's, which
// Ubuntu installs as sudo and which may be run by its own name too.
var sudoComms = []string{"sudo", "sudo-rs"}

// startedBySudo reads the environment of the sudo that started us, whose
// SUDO_UID and SUDO_COMMAND, uid and command, we carry: the nearest process
// named sudo (sudoComms) from pid up, through any process between, as a
// shell sudo ran. The walk stops at the runner's worker, whose step
// started us. Carrying our SUDO_UID and SUDO_COMMAND itself, the worker was
// started under a sudo above it, the runner's (sudo ./run.sh), from which
// we inherited both, and our environment is the job's: that is nil, no
// error. Without them, a sudo between gave us ours and has gone from the
// chain, having exec'd us in its own place, and our environment is the one
// it scrubbed: unknown. The command tells such a sudo from the runner's
// even when one user ran both, which the uid cannot. A process with
// neither to find is unknown too, as one started detached (by setsid, or
// in the background of a shell that has since exited), which init has
// adopted.
func startedBySudo(pid int, uid, command string) (map[string]string, error) {
	found, comm, ok := procfs.AncestorByComm(pid, append([]string{procfs.RunnerWorkerComm}, sudoComms...)...)
	if !ok {
		return nil, errors.New("no sudo among cargowall's parents")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", found))
	if err != nil {
		return nil, err
	}
	env := parseEnviron(data)
	if comm == procfs.RunnerWorkerComm {
		if env["SUDO_UID"] != uid || env["SUDO_COMMAND"] != command {
			return nil, fmt.Errorf("no sudo between the runner's worker (pid %d), whose SUDO_UID and SUDO_COMMAND "+
				"are not our %s and %q, and us: one exec'd us in its place", found, uid, command)
		}
		return nil, nil
	}
	return env, nil
}

// parseEnviron parses a /proc/<pid>/environ: NUL-separated KEY=value. A
// key set twice keeps its first value, as getenv reads it, Go's and C's.
func parseEnviron(data []byte) map[string]string {
	env := make(map[string]string)
	for _, kv := range bytes.Split(data, []byte{0}) {
		if k, v, ok := strings.Cut(string(kv), "="); ok && k != "" {
			if _, set := env[k]; !set {
				env[k] = v
			}
		}
	}
	return env
}

// passwdHome is the home directory of the user with uid in the passwd
// database, or of the current user for "", or "".
var passwdHome = func(uid string) string {
	var u *user.User
	var err error
	if uid != "" {
		u, err = user.LookupId(uid)
	} else {
		u, err = user.Current()
	}
	if err == nil {
		return u.HomeDir
	}
	return ""
}

// readConfig reads a docker config file, at a path the job's environment
// picks, as root reads it: found first with O_PATH, which opens nothing (a
// device's open, a FIFO's wait for a writer), and read through that handle
// only if it is a regular file, so whatever is there, or a symlink leads
// to, is never opened otherwise. At most 1 MiB is read.
func readConfig(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file (mode %#o)", path, st.Mode&unix.S_IFMT)
	}
	// The handle, not the path, is reopened: the file checked is the one
	// read.
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// dockerCLIHost is the daemon address the docker CLI would use in the
// environment getenv reads, run as uid ("" for our own user), resolved as
// the CLI resolves it: DOCKER_HOST; else the context DOCKER_CONTEXT names,
// else the config file's current context, through that context's stored
// endpoint. setting says which; "" is the default context, the default
// socket. A context that cannot be read is an error, as it is to the CLI.
func dockerCLIHost(getenv func(string) string, uid string) (host, setting string, err error) {
	if h := getenv("DOCKER_HOST"); h != "" {
		return h, "DOCKER_HOST", nil
	}
	dir := getenv("DOCKER_CONFIG")
	if dir == "" {
		// The CLI falls back on its user's passwd entry without HOME.
		home := getenv("HOME")
		if home == "" {
			home = passwdHome(uid)
		}
		if home != "" {
			dir = filepath.Join(home, ".docker")
		}
	}
	name, setting := getenv("DOCKER_CONTEXT"), "DOCKER_CONTEXT"
	if name == "" && dir != "" {
		config := filepath.Join(dir, "config.json")
		data, err := readConfig(config)
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
	data, err := readConfig(filepath.Join(dir, "contexts", "meta", hex.EncodeToString(sum[:]), "meta.json"))
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
