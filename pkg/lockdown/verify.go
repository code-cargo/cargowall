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

// What a job step can still do once the lockdown is in place, asked of the
// system as a step would ask it. Editing /etc/group takes a group away from
// later logins only: a running process keeps the supplementary groups it
// started with, and every step descends from the runner's Runner.Worker,
// which started before the lockdown. So the check runs as the target user
// with the groups that worker holds, not the ones /etc/group now lists.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/code-cargo/cargowall/pkg/procfs"
)

const (
	probeTimeout = 10 * time.Second
	probePath    = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	dockerSocket = "/var/run/docker.sock"
)

// sudoProbes are the commands the escalation check asks sudo to run as
// root, the first that exists and the allowlist does not name. Each does
// nothing.
var sudoProbes = [][]string{
	{"/usr/bin/true"},
	{"/bin/true"},
	{"/usr/bin/id", "-u"},
	{"/bin/sh", "-c", ":"},
}

// jobView is what a job step runs with, as far as the lockdown is
// concerned.
type jobView struct {
	uid, gid uint32
	groups   []uint32
	// from says where groups came from, for the log.
	from string
	// dockerHosts are the DOCKER_HOST values the runner's workers carry.
	dockerHosts []string
}

// workerView reads the supplementary groups and DOCKER_HOST of every
// Runner.Worker under procRoot owned by uid. Several workers' groups are
// joined: a step of any of them is a step this lockdown must hold against.
func workerView(procRoot string, uid uint32) (groups []uint32, dockerHosts []string, found bool) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, nil, false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || procfs.CommIn(procRoot, pid) != procfs.RunnerWorkerComm {
			continue
		}
		owner, gs, ok := parseStatusCreds(filepath.Join(procRoot, e.Name(), "status"))
		if !ok || owner != uid {
			continue
		}
		found = true
		for _, g := range gs {
			if !slices.Contains(groups, g) {
				groups = append(groups, g)
			}
		}
		if h := environValue(filepath.Join(procRoot, e.Name(), "environ"), "DOCKER_HOST"); h != "" && !slices.Contains(dockerHosts, h) {
			dockerHosts = append(dockerHosts, h)
		}
	}
	return groups, dockerHosts, found
}

// parseStatusCreds reads the real uid and the supplementary groups from a
// /proc/<pid>/status.
func parseStatusCreds(path string) (uid uint32, groups []uint32, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, false
	}
	defer f.Close()
	haveUID := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, found := strings.Cut(sc.Text(), ":")
		if !found {
			continue
		}
		fields := strings.Fields(val)
		switch key {
		case "Uid":
			if len(fields) == 0 {
				return 0, nil, false
			}
			n, err := strconv.ParseUint(fields[0], 10, 32)
			if err != nil {
				return 0, nil, false
			}
			uid, haveUID = uint32(n), true
		case "Groups":
			for _, f := range fields {
				n, err := strconv.ParseUint(f, 10, 32)
				if err != nil {
					return 0, nil, false
				}
				groups = append(groups, uint32(n))
			}
		}
	}
	return uid, groups, haveUID
}

// environValue is key's first value in a NUL-separated environ file, as
// getenv reads it, or "".
func environValue(path, key string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, kv := range strings.Split(string(data), "\x00") {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v
		}
	}
	return ""
}

// lookupJobView is the target user's credentials as a step holds them: the
// groups of the runner's workers when one is visible, else the groups the
// user had before the lockdown removed any (preGIDs), which a process
// started before it still holds.
func lookupJobView(username string, preGIDs map[string]bool) (*jobView, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	v := &jobView{uid: uint32(uid), gid: uint32(gid)}
	if gs, hosts, ok := workerView("/proc", v.uid); ok {
		v.groups, v.dockerHosts, v.from = gs, hosts, procfs.RunnerWorkerComm
		return v, nil
	}
	for g := range preGIDs {
		n, err := strconv.ParseUint(g, 10, 32)
		if err == nil {
			v.groups = append(v.groups, uint32(n))
		}
	}
	slices.Sort(v.groups)
	v.from = "the user's groups before the lockdown"
	return v, nil
}

// runAs runs argv as the job's user with the job's groups, with nothing of
// cargowall's environment but a PATH, no terminal and a timeout, and
// returns its exit status.
func (v *jobView) runAs(argv ...string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{probePath}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Credential: &syscall.Credential{Uid: v.uid, Gid: v.gid, Groups: v.groups},
	}
	err := cmd.Run()
	if ctx.Err() != nil {
		return -1, fmt.Errorf("%s timed out after %s", argv[0], probeTimeout)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// sudoProbe is the first of sudoProbes that exists and that allow does not
// name, by path or as the same file, or nil.
func sudoProbe(allow []string) []string {
	for _, p := range sudoProbes {
		fi, err := os.Stat(p[0])
		if err != nil {
			continue
		}
		allowed := false
		for _, a := range allow {
			if a == p[0] {
				allowed = true
				break
			}
			if ai, err := os.Stat(a); err == nil && os.SameFile(ai, fi) {
				allowed = true
				break
			}
		}
		if !allowed {
			return p
		}
	}
	return nil
}

// errLockdownIneffective is a lockdown that a job step can still escalate
// past.
var errLockdownIneffective = errors.New("sudo lockdown does not hold")

// verifyLockdown asks sudo, as a job step would, to run a command the
// allowlist does not name, and returns errLockdownIneffective when it does.
// Whatever stops the question being asked (no sudo, no probe command, a
// timeout) is logged and leaves the lockdown in place: that is what was
// asked for, and nothing shows it does not hold.
func verifyLockdown(v *jobView, allow []string, logger *slog.Logger) error {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		logger.Debug("No sudo binary, nothing to verify the lockdown against")
		return nil
	}
	probe := sudoProbe(allow)
	if probe == nil {
		logger.Warn("Cannot verify sudo lockdown: every probe command is on the allowlist")
		return nil
	}
	code, err := v.runAs(append([]string{sudo, "-n", "--"}, probe...)...)
	if err != nil {
		logger.Warn("Cannot verify sudo lockdown", "error", err)
		return nil
	}
	if code == 0 {
		return fmt.Errorf("%w: as uid %d with %s (%v), sudo ran %s as root",
			errLockdownIneffective, v.uid, v.from, v.groups, strings.Join(probe, " "))
	}
	logger.Info("Verified sudo lockdown", "uid", v.uid, "groups", v.groups, "groups_from", v.from)
	return nil
}

// warnDockerAccess warns when a job step can still reach a docker daemon,
// which is root on the host to anything that can start a container, and so
// a way around the lockdown. Removing the user from the docker group does
// not take the socket from a running step; cutting it would take docker
// from every job that runs under the lockdown, so this reports it instead.
func warnDockerAccess(v *jobView, logger *slog.Logger) {
	sockets := []string{dockerSocket}
	for _, h := range v.dockerHosts {
		p, ok := strings.CutPrefix(h, "unix://")
		if !ok {
			logger.Warn("Sudo lockdown leaves docker reachable: the job's DOCKER_HOST is a network address, which no group restricts",
				"docker_host", h)
			continue
		}
		if p != "" && !slices.Contains(sockets, p) {
			sockets = append(sockets, p)
		}
	}
	for _, s := range sockets {
		if fi, err := os.Stat(s); err != nil || fi.Mode()&os.ModeSocket == 0 {
			continue
		}
		// The shell's own test: not every distribution ships a test binary.
		if code, err := v.runAs("/bin/sh", "-c", `test -w "$1"`, "sh", s); err == nil && code == 0 {
			logger.Warn("Sudo lockdown leaves docker reachable: job steps can still use the docker socket, which is root-equivalent",
				"socket", s, "uid", v.uid, "groups_from", v.from)
		}
	}
}
