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
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/code-cargo/cargowall/pkg/procfs"
)

// procDir is where the runner's workers are read from.
const procDir = "/proc"

// ciUsernames are the runner accounts guessed at when nothing names one.
var ciUsernames = []string{"runner", "github", "ci"}

// errRootWorker is a runner whose job steps run as root.
var errRootWorker = errors.New("a Runner.Worker runs as root: its job steps have root without sudo, which the lockdown cannot take away")

// resolveUsername determines whose sudo the lockdown takes, reading the
// runner's workers from /proc and the user who ran cargowall through sudo
// from SUDO_USER (resolveTarget).
func resolveUsername(cfgUsername string) (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}
	return resolveTarget(cfgUsername, procDir, os.Getenv("SUDO_USER"), current, ciUsernames)
}

// resolveTarget determines whose sudo the lockdown takes. A worker running
// as root is an error first of all: its steps have root without sudo, which
// no lockdown takes away, and locking any account, a configured one
// included, would report a lockdown that holds against nothing the job runs.
//
// A configured user is then taken as given. Otherwise it is the owner of the
// runner's Runner.Worker, whose job steps the lockdown must hold against.
// With no worker visible it is the current user when not root, then the
// first of guesses that exists, then the user who ran cargowall through
// sudo, unless root: SUDO_USER comes last, since an account that started
// cargowall before any job ran is not the job's, where an existing runner
// account is. Workers of several users that sudoUser does not choose
// between are an error, and so is a worker whose uid /etc/passwd does not
// name.
func resolveTarget(cfgUsername, procRoot, sudoUser string, current *user.User, guesses []string) (string, error) {
	owners := workerOwners(procRoot)
	if slices.Contains(owners, 0) {
		return "", errRootWorker
	}
	if cfgUsername != "" {
		return cfgUsername, nil
	}
	if len(owners) > 1 {
		if u, err := user.Lookup(sudoUser); err == nil && sudoUser != "" && slices.Contains(owners, uidOf(u)) {
			return sudoUser, nil
		}
		return "", fmt.Errorf("the runner's Runner.Workers run as several users (uids %v), and SUDO_USER does not name one of them", owners)
	}
	if len(owners) == 1 {
		u, err := user.LookupId(strconv.FormatUint(uint64(owners[0]), 10))
		if err != nil {
			return "", fmt.Errorf("the Runner.Worker runs as uid %d, which /etc/passwd does not name: %w", owners[0], err)
		}
		return u.Username, nil
	}
	if current.Uid != "0" {
		return current.Username, nil
	}
	for _, u := range guesses {
		if _, err := user.Lookup(u); err == nil {
			return u, nil
		}
	}
	if sudoUser != "" && sudoUser != "root" {
		return sudoUser, nil
	}
	return "", fmt.Errorf("could not determine target username for sudo lockdown")
}

// uidOf is u's uid, or a value no worker has when it does not parse.
func uidOf(u *user.User) uint32 {
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return ^uint32(0)
	}
	return uint32(n)
}

// workerOwners is the distinct real uids of the Runner.Workers under
// procRoot, in the order found.
func workerOwners(procRoot string) []uint32 {
	var owners []uint32
	for _, dir := range workerDirs(procRoot) {
		if owner, _, ok := parseStatusCreds(filepath.Join(dir, "status")); ok && !slices.Contains(owners, owner) {
			owners = append(owners, owner)
		}
	}
	return owners
}

// workerDirs is the /proc/<pid> of each Runner.Worker under procRoot.
func workerDirs(procRoot string) []string {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err == nil && procfs.CommIn(procRoot, pid) == procfs.RunnerWorkerComm {
			dirs = append(dirs, filepath.Join(procRoot, e.Name()))
		}
	}
	return dirs
}

// sudoNames are the names sudo, classic or sudo-rs, is installed under:
// next to sudo-rs, classic sudo is sudo.ws, and sudo itself is only the
// alternatives link to one of them.
var sudoNames = []string{"sudo", "sudo.ws", "sudo-rs", "sudoedit", "sudoedit.ws"}

// sudoDirs are where sudo is installed, looked in as well as cargowall's own
// PATH and the runner's workers' PATH, either of which can miss one: a sudo
// missed here would be a lockdown skipped with sudo in place.
var sudoDirs = []string{
	"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin",
	"/usr/lib/cargo/bin", // sudo-rs, before the alternatives link
	"/run/wrappers/bin",  // NixOS's setuid wrapper
}

// sudoPolicies are the policy files sudo reads; one left behind by a removed
// sudo is worth a Warn, not a lockdown.
var sudoPolicies = []string{mainSudoers, sudoRsSudoers}

// hasSudo reports whether this host has a sudo for a job step to run: any of
// sudoNames, a dangling link included, in sudoDirs, in cargowall's PATH or in
// the PATH of a Runner.Worker under procRoot. When it finds none, policy is
// a sudo policy file still in place, or "".
func hasSudo(procRoot string) (found bool, policy string) {
	dirs := slices.Clone(sudoDirs)
	dirs = append(dirs, filepath.SplitList(os.Getenv("PATH"))...)
	for _, dir := range workerDirs(procRoot) {
		dirs = append(dirs, filepath.SplitList(environValue(filepath.Join(dir, "environ"), "PATH"))...)
	}
	for _, dir := range dirs {
		if !strings.HasPrefix(dir, "/") {
			continue // a relative PATH entry names nothing fixed
		}
		for _, name := range sudoNames {
			if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
				return true, ""
			}
		}
	}
	for _, p := range sudoPolicies {
		if _, err := os.Lstat(p); err == nil {
			return false, p
		}
	}
	return false, ""
}
