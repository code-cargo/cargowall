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
	"syscall"

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
// no lockdown takes away, and locking any account would report a lockdown
// that holds against nothing the job runs.
//
// With workers visible the target is their owner, the user the job's steps
// run as. A configured user must be that owner, and of workers of several
// users, the configured user or else SUDO_USER chooses; anything else is an
// error, as is a worker whose uid /etc/passwd does not name.
//
// With no worker visible the target is the configured user, else the
// current user when not root, else whichever of two candidates exists: the
// first of guesses, a runner account, and the user who ran cargowall
// through sudo, unless root. Both existing and differing is an error: either
// could be the job's (an operator who started cargowall before any job, a
// CI system's own account on a host that also has a runner account), and
// locking the other would verify against it and report a lockdown applied.
func resolveTarget(cfgUsername, procRoot, sudoUser string, current *user.User, guesses []string) (string, error) {
	owners := workerOwners(procRoot)
	if slices.Contains(owners, 0) {
		return "", errRootWorker
	}
	if len(owners) > 0 {
		return workerTarget(owners, cfgUsername, sudoUser)
	}
	if cfgUsername != "" {
		return cfgUsername, nil
	}
	if current.Uid != "0" {
		return current.Username, nil
	}
	guess := ""
	for _, u := range guesses {
		if _, err := user.Lookup(u); err == nil {
			guess = u
			break
		}
	}
	if _, err := user.Lookup(sudoUser); sudoUser == "root" || err != nil {
		sudoUser = "" // root names nobody, and a missing user is no one's
	}
	switch {
	case guess != "" && sudoUser != "" && guess != sudoUser:
		return "", fmt.Errorf("no Runner.Worker is visible, and both the runner account %q and SUDO_USER %q could be the job's user; name it with --sudo-lockdown-user", guess, sudoUser)
	case guess != "":
		return guess, nil
	case sudoUser != "":
		return sudoUser, nil
	}
	return "", errors.New("could not determine target username for sudo lockdown: no Runner.Worker is visible, no runner account exists and SUDO_USER names none; name it with --sudo-lockdown-user")
}

// workerTarget is the owner of the visible workers, owners, that the
// configured user, else SUDO_USER, names; with a single owner and neither
// set, that owner.
func workerTarget(owners []uint32, cfgUsername, sudoUser string) (string, error) {
	if cfgUsername != "" {
		if u, err := user.Lookup(cfgUsername); err == nil && slices.Contains(owners, uidOf(u)) {
			return cfgUsername, nil
		}
		return "", fmt.Errorf("the configured lockdown user %q is not the user the runner's Runner.Worker runs as (uids %v)", cfgUsername, owners)
	}
	if len(owners) > 1 {
		if u, err := user.Lookup(sudoUser); err == nil && sudoUser != "" && slices.Contains(owners, uidOf(u)) {
			return sudoUser, nil
		}
		return "", fmt.Errorf("the runner's Runner.Workers run as several users (uids %v), and SUDO_USER does not name one of them", owners)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(owners[0]), 10))
	if err != nil {
		return "", fmt.Errorf("the Runner.Worker runs as uid %d, which /etc/passwd does not name: %w", owners[0], err)
	}
	return u.Username, nil
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
// alternatives link to one of them. The first three run commands.
var sudoNames = []string{"sudo", "sudo.ws", "sudo-rs", "sudoedit", "sudoedit.ws"}

// visudoNames are visudo's names: sudo-rs alone ships it as visudo-rs.
var visudoNames = []string{"visudo", "visudo-rs"}

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

// toolPaths is every path that holds one of names, in search order: on
// cargowall's PATH, as a command run by name resolves it, then on the PATH of
// a Runner.Worker under procRoot when withWorkers, then in sudoDirs. Anything
// there counts, a dangling link included.
//
// A worker's PATH is the job's own environment, and can name directories the
// job writes. It is searched only to find whether a sudo is there, where a
// hit only refuses the no-sudo shortcut; never to pick a binary cargowall
// runs or trusts (trustedTool).
func toolPaths(names []string, procRoot string, withWorkers bool) []string {
	dirs := filepath.SplitList(os.Getenv("PATH"))
	if withWorkers {
		for _, dir := range workerDirs(procRoot) {
			dirs = append(dirs, filepath.SplitList(environValue(filepath.Join(dir, "environ"), "PATH"))...)
		}
	}
	dirs = append(dirs, sudoDirs...)
	var found []string
	for _, dir := range dirs {
		if !strings.HasPrefix(dir, "/") {
			continue // a relative PATH entry names nothing fixed
		}
		for _, name := range names {
			path := filepath.Join(dir, name)
			if _, err := os.Lstat(path); err == nil && !slices.Contains(found, path) {
				found = append(found, path)
			}
		}
	}
	return found
}

// hasSudo reports whether this host has a sudo for a job step to run: any of
// sudoNames where toolPaths looks, the workers' PATH included. When it finds
// none, policy is a sudo policy file still in place, or "".
func hasSudo(procRoot string) (found bool, policy string) {
	if len(toolPaths(sudoNames, procRoot, true)) > 0 {
		return true, ""
	}
	for _, p := range sudoPolicies {
		if _, err := os.Lstat(p); err == nil {
			return false, p
		}
	}
	return false, ""
}

// trustedTool is the first of names, on cargowall's PATH or in sudoDirs, that
// is an executable file cargowall's own user owns and only it can write, in
// a directory likewise, links resolved; or "". cargowall runs the visudo it
// returns as root, and trusts the exit status of the sudo it returns, so
// nothing another user can write is either.
func trustedTool(names []string) string {
	for _, p := range toolPaths(names, "", false) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		fi, err := os.Stat(real)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 || !ownedAndClosed(fi) {
			continue
		}
		if di, err := os.Stat(filepath.Dir(real)); err == nil && ownedAndClosed(di) {
			return real
		}
	}
	return ""
}

// ownedAndClosed is whether fi is owned by the user cargowall runs as and
// writable by no group or other user.
func ownedAndClosed(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && fi.Mode().Perm()&0o022 == 0
}

// sudoBinary is the sudo the verification probes with: the first trusted one
// that runs commands, or "".
func sudoBinary() string {
	return trustedTool(sudoNames[:3])
}

// visudoBinary is the visudo the lockdown validates sudoers with.
func visudoBinary() (string, error) {
	if p := trustedTool(visudoNames); p != "" {
		return p, nil
	}
	return "", errors.New("no visudo, owned by root and writable by no one else, to validate sudoers with")
}
