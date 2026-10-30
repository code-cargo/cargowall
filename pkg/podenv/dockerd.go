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

// What daemon is behind the Docker socket, and where it makes its
// containers' cgroups.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// DockerdKind is what is behind the Docker socket.
type DockerdKind int

const (
	DockerdUnknown DockerdKind = iota // the probe failed
	DockerdAbsent                     // no socket
	// DockerdLocal: the daemon shares our mount namespace, so its
	// daemon.json is ours and our service manager can restart it.
	DockerdLocal
	// DockerdForeign: the daemon's pid is visible but its mount namespace is
	// not ours: another container sharing our pid namespace, or the host's
	// own daemon when we share the host's.
	DockerdForeign
	// DockerdHidden: the daemon's pid is outside our pid namespace, so
	// neither it nor any container it starts is visible to us.
	DockerdHidden
)

func (k DockerdKind) String() string {
	switch k {
	case DockerdAbsent:
		return "absent"
	case DockerdLocal:
		return "local"
	case DockerdForeign:
		return "foreign"
	case DockerdHidden:
		return "hidden"
	}
	return "unknown"
}

// Dockerd describes the daemon behind the Docker socket.
type Dockerd struct {
	Kind DockerdKind
	// Reason is the evidence for Foreign or Hidden, or the probe error for
	// Unknown, and why a fact below could not be read.
	Reason string
	// Cgroup is a Foreign daemon's cgroup v2 path as /proc/<pid>/cgroup
	// gives it in our cgroup namespace, "" when it could not be read. A
	// path under our namespace's root does not start with "/..".
	Cgroup string
	// CgroupDriver is how the daemon places its containers' cgroups, as it
	// reports it: "cgroupfs", in its own cgroup mount, or "systemd",
	// through the systemd it reaches. Read with ContainerTree, only in a
	// private cgroup namespace.
	CgroupDriver string
	// ContainerTree is the root of the cgroup v2 tree the daemon's
	// containers are made in, as our cgroup namespace reads it: under
	// cgroupfs its own mount at CgroupRoot, under systemd that systemd's.
	// "/" is our own root, "/../x" another beside it, and "" unread.
	ContainerTree string
	// pid is the daemon's pid in our pid namespace, 0 when not visible.
	pid int32
}

// note adds why a fact could not be read to the reason.
func (d *Dockerd) note(fact string, err error) {
	if d.Reason != "" {
		d.Reason += "; "
	}
	d.Reason += fact + ": " + err.Error()
}

// probeDockerd identifies the daemon through SO_PEERCRED on a connection
// to its socket: the kernel reports the listener's pid translated into our
// pid namespace, 0 when it is not visible there. A visible pid can still
// be another container's process once the pod shares one pid namespace, so
// the mount namespace is the decisive comparison. A socket-activated
// daemon reports the activating service manager, which shares ours on a
// host.
func probeDockerd(socket string) Dockerd {
	unknown := func(err error) Dockerd { return Dockerd{Kind: DockerdUnknown, Reason: err.Error()} }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		// A missing socket is absent, and so is anything at its path that
		// is not a socket, which refuses too: a directory a bind mount
		// made where no socket existed holds no daemon. A socket that
		// refuses was made by a daemon that is not listening: still
		// starting, or gone and perhaps coming back, which this one probe
		// cannot tell apart.
		if errors.Is(err, os.ErrNotExist) {
			return Dockerd{Kind: DockerdAbsent}
		}
		if errors.Is(err, unix.ECONNREFUSED) {
			if fi, serr := os.Stat(socket); serr == nil && fi.Mode().Type() != os.ModeSocket {
				return Dockerd{Kind: DockerdAbsent}
			}
		}
		return unknown(fmt.Errorf("dial %s: %w", socket, err))
	}
	defer conn.Close()
	pid, err := peerPid(conn.(*net.UnixConn))
	if err != nil {
		return unknown(err)
	}
	if pid == 0 {
		return Dockerd{Kind: DockerdHidden, Reason: "its pid is outside our pid namespace"}
	}
	ours, err := nsInode("/proc/self/ns/mnt")
	if err != nil {
		return unknown(err)
	}
	theirs, err := nsInode("/proc/" + strconv.Itoa(int(pid)) + "/ns/mnt")
	if err != nil {
		return unknown(err)
	}
	if ours != theirs {
		d := Dockerd{Kind: DockerdForeign, Reason: fmt.Sprintf("pid %d has another mount namespace", pid), pid: pid}
		d.Cgroup, _ = ReadCgroupPath("/proc/" + strconv.Itoa(int(pid)) + "/cgroup")
		return d
	}
	return Dockerd{Kind: DockerdLocal, pid: pid}
}

// probeContainerTree reads where the daemon makes its containers' cgroups:
// it asks the daemon for its cgroup driver over the socket, and finds the
// tree that driver uses. Only a daemon whose pid we see has one to find.
// One that does not answer in time, as a busy one may not, is judged by
// both drivers' trees (unaskedTree).
func (d *Dockerd) probeContainerTree(socket string) {
	driver, err := cgroupDriver(socket)
	if err != nil {
		d.note("its cgroup driver", err)
		if d.ContainerTree, err = unaskedTree(d.pid); err != nil {
			d.note("its containers' cgroup tree", err)
		}
		return
	}
	d.CgroupDriver = driver
	var tree string
	switch driver {
	case "cgroupfs":
		tree, err = mountRootOf(d.pid)
	case "systemd":
		tree, err = systemdTree(d.pid)
	default:
		err = fmt.Errorf("cgroup driver %q has no rule", driver)
	}
	if err != nil {
		d.note("its containers' cgroup tree", err)
		return
	}
	d.ContainerTree = tree
}

// unaskedTree is the tree a daemon whose cgroup driver is unknown makes
// its containers in, as far as either driver allows: its own cgroup
// mount, or, should a systemd answer at a socket the systemd driver would
// reach it by, that systemd's tree. Both under our root put its
// containers under it whichever it uses, and the tree returned is one
// outside, if either is, for privateScope to refuse.
func unaskedTree(pid int32) (string, error) {
	own, err := mountRootOf(pid)
	if err != nil {
		return "", err
	}
	sys, err := systemdTree(pid)
	switch {
	case errors.Is(err, errNoSystemd):
		return own, nil
	case err != nil:
		return "", err
	case !underRoot(sys):
		return sys, nil
	}
	return own, nil
}

// cgroupDriver asks the daemon at socket for its cgroup driver (GET /info).
func cgroupDriver(socket string) (string, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get("http://docker/info")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /info: %s", resp.Status)
	}
	var info struct{ CgroupDriver string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return "", fmt.Errorf("GET /info: %w", err)
	}
	if info.CgroupDriver == "" {
		return "", errors.New("GET /info names no cgroup driver")
	}
	return info.CgroupDriver, nil
}

// mountRootOf is the root of pid's cgroup v2 mount at CgroupRoot, as our
// cgroup namespace reads it.
func mountRootOf(pid int32) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/mountinfo")
	if err != nil {
		return "", err
	}
	return cgroupMountRoot(data)
}

// systemdSockets are where the systemd cgroup driver reaches systemd, in
// the order its D-Bus client tries them: the system bus, then systemd's
// own socket. DBUS_SYSTEM_BUS_ADDRESS, in the daemon's environment, moves
// the first.
const (
	systemBusSocket      = "/var/run/dbus/system_bus_socket"
	systemdPrivateSocket = "/run/systemd/private"
)

// systemdTree is the root of the cgroup tree a daemon at pid places its
// containers in under the systemd driver: the cgroup mount of the systemd
// it reaches, found as the peer of the first of its sockets that takes a
// connection, resolved in the daemon's root. A bus daemon there, or
// systemd itself where it holds the bus's socket, is of that systemd's
// machine and shares its tree. A systemd outside our pid namespace, such
// as the host's over a bind-mounted bus, is not shown to share ours.
func systemdTree(pid int32) (string, error) {
	proc := "/proc/" + strconv.Itoa(int(pid))
	buses, unfollowed := []string{systemBusSocket}, ""
	if env, err := os.ReadFile(proc + "/environ"); err == nil {
		if addr := parseEnviron(env)["DBUS_SYSTEM_BUS_ADDRESS"]; addr != "" {
			if buses, unfollowed, err = busSocketPaths(addr); err != nil {
				return "", err
			}
		}
	}
	root, err := unix.Open(proc+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	var errs []error
	for i, path := range append(buses, systemdPrivateSocket) {
		if i == len(buses) && unfollowed != "" {
			return "", fmt.Errorf("its D-Bus client would try %q next, which is not a socket path (%w)",
				unfollowed, errors.Join(errs...))
		}
		peer, err := socketPeerIn(root, path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if peer == 0 {
			return "", fmt.Errorf("the systemd it reaches at %s is outside our pid namespace", path)
		}
		return mountRootOf(peer)
	}
	for _, err := range errs {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, unix.ECONNREFUSED) {
			return "", fmt.Errorf("no systemd it reaches answers: %w", errors.Join(errs...))
		}
	}
	return "", fmt.Errorf("%w: %w", errNoSystemd, errors.Join(errs...))
}

// errNoSystemd is systemdTree's error when nothing listens at any socket
// the systemd driver would reach systemd by.
var errNoSystemd = errors.New("no systemd to reach")

// busSocketPaths is the socket paths a D-Bus address names, in the order
// a client tries them, up to the first entry that is not one (an abstract
// socket, tcp), which this probe cannot follow and which it returns as
// unfollowed: the client reaches it only if every path before it fails.
// The address is a list of entries separated by ";", each a transport and
// its "key=value" parameters separated by ",".
func busSocketPaths(addr string) (paths []string, unfollowed string, err error) {
	for _, entry := range strings.Split(addr, ";") {
		if entry == "" {
			continue
		}
		transport, params, _ := strings.Cut(entry, ":")
		path := ""
		for _, kv := range strings.Split(params, ",") {
			if v, ok := strings.CutPrefix(kv, "path="); ok && transport == "unix" {
				path = v
			}
		}
		if path == "" {
			return paths, entry, nil
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil, "", fmt.Errorf("its system bus address %q names no bus", addr)
	}
	return paths, "", nil
}

// socketPeerIn connects to the unix socket at path, resolved inside root
// as a chroot would resolve it, and returns its listener's pid in our pid
// namespace. The socket itself is opened there, to its last component, and
// connected through its descriptor: a symlink at the socket's own name is
// followed inside root too, not in ours.
func socketPeerIn(root int, path string) (int32, error) {
	sock, err := unix.Openat2(root, path, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT,
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	defer unix.Close(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", fmt.Sprintf("/proc/self/fd/%d", sock))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	defer conn.Close()
	return peerPid(conn.(*net.UnixConn))
}

// cgroupMountRoot is the root of the cgroup v2 mount at CgroupRoot in a
// mountinfo, the last mounted there, which is the one in sight. The kernel
// gives a cgroup2 mount's root as the reader's cgroup namespace sees it,
// so its path compares with ours.
func cgroupMountRoot(mountinfo []byte) (string, error) {
	var root, fstype string
	sc := bufio.NewScanner(bytes.NewReader(mountinfo))
	for sc.Scan() {
		// id parent major:minor root mountpoint options [optional...] - fstype source super-options
		f := strings.Fields(sc.Text())
		sep := slices.Index(f, "-")
		if sep < 6 || sep+1 >= len(f) || unescapeMountinfo(f[4]) != CgroupRoot {
			continue
		}
		root, fstype = unescapeMountinfo(f[3]), f[sep+1]
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	switch fstype {
	case "":
		return "", fmt.Errorf("nothing is mounted at %s", CgroupRoot)
	case "cgroup2":
		return root, nil
	default:
		return "", fmt.Errorf("%s is %s, not cgroup v2", CgroupRoot, fstype)
	}
}

// unescapeMountinfo undoes mountinfo's escapes: a space, tab, newline or
// backslash in a path is written as a backslash and three octal digits.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func peerPid(conn *net.UnixConn) (int32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	return cred.Pid, nil
}
