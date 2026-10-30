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
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/procfs"
)

// DockerdKind is what is behind the Docker socket.
type DockerdKind int

const (
	DockerdUnknown DockerdKind = iota // the probe failed
	DockerdAbsent                     // no socket
	// DockerdLocal: the socket's listener shares our mount namespace, so
	// the daemon's daemon.json is ours and our service manager can
	// restart it: the listener is the daemon, or the service manager that
	// made the socket it was activated on.
	DockerdLocal
	// DockerdForeign: the listener's pid is visible but its mount
	// namespace is not ours: another container sharing our pid namespace,
	// or the host's own daemon when we share the host's.
	DockerdForeign
	// DockerdHidden: the listener's pid is outside our pid namespace, so
	// neither the daemon nor any container it starts is visible to us.
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
	// Cgroup is a Foreign listener's cgroup v2 path as /proc/<pid>/cgroup
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
	// Runtime is the pid, in our pid namespace, of the process whose
	// children its containers' tasks are, and whose view of the machine
	// decides where their cgroups are made: containerd, or the daemon
	// itself (runtimePid). 0 when it could not be shown, and Reason says
	// why. Read only where the scope depends on it.
	Runtime int32
	// pid is the pid, in our pid namespace, of the process serving the
	// socket, looked for only where the scope reads the daemon's runtime
	// (probeDockerd), and 0 elsewhere or when it could not be shown.
	pid int32
	// info is the daemon's GET /info, asked once (askInfo).
	info    *daemonInfo
	infoErr error
}

// note adds why a fact could not be read to the reason.
func (d *Dockerd) note(fact string, err error) {
	if d.Reason != "" {
		d.Reason += "; "
	}
	d.Reason += fact + ": " + err.Error()
}

// probeDockerd identifies the daemon behind the socket by its listener:
// SO_PEERCRED on a connection gives the listener's pid translated into our
// pid namespace, 0 when it is not visible there, and then neither is what
// it serves. The listener's mount namespace decides whether the daemon's
// config and service are ours, which is all the daemon.json rewrite reads:
// the daemon's own, or a socket-activated daemon's service manager's
// (systemd, for docker.socket and dockerd -H fd://), whose unit may give
// the daemon a mount namespace of its own (PrivateTmp) over the same
// config. A visible pid can still be another container's process once the
// pod shares one pid namespace, so the mount namespace is the decisive
// comparison.
//
// With findServer, where the scope reads the daemon's runtime, it also
// finds the process serving the socket (servingPid), the daemon itself
// whatever made its listener. One that cannot be shown (no unix_diag, a
// daemon still starting, a connection held by none or by two) leaves no
// runtime to look for, and the scope refuses.
func probeDockerd(socket string, findServer bool) Dockerd {
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
	daemon := Dockerd{Kind: DockerdLocal}
	if ours != theirs {
		daemon = Dockerd{Kind: DockerdForeign, Reason: fmt.Sprintf("pid %d has another mount namespace", pid)}
		daemon.Cgroup, _ = ReadCgroupPath("/proc/" + strconv.Itoa(int(pid)) + "/cgroup")
	}
	if findServer {
		if server, err := servingPid(conn.(*net.UnixConn)); err != nil {
			daemon.note("the process serving it", err)
		} else {
			daemon.pid = server
		}
	}
	return daemon
}

// probeRuntime finds the daemon's runtime (runtimePid), asking the daemon
// at socket the address of its containerd should no connection show one.
// Only a daemon whose pid we see has one to find, and only one shown to
// serve the socket, not its listener standing in.
func (d *Dockerd) probeRuntime(socket string) {
	if d.pid == 0 {
		d.note("its runtime", errors.New("not looked for without the process serving the socket"))
		return
	}
	runtime, err := runtimePid(d.pid, func() (string, error) {
		info, err := d.askInfo(socket)
		return info.containerdAddress(), err
	})
	if err != nil {
		d.note("its runtime", err)
		return
	}
	d.Runtime = runtime
}

// probeContainerTree reads where the daemon makes its containers' cgroups:
// it asks the daemon for its cgroup driver over the socket, and finds the
// tree that driver uses, as its runtime sees the machine (probeRuntime
// first). One that does not answer in time, as a busy one may not, is
// judged by both drivers' trees (unaskedTree).
func (d *Dockerd) probeContainerTree(socket string) {
	runtime := d.Runtime
	if runtime == 0 {
		return
	}
	info, err := d.askInfo(socket)
	driver := info.CgroupDriver
	if err == nil && driver == "" {
		err = errors.New("GET /info names no cgroup driver")
	}
	if err != nil {
		d.note("its cgroup driver", err)
		if d.ContainerTree, err = unaskedTree(runtime); err != nil {
			d.note("its containers' cgroup tree", err)
		}
		return
	}
	d.CgroupDriver = driver
	var tree string
	switch driver {
	case "cgroupfs":
		tree, err = mountRootOf(runtime)
	case "systemd":
		tree, err = systemdTree(runtime)
	default:
		err = fmt.Errorf("cgroup driver %q has no rule", driver)
	}
	if err != nil {
		d.note("its containers' cgroup tree", err)
		return
	}
	d.ContainerTree = tree
}

// runtimePid is the process whose view of the machine decides where the
// daemon at pid makes its containers' cgroups: containerd, whose shims run
// runc, which makes them in its cgroup mount (cgroupfs) or asks the
// systemd its environment's bus leads to (systemd), both containerd's. It
// is the containerd the daemon is connected to, as the connections show
// it rather than as its flags, daemon.json and the sockets there now
// would pick it: the holder of the other end of each connection the
// daemon made, by inode, which unix_diag gives in the daemon's network
// namespace. A connection whose other end no process we see holds, looked
// at again a moment later (runtimeRetry), may be to a containerd outside
// our pid namespace, and refuses. A daemon connected to no containerd runs
// one in its own process (ownContainerd).
func runtimePid(pid int32, containerdAddr func() (string, error)) (int32, error) {
	containerd, unheld, err := connectedContainerd(pid)
	if err == nil && unheld != 0 {
		runtimeRetry()
		containerd, unheld, err = connectedContainerd(pid)
	}
	switch {
	case err != nil:
		return 0, err
	case unheld != 0:
		return 0, fmt.Errorf("no process we see holds the other end of a connection it made (socket %d), "+
			"which may be a containerd outside our pid namespace", unheld)
	case len(containerd) == 1 && containerd[0] > 0 && containerd[0] <= math.MaxInt32:
		return int32(containerd[0]), nil
	case len(containerd) > 1:
		return 0, fmt.Errorf("it is connected to more than one containerd (pids %v)", containerd)
	}
	if err := ownContainerd(pid, containerdAddr); err != nil {
		return 0, fmt.Errorf("it is connected to no containerd, and %w", err)
	}
	return pid, nil
}

// runtimeRetry waits before runtimePid looks again at a connection whose
// other end no process held: a holder exiting has closed it by then, and
// a descriptor in flight between processes has landed. A test stands in.
var runtimeRetry = func() { time.Sleep(100 * time.Millisecond) }

// connectedContainerd is the containerd processes at the other end of the
// connections the daemon at pid made, and a socket at the other end of
// one that no process we see holds, 0 for none.
func connectedContainerd(pid int32) (containerd []int, unheld uint64, err error) {
	proc := "/proc/" + strconv.Itoa(int(pid))
	inodes, err := procfs.Sockets(int(pid))
	if err != nil {
		return nil, 0, fmt.Errorf("its sockets: %w", err)
	}
	netns := proc + "/ns/net"
	ours, err := nsInode("/proc/self/ns/net")
	if err != nil {
		return nil, 0, err
	}
	if theirs, err := nsInode(netns); err != nil {
		return nil, 0, err
	} else if theirs == ours {
		netns = ""
	}
	socks, err := unixDiag(netns, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("its connections: %w", err)
	}
	held := make(map[uint64]bool, len(inodes))
	for _, ino := range inodes {
		held[ino] = true
	}
	peers := map[uint64]bool{}
	for _, s := range socks {
		// A connection it made is an unbound stream socket of its, still
		// open at the other end: one it accepted carries its listener's
		// address.
		if held[s.ino] && s.stream && !s.named && !s.closed && s.peer != 0 {
			peers[s.peer] = true
		}
	}
	holders, err := procfs.SocketHolders(peers)
	if err != nil {
		return nil, 0, fmt.Errorf("its connections' other ends: %w", err)
	}
	for peer := range peers {
		if len(holders[peer]) == 0 {
			unheld = peer
		}
		for _, p := range holders[peer] {
			if procfs.Comm(p) == "containerd" && !slices.Contains(containerd, p) {
				containerd = append(containerd, p)
			}
		}
	}
	return containerd, unheld, nil
}

// ownContainerd says why the daemon at pid, connected to no containerd,
// cannot be shown to run its containers itself, or nil. A dockerd with no
// containerd binary embeds one, and serves the address it names in GET
// /info itself, which its shims connect back to; a podman service names
// none, and runs them through conmon. A daemon that names one another
// process serves has yet to reach it, and one that names none is shown to
// run them itself only when not a dockerd, which before embedding one
// (API 1.46, which names it) always reached one of its own.
func ownContainerd(pid int32, containerdAddr func() (string, error)) error {
	addr, err := containerdAddr()
	switch {
	case err != nil:
		return fmt.Errorf("the one it names is unread: %w", err)
	case addr == "" && procfs.Comm(int(pid)) == "dockerd":
		return errors.New("names none, though a dockerd running one itself names it")
	case addr == "":
		return nil
	case !filepath.IsAbs(addr):
		return fmt.Errorf("the one it names at %q is relative to a working directory this probe does not follow", addr)
	}
	root, err := unix.Open("/proc/"+strconv.Itoa(int(pid))+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	server, err := socketPeerIn(root, addr)
	if err != nil {
		return fmt.Errorf("the one it names: %w", err)
	}
	switch server {
	case pid:
		return nil
	case 0:
		return fmt.Errorf("the one it names at %s is outside our pid namespace", addr)
	}
	return fmt.Errorf("the one it names at %s is served by pid %d, not by itself", addr, server)
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

// daemonInfo is what the probes read from the daemon's GET /info: its
// cgroup driver, and where it reaches its containerd.
type daemonInfo struct {
	CgroupDriver string
	Containerd   *struct{ Address string }
}

// containerdAddress is the address of the daemon's containerd, without the
// unix:// scheme, "" for none named.
func (i daemonInfo) containerdAddress() string {
	if i.Containerd == nil {
		return ""
	}
	return strings.TrimPrefix(i.Containerd.Address, "unix://")
}

// askInfo asks the daemon at socket for GET /info, once for every probe
// that reads it, so a busy daemon costs its timeout once.
func (d *Dockerd) askInfo(socket string) (daemonInfo, error) {
	if d.info == nil {
		d.info = &daemonInfo{}
		d.infoErr = dockerGet(socket, "/info", d.info)
	}
	return *d.info, d.infoErr
}

// dockerGet asks the daemon at socket for path, within 2s, and decodes
// its JSON answer into out, unless out is nil.
func dockerGet(socket, path string, out any) error {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	return nil
}

// servingPid is the process serving the socket conn is connected to: the
// one holding the connection its listener accepted, found by the inode
// unix_diag gives as conn's peer, among every process's descriptors. Only
// a server that has accepted holds it, which its answer shows (GET
// /_ping), and a socket-activated daemon may be starting, so it is given a
// while. Whatever serves is the daemon, whatever its name: a podman
// service, or a stand-in.
func servingPid(conn *net.UnixConn) (int32, error) {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return 0, err
	}
	if err := req.Write(conn); err != nil {
		return 0, fmt.Errorf("GET /_ping: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return 0, fmt.Errorf("GET /_ping: %w", err)
	}
	resp.Body.Close()
	peer, err := connPeer(conn)
	if err != nil {
		return 0, err
	}
	holders, err := procfs.SocketHolders(map[uint64]bool{peer: true})
	if err != nil {
		return 0, err
	}
	switch pids := holders[peer]; {
	case len(pids) == 1 && pids[0] > 0 && pids[0] <= math.MaxInt32:
		return int32(pids[0]), nil
	case len(pids) == 0:
		return 0, errors.New("no process we see holds the connection its socket accepted from us: " +
			"its server is outside our pid namespace, or closed it once it answered")
	default:
		return 0, fmt.Errorf("the connection its socket accepted from us is held by more than one process (pids %v)", pids)
	}
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
	env, err := os.ReadFile(proc + "/environ")
	if err != nil {
		return "", fmt.Errorf("its environment, which may name its system bus: %w", err)
	}
	buses, unfollowed := []string{systemBusSocket}, ""
	if addr := parseEnviron(env)["DBUS_SYSTEM_BUS_ADDRESS"]; addr != "" {
		if buses, unfollowed, err = busSocketPaths(addr); err != nil {
			return "", err
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
// its "key=value" parameters separated by ",", whose values may escape a
// byte as %XX.
func busSocketPaths(addr string) (paths []string, unfollowed string, err error) {
	for _, entry := range strings.Split(addr, ";") {
		if entry == "" {
			continue
		}
		transport, params, _ := strings.Cut(entry, ":")
		path := ""
		for _, kv := range strings.Split(params, ",") {
			if v, ok := strings.CutPrefix(kv, "path="); ok && transport == "unix" {
				// Values may escape any byte as %XX, as URL paths do.
				if path, err = url.PathUnescape(v); err != nil {
					return nil, "", fmt.Errorf("its system bus address %q: %w", entry, err)
				}
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
