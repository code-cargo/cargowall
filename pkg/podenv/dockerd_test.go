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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeDaemon serves an /info answer, and /_ping, on a unix socket of its
// own, and returns the socket's path.
func fakeDaemon(t *testing.T, status int, body string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
			fmt.Fprint(w, "OK")
		case "/info":
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// The daemon names its cgroup driver in /info; an answer without one, or
// an error, leaves it unread.
func TestCgroupDriver(t *testing.T) {
	if got, err := cgroupDriver(fakeDaemon(t, http.StatusOK, `{"CgroupDriver":"systemd","CgroupVersion":"2"}`)); err != nil || got != "systemd" {
		t.Errorf("cgroupDriver = %q, %v; want systemd", got, err)
	}
	for _, d := range []struct {
		status int
		body   string
	}{{http.StatusOK, `{"CgroupVersion":"2"}`}, {http.StatusInternalServerError, `{}`}, {http.StatusOK, `{not json`}} {
		if got, err := cgroupDriver(fakeDaemon(t, d.status, d.body)); err == nil {
			t.Errorf("cgroupDriver(%d %s) = %q, want an error", d.status, d.body, got)
		}
	}
}

// The tree a daemon's containers are made in follows its driver: under
// cgroupfs, its own cgroup mount, here ours, since it runs in our process.
// A driver with no rule leaves the tree unread, with the reason.
func TestProbeContainerTree(t *testing.T) {
	ours, err := mountRootOf(int32(os.Getpid()))
	if err != nil {
		t.Skipf("no cgroup v2 mount at %s: %v", CgroupRoot, err)
	}
	// The daemon stands in for one connected to no containerd: its own
	// view decides.
	probe := func(d Dockerd, socket string) Dockerd {
		d.probeRuntime(socket)
		d.probeContainerTree(socket)
		return d
	}
	d := probe(Dockerd{Kind: DockerdLocal, pid: int32(os.Getpid())}, fakeDaemon(t, http.StatusOK, `{"CgroupDriver":"cgroupfs"}`))
	if d.CgroupDriver != "cgroupfs" || d.ContainerTree != ours {
		t.Errorf("cgroupfs: got %+v, want our own mount's root %q", d, ours)
	}
	d = probe(Dockerd{Kind: DockerdLocal, pid: int32(os.Getpid())}, fakeDaemon(t, http.StatusOK, `{"CgroupDriver":"none"}`))
	if d.ContainerTree != "" || !strings.Contains(d.Reason, "no rule") {
		t.Errorf("unknown driver: got %+v, want no tree, with the reason", d)
	}
	// A daemon that does not say, as a busy one may not in time, is judged
	// by both drivers' trees as its runtime sees them, a containerd it is
	// connected to: its own mount, and that of any systemd it could reach,
	// here on a bus this process listens on, so ours too.
	sock := filepath.Join(t.TempDir(), "containerd.sock")
	runtime := standIn(t, "containerd", "listen", []string{"CARGOWALL_TEST_SOCK=" + sock, "DBUS_SYSTEM_BUS_ADDRESS=unix:path=" + busListener(t)})
	d = probe(Dockerd{Kind: DockerdLocal, pid: standInDaemon(t, "dockerd", sock)}, fakeDaemon(t, http.StatusServiceUnavailable, `{}`))
	if d.Runtime != runtime || d.CgroupDriver != "" || d.ContainerTree != ours || !strings.Contains(d.Reason, "its cgroup driver") {
		t.Errorf("unasked: got %+v, want containerd %d's view, our own mount's root %q, noting the driver unread", d, runtime, ours)
	}
}

// standIn starts the test binary as a process named name, playing role
// (TestStandIn), with env added and files from descriptor 3, and returns
// its pid once it has created its ready file.
func standIn(t *testing.T, name, role string, env []string, files ...*os.File) int32 {
	t.Helper()
	return standInWith(t, nil, name, role, env, files...)
}

// standInDaemon starts a stand-in named name holding a connection to each
// of socks.
func standInDaemon(t *testing.T, name string, socks ...string) int32 {
	t.Helper()
	return standIn(t, name, "connect", []string{"CARGOWALL_TEST_SOCK=" + strings.Join(socks, string(filepath.ListSeparator))})
}

// standInWith is standIn in the namespaces attr gives.
func standInWith(t *testing.T, attr *syscall.SysProcAttr, name, role string, env []string, files ...*os.File) int32 {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, name)
	if err := os.Symlink(os.Args[0], bin); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(dir, "ready")
	cmd := exec.Command(bin, "-test.run", "^TestStandIn$")
	cmd.Env = append(os.Environ(), append(env, "CARGOWALL_TEST_ROLE="+role, "CARGOWALL_TEST_READY="+ready)...)
	cmd.ExtraFiles = files
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	for i := 0; i < 250; i++ {
		if _, err := os.Stat(ready); err == nil {
			return int32(cmd.Process.Pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stand-in %s (%s) never got ready", name, role)
	return 0
}

// standInHeld keeps a stand-in's connections from being collected, and
// closed.
var standInHeld []net.Conn

// TestStandIn is the process standIn starts; on its own it skips. As
// "listen" it accepts connections at $CARGOWALL_TEST_SOCK and holds them
// open; as "drop" it closes each; as "hide" it holds none of them, each
// parked in flight in a message to itself, so no process holds a
// descriptor for it; as "serve" it answers HTTP on the listener it was
// handed; as "connect" it holds a connection to each socket in the list
// $CARGOWALL_TEST_SOCK, once each has answered, and holds those it
// accepts at $CARGOWALL_TEST_LISTEN, if set. Each connection it accepts is
// answered with a byte.
func TestStandIn(t *testing.T) {
	role, sock, ready := os.Getenv("CARGOWALL_TEST_ROLE"), os.Getenv("CARGOWALL_TEST_SOCK"), os.Getenv("CARGOWALL_TEST_READY")
	if role == "" {
		t.Skip("run by standIn")
	}
	switch role {
	case "listen", "drop", "hide":
		standInAccept(t, sock, role)
	case "serve":
		l, err := net.FileListener(os.NewFile(3, "listener"))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "OK") }))
		}()
	case "connect":
		for _, path := range filepath.SplitList(sock) {
			c, err := net.Dial("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Read(make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			standInHeld = append(standInHeld, c)
		}
		if l := os.Getenv("CARGOWALL_TEST_LISTEN"); l != "" {
			standInAccept(t, l, "listen")
		}
	default:
		t.Fatalf("no role %q", role)
	}
	if err := os.WriteFile(ready, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {}
}

// standInAccept accepts connections at sock for TestStandIn, as role.
func standInAccept(t *testing.T, sock, role string) {
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	park, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if _, err := c.Write([]byte("x")); err != nil {
				t.Error(err)
			}
			switch role {
			case "listen":
				standInHeld = append(standInHeld, c)
				continue
			case "hide":
				if err := parkConn(park[0], c); err != nil {
					t.Error(err)
				}
			}
			c.Close()
		}
	}()
}

// parkConn sends a descriptor for c in a message on sock, where it stays
// in flight, unreceived: c's socket stays open, held by no process.
func parkConn(sock int, c net.Conn) error {
	f, err := c.(*net.UnixConn).File()
	if err != nil {
		return err
	}
	defer f.Close()
	return unix.Sendmsg(sock, []byte("x"), unix.UnixRights(int(f.Fd())), nil, 0)
}

// The daemon is whoever serves the socket, not whoever made its listener:
// a socket-activated one was handed the listener by its service manager,
// which keeps it but never accepts. Here this process makes the listener
// and keeps it, and a stand-in, handed it, serves.
func TestServingPid(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f, err := l.File()
	if err != nil {
		t.Fatal(err)
	}
	server := standIn(t, "anyname", "serve", nil, f)
	f.Close()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if listener, err := peerPid(conn.(*net.UnixConn)); err != nil || listener != int32(os.Getpid()) {
		t.Fatalf("peerPid = %d, %v; want the listener's maker, this process %d", listener, err, os.Getpid())
	}
	if got, err := servingPid(conn.(*net.UnixConn)); err != nil || got != server {
		t.Errorf("servingPid = %d, %v; want the stand-in serving it, %d", got, err, server)
	}
	if d := probeDockerd(sock); d.Kind != DockerdLocal || d.pid != server {
		t.Errorf("probeDockerd = %+v, want the stand-in %d, local", d, server)
	}
}

// The runtime is the containerd at the other end of a connection the
// daemon made, whatever its flags or the sockets there would pick, and,
// with the daemon in a network namespace of its own, the connection is
// read in that one. Two refuse, and so does a connection whose other end
// no process we see holds. A daemon connected to none runs one itself
// where it serves the address it names (dockerd's embedded containerd);
// one of another name that names none is its own runtime, and a dockerd
// that names none, or names one another process serves, refuses.
func TestRuntimePid(t *testing.T) {
	listen := func(name, role string) (int32, string) {
		sock := filepath.Join(t.TempDir(), name+".sock")
		return standIn(t, name, role, []string{"CARGOWALL_TEST_SOCK=" + sock}), sock
	}
	daemon := func(name string, socks ...string) int32 { return standInDaemon(t, name, socks...) }
	containerd, sock := listen("containerd", "listen")
	_, otherSock := listen("containerd", "listen")
	_, plugin := listen("plugin", "listen")
	_, hidden := listen("containerd", "hide")
	_, dropped := listen("containerd", "drop")
	// A client of the daemon's own socket whose end no process holds is
	// not a connection it made.
	api := filepath.Join(t.TempDir(), "docker.sock")
	serving := standIn(t, "dockerd", "connect", []string{"CARGOWALL_TEST_SOCK=" + sock, "CARGOWALL_TEST_LISTEN=" + api})
	client, err := net.Dial("unix", api)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	park, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(park[0])
	defer unix.Close(park[1])
	if err := parkConn(park[0], client); err != nil {
		t.Fatal(err)
	}
	client.Close()
	// A dockerd connected to none, serving a containerd of its own.
	embedded := filepath.Join(t.TempDir(), "containerd.sock")
	embedding := standIn(t, "dockerd", "connect", []string{"CARGOWALL_TEST_SOCK=" + plugin, "CARGOWALL_TEST_LISTEN=" + embedded})
	names := func(addr string) func() (string, error) { return func() (string, error) { return addr, nil } }
	unread := func() (string, error) { return "", errors.New("GET /info: 503 Service Unavailable") }
	for _, c := range []struct {
		name  string
		pid   int32
		named func() (string, error)
		want  int32 // 0 wants an error; -1 the daemon itself
	}{
		{"connected to containerd, and a plugin", daemon("dockerd", plugin, sock), unread, containerd},
		{"connected to containerd, and to one that closed its end", daemon("dockerd", sock, dropped), unread, containerd},
		{"connected to containerd, with a client no process holds", serving, unread, containerd},
		{"connected to two", daemon("dockerd", sock, otherSock), names(""), 0},
		{"connected to one whose end no process holds", daemon("dockerd", sock, hidden), names(""), 0},
		{"connected to none, serving the one it names", embedding, names(embedded), -1},
		{"connected to none, naming one it does not serve", daemon("dockerd", plugin), names(sock), 0},
		{"connected to none, naming none", daemon("dockerd", plugin), names(""), 0},
		{"connected to none, naming one unread", daemon("podman", plugin), unread, 0},
		// From the daemon's working directory, which the probe does not
		// follow; from its root it is the one it serves.
		{"connected to none, naming one relative", embedding, names(strings.TrimPrefix(embedded, "/")), 0},
		{"another name, connected to none, naming none", daemon("podman", plugin), names(""), -1},
	} {
		got, err := runtimePid(c.pid, c.named)
		switch {
		case c.want == 0 && err == nil:
			t.Errorf("%s: runtimePid = %d, want an error", c.name, got)
		case c.want == -1 && (err != nil || got != c.pid):
			t.Errorf("%s: runtimePid = %d, %v; want the daemon itself, %d", c.name, got, err, c.pid)
		case c.want > 0 && (err != nil || got != c.want):
			t.Errorf("%s: runtimePid = %d, %v; want containerd's %d", c.name, got, err, c.want)
		}
	}
	if os.Geteuid() != 0 {
		return
	}
	netns := &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	apart := standInWith(t, netns, "dockerd", "connect", []string{"CARGOWALL_TEST_SOCK=" + sock})
	if got, err := runtimePid(apart, unread); err != nil || got != containerd {
		t.Errorf("in a network namespace of its own: runtimePid = %d, %v; want containerd's %d", got, err, containerd)
	}
}

// A daemon names its containerd's address in /info, without the scheme,
// or none.
func TestContainerdAddress(t *testing.T) {
	for body, want := range map[string]string{
		`{"Containerd":{"Address":"/var/run/docker/containerd/containerd.sock","Namespaces":{"Containers":"moby"}}}`: "/var/run/docker/containerd/containerd.sock",
		`{"Containerd":{"Address":"unix:///run/containerd/containerd.sock"}}`:                                        "/run/containerd/containerd.sock",
		`{"CgroupDriver":"cgroupfs"}`: "",
	} {
		if got, err := containerdAddress(fakeDaemon(t, http.StatusOK, body)); err != nil || got != want {
			t.Errorf("containerdAddress(%s) = %q, %v; want %q", body, got, err, want)
		}
	}
	if got, err := containerdAddress(fakeDaemon(t, http.StatusInternalServerError, `{}`)); err == nil {
		t.Errorf("containerdAddress(500) = %q, want an error", got)
	}
}

// Unasked, a daemon whose systemd cannot be shown (here, on a tcp bus) has
// no tree; one with no systemd to reach has its own mount's.
func TestUnaskedTree(t *testing.T) {
	ours, err := mountRootOf(int32(os.Getpid()))
	if err != nil {
		t.Skipf("no cgroup v2 mount at %s: %v", CgroupRoot, err)
	}
	if got, err := unaskedTree(busDaemon(t, "tcp:host=localhost,port=4242")); err == nil {
		t.Errorf("unaskedTree, tcp bus = %q, want an error", got)
	}
	// A bus where nothing listens leaves systemd's own socket, which only
	// root may reach: the machine's systemd, whose tree is ours.
	if os.Geteuid() == 0 {
		if got, err := unaskedTree(busDaemon(t, "unix:path="+filepath.Join(t.TempDir(), "nothing"))); err != nil || got != ours {
			t.Errorf("unaskedTree, no bus = %q, %v; want our own mount's root %q", got, err, ours)
		}
	}
}

// busListener listens on a unix socket of its own, standing in for a
// system bus, and returns its path.
func busListener(t *testing.T) string {
	t.Helper()
	bus := filepath.Join(t.TempDir(), "bus")
	l, err := net.Listen("unix", bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return bus
}

// busDaemon starts a process standing in for a daemon whose environment
// names the system bus at addr, and returns its pid.
func busDaemon(t *testing.T, addr string) int32 {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	cmd.Env = []string{"DBUS_SYSTEM_BUS_ADDRESS=" + addr}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitEnviron(t, cmd.Process.Pid)
	return int32(cmd.Process.Pid)
}

// The socket is found as a chroot would find it, so an absolute symlink
// in the daemon's root (/var/run to /run) stays inside that root, and its
// listener's pid is read through it.
func TestSocketPeerIn(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run", "dbus"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/run", filepath.Join(root, "var", "run")); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(root, "run", "dbus", "system_bus_socket"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if pid, err := socketPeerIn(fd, systemBusSocket); err != nil || pid != int32(os.Getpid()) {
		t.Errorf("socketPeerIn(%s) = %d, %v; want our pid %d", systemBusSocket, pid, err, os.Getpid())
	}
	if _, err := socketPeerIn(fd, systemdPrivateSocket); err == nil {
		t.Errorf("socketPeerIn(%s): want an error, nothing listens there", systemdPrivateSocket)
	}
	// A symlink at the socket's own name, to an absolute path, is followed
	// inside the root too: here the target exists only in ours.
	ours := filepath.Join(t.TempDir(), "ours.sock")
	lo, err := net.Listen("unix", ours)
	if err != nil {
		t.Fatal(err)
	}
	defer lo.Close()
	if err := os.MkdirAll(filepath.Join(root, "run", "systemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ours, filepath.Join(root, "run", "systemd", "private")); err != nil {
		t.Fatal(err)
	}
	if pid, err := socketPeerIn(fd, systemdPrivateSocket); err == nil {
		t.Errorf("socketPeerIn through a symlink out of the root = %d, want an error", pid)
	}
}

// Under the systemd driver the tree is that of the systemd the daemon
// reaches, on the bus its environment names, if it names one. Here a
// child names a bus this process listens on, so the systemd is us, and
// the tree is our own mount's.
func TestSystemdTree(t *testing.T) {
	ours, err := mountRootOf(int32(os.Getpid()))
	if err != nil {
		t.Skipf("no cgroup v2 mount at %s: %v", CgroupRoot, err)
	}
	bus := busListener(t)
	if got, err := systemdTree(busDaemon(t, "unix:path="+bus+",guid=0123")); err != nil || got != ours {
		t.Errorf("systemdTree = %q, %v; want our mount's root %q", got, err, ours)
	}
	if got, err := systemdTree(busDaemon(t, "tcp:host=localhost,port=4242")); err == nil {
		t.Errorf("systemdTree over tcp = %q, want an error", got)
	}
}

// waitEnviron waits for a child just started to have its environment:
// Start returns once exec has closed the child's descriptors, before the
// kernel has laid out its new environment, which reads empty until then.
func waitEnviron(t *testing.T, pid int) {
	t.Helper()
	environ := fmt.Sprintf("/proc/%d/environ", pid)
	for i := 0; i < 250; i++ {
		if data, _ := os.ReadFile(environ); len(data) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s stayed empty", environ)
}

// A D-Bus address is a ";" list of transports with "," parameters, tried
// in turn; the paths come in order, up to the first entry that is not one.
func TestBusSocketPaths(t *testing.T) {
	for addr, want := range map[string]struct {
		paths      []string
		unfollowed string
	}{
		"unix:path=/run/dbus/system_bus_socket":                         {[]string{"/run/dbus/system_bus_socket"}, ""},
		"unix:path=%2frun%2fdbus%2fsystem_bus_socket":                   {[]string{"/run/dbus/system_bus_socket"}, ""},
		"unix:path=/host/bus,guid=0123":                                 {[]string{"/host/bus"}, ""},
		"unix:path=/host/run/dbus/system_bus_socket;unix:path=/run/bus": {[]string{"/host/run/dbus/system_bus_socket", "/run/bus"}, ""},
		"unix:guid=0123,path=/run/bus;":                                 {[]string{"/run/bus"}, ""},
		"unix:path=/run/bus;tcp:host=h;unix:path=/x":                    {[]string{"/run/bus"}, "tcp:host=h"},
		"unix:abstract=/tmp/dbus-x":                                     {nil, "unix:abstract=/tmp/dbus-x"},
	} {
		paths, unfollowed, err := busSocketPaths(addr)
		if err != nil || !slices.Equal(paths, want.paths) || unfollowed != want.unfollowed {
			t.Errorf("busSocketPaths(%q) = %q, %q, %v; want %q, %q", addr, paths, unfollowed, err, want.paths, want.unfollowed)
		}
	}
	for _, addr := range []string{";", "unix:path=%zz"} {
		if _, _, err := busSocketPaths(addr); err == nil {
			t.Errorf("busSocketPaths(%q): want an error", addr)
		}
	}
}

// A tree is shared when any cgroup in it lists a task as 0, outside our
// pid namespace; files of a cgroup removed during the look are passed
// over.
func TestProbeCgroupTree(t *testing.T) {
	root := t.TempDir()
	write := func(rel, threads string) {
		dir := filepath.Join(root, rel)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if threads != "" {
			if err := os.WriteFile(filepath.Join(dir, "cgroup.threads"), []byte(threads), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(".", "")
	write("init", "1\n7\n")
	write("docker/abc", "12\n13\n")
	write("gone", "")
	if got, why := probeCgroupTree(root); got != CgroupTreeOurs {
		t.Errorf("every task ours: got %v (%s), want ours", got, why)
	}
	write("kubelet.slice", "40\n0\n")
	if got, why := probeCgroupTree(root); got != CgroupTreeShared || !strings.Contains(why, "kubelet.slice") {
		t.Errorf("a task outside: got %v (%s), want shared, naming the cgroup", got, why)
	}
}
