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
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeDaemon serves an /info answer on a unix socket of its own, and
// returns the socket's path.
func fakeDaemon(t *testing.T, status int, body string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/info" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
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
	// No containerd to find: the daemon's own view decides.
	saved := containerdDefaults
	containerdDefaults = nil
	t.Cleanup(func() { containerdDefaults = saved })
	probe := func(d Dockerd, socket string) Dockerd {
		d.probeRuntime()
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
	// by both drivers' trees: its own mount, and that of any systemd it
	// could reach, here on a bus this process listens on, so ours too.
	d = probe(Dockerd{Kind: DockerdLocal, pid: busDaemon(t, "unix:path="+busListener(t))}, fakeDaemon(t, http.StatusServiceUnavailable, `{}`))
	if d.CgroupDriver != "" || d.ContainerTree != ours || !strings.Contains(d.Reason, "its cgroup driver") {
		t.Errorf("unasked: got %+v, want our own mount's root %q, noting the driver unread", d, ours)
	}
}

// The runtime whose view decides is the containerd at the socket dockerd
// uses, as dockerd picks it: the address it was given, by flag or in its
// daemon.json, else the first default that is there; with none of those,
// the daemon itself. A socket that is there but does not answer refuses.
// A child of the test, listening, stands in for containerd, and shells
// whose command lines carry dockerd's flags for dockerd.
func TestRuntimePid(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "containerd.sock")
	cmd := exec.Command(os.Args[0], "-test.run", "^TestRuntimeListener$")
	cmd.Env = append(os.Environ(), "CARGOWALL_TEST_LISTEN="+sock)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	for i := 0; i < 250; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	containerd := int32(cmd.Process.Pid)
	// dockerd stands in for a dockerd started with these flags; the
	// trailing command keeps the shell from exec'ing sleep in its place.
	dockerd := func(flags ...string) int32 {
		d := exec.Command("sh", append([]string{"-c", "sleep 60; :", "dockerd"}, flags...)...)
		if err := d.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = d.Process.Kill()
			_ = d.Wait()
		})
		for i := 0; i < 250; i++ {
			if data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", d.Process.Pid)); strings.Contains(string(data), "sleep 60") {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		return int32(d.Process.Pid)
	}
	saved := containerdDefaults
	t.Cleanup(func() { containerdDefaults = saved })
	absent := filepath.Join(dir, "absent.sock")
	dead := filepath.Join(dir, "dead.sock")
	if err := os.WriteFile(dead, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "daemon.json")
	if err := os.WriteFile(config, []byte(`{"containerd":"unix://`+sock+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	noConfig := "--config-file=" + filepath.Join(dir, "none.json")
	for _, c := range []struct {
		name     string
		defaults []string
		flags    []string
		want     int32 // 0 wants an error; -1 the stand-in dockerd itself
	}{
		{"a default that is there", []string{absent, sock}, []string{noConfig}, containerd},
		{"--containerd, over the defaults", []string{dead}, []string{noConfig, "--containerd", sock}, containerd},
		{"the daemon.json's containerd", []string{dead}, []string{"--config-file=" + config}, containerd},
		{"a default that is there and does not answer", []string{dead, sock}, []string{noConfig}, 0},
		{"a given address that does not answer", nil, []string{noConfig, "--containerd=" + absent}, 0},
		{"none there", []string{absent}, []string{noConfig}, -1},
	} {
		containerdDefaults = c.defaults
		pid := dockerd(c.flags...)
		got, err := runtimePid(pid)
		switch {
		case c.want == 0 && err == nil:
			t.Errorf("%s: runtimePid = %d, want an error", c.name, got)
		case c.want == -1 && (err != nil || got != pid):
			t.Errorf("%s: runtimePid = %d, %v; want the daemon's own %d", c.name, got, err, pid)
		case c.want > 0 && (err != nil || got != c.want):
			t.Errorf("%s: runtimePid = %d, %v; want containerd's %d", c.name, got, err, c.want)
		}
	}
}

// A dockerd command line gives the containerd address and daemon.json
// path, as --flag=value or --flag value.
func TestDockerdFlags(t *testing.T) {
	for in, want := range map[string][2]string{
		"dockerd\x00--host=unix:///var/run/docker.sock\x00":                      {"", defaultDaemonConfig},
		"dockerd\x00--containerd=/run/k3s/containerd/containerd.sock\x00":        {"/run/k3s/containerd/containerd.sock", defaultDaemonConfig},
		"dockerd\x00--containerd\x00unix:///x.sock\x00--config-file=/c.json\x00": {"/x.sock", "/c.json"},
		"dockerd\x00--config-file\x00/d.json\x00":                                {"", "/d.json"},
	} {
		addr, config := dockerdFlags([]byte(in))
		if addr != want[0] || config != want[1] {
			t.Errorf("dockerdFlags(%q) = %q, %q; want %q, %q", in, addr, config, want[0], want[1])
		}
	}
}

// TestRuntimeListener is TestRuntimePid's stand-in containerd; on its own
// it skips.
func TestRuntimeListener(t *testing.T) {
	sock := os.Getenv("CARGOWALL_TEST_LISTEN")
	if sock == "" {
		t.Skip("run by TestRuntimePid")
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Close()
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
