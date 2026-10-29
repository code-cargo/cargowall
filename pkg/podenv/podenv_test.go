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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCgroupV2Path(t *testing.T) {
	cases := map[string]string{
		"0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope\n": "/kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope",
		"0::/\n": "/",
		"12:memory:/docker/x\n1:name=systemd:/docker/x\n":      "",
		"1:name=systemd:/x\n0::/system.slice/runner.service\n": "/system.slice/runner.service",
	}
	for in, want := range cases {
		if got := parseCgroupV2Path([]byte(in)); got != want {
			t.Errorf("parseCgroupV2Path(%q) = %q, want %q", in, got, want)
		}
	}
}

// The hook loads only when the facts that decide who it judges are proven.
// An unknown that decides that refuses; one that cannot change it (a runner
// VM's daemon or DOCKER_HOST, a private cgroup namespace's pid namespace)
// is not read.
func TestHookScope(t *testing.T) {
	pod := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-a.scope"
	runner := "/system.slice/runner.service"
	local := Dockerd{Kind: DockerdLocal}
	foreign := Dockerd{Kind: DockerdForeign, Reason: "pid 7 has another mount namespace"}
	hidden := Dockerd{Kind: DockerdHidden, Reason: "its pid is outside our pid namespace"}
	unknownD := Dockerd{Kind: DockerdUnknown, Reason: "dial: timeout"}
	// Both helpers have the mount proven, so each case is decided by the
	// fact it names.
	host := func(path string, pidns PidNS, d Dockerd) Shape {
		return Shape{CgroupNS: CgroupNSHost, CgroupPath: path, CgroupMount: CgroupMountOurs, PidNS: pidns, Dockerd: d}
	}
	private := func(d Dockerd) Shape {
		return Shape{CgroupNS: CgroupNSPrivate, CgroupPath: "/", CgroupMount: CgroupMountOurs, PidNS: PidNSPrivate, Dockerd: d}
	}
	with := func(s Shape, f func(*Shape)) Shape { f(&s); return s }
	remoteDaemon := func(s *Shape) { s.DockerHost = "tcp://localhost:2376" }
	cases := []struct {
		name   string
		shape  Shape
		ok     bool
		scoped bool
	}{
		{"hosted runner", host(runner, PidNSHost, local), true, false},
		{"hosted runner, daemon unidentified", host(runner, PidNSHost, unknownD), true, false},
		{"hostPID pod: node root, every task visible", host(pod, PidNSHost, local), false, false},
		{"ARC runner pod sharing a pid namespace with dind", host(pod, PidNSPrivate, foreign), true, true},
		{"privileged pod, no dockerd", host(pod, PidNSPrivate, Dockerd{Kind: DockerdAbsent}), true, true},
		{"privileged pod running its own dockerd", host(pod, PidNSPrivate, local), true, true},
		{"privileged pod, dind not sharing the pid namespace", host(pod, PidNSPrivate, hidden), false, false},
		{"privileged pod, daemon unidentified", host(pod, PidNSPrivate, unknownD), false, false},
		{"privileged container outside Kubernetes", host("/system.slice/docker-a.scope", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), true, true},
		// The host's daemon, through its socket, starts containers outside
		// our pid namespace, which the scope never reaches.
		{"privileged container outside Kubernetes, the host's dockerd", host("/system.slice/docker-a.scope", PidNSPrivate, hidden), false, false},
		{"hostPID pod, systemd driver under a custom cgroup root", host("/custom.slice/custom-kubepods.slice/custom-kubepods-pod1.slice/cri-containerd-a.scope", PidNSHost, local), false, false},
		{"host cgroupns, pid namespace unread", with(host(runner, PidNSUnknown, local), func(s *Shape) { s.PidNSReason = "stat: permission denied" }), false, false},
		{"host cgroupns, path unread", Shape{CgroupNS: CgroupNSHost, CgroupPathReason: "open /proc/self/cgroup: permission denied", PidNS: PidNSHost, Dockerd: local}, false, false},
		{"host cgroupns, mount unproven", with(host(runner, PidNSHost, local), func(s *Shape) { s.CgroupMount = CgroupMountUnknown }), false, false},
		{"host cgroupns, mount is another tree", with(host(runner, PidNSHost, local), func(s *Shape) { s.CgroupMount = CgroupMountOther }), false, false},
		{"privileged pod, DOCKER_HOST names another daemon", with(host(pod, PidNSPrivate, Dockerd{Kind: DockerdAbsent}), remoteDaemon), false, false},
		{"hosted runner, DOCKER_HOST names another daemon", with(host(runner, PidNSHost, local), remoteDaemon), true, false},
		{"private cgroupns, foreign dockerd", private(foreign), false, false},
		{"private cgroupns, hidden dockerd", private(hidden), false, false},
		{"private cgroupns, unidentified dockerd", private(unknownD), false, false},
		{"private cgroupns, no dockerd", private(Dockerd{Kind: DockerdAbsent}), true, false},
		{"private cgroupns, own dockerd", private(local), true, false},
		{"host cgroupfs bound into a private cgroupns", with(private(local), func(s *Shape) { s.CgroupMount = CgroupMountOther }), false, false},
		{"private cgroupns, path unread", with(private(local), func(s *Shape) { s.CgroupPath = "" }), false, false},
		{"private cgroupns, DOCKER_HOST names another daemon", with(private(local), remoteDaemon), false, false},
		{"private cgroupns, pid namespace unread", with(private(local), func(s *Shape) { s.PidNS = PidNSUnknown }), true, false},
		{"private cgroupns, host pid namespace", with(private(local), func(s *Shape) { s.PidNS = PidNSHost }), true, false},
		{"unprobed", Shape{}, false, false},
		// A kind with no rule fails closed, wherever its switch sits.
		{"unnamed cgroup namespace kind", Shape{CgroupNS: CgroupNS(99), CgroupPath: "/", CgroupMount: CgroupMountOurs, PidNS: PidNSHost, Dockerd: local}, false, false},
		{"unnamed cgroup mount kind", with(host(runner, PidNSHost, local), func(s *Shape) { s.CgroupMount = CgroupMount(99) }), false, false},
		{"unnamed pid namespace kind", host(pod, PidNS(99), foreign), false, false},
		{"unnamed dockerd kind, privileged pod", host(pod, PidNSPrivate, Dockerd{Kind: DockerdKind(99)}), false, false},
		{"unnamed dockerd kind, private cgroupns", private(Dockerd{Kind: DockerdKind(99)}), false, false},
	}
	for _, tc := range cases {
		scoped, err := tc.shape.HookScope()
		if (err == nil) != tc.ok {
			t.Errorf("%s: HookScope() error = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if scoped != tc.scoped {
			t.Errorf("%s: HookScope() scoped = %v, want %v", tc.name, scoped, tc.scoped)
		}
		// A refused hook never asks for a scope: nothing would read it.
		if err != nil && scoped {
			t.Errorf("%s: HookScope() refused and still asked for a scope", tc.name)
		}
	}

	// An unknown fact carries its probe error into the posture reason.
	_, err := Shape{CgroupNS: CgroupNSHost, CgroupPathReason: "open /proc/self/cgroup: permission denied"}.HookScope()
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("unread cgroup path: HookScope() = %v, want the read error in it", err)
	}
}

// The test process's own namespaces are known, whichever they are, and
// /sys/fs/cgroup is the tree it is in.
func TestDetect_Namespaces(t *testing.T) {
	s := Detect(filepath.Join(t.TempDir(), "docker.sock"))
	if s.CgroupNS == CgroupNSUnknown || s.PidNS == PidNSUnknown {
		t.Fatalf("Detect() = %+v, want both namespaces identified", s)
	}
	if s.CgroupMount != CgroupMountOurs {
		t.Fatalf("Detect() cgroup mount = %v (%s), want ours", s.CgroupMount, s.CgroupMountReason)
	}
}

// The mount is ours only when our pid is in our cgroup's member list there.
func TestProbeCgroupMount(t *testing.T) {
	root := t.TempDir()
	cg := filepath.Join(root, "system.slice", "runner.service")
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(procs string) {
		if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(procs), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("1\n4242\n77\n")
	if m, why := probeCgroupMount(root, "/system.slice/runner.service", 4242); m != CgroupMountOurs {
		t.Errorf("pid listed: got %v (%s), want ours", m, why)
	}
	// A pid that is only a prefix of a listed one is not listed.
	if m, _ := probeCgroupMount(root, "/system.slice/runner.service", 424); m != CgroupMountOther {
		t.Errorf("pid not listed: got %v, want other", m)
	}
	// The host's cgroupfs bound where a private namespace expects its own:
	// "/" names the machine's root, which lists other processes.
	if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("1\n2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m, _ := probeCgroupMount(root, "/", 4242); m != CgroupMountOther {
		t.Errorf("machine root without our pid: got %v, want other", m)
	}
	if m, _ := probeCgroupMount(root, "/kubepods.slice/x.scope", 4242); m != CgroupMountOther {
		t.Errorf("no such cgroup in the mount: got %v, want other", m)
	}
	// An unreadable member list proves nothing.
	if err := os.Remove(filepath.Join(cg, "cgroup.procs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cg, "cgroup.procs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if m, why := probeCgroupMount(root, "/system.slice/runner.service", 4242); m != CgroupMountUnknown || why == "" {
		t.Errorf("unreadable cgroup.procs: got %v (%q), want unknown with a reason", m, why)
	}
}

func TestDockerHostElsewhere(t *testing.T) {
	const sock = "/var/run/docker.sock"
	cases := map[string]string{
		"":                                  "",
		"unix:///var/run/docker.sock":       "",
		"unix:///var/run//docker.sock":      "",
		"unix:///run/user/1000/docker.sock": "unix:///run/user/1000/docker.sock",
		"tcp://localhost:2376":              "tcp://localhost:2376",
		"ssh://builder@remote.example.com":  "ssh://builder@remote.example.com",
	}
	for in, want := range cases {
		if got := dockerHostElsewhere(in, sock); got != want {
			t.Errorf("dockerHostElsewhere(%q) = %q, want %q", in, got, want)
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
	if got := dockerHostElsewhere("unix://"+filepath.Join(root, "var", "run", "docker.sock"), probed); got != "" {
		t.Errorf("symlinked spelling of the socket: got %q, want the same daemon", got)
	}
	if missing := "unix://" + filepath.Join(root, "var", "run", "other.sock"); dockerHostElsewhere(missing, probed) != missing {
		t.Errorf("a socket that does not exist is not the probed one")
	}
}

func TestProbeDockerd_NoSocket(t *testing.T) {
	if d := probeDockerd(filepath.Join(t.TempDir(), "docker.sock")); d.Kind != DockerdAbsent {
		t.Fatalf("absent socket: got %+v, want absent", d)
	}
}

// A dial failing with anything but ENOENT (here EINVAL, a path longer than
// sun_path) is unknown, with the error kept.
func TestProbeDockerd_Unknown(t *testing.T) {
	d := probeDockerd("/" + strings.Repeat("x", 200))
	if d.Kind != DockerdUnknown || d.Reason == "" {
		t.Fatalf("non-socket path: got %+v, want unknown with a reason", d)
	}
}

// A socket with nothing listening on it was made by a daemon that is still
// starting or has gone, so it is unknown, not absent.
func TestProbeDockerd_Refused(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	if d := probeDockerd(sock); d.Kind != DockerdUnknown || !strings.Contains(d.Reason, "refused") {
		t.Fatalf("socket with no listener: got %+v, want unknown, refused", d)
	}
}

// A listener in our own process shares our mount namespace: local.
func TestProbeDockerd_Local(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	if d := probeDockerd(sock); d.Kind != DockerdLocal {
		t.Fatalf("local listener: got %+v, want local", d)
	}
}
