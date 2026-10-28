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
// VM's daemon, a private cgroup namespace's pid namespace) is not read.
func TestHookScope(t *testing.T) {
	pod := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-a.scope"
	runner := "/system.slice/runner.service"
	local := Dockerd{Kind: DockerdLocal}
	foreign := Dockerd{Kind: DockerdForeign, Reason: "pid 7 has another mount namespace"}
	hidden := Dockerd{Kind: DockerdHidden, Reason: "its pid is outside our pid namespace"}
	unknownD := Dockerd{Kind: DockerdUnknown, Reason: "dial: timeout"}
	host := func(path string, pidns PidNS, d Dockerd) Shape {
		return Shape{CgroupNS: CgroupNSHost, CgroupPath: path, PidNS: pidns, Dockerd: d}
	}
	private := func(d Dockerd) Shape {
		return Shape{CgroupNS: CgroupNSPrivate, CgroupPath: "/", PidNS: PidNSPrivate, Dockerd: d}
	}
	cases := []struct {
		name    string
		shape   Shape
		ok      bool
		stamped bool
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
		{"host cgroupns, pid namespace unread", Shape{CgroupNS: CgroupNSHost, CgroupPath: runner, PidNSReason: "stat: permission denied", Dockerd: local}, false, false},
		{"host cgroupns, path unread", Shape{CgroupNS: CgroupNSHost, CgroupPathReason: "open /proc/self/cgroup: permission denied", PidNS: PidNSHost, Dockerd: local}, false, false},
		{"private cgroupns, foreign dockerd", private(foreign), false, false},
		{"private cgroupns, hidden dockerd", private(hidden), false, false},
		{"private cgroupns, unidentified dockerd", private(unknownD), false, false},
		{"private cgroupns, no dockerd", private(Dockerd{Kind: DockerdAbsent}), true, false},
		{"private cgroupns, own dockerd", private(local), true, false},
		{"unprobed", Shape{}, false, false},
		// A kind with no rule fails closed, wherever its switch sits.
		{"unnamed cgroup namespace kind", Shape{CgroupNS: CgroupNS(99), CgroupPath: "/", PidNS: PidNSHost, Dockerd: local}, false, false},
		{"unnamed pid namespace kind", host(pod, PidNS(99), foreign), false, false},
		{"unnamed dockerd kind, privileged pod", host(pod, PidNSPrivate, Dockerd{Kind: DockerdKind(99)}), false, false},
		{"unnamed dockerd kind, private cgroupns", private(Dockerd{Kind: DockerdKind(99)}), false, false},
	}
	for _, tc := range cases {
		stamped, err := tc.shape.HookScope()
		if (err == nil) != tc.ok {
			t.Errorf("%s: HookScope() error = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if stamped != tc.stamped {
			t.Errorf("%s: HookScope() stamped = %v, want %v", tc.name, stamped, tc.stamped)
		}
		// A refused hook never asks for stamps: nothing would read them.
		if err != nil && stamped {
			t.Errorf("%s: HookScope() refused and still asked for stamps", tc.name)
		}
	}

	// An unknown fact carries its probe error into the posture reason.
	_, err := Shape{CgroupNS: CgroupNSHost, CgroupPathReason: "open /proc/self/cgroup: permission denied"}.HookScope()
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("unread cgroup path: HookScope() = %v, want the read error in it", err)
	}
}

// The test process's own namespaces are known, whichever they are.
func TestDetect_Namespaces(t *testing.T) {
	s := Detect(filepath.Join(t.TempDir(), "docker.sock"))
	if s.CgroupNS == CgroupNSUnknown || s.PidNS == PidNSUnknown {
		t.Fatalf("Detect() = %+v, want both namespaces identified", s)
	}
}

func TestProbeDockerd_NoSocket(t *testing.T) {
	if d := probeDockerd(filepath.Join(t.TempDir(), "docker.sock")); d.Kind != DockerdAbsent {
		t.Fatalf("absent socket: got %+v, want absent", d)
	}
}

// A dial failing with neither ENOENT nor ECONNREFUSED (here EINVAL, a path
// longer than sun_path) is unknown, with the error kept.
func TestProbeDockerd_Unknown(t *testing.T) {
	d := probeDockerd("/" + strings.Repeat("x", 200))
	if d.Kind != DockerdUnknown || d.Reason == "" {
		t.Fatalf("non-socket path: got %+v, want unknown with a reason", d)
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
