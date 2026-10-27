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

// Only a positively proven shape lets the hook load; every unknown is a
// problem, never the permissive answer.
func TestHookScope(t *testing.T) {
	pod := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-a.scope"
	foreign := Dockerd{Kind: DockerdForeign, Reason: "its pid is outside our pid namespace"}
	unknownD := Dockerd{Kind: DockerdUnknown, Reason: "dial: timeout"}
	cases := []struct {
		name  string
		shape Shape
		ok    bool
	}{
		{"hosted runner", Shape{CgroupNS: CgroupNSHost, CgroupPath: "/system.slice/runner.service", Dockerd: Dockerd{Kind: DockerdLocal}}, true},
		{"hosted runner, daemon unidentified", Shape{CgroupNS: CgroupNSHost, CgroupPath: "/system.slice/runner.service", Dockerd: unknownD}, true},
		{"privileged pod: node root", Shape{CgroupNS: CgroupNSHost, CgroupPath: pod}, false},
		{"privileged pod with dind: still node root", Shape{CgroupNS: CgroupNSHost, CgroupPath: pod, Dockerd: foreign}, false},
		{"host cgroupns, path unread", Shape{CgroupNS: CgroupNSHost, CgroupPathReason: "open /proc/self/cgroup: permission denied", Dockerd: Dockerd{Kind: DockerdLocal}}, false},
		{"private cgroupns, foreign dockerd", Shape{CgroupNS: CgroupNSPrivate, CgroupPath: "/", Dockerd: foreign}, false},
		{"private cgroupns, unidentified dockerd", Shape{CgroupNS: CgroupNSPrivate, CgroupPath: "/", Dockerd: unknownD}, false},
		{"private cgroupns, no dockerd", Shape{CgroupNS: CgroupNSPrivate, CgroupPath: "/", Dockerd: Dockerd{Kind: DockerdAbsent}}, true},
		{"private cgroupns, own dockerd", Shape{CgroupNS: CgroupNSPrivate, CgroupPath: "/", Dockerd: Dockerd{Kind: DockerdLocal}}, true},
		{"unprobed", Shape{}, false},
	}
	for _, tc := range cases {
		err := tc.shape.HookScope()
		if (err == nil) != tc.ok {
			t.Errorf("%s: HookScope() = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}

	// An unknown fact carries its probe error into the posture reason.
	err := Shape{CgroupNS: CgroupNSHost, CgroupPathReason: "open /proc/self/cgroup: permission denied"}.HookScope()
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("unread cgroup path: HookScope() = %v, want the read error in it", err)
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
