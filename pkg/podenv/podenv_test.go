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

func TestHookScopeProblem(t *testing.T) {
	pod := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-a.scope"
	foreign := Dockerd{Foreign: true, Reason: "its pid is outside our pid namespace"}
	cases := []struct {
		name  string
		shape Shape
		want  bool
	}{
		{"hosted runner", Shape{HostCgroupNS: true, CgroupPath: "/system.slice/runner.service"}, false},
		{"privileged pod: node root", Shape{HostCgroupNS: true, CgroupPath: pod}, true},
		{"privileged pod with dind: still node root", Shape{HostCgroupNS: true, CgroupPath: pod, Dockerd: foreign}, true},
		{"private cgroupns, foreign dockerd", Shape{CgroupPath: "/", Dockerd: foreign}, true},
		{"private cgroupns, own or no dockerd", Shape{CgroupPath: "/"}, false},
		{"unprobed", Shape{}, false},
	}
	for _, tc := range cases {
		if got := tc.shape.HookScopeProblem() != ""; got != tc.want {
			t.Errorf("%s: problem=%v, want %v (%q)", tc.name, got, tc.want, tc.shape.HookScopeProblem())
		}
	}
}

func TestProbeDockerd_NoSocket(t *testing.T) {
	d, err := probeDockerd(filepath.Join(t.TempDir(), "docker.sock"))
	if err != nil || d.Foreign {
		t.Fatalf("absent socket: got %+v, %v; want not foreign, no error", d, err)
	}
}

// A listener in our own process shares our mount namespace: not foreign.
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
	d, err := probeDockerd(sock)
	if err != nil || d.Foreign {
		t.Fatalf("local listener: got %+v, %v; want not foreign, no error", d, err)
	}
}
