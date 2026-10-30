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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
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
	const podCg = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod0e4b1f2a_7c3d_4e5f_8a9b_0c1d2e3f4a5b.slice"
	pod := podCg + "/cri-containerd-a.scope"
	runner := "/system.slice/runner.service"
	// Our own container's daemon, on the cgroupfs driver, so in our mount;
	// on the systemd driver with our container's systemd; and with the
	// host's systemd, over a bus bound in, or one it could not be asked.
	local := Dockerd{Kind: DockerdLocal, Runtime: 7, CgroupDriver: "cgroupfs", ContainerTree: "/"}
	localSystemd := Dockerd{Kind: DockerdLocal, Runtime: 7, CgroupDriver: "systemd", ContainerTree: "/"}
	localHostSystemd := Dockerd{Kind: DockerdLocal, Runtime: 7, CgroupDriver: "systemd", ContainerTree: "/../.."}
	localUnasked := Dockerd{Kind: DockerdLocal, Runtime: 7, Reason: "its cgroup driver: GET /info: 500 Internal Server Error"}
	foreign := Dockerd{Kind: DockerdForeign, Runtime: 7, Reason: "pid 7 has another mount namespace"}
	hidden := Dockerd{Kind: DockerdHidden, Reason: "its pid is outside our pid namespace"}
	// A foreign daemon in our cgroup namespace (a dind sidecar in the
	// node's), one in a namespace of its own below our root, one above it,
	// and one under our root that makes its containers in the host's tree.
	foreignUnder := Dockerd{Kind: DockerdForeign, Runtime: 7, Reason: "pid 7 has another mount namespace", Cgroup: "/dind", ContainerTree: "/"}
	foreignOwnNS := Dockerd{Kind: DockerdForeign, Runtime: 7, Reason: "pid 7 has another mount namespace", Cgroup: "/dind", ContainerTree: "/dind"}
	foreignAbove := Dockerd{Kind: DockerdForeign, Runtime: 7, Reason: "pid 7 has another mount namespace", Cgroup: "/../../dind", ContainerTree: "/../.."}
	foreignHostTree := Dockerd{Kind: DockerdForeign, Runtime: 7, Reason: "pid 7 has another mount namespace", Cgroup: "/dind", ContainerTree: "/../.."}
	foreignMountUnread := Dockerd{Kind: DockerdForeign, Runtime: 7, Reason: "pid 7 has another mount namespace; its cgroup mount: nothing is mounted", Cgroup: "/dind"}
	unknownD := Dockerd{Kind: DockerdUnknown, Reason: "dial: timeout"}
	// Both helpers have the mount proven on a kernel that keeps socket
	// cgroups, so each case is decided by the fact it names.
	// Our pid namespace's init is in our own cgroup, as a pod's or our
	// container's is.
	host := func(path string, pidns PidNS, d Dockerd) Shape {
		return Shape{CgroupNS: CgroupNSHost, CgroupPath: path, CgroupMount: CgroupMountOurs, PidNS: pidns, InitCgroup: path, OwnTree: CgroupTreeOurs, Dockerd: d, SocketCgroups: SocketCgroupsKept}
	}
	initIn := func(path string) func(*Shape) { return func(s *Shape) { s.InitCgroup = path } }
	private := func(d Dockerd) Shape {
		return Shape{CgroupNS: CgroupNSPrivate, CgroupPath: "/", CgroupMount: CgroupMountOurs, PidNS: PidNSPrivate, Dockerd: d, SocketCgroups: SocketCgroupsKept}
	}
	sockets := func(c SocketCgroups) func(*Shape) { return func(s *Shape) { s.SocketCgroups = c } }
	tree := func(c CgroupTree) func(*Shape) { return func(s *Shape) { s.CgroupTree = c } }
	ownTree := func(c CgroupTree) func(*Shape) { return func(s *Shape) { s.OwnTree = c } }
	with := func(s Shape, f func(*Shape)) Shape { f(&s); return s }
	nested := func(path string, pidns PidNS, d Dockerd) Shape {
		return with(host(path, pidns, d), func(s *Shape) { s.CgroupNS = CgroupNSPrivate })
	}
	kubeletHosts := func(s *Shape) { s.KubeletHosts = true }
	hostsUnread := func(s *Shape) { s.KubeletHostsReason = "open /etc/hosts: permission denied" }
	remoteDaemon := func(s *Shape) { s.DockerHost, s.DockerHostSetting = "tcp://localhost:2376", "DOCKER_HOST" }
	unreadContext := func(s *Shape) { s.DockerHostReason = `docker context "ci" (from DOCKER_CONTEXT): no such file` }
	all := Scope{}
	inPod := Scope{Subtree: podCg}
	cases := []struct {
		name  string
		shape Shape
		ok    bool
		want  Scope
	}{
		{"hosted runner", host(runner, PidNSHost, local), true, all},
		{"hosted runner, daemon unidentified", host(runner, PidNSHost, unknownD), true, all},
		{"hostPID pod: node root, every task visible", host(pod, PidNSHost, local), false, all},
		{"ARC runner pod sharing a pid namespace with dind", host(pod, PidNSPrivate, foreign), true, inPod},
		{"privileged pod, no dockerd", host(pod, PidNSPrivate, Dockerd{Kind: DockerdAbsent}), true, inPod},
		{"privileged pod running its own dockerd", host(pod, PidNSPrivate, local), true, inPod},
		{"privileged pod, dind not sharing the pid namespace", host(pod, PidNSPrivate, hidden), false, all},
		{"privileged pod, daemon unidentified", host(pod, PidNSPrivate, unknownD), false, all},
		// Outside Kubernetes our own container's cgroup is the job's whole:
		// a runtime's exec into it enters from outside our pid namespace.
		{
			"privileged container outside Kubernetes", host("/system.slice/docker-a.scope", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), true,
			Scope{Subtree: "/system.slice/docker-a.scope"},
		},
		{"own pid namespace in the root cgroup", host("/", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), false, all},
		// Outside a pod our cgroup is judged whole, so it must hold only
		// our pid namespace's tasks: a pid namespace made in a service or a
		// session (unshare -pf) is beside its other tasks.
		{"own pid namespace in a shared service cgroup", with(host("/system.slice/ci.service", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), ownTree(CgroupTreeShared)), false, all},
		{"own pid namespace, our cgroup unread", with(host("/system.slice/docker-a.scope", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), ownTree(CgroupTreeUnknown)), false, all},
		{"private cgroupns below its root, our cgroup shared", with(nested("/init", PidNSPrivate, local), ownTree(CgroupTreeShared)), false, all},
		{"privileged pod, its container's cgroup not looked at", with(host(pod, PidNSPrivate, foreign), ownTree(CgroupTreeUnknown)), true, inPod},
		// A pod is judged whole, by its cgroup: one whose kubelet makes no
		// pod cgroups (cgroupsPerQOS=false) shows only by its hosts file,
		// and one whose hosts file could not be read cannot be shown not
		// to be one.
		{"privileged pod without pod cgroups", with(host("/system.slice/cri-containerd-a.scope", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), kubeletHosts), false, all},
		{"privileged container, hosts file unread", with(host("/system.slice/docker-a.scope", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), hostsUnread), false, all},
		{"nested node, tree read as ours alone, hosts file unread", with(with(nested("/system.slice/cri-containerd-a.scope", PidNSPrivate, local), tree(CgroupTreeOurs)), hostsUnread), false, all},
		// In the host pid namespace only a sign of a pod counts: nothing
		// else marks a machine single-tenant.
		{"runner VM, hosts file unread", with(host(runner, PidNSHost, local), hostsUnread), true, all},
		{"ARC runner pod, hosts file unread", with(host(pod, PidNSPrivate, foreign), hostsUnread), true, inPod},
		{"hostPID pod without pod cgroups", with(host("/system.slice/cri-containerd-a.scope", PidNSHost, local), kubeletHosts), false, all},
		{"nested node, pod without pod cgroups", with(with(nested("/system.slice/cri-containerd-a.scope", PidNSPrivate, local), tree(CgroupTreeOurs)), kubeletHosts), false, all},
		{"ARC runner pod, kubelet's hosts file", with(host(pod, PidNSPrivate, foreign), kubeletHosts), true, inPod},
		// A private cgroup namespace rooted above our cgroup is a tree others
		// share: a nested node's (kind, minikube's docker driver), whose
		// privileged pods share the node's namespace, or our container's
		// own when we sit below its root (dind's /init).
		{
			"nested node: privileged pod in the node's cgroup namespace", nested("/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/0123abcd", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), true,
			Scope{Subtree: "/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b"},
		},
		{"nested node: hostPID pod", nested("/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/0123abcd", PidNSHost, local), false, all},
		{"private cgroupns below its root, own pid namespace", nested("/init", PidNSPrivate, local), true, Scope{Subtree: "/init"}},
		{"nested node: hostPID pod, in the node container's pid namespace", with(nested("/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/0123abcd", PidNSPrivate, Dockerd{Kind: DockerdAbsent}), initIn("/init.scope")), false, all},
		{"privileged pod sharing its pid namespace with the pause container", with(host(pod, PidNSPrivate, local), initIn(podCg+"/cri-containerd-pause.scope")), true, inPod},
		{"privileged pod in a pid namespace whose init is another pod's", with(host(pod, PidNSPrivate, local), initIn("/kubepods.slice/kubepods-pod1.slice/x.scope")), false, all},
		{"privileged pod, our pid namespace's init unread", with(host(pod, PidNSPrivate, local), func(s *Shape) { s.InitCgroup, s.InitCgroupReason = "", "permission denied" }), false, all},
		{"outside Kubernetes, a pid namespace whose init is a sibling's", with(host(runner, PidNSPrivate, local), initIn("/system.slice/runner.service2")), false, all},
		{"private cgroupns below its root, own pid namespace, tree shared", with(nested("/init", PidNSPrivate, local), tree(CgroupTreeShared)), true, Scope{Subtree: "/init"}},
		{"private cgroupns below its root, own pid namespace, tree ours alone", with(nested("/init", PidNSPrivate, local), tree(CgroupTreeOurs)), true, all},
		{"nested node, tree read as ours alone", with(nested("/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/0123abcd", PidNSPrivate, local), tree(CgroupTreeOurs)), true, Scope{Subtree: "/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b"}},
		// In a private cgroup namespace the hook sees only what is under its
		// root, whatever the scope, so a daemon whose containers could live
		// outside it refuses, whatever our path and pid namespace, unless its
		// own cgroup shows it is under the root.
		{"private cgroupns below its root, another container's dockerd, cgroup unread", nested("/init", PidNSPrivate, foreign), false, all},
		{"private cgroupns below its root, another container's dockerd under the root", nested("/init", PidNSPrivate, foreignUnder), true, Scope{Subtree: "/init"}},
		{"private cgroupns below its root, another container's dockerd above the root", nested("/init", PidNSPrivate, foreignAbove), false, all},
		{"private cgroupns below its root, host pid namespace", nested("/init", PidNSHost, local), true, all},
		{"private cgroupns below its root, host pid namespace, the host's dockerd", nested("/init", PidNSHost, foreign), false, all},
		{"private cgroupns below its root, host pid namespace, hidden dockerd", nested("/init", PidNSHost, hidden), false, all},
		{
			"nested node: ARC pod with a dind sidecar sharing its pid namespace", nested("/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/0123abcd", PidNSPrivate,
				Dockerd{Kind: DockerdForeign, Runtime: 7, Reason: "pid 7 has another mount namespace", Cgroup: "/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/4567ef01", CgroupDriver: "cgroupfs", ContainerTree: "/"}), true,
			Scope{Subtree: "/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b"},
		},
		{"private cgroupns below its root, host pid namespace, socket cgroups shared", with(nested("/init", PidNSHost, local), sockets(SocketCgroupsShared)), false, all},
		// The pod's other containers are judged by its cgroup, so a pod
		// whose cgroup cannot be found would leave them out.
		{"privileged pod, no pod cgroup in the path", host("/kubepods.slice/cri-containerd-a.scope", PidNSPrivate, foreign), false, all},
		{
			"privileged pod, cgroupfs driver", host("/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/0123abcd", PidNSPrivate, foreign), true,
			Scope{Subtree: "/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b"},
		},
		// A socket's cgroup must be whose it is wherever the hook is
		// attached below the machine's root or judges only our cgroups,
		// which a kernel that shares it with the v1 data can stop
		// tracking. Attached at the machine's root and unscoped, it judges
		// every socket whatever its cgroup.
		{"privileged pod, socket cgroups shared", with(host(pod, PidNSPrivate, foreign), sockets(SocketCgroupsShared)), false, all},
		{"privileged pod, socket cgroups unknown", with(host(pod, PidNSPrivate, foreign), sockets(SocketCgroupsUnknown)), false, all},
		{"hosted runner, socket cgroups shared", with(host(runner, PidNSHost, local), sockets(SocketCgroupsShared)), true, all},
		{"private cgroupns, socket cgroups shared", with(private(local), sockets(SocketCgroupsShared)), false, all},
		{"private cgroupns, socket cgroups unknown", with(private(local), sockets(SocketCgroupsUnknown)), false, all},
		// The host's daemon, through its socket, starts containers outside
		// our pid namespace, which the scope never reaches.
		{"privileged container outside Kubernetes, the host's dockerd", host("/system.slice/docker-a.scope", PidNSPrivate, hidden), false, all},
		{"runner VM, a unit named for kubepods", host("/system.slice/ci-kubepods-builder.service", PidNSHost, local), true, all},
		{"hostPID pod, cgroupfs driver under a custom cgroup root", host("/custom/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/a", PidNSHost, local), false, all},
		{"hostPID pod, systemd driver under a custom cgroup root", host("/custom.slice/custom-kubepods.slice/custom-kubepods-pod0e4b1f2a_7c3d_4e5f_8a9b_0c1d2e3f4a5b.slice/cri-containerd-a.scope", PidNSHost, local), false, all},
		{"host cgroupns, pid namespace unread", with(host(runner, PidNSUnknown, local), func(s *Shape) { s.PidNSReason = "stat: permission denied" }), false, all},
		{"host cgroupns, path unread", Shape{CgroupNS: CgroupNSHost, CgroupPathReason: "open /proc/self/cgroup: permission denied", PidNS: PidNSHost, Dockerd: local}, false, all},
		{"host cgroupns, mount unproven", with(host(runner, PidNSHost, local), func(s *Shape) { s.CgroupMount = CgroupMountUnknown }), false, all},
		{"host cgroupns, mount is another tree", with(host(runner, PidNSHost, local), func(s *Shape) { s.CgroupMount = CgroupMountOther }), false, all},
		{"privileged pod, DOCKER_HOST names another daemon", with(host(pod, PidNSPrivate, Dockerd{Kind: DockerdAbsent}), remoteDaemon), false, all},
		{"hosted runner, DOCKER_HOST names another daemon", with(host(runner, PidNSHost, local), remoteDaemon), true, all},
		{"privileged pod, docker context unread", with(host(pod, PidNSPrivate, Dockerd{Kind: DockerdAbsent}), unreadContext), false, all},
		{"private cgroupns, docker context unread", with(private(local), unreadContext), false, all},
		{"hosted runner, docker context unread", with(host(runner, PidNSHost, local), unreadContext), true, all},
		{"private cgroupns, foreign dockerd", private(foreign), false, all},
		{"private cgroupns, foreign dockerd under our root", private(foreignUnder), true, all},
		{"private cgroupns, foreign dockerd in a cgroup namespace below our root", private(foreignOwnNS), true, all},
		{"private cgroupns, foreign dockerd under our root making containers in the host's tree", private(foreignHostTree), false, all},
		{"private cgroupns, foreign dockerd whose cgroup mount is unread", private(foreignMountUnread), false, all},
		{"private cgroupns, hidden dockerd", private(hidden), false, all},
		{"private cgroupns, unidentified dockerd", private(unknownD), false, all},
		{"private cgroupns, no dockerd", private(Dockerd{Kind: DockerdAbsent}), true, all},
		{"private cgroupns, own dockerd", private(local), true, all},
		{"private cgroupns, own dockerd on our systemd", private(localSystemd), true, all},
		{"private cgroupns, own dockerd on the host's systemd", private(localHostSystemd), false, all},
		{"private cgroupns, own dockerd that could not be asked its driver", private(localUnasked), false, all},
		{"host cgroupns, own dockerd not asked its driver", host(pod, PidNSPrivate, localUnasked), true, inPod},
		{"privileged pod, a dockerd whose runtime is the node's containerd", host(pod, PidNSPrivate, Dockerd{Kind: DockerdLocal, Reason: "its runtime: the containerd it reaches at /run/containerd/containerd.sock is outside our pid namespace"}), false, all},
		{"privileged pod, another container's dockerd whose runtime is unseen", host(pod, PidNSPrivate, Dockerd{Kind: DockerdForeign, Reason: "pid 7 has another mount namespace; its runtime: no such file"}), false, all},
		{"private cgroupns, own dockerd whose runtime is outside", private(Dockerd{Kind: DockerdLocal, CgroupDriver: "cgroupfs", ContainerTree: "/"}), false, all},
		{"host cgroupfs bound into a private cgroupns", with(private(local), func(s *Shape) { s.CgroupMount = CgroupMountOther }), false, all},
		{"private cgroupns, path unread", with(private(local), func(s *Shape) { s.CgroupPath = "" }), false, all},
		{"private cgroupns, DOCKER_HOST names another daemon", with(private(local), remoteDaemon), false, all},
		{"private cgroupns, pid namespace unread", with(private(local), func(s *Shape) { s.PidNS = PidNSUnknown }), true, all},
		{"private cgroupns, host pid namespace", with(private(local), func(s *Shape) { s.PidNS = PidNSHost }), true, all},
		{"unprobed", Shape{}, false, all},
		// A kind with no rule fails closed, wherever its switch sits.
		{"unnamed cgroup namespace kind", Shape{CgroupNS: CgroupNS(99), CgroupPath: "/", CgroupMount: CgroupMountOurs, PidNS: PidNSHost, Dockerd: local}, false, all},
		{"unnamed cgroup mount kind", with(host(runner, PidNSHost, local), func(s *Shape) { s.CgroupMount = CgroupMount(99) }), false, all},
		{"unnamed pid namespace kind", host(pod, PidNS(99), foreign), false, all},
		{"unnamed dockerd kind, privileged pod", host(pod, PidNSPrivate, Dockerd{Kind: DockerdKind(99)}), false, all},
		{"unnamed dockerd kind, private cgroupns", private(Dockerd{Kind: DockerdKind(99)}), false, all},
		{"unnamed socket cgroups kind", with(private(local), sockets(SocketCgroups(99))), false, all},
	}
	for _, tc := range cases {
		got, err := tc.shape.HookScope()
		if (err == nil) != tc.ok {
			t.Errorf("%s: HookScope() error = %v, want ok=%v", tc.name, err, tc.ok)
		}
		// A refused hook gets the zero scope: nothing would read it.
		if got != tc.want {
			t.Errorf("%s: HookScope() = %+v, want %+v", tc.name, got, tc.want)
		}
	}

	// An unknown fact carries its probe error into the posture reason.
	_, err := Shape{CgroupNS: CgroupNSHost, CgroupPathReason: "open /proc/self/cgroup: permission denied"}.HookScope()
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("unread cgroup path: HookScope() = %v, want the read error in it", err)
	}
}

// kubelet's hosts file is told by how it starts, on the pod's network or
// the node's; Docker's, or none, is not kubelet's.
func TestProbeKubeletHosts(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]bool{
		"# Kubernetes-managed hosts file.\n127.0.0.1\tlocalhost\n":               true,
		"# Kubernetes-managed hosts file (host network).\n127.0.0.1 localhost\n": true,
		"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n":      false,
		"# Kubernetes": false,
		"":             false,
	} {
		path := filepath.Join(dir, "hosts")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := probeKubeletHosts(path); err != nil || got != want {
			t.Errorf("probeKubeletHosts(%q) = %v, %v; want %v", content, got, err, want)
		}
	}
	if got, err := probeKubeletHosts(filepath.Join(dir, "none")); err != nil || got {
		t.Errorf("probeKubeletHosts(no file) = %v, %v; want false", got, err)
	}
	if _, err := probeKubeletHosts(dir); err == nil {
		t.Errorf("probeKubeletHosts(a directory): want an error")
	}
}

// Our own cgroup is looked at twice before it reads as shared: a task
// outside that has left by the second look, as a runtime's exec stage
// does, leaves it ours.
func TestProbeOwnTree(t *testing.T) {
	dir := t.TempDir()
	threads := filepath.Join(dir, "cgroup.threads")
	if err := os.WriteFile(threads, []byte("7\n0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := ownTreeRetry
	t.Cleanup(func() { ownTreeRetry = saved })
	ownTreeRetry = func() {
		if err := os.WriteFile(threads, []byte("7\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, why := probeOwnTree(dir); got != CgroupTreeOurs {
		t.Errorf("a task outside gone by the second look: got %v (%s), want ours", got, why)
	}
	ownTreeRetry = func() {}
	if err := os.WriteFile(threads, []byte("7\n0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, why := probeOwnTree(dir); got != CgroupTreeShared {
		t.Errorf("a task outside that stays: got %v (%s), want shared", got, why)
	}
}

// HookScope reads the daemon's runtime below the machine's root or
// scoped, and only past the refusals that need nothing of the daemon's,
// so Detect looks for it only there.
func TestReadsRuntime(t *testing.T) {
	scoped := Shape{
		CgroupNS: CgroupNSHost, CgroupPath: "/kubepods/pod1/a", CgroupMount: CgroupMountOurs,
		PidNS: PidNSPrivate, SocketCgroups: SocketCgroupsKept,
	}
	with := func(f func(*Shape)) Shape { s := scoped; f(&s); return s }
	for name, c := range map[string]struct {
		shape      Shape
		hook, want bool
	}{
		"scoped":                               {scoped, true, true},
		"the hook off":                         {scoped, false, false},
		"private cgroupns, host pid namespace": {with(func(s *Shape) { s.CgroupNS, s.PidNS = CgroupNSPrivate, PidNSHost }), true, true},
		"runner VM":                            {with(func(s *Shape) { s.PidNS = PidNSHost }), true, false},
		"cgroup namespace unknown":             {with(func(s *Shape) { s.CgroupNS = CgroupNSUnknown }), true, false},
		"mount unproven":                       {with(func(s *Shape) { s.CgroupMount = CgroupMountUnknown }), true, false},
		"socket cgroups shared":                {with(func(s *Shape) { s.SocketCgroups = SocketCgroupsShared }), true, false},
		"DOCKER_HOST elsewhere":                {with(func(s *Shape) { s.DockerHost = "tcp://a:2375" }), true, false},
	} {
		if got := c.shape.readsRuntime(c.hook); got != c.want {
			t.Errorf("%s: readsRuntime = %v, want %v", name, got, c.want)
		}
	}
}

// The pod's cgroup is the deepest component of kubelet's tree that names a
// pod, under either driver; nothing else that merely says "pod" counts.
func TestPodCgroup(t *testing.T) {
	const uid = "0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b"
	escaped := strings.ReplaceAll(uid, "-", "_")
	cases := map[string]string{
		"/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + escaped + ".slice/cri-containerd-a.scope": "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + escaped + ".slice",
		"/kubepods.slice/kubepods-pod" + escaped + ".slice/cri-containerd-a.scope":                                      "/kubepods.slice/kubepods-pod" + escaped + ".slice",
		"/custom.slice/custom-kubepods.slice/custom-kubepods-pod" + escaped + ".slice/cri-containerd-a.scope":           "/custom.slice/custom-kubepods.slice/custom-kubepods-pod" + escaped + ".slice",
		"/kubepods/burstable/pod" + uid + "/0123abcd":                                                                   "/kubepods/burstable/pod" + uid,
		"/kubepods/pod" + uid + "/0123abcd":                                                                             "/kubepods/pod" + uid,
		// A static pod's uid is a hash of its manifest.
		"/kubepods/burstable/pod0123456789abcdef0123456789abcdef/0123abcd": "/kubepods/burstable/pod0123456789abcdef0123456789abcdef",
		"/kubepods.slice/kubepods-burstable.slice/cri-containerd-a.scope":  "",
		"/kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope":       "",
		"/kubepods.slice/podman-" + uid + ".scope":                         "",
		"/": "",
	}
	for in, want := range cases {
		if got := podCgroup(in); got != want {
			t.Errorf("podCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

// The test process's own namespaces are known, whichever they are, and
// /sys/fs/cgroup is the tree it is in.
func TestDetect_Namespaces(t *testing.T) {
	s := Detect(filepath.Join(t.TempDir(), "docker.sock"), "6.17.0-1022-azure", true)
	if s.CgroupNS == CgroupNSUnknown || s.PidNS == PidNSUnknown {
		t.Fatalf("Detect() = %+v, want both namespaces identified", s)
	}
	if s.Kernel != "6.17.0-1022-azure" {
		t.Fatalf("Detect() kernel = %q, want the release it was given", s.Kernel)
	}
	// On a runner VM nothing reads it, so it is not probed.
	if probed := !(s.CgroupNS == CgroupNSHost && s.PidNS == PidNSHost); probed == (s.SocketCgroups == SocketCgroupsUnknown) {
		t.Fatalf("Detect() socket cgroups %v (%s), probed=%v", s.SocketCgroups, s.SocketCgroupsReason, probed)
	}
	// The mount can only be ours where /sys/fs/cgroup is the unified
	// hierarchy itself, not a v1 or hybrid layout.
	var fs unix.Statfs_t
	if err := unix.Statfs(CgroupRoot, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Skipf("%s is not a cgroup2 mount here; the mount check has nothing to prove", CgroupRoot)
	}
	if s.CgroupMount != CgroupMountOurs {
		t.Fatalf("Detect() cgroup mount = %v (%s), want ours", s.CgroupMount, s.CgroupMountReason)
	}
}

// A cgroup2 mount's root in mountinfo is the reader's view of it, and the
// last mount at /sys/fs/cgroup is the one in sight.
func TestCgroupMountRoot(t *testing.T) {
	const (
		proc   = "22 1 0:21 / /proc rw,nosuid - proc proc rw\n"
		host   = "77 74 0:32 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw\n"
		above  = "78 77 0:32 /../.. /sys/fs/cgroup rw,relatime - cgroup2 cgroup2 rw\n"
		spaced = "79 77 0:32 /dind\\040one /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
		tmpfs  = "80 74 0:40 / /sys/fs/cgroup ro,nosuid - tmpfs tmpfs ro,mode=755\n"
		v1     = "81 80 0:41 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n"
		elsewh = "82 74 0:32 / /mnt/cgroup rw - cgroup2 cgroup2 rw\n"
	)
	for in, want := range map[string]string{
		proc + host:          "/",
		host + above:         "/../..",
		host + spaced:        "/dind one",
		proc + elsewh + host: "/",
	} {
		got, err := cgroupMountRoot([]byte(in))
		if err != nil || got != want {
			t.Errorf("cgroupMountRoot(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{proc, proc + elsewh, host + tmpfs + v1} {
		if got, err := cgroupMountRoot([]byte(in)); err == nil {
			t.Errorf("cgroupMountRoot(%q) = %q, want an error", in, got)
		}
	}
}

// A path's depth is its level, and an empty or root path is the root's.
func TestCgroupLevel(t *testing.T) {
	for path, want := range map[string]uint32{"": 0, "/": 0, "/a": 1, "/a/b/": 2, "a/b": 2, "/a//b": 2} {
		if got := CgroupLevel(path); got != want {
			t.Errorf("CgroupLevel(%q) = %d, want %d", path, got, want)
		}
	}
}

func TestUnder(t *testing.T) {
	const pod = "/kubepods.slice/kubepods-pod1.slice"
	for _, c := range []struct {
		path, sub string
		want      bool
	}{
		{pod, pod, true},
		{pod + "/cri-containerd-a.scope", pod, true},
		{pod + "x/cri-containerd-a.scope", pod, false}, // a sibling whose name extends the pod's
		{"/docker/a", pod, false},
		{pod, "", false},         // no cgroup covers nothing
		{"/docker/a", "/", true}, // the root covers every cgroup
		{pod + "/a", pod + "/", true},
	} {
		if got := Under(c.path, c.sub); got != c.want {
			t.Errorf("Under(%q, %q) = %v, want %v", c.path, c.sub, got, c.want)
		}
	}
}

// The kernel starts a path outside the reader's cgroup namespace's root
// with "/.."; a cgroup may be named "..x" under it.
func TestUnderRoot(t *testing.T) {
	for in, want := range map[string]bool{
		"/": true, "/dind": true, "/..x": true,
		"/..": false, "/../..": false, "/../dind": false, "": false,
	} {
		if got := underRoot(in); got != want {
			t.Errorf("underRoot(%q) = %v, want %v", in, got, want)
		}
	}
}

// A threaded cgroup has no process list (reading cgroup.procs fails with
// EOPNOTSUPP), so the mount is proven from its thread list, which holds
// our main thread.
func TestProbeCgroupMount_Threaded(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make cgroups")
	}
	home, err := ReadCgroupPath("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	domain := filepath.Join(CgroupRoot, fmt.Sprintf("cargowall-podenv-test-%d", os.Getpid()))
	threaded := filepath.Join(domain, "t")
	self := []byte(strconv.Itoa(os.Getpid()))
	// Registered before either is made, so a skip after the first leaves
	// nothing behind; removing one never made is a no-op.
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(CgroupRoot, home, "cgroup.procs"), self, 0)
		for _, d := range []string{threaded, domain} {
			for i := 0; i < 50; i++ {
				if err := os.Remove(d); err == nil || os.IsNotExist(err) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	for _, d := range []string{domain, threaded} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Skipf("cannot make test cgroup: %v", err)
		}
	}
	write := func(file, data string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(data), 0); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(domain, "cgroup.procs"), string(self))
	write(filepath.Join(threaded, "cgroup.type"), "threaded")
	write(filepath.Join(threaded, "cgroup.threads"), string(self))
	rel := strings.TrimPrefix(threaded, CgroupRoot)
	if m, why := probeCgroupMount(CgroupRoot, rel, os.Getpid()); m != CgroupMountOurs {
		t.Fatalf("threaded cgroup: got %v (%s), want ours", m, why)
	}
}

// With the egress hook off nothing reads the socket cgroups, so the BTF
// read is skipped wherever the process runs.
func TestDetect_NoHookNoProbe(t *testing.T) {
	s := Detect(filepath.Join(t.TempDir(), "docker.sock"), "6.17.0-1022-azure", false)
	if s.SocketCgroups != SocketCgroupsUnknown || !strings.Contains(s.SocketCgroupsReason, "hook is off") {
		t.Fatalf("Detect() socket cgroups %v (%s), want not probed", s.SocketCgroups, s.SocketCgroupsReason)
	}
}

func TestPidNamespaceInode_MatchesProcLink(t *testing.T) {
	got, err := PidNamespaceInode()
	if err != nil {
		t.Fatal(err)
	}
	link, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	want, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "pid:["), "]"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	if uint32(want) != got {
		t.Fatalf("PidNamespaceInode() = %d, want %d from %s", got, want, link)
	}
}

// The kernel keeps socket cgroups once sock_cgroup_data has a cgroup
// member of its own; before, the pointer shared a union with the v1 data.
func TestSocketCgroupsOf(t *testing.T) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	kept := &btf.Struct{Name: "sock_cgroup_data", Size: 16, Members: []btf.Member{
		{Name: "cgroup", Type: &btf.Pointer{Target: &btf.Struct{Name: "cgroup"}}},
		{Name: "classid", Type: u32, Offset: 64},
	}}
	shared := &btf.Struct{Name: "sock_cgroup_data", Size: 8, Members: []btf.Member{
		{Name: "", Type: &btf.Union{Size: 8, Members: []btf.Member{{Name: "val", Type: &btf.Int{Name: "u64", Size: 8}}}}},
	}}
	if got := socketCgroupsOf(kept); got != SocketCgroupsKept {
		t.Errorf("5.15 layout: got %v, want kept", got)
	}
	if got := socketCgroupsOf(shared); got != SocketCgroupsShared {
		t.Errorf("5.10 layout before the fix: got %v, want shared", got)
	}
}

// The probe answers on this kernel, from its BTF when it has any.
func TestProbeSocketCgroups(t *testing.T) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	got, why := probeSocketCgroups(release)
	t.Logf("kernel %s: socket cgroups %v (%s)", release, got, why)
	if got == SocketCgroupsUnknown {
		t.Fatalf("probe failed: %s", why)
	}
	if _, err := btf.LoadKernelSpec(); err == nil && why != "kernel BTF" {
		t.Errorf("kernel BTF loads, but the probe decided by %q", why)
	}
}

// A /proc cgroup file gives its v2 path, and one with none is an error.
func TestReadCgroupPath(t *testing.T) {
	dir := t.TempDir()
	write := func(data string) string {
		f := filepath.Join(dir, "cgroup")
		if err := os.WriteFile(f, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		return f
	}
	if got, err := ReadCgroupPath(write("1:name=systemd:/x\n0::/kubepods.slice/a.scope\n")); err != nil || got != "/kubepods.slice/a.scope" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := ReadCgroupPath(write("12:memory:/docker/x\n")); err == nil {
		t.Errorf("a v1-only file must be an error")
	}
	if _, err := ReadCgroupPath(filepath.Join(dir, "gone")); err == nil {
		t.Errorf("a missing file must be an error")
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

func TestProbeDockerd_NoSocket(t *testing.T) {
	if d := probeDockerd(filepath.Join(t.TempDir(), "docker.sock"), true); d.Kind != DockerdAbsent {
		t.Fatalf("absent socket: got %+v, want absent", d)
	}
}

// A dial failing with anything but ENOENT (here EINVAL, a path longer than
// sun_path) is unknown, with the error kept.
func TestProbeDockerd_Unknown(t *testing.T) {
	d := probeDockerd("/"+strings.Repeat("x", 200), true)
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
	if d := probeDockerd(sock, true); d.Kind != DockerdUnknown || !strings.Contains(d.Reason, "refused") {
		t.Fatalf("socket with no listener: got %+v, want unknown, refused", d)
	}
}

// Something at the socket's path that is not a socket refuses a connection
// too, but no daemon made it: a directory a bind mount left where no
// socket existed, or a file. Neither is a daemon.
func TestProbeDockerd_NotASocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if d := probeDockerd(dir, true); d.Kind != DockerdAbsent {
		t.Errorf("directory at the socket path: got %+v, want absent", d)
	}
	file := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if d := probeDockerd(file, true); d.Kind != DockerdAbsent {
		t.Errorf("file at the socket path: got %+v, want absent", d)
	}
}

// A daemon in our own process shares our mount namespace: local, and
// where the scope reads its runtime, found serving. A listener that
// accepts and does not answer is local by its mount namespace, with no
// server shown to look for a runtime by; where nothing reads the runtime,
// it is not asked.
func TestProbeDockerd_Local(t *testing.T) {
	served := fakeDaemon(t, http.StatusOK, `{}`)
	if d := probeDockerd(served, true); d.Kind != DockerdLocal || d.pid != int32(os.Getpid()) {
		t.Errorf("local daemon: got %+v, want local, this process", d)
	}
	if d := probeDockerd(served, false); d.Kind != DockerdLocal || d.pid != 0 || d.Reason != "" {
		t.Errorf("local daemon, no runtime read: got %+v, want local, no server looked for", d)
	}
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
	if d := probeDockerd(sock, true); d.Kind != DockerdLocal || d.pid != 0 || !strings.Contains(d.Reason, "the process serving it") || !strings.Contains(d.Reason, "_ping") {
		t.Errorf("silent listener: got %+v, want local by the listener, unanswered, no server", d)
	}
}
