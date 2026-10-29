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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
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
	local := Dockerd{Kind: DockerdLocal}
	foreign := Dockerd{Kind: DockerdForeign, Reason: "pid 7 has another mount namespace"}
	hidden := Dockerd{Kind: DockerdHidden, Reason: "its pid is outside our pid namespace"}
	foreignUnder := Dockerd{Kind: DockerdForeign, Reason: "pid 7 has another mount namespace", Cgroup: "/dind"}
	foreignAbove := Dockerd{Kind: DockerdForeign, Reason: "pid 7 has another mount namespace", Cgroup: "/../../dind"}
	unknownD := Dockerd{Kind: DockerdUnknown, Reason: "dial: timeout"}
	// Both helpers have the mount proven on a kernel that keeps socket
	// cgroups, so each case is decided by the fact it names.
	host := func(path string, pidns PidNS, d Dockerd) Shape {
		return Shape{CgroupNS: CgroupNSHost, CgroupPath: path, CgroupMount: CgroupMountOurs, PidNS: pidns, Dockerd: d, SocketCgroups: SocketCgroupsKept}
	}
	private := func(d Dockerd) Shape {
		return Shape{CgroupNS: CgroupNSPrivate, CgroupPath: "/", CgroupMount: CgroupMountOurs, PidNS: PidNSPrivate, Dockerd: d, SocketCgroups: SocketCgroupsKept}
	}
	sockets := func(c SocketCgroups) func(*Shape) { return func(s *Shape) { s.SocketCgroups = c } }
	with := func(s Shape, f func(*Shape)) Shape { f(&s); return s }
	nested := func(path string, pidns PidNS, d Dockerd) Shape {
		return with(host(path, pidns, d), func(s *Shape) { s.CgroupNS = CgroupNSPrivate })
	}
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
				Dockerd{Kind: DockerdForeign, Reason: "pid 7 has another mount namespace", Cgroup: "/kubepods/besteffort/pod0e4b1f2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b/4567ef01"}), true,
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
		{"private cgroupns, hidden dockerd", private(hidden), false, all},
		{"private cgroupns, unidentified dockerd", private(unknownD), false, all},
		{"private cgroupns, no dockerd", private(Dockerd{Kind: DockerdAbsent}), true, all},
		{"private cgroupns, own dockerd", private(local), true, all},
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

// /proc/<pid>/environ is NUL-separated KEY=value, values free to hold "=".
func TestParseEnviron(t *testing.T) {
	env := parseEnviron([]byte("HOME=/home/runner\x00DOCKER_HOST=tcp://a:2376\x00X=a=b\x00\x00junk\x00"))
	want := map[string]string{"HOME": "/home/runner", "DOCKER_HOST": "tcp://a:2376", "X": "a=b"}
	if len(env) != len(want) {
		t.Fatalf("parseEnviron = %v, want %v", env, want)
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("parseEnviron[%q] = %q, want %q", k, env[k], v)
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
	for _, d := range []string{domain, threaded} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Skipf("cannot make test cgroup: %v", err)
		}
	}
	self := []byte(strconv.Itoa(os.Getpid()))
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(CgroupRoot, home, "cgroup.procs"), self, 0)
		for _, d := range []string{threaded, domain} {
			for i := 0; i < 50 && os.Remove(d) != nil; i++ {
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
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

func TestDockerHostElsewhere(t *testing.T) {
	const sock = "/var/run/docker.sock"
	for in, want := range map[string]bool{
		"unix:///var/run/docker.sock":       false,
		"unix:///var/run//docker.sock":      false,
		"unix://":                           false, // the CLI's default socket
		"unix:///run/user/1000/docker.sock": true,
		"tcp://localhost:2376":              true,
		"ssh://builder@remote.example.com":  true,
	} {
		if got := dockerHostElsewhere(in, sock); got != want {
			t.Errorf("dockerHostElsewhere(%q) = %v, want %v", in, got, want)
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
	if dockerHostElsewhere("unix://"+filepath.Join(root, "var", "run", "docker.sock"), probed) {
		t.Errorf("symlinked spelling of the socket: want the same daemon")
	}
	if !dockerHostElsewhere("unix://"+filepath.Join(root, "var", "run", "other.sock"), probed) {
		t.Errorf("a socket that does not exist is not the probed one")
	}
	// Before the daemon has made its socket, the spellings still match.
	notYet := filepath.Join(root, "run", "later.sock")
	if dockerHostElsewhere("unix://"+filepath.Join(root, "var", "run", "later.sock"), notYet) {
		t.Errorf("symlinked spelling of a socket not yet made: want the same daemon")
	}
}

// The CLI's daemon comes from DOCKER_HOST, else the context DOCKER_CONTEXT
// or the config's currentContext names, through the context's stored
// endpoint, as the docker CLI resolves it.
func TestDockerCLIHost(t *testing.T) {
	dir := t.TempDir()
	context := func(name, host string) {
		sum := sha256.Sum256([]byte(name))
		meta := filepath.Join(dir, "contexts", "meta", hex.EncodeToString(sum[:]))
		if err := os.MkdirAll(meta, 0o755); err != nil {
			t.Fatal(err)
		}
		data := `{"Name":"` + name + `","Metadata":{},"Endpoints":{"docker":{"Host":"` + host + `","SkipTLSVerify":false}}}`
		if err := os.WriteFile(filepath.Join(meta, "meta.json"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	config := func(data string) {
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	context("remote", "tcp://builder:2376")
	env := func(kv ...string) func(string) string {
		m := map[string]string{"DOCKER_CONFIG": dir}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	check := func(name string, getenv func(string) string, wantHost string, wantErr bool) {
		t.Helper()
		host, setting, err := dockerCLIHost(getenv)
		if (err != nil) != wantErr || host != wantHost {
			t.Errorf("%s: got %q (%s), %v; want %q, error %v", name, host, setting, err, wantHost, wantErr)
		}
	}
	check("no config at all", env(), "", false)
	check("DOCKER_HOST", env("DOCKER_HOST", "tcp://a:2375", "DOCKER_CONTEXT", "remote"), "tcp://a:2375", false)
	check("DOCKER_CONTEXT", env("DOCKER_CONTEXT", "remote"), "tcp://builder:2376", false)
	check("DOCKER_CONTEXT naming the default", env("DOCKER_CONTEXT", "default"), "", false)
	check("DOCKER_CONTEXT naming no stored context", env("DOCKER_CONTEXT", "gone"), "", true)
	config(`{"auths":{},"currentContext":"remote"}`)
	check("the config's currentContext", env(), "tcp://builder:2376", false)
	check("DOCKER_CONTEXT over the config", env("DOCKER_CONTEXT", "default"), "", false)
	config(`{"auths":{}}`)
	check("a config with no current context", env(), "", false)
	// As the CLI reads it: an empty config is none, and one it cannot
	// parse is ignored for the default context.
	config(``)
	check("an empty config", env(), "", false)
	config(`{not json`)
	check("a config the CLI cannot parse either", env(), "", false)
	home := func(k string) string { return map[string]string{"HOME": filepath.Dir(dir)}[k] }
	check("a HOME with no .docker", home, "", false)

	// Without HOME the CLI reads the passwd entry's home, as here.
	passwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(passwd, ".docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(passwd, ".docker")
	context("remote", "tcp://builder:2376")
	config(`{"currentContext":"remote"}`)
	saved := passwdHome
	passwdHome = func() string { return passwd }
	t.Cleanup(func() { passwdHome = saved })
	check("no HOME: the passwd home's config", func(string) string { return "" }, "tcp://builder:2376", false)
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

// Something at the socket's path that is not a socket refuses a connection
// too, but no daemon made it: a directory a bind mount left where no
// socket existed, or a file. Neither is a daemon.
func TestProbeDockerd_NotASocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if d := probeDockerd(dir); d.Kind != DockerdAbsent {
		t.Errorf("directory at the socket path: got %+v, want absent", d)
	}
	file := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if d := probeDockerd(file); d.Kind != DockerdAbsent {
		t.Errorf("file at the socket path: got %+v, want absent", d)
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
