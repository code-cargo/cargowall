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

// Package podenv describes the container environment cargowall itself runs
// in: whose cgroup tree its root-cgroup hooks land on, whose processes share
// its pid namespace, and whether the Docker daemon on the socket is one it
// can reconfigure. A runner VM, a Kubernetes pod with a Docker-in-Docker
// sidecar and a SaaS sidecar all look alike from the flags; these facts are
// what tell them apart.
//
// Every fact has an explicit unknown state. A probe that fails says so, and
// no caller may read an unknown it depends on as the permissive answer: an
// unknown cgroup namespace or mount keeps the cgroup egress hook out, and an
// unknown daemon keeps its config untouched.
package podenv

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
)

// Inodes of the initial cgroup and pid namespaces, fixed kernel constants
// (PROC_CGROUP_INIT_INO, PROC_PID_INIT_INO).
const (
	initCgroupNamespace = 0xEFFFFFFB
	InitPidNamespace    = 0xEFFFFFFC
)

// PidNamespaceInode is the inode of our own pid namespace, which the BPF
// programs compare each task's pid chain against.
func PidNamespaceInode() (uint32, error) {
	ino, err := nsInode("/proc/self/ns/pid")
	return uint32(ino), err
}

// CgroupRoot is where every cgroup program attaches: the tree whose mount
// Detect proves (CgroupMount) and whose paths /proc/<pid>/cgroup gives.
const CgroupRoot = "/sys/fs/cgroup"

// CgroupID is the id of the cgroup at path below CgroupRoot, as a BPF
// program reads it: its cgroupfs inode, on 64-bit kernels.
func CgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(CgroupRoot, path), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// CgroupLevel is the depth of the cgroup at an absolute path below the
// root, which is level 0.
func CgroupLevel(path string) uint32 {
	path = strings.Trim(filepath.Clean("/"+path), "/")
	if path == "" {
		return 0
	}
	return uint32(strings.Count(path, "/") + 1)
}

// CgroupNS is which cgroup namespace cargowall runs in.
type CgroupNS int

const (
	CgroupNSUnknown CgroupNS = iota // the probe failed
	// CgroupNSHost: the initial namespace, so /sys/fs/cgroup, where every
	// cgroup program attaches, is the root of the whole machine's tree.
	CgroupNSHost
	// CgroupNSPrivate: a namespace below the machine's root. It is our own
	// container's only where our path in it is "/"; one rooted above us is
	// a tree others may share, such as a nested node's, whose privileged
	// pods share the node container's namespace (privateScope).
	CgroupNSPrivate
)

func (c CgroupNS) String() string {
	switch c {
	case CgroupNSHost:
		return "host"
	case CgroupNSPrivate:
		return "private"
	}
	return "unknown"
}

// CgroupMount is whether /sys/fs/cgroup is the cgroup tree /proc/self/cgroup
// describes. The cgroup namespace alone does not say: the tree a path names
// is the mount's, so the host's cgroupfs bound into a container with a
// private cgroup namespace reads "/" in /proc/self/cgroup while
// /sys/fs/cgroup is the machine's root.
type CgroupMount int

const (
	CgroupMountUnknown CgroupMount = iota // the probe failed
	// CgroupMountOurs: our pid is in /sys/fs/cgroup<CgroupPath>/cgroup.procs.
	CgroupMountOurs
	// CgroupMountOther: it is not, so the mount is some other tree.
	CgroupMountOther
)

func (m CgroupMount) String() string {
	switch m {
	case CgroupMountOurs:
		return "ours"
	case CgroupMountOther:
		return "other"
	}
	return "unknown"
}

// PidNS is which pid namespace cargowall runs in.
type PidNS int

const (
	PidNSUnknown PidNS = iota // the probe failed
	// PidNSHost: the initial namespace, where every task on the machine is
	// visible.
	PidNSHost
	// PidNSPrivate: a namespace of our own: our container's processes and,
	// in a pod that shares one namespace, every container's in the pod.
	PidNSPrivate
)

func (p PidNS) String() string {
	switch p {
	case PidNSHost:
		return "host"
	case PidNSPrivate:
		return "private"
	}
	return "unknown"
}

// SocketCgroups is whether the kernel keeps each socket's cgroup v2 apart
// from its v1 net_cls and net_prio data, which a hook below the machine's
// root, or one that judges only this job's cgroups, depends on.
type SocketCgroups int

const (
	// SocketCgroupsUnknown: the probe failed, or was not run because
	// nothing reads it (the hook is off, or on a runner VM it is at the
	// machine's root and unscoped).
	SocketCgroupsUnknown SocketCgroups = iota
	// SocketCgroupsKept: a socket's cgroup is always the one it was made in.
	SocketCgroupsKept
	// SocketCgroupsShared: the cgroup shares a word with the v1 data, so a
	// v1 net_cls or net_prio hierarchy in use anywhere on the machine turns
	// socket cgroups off, and every socket made after that reads as the
	// root cgroup.
	SocketCgroupsShared
)

func (c SocketCgroups) String() string {
	switch c {
	case SocketCgroupsKept:
		return "kept"
	case SocketCgroupsShared:
		return "shared"
	}
	return "unknown"
}

// Shape is what Detect found.
type Shape struct {
	CgroupNS CgroupNS
	// CgroupNSReason is the probe error when CgroupNS is unknown.
	CgroupNSReason string
	// CgroupPath is our cgroup v2 path as /proc/self/cgroup reports it:
	// absolute in the host namespace, relative to our own root otherwise.
	// Empty when it could not be read.
	CgroupPath string
	// CgroupPathReason is why CgroupPath is empty: the read error, or a
	// file with no cgroup v2 entry.
	CgroupPathReason string
	// CgroupMount is whether /sys/fs/cgroup is the tree CgroupPath is in.
	CgroupMount CgroupMount
	// CgroupMountReason is the evidence for Other, or the probe error for
	// Unknown.
	CgroupMountReason string
	// CgroupTree is who holds the tasks in the tree under /sys/fs/cgroup,
	// probed only in a private cgroup namespace below its root, and
	// CgroupTreeReason the evidence, or why it is unknown.
	CgroupTree       CgroupTree
	CgroupTreeReason string
	PidNS            PidNS
	// PidNSReason is the probe error when PidNS is unknown.
	PidNSReason string
	// InitCgroup is the cgroup of our pid namespace's init, pid 1, as
	// /proc/1/cgroup gives it, read only in a private pid namespace, and
	// InitCgroupReason why it is empty.
	InitCgroup       string
	InitCgroupReason string
	// KubeletHosts is whether /etc/hosts is the one kubelet writes into
	// every container of a pod, and KubeletHostsReason why it could not be
	// read, which counts as kubelet's (inPod).
	KubeletHosts       bool
	KubeletHostsReason string
	Dockerd            Dockerd
	// DockerHost is the daemon the docker CLI is set to use, when it is not
	// the probed socket, and DockerHostSetting what set it (DOCKER_HOST, or
	// a docker context). The job's containers then belong to a daemon
	// nothing probed, so an absent or local result on the socket says
	// nothing about them. DockerHostReason is why the CLI's daemon could
	// not be identified.
	DockerHost        string
	DockerHostSetting string
	DockerHostReason  string
	// Kernel is the running kernel's release, as Detect was given it.
	Kernel string
	// SocketCgroups is whether this kernel keeps socket cgroups, and
	// SocketCgroupsReason the evidence, or the probe error for Unknown.
	SocketCgroups       SocketCgroups
	SocketCgroupsReason string
}

// Scope is what a cgroup program attached at /sys/fs/cgroup judges. The
// zero value is every socket under the attach point.
type Scope struct {
	// Subtree, when set, limits the hook to this job's sockets: those under
	// this cgroup, whose whole subtree is the job's whatever enters it, and
	// those in a cgroup a task of our pid namespace has entered. Every other
	// socket passes: the attach point is the root of a tree other workloads
	// share. The subtree is our Kubernetes pod's cgroup, since every
	// container in the pod is the job's, whichever pid namespace it shares
	// and whoever started it; outside Kubernetes, our own (our container's),
	// which a runtime's exec into it enters from outside our pid namespace.
	// A path as our cgroup namespace gives it.
	Subtree string
}

// Limited reports whether the hook judges only this job's sockets.
func (s Scope) Limited() bool { return s.Subtree != "" }

// HookScope decides whether a cgroup program attached at /sys/fs/cgroup can
// judge exactly this job's traffic, and how: loading the hook and scoping
// it are one decision. A nil error with the zero Scope judges every socket
// under the attach point, which is all this job's (a runner VM, or a
// private cgroup namespace rooted at our own cgroup). A Limited Scope is
// for a cgroup tree others share, outside the host pid namespace (a
// privileged pod), where the attach point is that tree's root: the
// machine's, or a nested node's. An error means the hook must not
// load, and says why it would not judge exactly this job or why that
// cannot be shown. Every leaf returns its own answer, an unidentified fact
// refuses wherever it could change who the hook judges, and a kind with no
// rule here is refused. design.md (Docker Integration) gives the rules,
// with the premises and limits they accept.
func (s Shape) HookScope() (Scope, error) {
	switch s.CgroupNS {
	case CgroupNSUnknown:
		return Scope{}, fmt.Errorf("cgroup namespace unknown (%s)", s.CgroupNSReason)
	case CgroupNSHost, CgroupNSPrivate:
	default:
		return Scope{}, fmt.Errorf("cgroup namespace kind %d has no hook-scope rule", s.CgroupNS)
	}
	if err := s.attachPointRefusal(); err != nil {
		return Scope{}, err
	}
	if s.CgroupNS == CgroupNSPrivate {
		return s.privateScope()
	}
	// /sys/fs/cgroup is the machine's root, which every pod and daemon on
	// it shares.
	pod := s.inPod()
	if scope, done, err := s.sharedPidNS(pod, "the host cgroup namespace", "the host"); done {
		return scope, err // the host pid namespace outside a pod is machineFirewall
	}
	if err := s.partialRefusal(); err != nil {
		return Scope{}, err
	}
	scope, err := s.limitedScope(pod)
	if err != nil {
		return Scope{}, err
	}
	// Under the machine's root every daemon's containers reach the hook,
	// and those of one whose runtime is in our pid namespace are recorded
	// as they start.
	if err := s.daemonRefusal(false); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

// daemonRefusal says why the daemon behind the socket may make containers
// the hook does not judge, in either cgroup namespace, or nil: one we
// cannot see, or cannot identify, or whose runtime is outside our pid
// namespace (runtimeRefusal). In a private one (private) the hook sees
// only what is under the namespace's root, so a daemon we see must show
// its containers' tree under it too, and another container's daemon its
// own cgroup.
func (s Shape) daemonRefusal(private bool) error {
	switch s.Dockerd.Kind {
	case DockerdAbsent:
		return nil
	case DockerdLocal, DockerdForeign:
		if err := s.runtimeRefusal(); err != nil {
			return err
		}
		// Its containers are made in the tree its cgroup driver uses: its
		// runtime's cgroup mount, or the one of the systemd it reaches,
		// which is that one's cgroup namespace's root unless it was given
		// another tree, such as the host's. When that root is under ours,
		// and a foreign daemon's own cgroup too, so are its containers.
		if private && (!underRoot(s.Dockerd.ContainerTree) || (s.Dockerd.Kind == DockerdForeign && !underRoot(s.Dockerd.Cgroup))) {
			return fmt.Errorf("the cgroup hook cannot be shown to reach the containers of a %s dockerd, "+
				"which may be outside this container (%s; its cgroup %q, cgroup driver %q, containers' cgroup tree %q)",
				s.Dockerd.Kind, s.Dockerd.Reason, s.Dockerd.Cgroup, s.Dockerd.CgroupDriver, s.Dockerd.ContainerTree)
		}
		return nil
	case DockerdHidden:
		return fmt.Errorf("the docker daemon's pid is outside our pid namespace, and so are the containers it "+
			"makes, which the cgroup hook cannot be shown to judge, possibly the host's own (%s)", s.Dockerd.Reason)
	case DockerdUnknown:
		return fmt.Errorf("beside an unidentified dockerd, the cgroup hook cannot be shown to judge this job's "+
			"containers (%s)", s.Dockerd.Reason)
	default:
		return fmt.Errorf("dockerd kind %d has no hook-scope rule", s.Dockerd.Kind)
	}
}

// runtimeRefusal says why a daemon whose pid we see may make containers
// the scope never reaches: their tasks are children of its runtime
// (containerd, or the daemon itself), and one outside our pid namespace,
// such as the machine's containerd a daemon of ours was given the socket
// of, makes them outside it, where no entry of theirs is recorded.
func (s Shape) runtimeRefusal() error {
	if s.Dockerd.Runtime == 0 {
		return fmt.Errorf("the cgroup hook judges only our pid namespace, and the docker daemon's runtime, "+
			"whose children its containers' tasks are, cannot be shown to be in it (%s)", s.Dockerd.Reason)
	}
	return nil
}

// privateScope decides for a private cgroup namespace, where
// /sys/fs/cgroup is the namespace's root, below the machine's. The hook
// sees only what is under it, and no scope widens that, so a daemon whose
// containers could live outside it refuses whatever our path. The path
// then decides only how much the hook judges: where our cgroup is the root
// it is our own container's, and the hook judges all of it; where the root
// is above us it is a tree others may share, such as a nested node's
// (kind, minikube's docker driver), whose privileged pods share the node
// container's namespace.
func (s Shape) privateScope() (Scope, error) {
	if err := s.partialRefusal(); err != nil {
		return Scope{}, err
	}
	if err := s.daemonRefusal(true); err != nil {
		return Scope{}, err
	}
	if s.CgroupPath == "/" {
		return Scope{}, nil
	}
	pod := s.inPod()
	if scope, done, err := s.sharedPidNS(pod, "a cgroup namespace rooted above our cgroup", "the node's"); done {
		return scope, err
	}
	// A tree with no task outside our pid namespace anywhere in it is our
	// container's alone, below whose root it moved its own tasks (an
	// entrypoint making room for nested cgroups, or systemd as its init),
	// and the hook judges all of it, as at "/". A nested node always has
	// some: its kubelet and runtime are outside every pod's pid namespace.
	if !pod && s.CgroupTree == CgroupTreeOurs {
		return Scope{}, nil
	}
	return s.limitedScope(pod)
}

// sharedPidNS decides for every pid namespace but a private one, the same
// wherever the hook sits: an unknown one refuses, and the host one judges
// every socket under the attach point, unless in a pod, where that is
// every pod on the node. done is false for a private one, which
// the caller decides. For the errors, in names the cgroup namespace we are
// in, and whose the machine whose cgroup and pid namespaces we share.
func (s Shape) sharedPidNS(pod bool, in, whose string) (scope Scope, done bool, err error) {
	switch s.PidNS {
	case PidNSUnknown:
		return Scope{}, true, fmt.Errorf("pid namespace unknown in %s (%s)", in, s.PidNSReason)
	case PidNSHost:
		if pod {
			return Scope{}, true, fmt.Errorf("running in a Kubernetes pod in %s cgroup and pid namespaces: "+
				"the cgroup hook would attach at the node root and judge every pod on the node", whose)
		}
		return Scope{}, true, nil
	case PidNSPrivate:
		return Scope{}, false, nil
	default:
		return Scope{}, true, fmt.Errorf("pid namespace kind %d has no hook-scope rule", s.PidNS)
	}
}

// Under reports whether the cgroup at path is sub or below it, by path, as
// one cgroup namespace gives both: "" is no cgroup, which covers nothing,
// and "/" covers every cgroup. scopebpf.c's in_subtree asks the same of an
// id, through at most 32 parents, and past that records a cgroup the hook
// judges anyway.
func Under(path, sub string) bool {
	return sub != "" && (path == sub || strings.HasPrefix(path, strings.TrimSuffix(sub, "/")+"/"))
}

// underRoot reports whether a cgroup path, as our cgroup namespace gives
// it, is under the namespace's root: the kernel starts one outside it with
// "/..". "" is unknown, and not under it.
func underRoot(path string) bool {
	return path != "" && path != "/.." && !strings.HasPrefix(path, "/../")
}

// inPod reports whether we are in a Kubernetes pod: our cgroup is in
// kubelet's tree (kubepods), or /etc/hosts is kubelet's, the one sign a
// kubelet that makes no pod cgroups (cgroupsPerQOS=false) leaves. A pod is
// judged whole, by its cgroup, which outside kubelet's tree no path shows,
// so the hosts file alone, or one that could not be read, only refuses.
func (s Shape) inPod() bool {
	return s.kubepods() || s.KubeletHosts || s.KubeletHostsReason != ""
}

// kubepods reports whether our cgroup is in kubelet's tree, by a whole
// path segment anywhere in the path: kubepods under the cgroupfs driver,
// kubepods.slice under the systemd driver, or <root>-kubepods.slice with a
// cgroup root of its own. A unit merely named for it is not (a VM's
// ci-kubepods-builder.service). A false match only refuses: outright in
// the host pid namespace, and outside it for want of a pod cgroup in the
// path.
func (s Shape) kubepods() bool {
	for _, seg := range strings.Split(s.CgroupPath, "/") {
		if seg == "kubepods" || seg == "kubepods.slice" || strings.HasSuffix(seg, "-kubepods.slice") {
			return true
		}
	}
	return false
}

// limitedScope is the scope that judges only this job's sockets, with the
// job's subtree: the pod's cgroup in a pod, our own cgroup outside one.
func (s Shape) limitedScope(pod bool) (Scope, error) {
	sub := s.CgroupPath
	if pod {
		if sub = podCgroup(s.CgroupPath); sub == "" {
			return Scope{}, fmt.Errorf("in a Kubernetes pod whose cgroup %s is in no pod cgroup of kubelet's "+
				"(kubelet's /etc/hosts %v, %q): the cgroup hook would not judge the pod's other containers",
				s.CgroupPath, s.KubeletHosts, s.KubeletHostsReason)
		}
	} else if CgroupLevel(s.CgroupPath) == 0 {
		return Scope{}, errors.New("in the root cgroup outside the host pid namespace: no cgroup of this job's own " +
			"holds its tasks, and the root holds every task on the machine")
	}
	if err := s.initRefusal(sub); err != nil {
		return Scope{}, err
	}
	return Scope{Subtree: sub}, nil
}

// initRefusal says why our pid namespace may hold more than the job whose
// cgroup is sub: every task in it counts as the job's. A pod's own
// namespace has its init, pid 1, under the pod's cgroup (the pause
// container, or our own container's init), and so does our container's
// outside Kubernetes. One whose init is elsewhere is a node's or a
// machine's that only reads as private from below: a hostPID pod on a
// nested node (kind, k3d) is in the node container's namespace, beside
// kubelet, the runtime and every pod's tasks.
func (s Shape) initRefusal(sub string) error {
	if s.InitCgroup == "" {
		return fmt.Errorf("the cgroup of our pid namespace's init is unknown (%s)", s.InitCgroupReason)
	}
	if !Under(s.InitCgroup, sub) {
		return fmt.Errorf("our pid namespace's init, pid 1, is in %s, outside this job's cgroup %s: the namespace "+
			"is a node's or a machine's, and every task in it would count as this job's", s.InitCgroup, sub)
	}
	return nil
}

// machineFirewall reports whether the hook would attach at the machine's
// root in the host pid namespace: a runner VM, where it judges every socket
// and reads neither the daemon nor the kernel's socket cgroups. Detect
// skips probing what only the other shapes read.
func (s Shape) machineFirewall() bool {
	return s.CgroupNS == CgroupNSHost && s.PidNS == PidNSHost
}

// partialRefusal says why a hook that judges part of the machine, below its
// root or limited to this job, could miss this job's traffic for reasons
// beyond the shape: the docker CLI uses a daemon nothing probed, or the
// kernel can lose sockets' cgroups. Nil when neither.
func (s Shape) partialRefusal() error {
	if err := s.dockerHostRefusal(); err != nil {
		return err
	}
	return s.socketCgroupRefusal()
}

// attachPointRefusal says why /sys/fs/cgroup cannot be shown to be the
// cgroup tree this process is in, or nil when it can.
func (s Shape) attachPointRefusal() error {
	if s.CgroupPath == "" {
		return fmt.Errorf("cgroup path unknown (%s)", s.CgroupPathReason)
	}
	switch s.CgroupMount {
	case CgroupMountOurs:
		return nil
	case CgroupMountOther:
		return fmt.Errorf("%s is not the cgroup tree this process is in (%s)", CgroupRoot, s.CgroupMountReason)
	case CgroupMountUnknown:
		return fmt.Errorf("cannot show %s is the cgroup tree this process is in (%s)", CgroupRoot, s.CgroupMountReason)
	default:
		return fmt.Errorf("cgroup mount kind %d has no hook-scope rule", s.CgroupMount)
	}
}

// dockerHostRefusal says why the job's daemon is not, or cannot be shown
// to be, the one probed, or nil.
func (s Shape) dockerHostRefusal() error {
	if s.DockerHostReason != "" {
		return fmt.Errorf("the docker daemon the CLI is set to use is unidentified (%s), "+
			"and its containers may be ones the hook does not see", s.DockerHostReason)
	}
	if s.DockerHost != "" {
		return fmt.Errorf("%s names %s, a docker daemon the probe did not reach, "+
			"whose containers the hook may not see", s.DockerHostSetting, s.DockerHost)
	}
	return nil
}

// socketCgroupRefusal says why this kernel cannot be shown to put this
// job's sockets in this job's cgroups, or nil when it can. A hook attached
// below the machine's root, or one that judges only this job's cgroups,
// depends on that: a socket that reads as the root cgroup never reaches a
// program attached below the root, and the scope never records the root.
func (s Shape) socketCgroupRefusal() error {
	switch s.SocketCgroups {
	case SocketCgroupsKept:
		return nil
	case SocketCgroupsShared:
		return fmt.Errorf("the cgroup hook needs sockets' cgroups, which kernel %s can stop tracking (%s)",
			s.Kernel, s.SocketCgroupsReason)
	case SocketCgroupsUnknown:
		return fmt.Errorf("the cgroup hook needs sockets' cgroups, and whether kernel %s keeps them is unknown (%s)",
			s.Kernel, s.SocketCgroupsReason)
	default:
		return fmt.Errorf("socket cgroups kind %d has no hook-scope rule", s.SocketCgroups)
	}
}

// probeSocketCgroups reads struct sock_cgroup_data from the kernel's BTF.
// The fix that keeps socket cgroups (8520e224f547, in 5.15) gave the
// cgroup pointer a member of its own, out of the union with the v1 data,
// and stable kernels that took it (5.10.y did) have that member too, which
// their release cannot show. Without BTF, or without the type, the release
// decides.
func probeSocketCgroups(kernel string) (SocketCgroups, string) {
	spec, err := btf.LoadKernelSpec()
	if err == nil {
		var st *btf.Struct
		if err = spec.TypeByName("sock_cgroup_data", &st); err == nil {
			return socketCgroupsOf(st), "kernel BTF"
		}
	}
	ok, verr := cargowallEbpf.KernelAtLeast(kernel, 5, 15)
	switch {
	case verr != nil:
		return SocketCgroupsUnknown, fmt.Sprintf("%v, and %v", err, verr)
	case ok:
		return SocketCgroupsKept, "release 5.15 or later"
	default:
		return SocketCgroupsShared, fmt.Sprintf("release older than 5.15, and %v", err)
	}
}

// socketCgroupsOf decides from struct sock_cgroup_data's members.
func socketCgroupsOf(st *btf.Struct) SocketCgroups {
	for _, m := range st.Members {
		if m.Name == "cgroup" {
			return SocketCgroupsKept
		}
	}
	return SocketCgroupsShared
}

// hostsFile is where kubelet puts the hosts file it writes for a pod, and
// kubeletHosts how that file starts, on the pod's network or the node's.
const (
	hostsFile    = "/etc/hosts"
	kubeletHosts = "# Kubernetes-managed hosts file"
)

// probeKubeletHosts reports whether the hosts file at path is kubelet's.
// No file is not kubelet's, which writes one into every container.
func probeKubeletHosts(path string) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, len(kubeletHosts))
	if _, err := io.ReadFull(f, head); errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return string(head) == kubeletHosts, nil
}

// podCgroupName matches the pod level of kubelet's tree: pod<uid> under the
// cgroupfs driver, <parent>-pod<uid>.slice under the systemd driver, which
// writes the uid's dashes as underscores. A uid is a UUID, or 32 hex
// digits for a static pod.
var podCgroupName = regexp.MustCompile(`^(?:.*-)?pod(?:[0-9a-f]{32}|[0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})(?:\.slice)?$`)

// podCgroup returns the pod's cgroup in an absolute cgroup path under
// kubelet's tree, the deepest component that names a pod, or "" when none
// does.
func podCgroup(path string) string {
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i > 0; i-- {
		if podCgroupName.MatchString(parts[i]) {
			return strings.Join(parts[:i+1], "/")
		}
	}
	return ""
}

// LogArgs is every fact and probe error, as slog key-value pairs.
func (s Shape) LogArgs() []any {
	return []any{
		"cgroupns", s.CgroupNS.String(), "cgroupns_reason", s.CgroupNSReason,
		"cgroup", s.CgroupPath, "cgroup_reason", s.CgroupPathReason,
		"cgroup_mount", s.CgroupMount.String(), "cgroup_mount_reason", s.CgroupMountReason,
		"pidns", s.PidNS.String(), "pidns_reason", s.PidNSReason,
		"init_cgroup", s.InitCgroup, "init_cgroup_reason", s.InitCgroupReason,
		"kubelet_hosts", s.KubeletHosts, "kubelet_hosts_reason", s.KubeletHostsReason,
		"cgroup_tree", s.CgroupTree.String(), "cgroup_tree_reason", s.CgroupTreeReason,
		"dockerd", s.Dockerd.Kind.String(), "dockerd_reason", s.Dockerd.Reason,
		"dockerd_cgroup", s.Dockerd.Cgroup, "dockerd_cgroup_driver", s.Dockerd.CgroupDriver,
		"dockerd_container_tree", s.Dockerd.ContainerTree, "dockerd_runtime", s.Dockerd.Runtime,
		"docker_host", s.DockerHost, "docker_host_setting", s.DockerHostSetting,
		"docker_host_reason", s.DockerHostReason, "kernel", s.Kernel,
		"socket_cgroups", s.SocketCgroups.String(), "socket_cgroups_reason", s.SocketCgroupsReason,
	}
}

// Detect probes the environment, on the kernel release given (uname -r).
// egressHook says whether the cgroup egress hook may load at all: when it
// may not, nothing reads the facts only HookScope uses, and the costly one
// of them, the kernel BTF read, is not probed. A probe that fails records
// unknown and its error in the Shape rather than leaving a zero that reads
// as a result.
func Detect(dockerSocket, kernel string, egressHook bool) Shape {
	s := Shape{Kernel: kernel}
	if ino, err := nsInode("/proc/self/ns/cgroup"); err != nil {
		s.CgroupNSReason = err.Error()
	} else if ino == initCgroupNamespace {
		s.CgroupNS = CgroupNSHost
	} else {
		s.CgroupNS = CgroupNSPrivate
	}
	if path, err := ReadCgroupPath("/proc/self/cgroup"); err != nil {
		s.CgroupPathReason = err.Error()
	} else {
		s.CgroupPath = path
	}
	if s.CgroupPath != "" {
		s.CgroupMount, s.CgroupMountReason = probeCgroupMount(CgroupRoot, s.CgroupPath, os.Getpid())
	} else {
		s.CgroupMountReason = "no cgroup path to look for"
	}
	if ino, err := PidNamespaceInode(); err != nil {
		s.PidNSReason = err.Error()
	} else if ino == InitPidNamespace {
		s.PidNS = PidNSHost
	} else {
		s.PidNS = PidNSPrivate
	}
	if hosts, err := probeKubeletHosts(hostsFile); err != nil {
		s.KubeletHostsReason = err.Error()
	} else {
		s.KubeletHosts = hosts
	}
	s.Dockerd = probeDockerd(dockerSocket)
	// A private cgroup namespace's root bounds the hook, so where a daemon
	// makes its containers, and who else is in the tree, matter there only.
	private := egressHook && s.CgroupNS == CgroupNSPrivate
	visible := s.Dockerd.Kind == DockerdLocal || s.Dockerd.Kind == DockerdForeign
	if visible && (private || egressHook && s.PidNS == PidNSPrivate) {
		s.Dockerd.probeRuntime(dockerSocket)
	}
	if private && visible {
		s.Dockerd.probeContainerTree(dockerSocket)
	}
	if private && s.CgroupPath != "" && s.CgroupPath != "/" && s.PidNS == PidNSPrivate && !s.inPod() {
		s.CgroupTree, s.CgroupTreeReason = probeCgroupTree(CgroupRoot)
	} else {
		s.CgroupTreeReason = "not probed: read only in a private cgroup namespace below its root, " +
			"outside a pod, in a pid namespace of our own"
	}
	if egressHook && s.PidNS == PidNSPrivate {
		if path, err := ReadCgroupPath("/proc/1/cgroup"); err != nil {
			s.InitCgroupReason = err.Error()
		} else {
			s.InitCgroup = path
		}
	} else {
		s.InitCgroupReason = "not probed: read only in a private pid namespace"
	}
	// The docker CLI's daemon matters only to a hook that judges part of
	// the machine (partialRefusal), not to one at a runner VM's root.
	if egressHook && !s.machineFirewall() {
		if env, uid, err := dockerEnv(); err != nil {
			s.DockerHostReason = err.Error()
		} else if host, setting, err := dockerCLIHost(env, uid); err != nil {
			s.DockerHostReason = err.Error()
		} else if host != "" && dockerHostElsewhere(host, dockerSocket) {
			s.DockerHost, s.DockerHostSetting = host, setting
		}
	}
	// The probe parses the kernel's BTF, and nothing reads its answer
	// without the hook, or on a runner VM (machineFirewall).
	if !egressHook {
		s.SocketCgroupsReason = "not probed: the cgroup egress hook is off"
	} else if s.machineFirewall() {
		s.SocketCgroupsReason = "not probed: the hook is at the machine's root and judges every socket"
	} else {
		s.SocketCgroups, s.SocketCgroupsReason = probeSocketCgroups(kernel)
	}
	return s
}

// CgroupTree is who holds the tasks in the cgroup tree under
// /sys/fs/cgroup.
type CgroupTree int

const (
	CgroupTreeUnknown CgroupTree = iota // the probe failed, or was not made
	CgroupTreeOurs                      // every task in it is in our pid namespace
	CgroupTreeShared                    // a task in it is outside our pid namespace
)

func (c CgroupTree) String() string {
	switch c {
	case CgroupTreeOurs:
		return "ours"
	case CgroupTreeShared:
		return "shared"
	}
	return "unknown"
}

// ThreadsMembers reads a cgroup.threads, which numbers each task as the
// reader's pid namespace does, for whether it lists tasks of that
// namespace (by their ids) and tasks outside it (as 0).
func ThreadsMembers(data []byte) (ours, theirs bool) {
	for _, line := range strings.Split(string(data), "\n") {
		switch line {
		case "":
		case "0":
			theirs = true
		default:
			ours = true
		}
	}
	return ours, theirs
}

// probeCgroupTree looks over every cgroup under root for a task outside
// our pid namespace, which its cgroup.threads lists as 0, as the reader's
// pid namespace numbers it. A cgroup removed during the look is passed
// over; one that cannot be read leaves the answer unknown.
func probeCgroupTree(root string) (CgroupTree, string) {
	tree, why := CgroupTreeOurs, ""
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(filepath.Join(path, "cgroup.threads"))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, theirs := ThreadsMembers(data); theirs {
			tree, why = CgroupTreeShared, "a task outside our pid namespace is in "+path
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return CgroupTreeUnknown, err.Error()
	}
	return tree, why
}

// probeCgroupMount reports whether root is the cgroup tree path is in,
// by looking for pid in that cgroup's member list. cgroup.procs lists pids
// as numbered in the reader's pid namespace, which is ours.
func probeCgroupMount(root, path string, pid int) (CgroupMount, string) {
	procs := filepath.Join(root, path, "cgroup.procs")
	data, err := os.ReadFile(procs)
	if errors.Is(err, unix.EOPNOTSUPP) {
		// A threaded cgroup has no process list; its thread list holds our
		// main thread, whose id is our pid.
		procs = filepath.Join(root, path, "cgroup.threads")
		data, err = os.ReadFile(procs)
	}
	if errors.Is(err, os.ErrNotExist) {
		return CgroupMountOther, fmt.Sprintf("%s has no cgroup %s", root, path)
	}
	if err != nil {
		return CgroupMountUnknown, err.Error()
	}
	want := strconv.Itoa(pid)
	for _, line := range strings.Split(string(data), "\n") {
		if line == want {
			return CgroupMountOurs, ""
		}
	}
	return CgroupMountOther, fmt.Sprintf("pid %d is not in %s", pid, procs)
}

// ReadCgroupPath returns the cgroup v2 path a /proc cgroup file gives
// (/proc/<pid>/cgroup, or a thread's under /proc/<pid>/task): absolute in
// the host cgroup namespace, relative to our own root otherwise. A v1-only
// file, with no v2 entry, is an error.
func ReadCgroupPath(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	path := parseCgroupV2Path(data)
	if path == "" {
		return "", fmt.Errorf("no cgroup v2 entry in %s", file)
	}
	return path, nil
}

// parseCgroupV2Path returns the path of the unified hierarchy line
// ("0::<path>"), or "" on a v1-only host.
func parseCgroupV2Path(data []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if path, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return path
		}
	}
	return ""
}

func nsInode(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return st.Ino, nil
}
