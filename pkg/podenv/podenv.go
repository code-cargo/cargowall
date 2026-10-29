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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	path = strings.Trim(filepath.Clean(path), "/")
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
	// CgroupNSPrivate: a namespace of our own, rooted at our container.
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

// DockerdKind is what is behind the Docker socket.
type DockerdKind int

const (
	DockerdUnknown DockerdKind = iota // the probe failed
	DockerdAbsent                     // no socket
	// DockerdLocal: the daemon shares our mount namespace, so its
	// daemon.json is ours and our service manager can restart it.
	DockerdLocal
	// DockerdForeign: the daemon's pid is visible but its mount namespace is
	// not ours: another container sharing our pid namespace, or the host's
	// own daemon when we share the host's.
	DockerdForeign
	// DockerdHidden: the daemon's pid is outside our pid namespace, so
	// neither it nor any container it starts is visible to us.
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
	// Unknown.
	Reason string
	// Cgroup is a Foreign daemon's cgroup v2 path as /proc/<pid>/cgroup
	// gives it in our cgroup namespace, "" when it could not be read. A
	// path under our namespace's root does not start with "/..".
	Cgroup string
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
	PidNS             PidNS
	// PidNSReason is the probe error when PidNS is unknown.
	PidNSReason string
	Dockerd     Dockerd
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
	kubepods := s.kubepods()
	switch s.PidNS {
	case PidNSUnknown:
		return Scope{}, fmt.Errorf("pid namespace unknown in the host cgroup namespace (%s)", s.PidNSReason)
	case PidNSHost:
		if kubepods {
			return Scope{}, errors.New("running in a Kubernetes pod in the host cgroup and pid namespaces: " +
				"the cgroup hook would attach at the node root and judge every pod on the node")
		}
		return Scope{}, nil // machineFirewall
	case PidNSPrivate:
	default:
		return Scope{}, fmt.Errorf("pid namespace kind %d has no hook-scope rule", s.PidNS)
	}
	if err := s.partialRefusal(); err != nil {
		return Scope{}, err
	}
	scope, err := s.limitedScope(kubepods)
	if err != nil {
		return Scope{}, err
	}
	// Under the machine's root every daemon's containers reach the hook,
	// and those of one in our pid namespace are recorded as they start.
	switch s.Dockerd.Kind {
	case DockerdAbsent, DockerdLocal, DockerdForeign:
		return scope, nil
	case DockerdHidden:
		return Scope{}, fmt.Errorf("the cgroup hook judges only our pid namespace, and the docker daemon's "+
			"containers are outside it (%s)", s.Dockerd.Reason)
	case DockerdUnknown:
		return Scope{}, fmt.Errorf("the cgroup hook judges only our pid namespace, beside an unidentified dockerd (%s)",
			s.Dockerd.Reason)
	default:
		return Scope{}, fmt.Errorf("dockerd kind %d has no hook-scope rule", s.Dockerd.Kind)
	}
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
	switch s.Dockerd.Kind {
	case DockerdAbsent, DockerdLocal:
	case DockerdForeign:
		// Its containers are where it puts them, under its own cgroup's
		// view; when that cgroup is under our root, so are they.
		if s.Dockerd.Cgroup == "" || strings.HasPrefix(s.Dockerd.Cgroup, "/..") {
			return Scope{}, fmt.Errorf("the cgroup hook cannot reach containers of a dockerd outside this container, "+
				"another container's or the host's own (%s)", s.Dockerd.Reason)
		}
	case DockerdHidden:
		return Scope{}, fmt.Errorf("the cgroup hook cannot reach containers of a dockerd we cannot see, "+
			"possibly the host's own (%s)", s.Dockerd.Reason)
	case DockerdUnknown:
		return Scope{}, fmt.Errorf("in a private cgroup namespace beside an unidentified dockerd (%s)", s.Dockerd.Reason)
	default:
		return Scope{}, fmt.Errorf("dockerd kind %d has no hook-scope rule", s.Dockerd.Kind)
	}
	if s.CgroupPath == "/" {
		return Scope{}, nil
	}
	kubepods := s.kubepods()
	switch s.PidNS {
	case PidNSUnknown:
		return Scope{}, fmt.Errorf("pid namespace unknown in a cgroup namespace rooted above our cgroup (%s)", s.PidNSReason)
	case PidNSHost:
		if kubepods {
			return Scope{}, errors.New("running in a Kubernetes pod in the node's cgroup and pid namespaces: " +
				"the cgroup hook would attach at the node root and judge every pod on the node")
		}
		return Scope{}, nil
	case PidNSPrivate:
		return s.limitedScope(kubepods)
	default:
		return Scope{}, fmt.Errorf("pid namespace kind %d has no hook-scope rule", s.PidNS)
	}
}

// kubepods reports whether our cgroup is in kubelet's tree: kubepods under
// the cgroupfs driver, <root>-kubepods.slice under the systemd driver with
// a cgroup root of its own, so the name is matched anywhere in the path. A
// false match only refuses: outright in the host pid namespace, and outside
// it for want of a pod cgroup in the path.
func (s Shape) kubepods() bool {
	return strings.Contains(s.CgroupPath, "kubepods")
}

// limitedScope is the scope that judges only this job's sockets, with the
// job's subtree: the pod's cgroup in kubelet's tree, our own cgroup
// outside it.
func (s Shape) limitedScope(kubepods bool) (Scope, error) {
	if kubepods {
		pod := podCgroup(s.CgroupPath)
		if pod == "" {
			return Scope{}, fmt.Errorf("in a Kubernetes pod whose cgroup is not in %s: the cgroup hook "+
				"would not judge the pod's other containers", s.CgroupPath)
		}
		return Scope{Subtree: pod}, nil
	}
	if CgroupLevel(s.CgroupPath) == 0 {
		return Scope{}, errors.New("in the root cgroup outside the host pid namespace: no cgroup of this job's own " +
			"holds its tasks, and the root holds every task on the machine")
	}
	return Scope{Subtree: s.CgroupPath}, nil
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
		"dockerd", s.Dockerd.Kind.String(), "dockerd_reason", s.Dockerd.Reason,
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
	s.Dockerd = probeDockerd(dockerSocket)
	if host, setting, err := dockerCLIHost(os.Getenv); err != nil {
		s.DockerHostReason = err.Error()
	} else if host != "" && dockerHostElsewhere(host, dockerSocket) {
		s.DockerHost, s.DockerHostSetting = host, setting
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

// defaultDockerHost is the docker CLI's default socket, which an empty
// unix:// address means too.
const defaultDockerHost = "/var/run/docker.sock"

// passwdHome is the current user's home directory from the passwd
// database, or "".
var passwdHome = func() string {
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// dockerCLIHost is the daemon address the docker CLI would use in the
// environment getenv reads, resolved as the CLI resolves it: DOCKER_HOST;
// else the context DOCKER_CONTEXT names, else the config file's current
// context, through that context's stored endpoint. setting says which; ""
// is the default context, the default socket. A context that cannot be
// read is an error, as it is to the CLI.
func dockerCLIHost(getenv func(string) string) (host, setting string, err error) {
	if h := getenv("DOCKER_HOST"); h != "" {
		return h, "DOCKER_HOST", nil
	}
	dir := getenv("DOCKER_CONFIG")
	if dir == "" {
		// The CLI falls back on the user's passwd entry without HOME.
		home := getenv("HOME")
		if home == "" {
			home = passwdHome()
		}
		if home != "" {
			dir = filepath.Join(home, ".docker")
		}
	}
	name, setting := getenv("DOCKER_CONTEXT"), "DOCKER_CONTEXT"
	if name == "" && dir != "" {
		config := filepath.Join(dir, "config.json")
		data, err := os.ReadFile(config)
		if errors.Is(err, fs.ErrNotExist) {
			return "", "", nil
		}
		if err != nil {
			return "", "", err
		}
		// As the CLI reads it: an empty file is no config, and one it
		// cannot parse is warned about and then ignored, for the default
		// context.
		var cfg struct {
			CurrentContext string `json:"currentContext"`
		}
		if len(bytes.TrimSpace(data)) == 0 || json.Unmarshal(data, &cfg) != nil {
			return "", "", nil
		}
		name, setting = cfg.CurrentContext, config+"'s currentContext"
	}
	if name == "" || name == "default" {
		return "", "", nil
	}
	setting = fmt.Sprintf("docker context %q (from %s)", name, setting)
	if dir == "" {
		return "", "", fmt.Errorf("%s: no docker config directory", setting)
	}
	sum := sha256.Sum256([]byte(name))
	data, err := os.ReadFile(filepath.Join(dir, "contexts", "meta", hex.EncodeToString(sum[:]), "meta.json"))
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", setting, err)
	}
	var meta struct {
		Endpoints map[string]struct{ Host string }
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", "", fmt.Errorf("%s: %w", setting, err)
	}
	if host = meta.Endpoints["docker"].Host; host == "" {
		return "", "", fmt.Errorf("%s names no docker endpoint", setting)
	}
	return host, setting, nil
}

// dockerHostElsewhere reports whether a docker daemon address names a
// daemon other than the one on socket. Two spellings of one socket are the
// same daemon: /var/run is a symlink to /run on most distributions. They
// are compared with their directories' symlinks resolved, so the spellings
// match before the daemon has made its socket too.
func dockerHostElsewhere(host, socket string) bool {
	p, ok := strings.CutPrefix(host, "unix://")
	if !ok {
		return true
	}
	if p == "" {
		p = defaultDockerHost
	}
	if resolveDir(p) == resolveDir(socket) {
		return false
	}
	if a, err := os.Stat(p); err == nil {
		if b, err := os.Stat(socket); err == nil && os.SameFile(a, b) {
			return false
		}
	}
	return true
}

// resolveDir is path with the symlinks in its directory resolved, or just
// cleaned when that directory cannot be resolved.
func resolveDir(path string) string {
	path = filepath.Clean(path)
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		return filepath.Join(dir, filepath.Base(path))
	}
	return path
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

// probeDockerd identifies the daemon through SO_PEERCRED on a connection
// to its socket: the kernel reports the listener's pid translated into our
// pid namespace, 0 when it is not visible there. A visible pid can still
// be another container's process once the pod shares one pid namespace, so
// the mount namespace is the decisive comparison. A socket-activated
// daemon reports the activating service manager, which shares ours on a
// host.
func probeDockerd(socket string) Dockerd {
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
	if ours != theirs {
		cgroup, _ := ReadCgroupPath("/proc/" + strconv.Itoa(int(pid)) + "/cgroup")
		return Dockerd{Kind: DockerdForeign, Reason: fmt.Sprintf("pid %d has another mount namespace", pid), Cgroup: cgroup}
	}
	return Dockerd{Kind: DockerdLocal}
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

func nsInode(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return st.Ino, nil
}
