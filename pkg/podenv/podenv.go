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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
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

// cgroupRoot is where every cgroup program attaches.
const cgroupRoot = "/sys/fs/cgroup"

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
	// DockerHost is DOCKER_HOST when it names a daemon other than the probed
	// socket. The job's containers then belong to a daemon nothing probed,
	// so an absent or local result on the socket says nothing about them.
	DockerHost string
	// Kernel is the running kernel's release, empty when uname failed.
	Kernel string
}

// HookScope decides whether a cgroup program attached at /sys/fs/cgroup can
// judge exactly this job's traffic, and how. Loading the hook and scoping it
// are one decision, so both answers come from here, and every leaf of the
// table below returns its own:
//
//   - nil error, scoped false: every socket under the attach point is this
//     job's (a runner VM, or a private cgroup namespace), and the hook
//     judges them all.
//   - nil error, scoped true: the host cgroup namespace outside the host
//     pid namespace. The attach point is the root of the machine's cgroup
//     tree, which other pods share, while our pid namespace holds only this
//     job's processes (in a pod that shares one, the runner's, dockerd's
//     and those of every container dockerd starts). The hook must judge
//     only sockets in the cgroups those processes have entered; judging the
//     rest would judge other pods.
//   - an error: the hook must not load, and scoped is false.
//
// The error says why the hook would not judge exactly this job, or why that
// cannot be shown:
//
//   - /sys/fs/cgroup must be shown to be the tree our cgroup path is in
//     (CgroupMount). Otherwise the attach point is not what the namespace
//     says: the host's cgroupfs bound into a private cgroup namespace would
//     put the unscoped hook at the machine's root.
//   - In a Kubernetes pod in the host cgroup and pid namespaces (a
//     privileged hostPID pod), /sys/fs/cgroup is the node root and every
//     task on the node is ours to see: the hook would judge every pod and
//     node daemon, other tenants' jobs included.
//   - Limited to our pid namespace, beside a dockerd outside it, the
//     daemon's containers are outside it too, and the hook never judges
//     their traffic.
//   - Limited to our pid namespace on a kernel older than 5.15, or one whose
//     release cannot be read, a socket's cgroup is not a reliable sign of
//     whose it is (see socketCgroupRefusal).
//   - In a private cgroup namespace beside a dockerd that is not ours
//     (another container's, or the host's own, whether its pid is visible
//     or not), the daemon's containers may live outside our subtree, where
//     the hook never sees them.
//   - Wherever the daemon decides coverage, a DOCKER_HOST naming a daemon
//     other than the probed socket refuses: the job's containers belong to
//     that daemon, and nothing here identified it.
//   - An unidentified fact refuses where it decides who the hook judges:
//     the cgroup namespace, the cgroup path and the mount always; in the
//     host cgroup namespace, the pid namespace; and the daemon wherever its
//     containers could escape the hook (limited to our pid namespace, or in
//     a private cgroup namespace). Elsewhere an unknown cannot change that
//     and is not read: on a runner VM the hook judges the whole machine
//     whatever the daemon is, and in a private cgroup namespace the proven
//     cgroup subtree, not the pid namespace, bounds it. A kind added later
//     with no rule here is refused until it is given one.
//
// Three premises are accepted rather than proven. A process in the host
// cgroup and pid namespaces outside kubelet's tree is taken to be the
// machine's own firewall, as on a runner VM: nothing positively marks a
// machine single-tenant, and the kubepods refusal guards the multi-tenant
// shape cargowall is known to be deployed in. The daemon probe identifies
// whoever listens on the socket, so a proxy in our own container forwarding
// to a remote daemon reads as local, and it runs once, so a daemon that
// has not yet made its socket reads as absent; scoped, that daemon's
// containers are judged anyway when it shares our pid namespace, and missed
// when it does not. And scoped, a cgroup one of our tasks has entered is
// taken to hold only this pod's tasks, as a container runtime arranges by
// giving each container a cgroup of its own: a process outside our pid
// namespace in such a cgroup would be judged as ours. The scope never records a
// cgroup a task merely shares with a parent outside our pid namespace, so
// a process a runtime places in our namespace from its own cgroup, before
// moving it (runc exec), does not bring the runtime's cgroup in.
//
// Three limits are accepted rather than refused, and design.md describes
// them. Scoped, a socket in a cgroup none of our tasks has entered passes
// with only TC's verdict, so it gets no L7 check. Work in other pods
// (ARC's Kubernetes container mode) is outside this pod's pid namespace and
// interface, beyond every layer here, as it was before the scope. And
// DOCKER_HOST is read once, from cargowall's own environment, so a step
// that later points docker at another daemon is not seen: that daemon's
// containers are judged only where they fall inside the scope anyway (our
// pid namespace, or our cgroup subtree).
func (s Shape) HookScope() (scoped bool, err error) {
	switch s.CgroupNS {
	case CgroupNSUnknown:
		return false, fmt.Errorf("cgroup namespace unknown (%s)", s.CgroupNSReason)
	case CgroupNSHost:
		if err := s.attachPointRefusal(); err != nil {
			return false, err
		}
		switch s.PidNS {
		case PidNSUnknown:
			return false, fmt.Errorf("pid namespace unknown in the host cgroup namespace (%s)", s.PidNSReason)
		case PidNSHost:
			// kubelet's tree is kubepods under the cgroupfs driver and
			// <root>-kubepods.slice under the systemd driver with a cgroup
			// root of its own, so the name is matched anywhere in the path:
			// a false match only refuses.
			if strings.Contains(s.CgroupPath, "kubepods") {
				return false, errors.New("running in a Kubernetes pod in the host cgroup and pid namespaces: " +
					"the cgroup hook would attach at the node root and judge every pod on the node")
			}
			return false, nil
		case PidNSPrivate:
			if err := s.dockerHostRefusal(); err != nil {
				return false, err
			}
			if err := s.socketCgroupRefusal(); err != nil {
				return false, err
			}
			switch s.Dockerd.Kind {
			case DockerdAbsent, DockerdLocal, DockerdForeign:
				return true, nil
			case DockerdHidden:
				return false, fmt.Errorf("the cgroup hook judges only our pid namespace, and the docker daemon's "+
					"containers are outside it (%s)", s.Dockerd.Reason)
			case DockerdUnknown:
				return false, fmt.Errorf("the cgroup hook judges only our pid namespace, beside an unidentified dockerd (%s)",
					s.Dockerd.Reason)
			default:
				return false, fmt.Errorf("dockerd kind %d has no hook-scope rule", s.Dockerd.Kind)
			}
		default:
			return false, fmt.Errorf("pid namespace kind %d has no hook-scope rule", s.PidNS)
		}
	case CgroupNSPrivate:
		if err := s.attachPointRefusal(); err != nil {
			return false, err
		}
		if err := s.dockerHostRefusal(); err != nil {
			return false, err
		}
		switch s.Dockerd.Kind {
		case DockerdAbsent, DockerdLocal:
			return false, nil
		case DockerdForeign:
			return false, fmt.Errorf("the cgroup hook cannot reach containers of a dockerd outside this container, "+
				"another container's or the host's own (%s)", s.Dockerd.Reason)
		case DockerdHidden:
			return false, fmt.Errorf("the cgroup hook cannot reach containers of a dockerd we cannot see, "+
				"possibly the host's own (%s)", s.Dockerd.Reason)
		case DockerdUnknown:
			return false, fmt.Errorf("in a private cgroup namespace beside an unidentified dockerd (%s)", s.Dockerd.Reason)
		default:
			return false, fmt.Errorf("dockerd kind %d has no hook-scope rule", s.Dockerd.Kind)
		}
	default:
		return false, fmt.Errorf("cgroup namespace kind %d has no hook-scope rule", s.CgroupNS)
	}
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
		return fmt.Errorf("%s is not the cgroup tree this process is in (%s)", cgroupRoot, s.CgroupMountReason)
	case CgroupMountUnknown:
		return fmt.Errorf("cannot show %s is the cgroup tree this process is in (%s)", cgroupRoot, s.CgroupMountReason)
	default:
		return fmt.Errorf("cgroup mount kind %d has no hook-scope rule", s.CgroupMount)
	}
}

// dockerHostRefusal says why the job's daemon is not the one probed, or nil.
func (s Shape) dockerHostRefusal() error {
	if s.DockerHost != "" {
		return fmt.Errorf("DOCKER_HOST=%s names a docker daemon the probe did not reach, "+
			"whose containers the hook may not see", s.DockerHost)
	}
	return nil
}

// socketCgroupRefusal says why this kernel cannot be trusted to put this
// job's sockets in this job's cgroups, which is what the scoped hook judges
// by, or nil from 5.15 on. Up to 5.14 a v1 net_cls or net_prio hierarchy
// in use anywhere on the machine turns socket cgroups off, and every socket
// made after that reads as the root cgroup, which the scope never records.
func (s Shape) socketCgroupRefusal() error {
	var major, minor int
	if _, err := fmt.Sscanf(s.Kernel, "%d.%d", &major, &minor); err != nil {
		return fmt.Errorf("the cgroup hook judges only our pid namespace's cgroups, "+
			"and the kernel release %q is unreadable", s.Kernel)
	}
	if major < 5 || major == 5 && minor < 15 {
		return fmt.Errorf("the cgroup hook judges only our pid namespace's cgroups, which kernel %s "+
			"can stop tracking for sockets (5.15 or later is needed)", s.Kernel)
	}
	return nil
}

// LogArgs is every fact and probe error, as slog key-value pairs.
func (s Shape) LogArgs() []any {
	return []any{
		"cgroupns", s.CgroupNS.String(), "cgroupns_reason", s.CgroupNSReason,
		"cgroup", s.CgroupPath, "cgroup_reason", s.CgroupPathReason,
		"cgroup_mount", s.CgroupMount.String(), "cgroup_mount_reason", s.CgroupMountReason,
		"pidns", s.PidNS.String(), "pidns_reason", s.PidNSReason,
		"dockerd", s.Dockerd.Kind.String(), "dockerd_reason", s.Dockerd.Reason,
		"docker_host", s.DockerHost, "kernel", s.Kernel,
	}
}

// Detect probes the environment. A probe that fails records unknown and
// its error in the Shape rather than leaving a zero that reads as a
// result.
func Detect(dockerSocket string) Shape {
	var s Shape
	if ino, err := nsInode("/proc/self/ns/cgroup"); err != nil {
		s.CgroupNSReason = err.Error()
	} else if ino == initCgroupNamespace {
		s.CgroupNS = CgroupNSHost
	} else {
		s.CgroupNS = CgroupNSPrivate
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err != nil {
		s.CgroupPathReason = err.Error()
	} else if s.CgroupPath = parseCgroupV2Path(data); s.CgroupPath == "" {
		s.CgroupPathReason = "no cgroup v2 entry in /proc/self/cgroup"
	}
	if s.CgroupPath != "" {
		s.CgroupMount, s.CgroupMountReason = probeCgroupMount(cgroupRoot, s.CgroupPath, os.Getpid())
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
	s.DockerHost = dockerHostElsewhere(os.Getenv("DOCKER_HOST"), dockerSocket)
	var uts unix.Utsname
	if unix.Uname(&uts) == nil {
		s.Kernel = unix.ByteSliceToString(uts.Release[:])
	}
	return s
}

// probeCgroupMount reports whether root is the cgroup tree path is in,
// by looking for pid in that cgroup's member list. cgroup.procs lists pids
// as numbered in the reader's pid namespace, which is ours.
func probeCgroupMount(root, path string, pid int) (CgroupMount, string) {
	procs := filepath.Join(root, path, "cgroup.procs")
	data, err := os.ReadFile(procs)
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

// dockerHostElsewhere returns DOCKER_HOST when it names a daemon other than
// the one on socket, and "" when it is unset or names that socket. Two
// spellings of one socket are the same daemon: /var/run is a symlink to
// /run on most distributions.
func dockerHostElsewhere(dockerHost, socket string) string {
	if dockerHost == "" {
		return ""
	}
	p, ok := strings.CutPrefix(dockerHost, "unix://")
	if !ok {
		return dockerHost
	}
	if filepath.Clean(p) == filepath.Clean(socket) {
		return ""
	}
	if a, err := os.Stat(p); err == nil {
		if b, err := os.Stat(socket); err == nil && os.SameFile(a, b) {
			return ""
		}
	}
	return dockerHost
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
		// Only a missing socket is absent. One that refuses was made by a
		// daemon that is not listening: still starting, or gone and
		// perhaps coming back, which this one probe cannot tell apart.
		if errors.Is(err, os.ErrNotExist) {
			return Dockerd{Kind: DockerdAbsent}
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
		return Dockerd{Kind: DockerdForeign, Reason: fmt.Sprintf("pid %d has another mount namespace", pid)}
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
