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
// can reconfigure. A runner VM, a
// Kubernetes pod with a Docker-in-Docker sidecar and a SaaS sidecar all
// look alike from the flags; these facts are what tell them apart.
//
// Every fact has an explicit unknown state. A probe that fails says so,
// and no caller may read unknown as the permissive answer: an unknown
// cgroup namespace keeps the cgroup egress hook out, and an unknown daemon
// keeps its config untouched.
package podenv

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Inodes of the initial cgroup and pid namespaces, fixed kernel constants
// (PROC_CGROUP_INIT_INO, PROC_PID_INIT_INO).
const (
	initCgroupNamespace = 0xEFFFFFFB
	initPidNamespace    = 0xEFFFFFFC
)

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
	DockerdAbsent                     // no socket, or nothing listening on it
	// DockerdLocal: the daemon shares our mount namespace, so its
	// daemon.json is ours and our service manager can restart it.
	DockerdLocal
	// DockerdForeign: the daemon runs in another container that shares our
	// pid namespace: its pid is visible, its mount namespace is not ours.
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
	PidNS            PidNS
	// PidNSReason is the probe error when PidNS is unknown.
	PidNSReason string
	Dockerd     Dockerd
}

// HookScope decides whether a cgroup program attached at /sys/fs/cgroup can
// judge exactly this job's traffic, and how. Loading the hook and stamping
// sockets are one decision, so both answers come from here, and every leaf
// of the table below returns its own:
//
//   - nil error, stamped false: every socket under the attach point is this
//     job's (a runner VM, or a private cgroup namespace), and the hook
//     judges them all.
//   - nil error, stamped true: the host cgroup namespace outside the host
//     pid namespace. The attach point is the root of the machine's cgroup
//     tree, which other containers share, while our pid namespace holds
//     only this job's processes (in a pod that shares one, the runner's,
//     dockerd's and those of every container dockerd starts). The hook must
//     judge only the sockets stamped as created there; without the stamps
//     it would judge other pods.
//   - an error: the hook must not load, and stamped is false.
//
// The error says why the hook would not judge exactly this job, or why that
// cannot be shown:
//
//   - In a Kubernetes pod in the host cgroup and pid namespaces (a
//     privileged hostPID pod), /sys/fs/cgroup is the node root and every
//     task on the node is ours to see: the hook would judge every pod and
//     node daemon, other tenants' jobs included.
//   - Limited to our pid namespace, beside a dockerd outside it, the
//     daemon's containers are outside it too, and the hook never judges
//     their traffic.
//   - In a private cgroup namespace beside a dockerd in another container,
//     the daemon's containers may live outside our subtree, where the hook
//     never sees them.
//   - A namespace, cgroup path or daemon that could not be identified
//     proves none of this, and a kind added later with no rule here is
//     refused until it is given one.
//
// Two limits of the scoped hook are accepted rather than refused, and
// design.md describes both. Our own sockets that missed a stamp pass with
// only TC's verdict, so they get no L7 check. Work in other pods (ARC's
// Kubernetes container mode) is outside this pod's pid namespace and
// interface, beyond every layer here, as it was before the scope.
func (s Shape) HookScope() (stamped bool, err error) {
	switch s.CgroupNS {
	case CgroupNSUnknown:
		return false, fmt.Errorf("cgroup namespace unknown (%s)", s.CgroupNSReason)
	case CgroupNSHost:
		if s.CgroupPath == "" {
			return false, fmt.Errorf("cgroup path unknown in the host cgroup namespace (%s)", s.CgroupPathReason)
		}
		switch s.PidNS {
		case PidNSUnknown:
			return false, fmt.Errorf("pid namespace unknown in the host cgroup namespace (%s)", s.PidNSReason)
		case PidNSHost:
			// kubelet names its tree kubepods under both the cgroupfs and
			// systemd drivers.
			if strings.Contains(s.CgroupPath, "/kubepods") {
				return false, errors.New("running in a Kubernetes pod in the host cgroup and pid namespaces: " +
					"the cgroup hook would attach at the node root and judge every pod on the node")
			}
			return false, nil
		case PidNSPrivate:
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
		switch s.Dockerd.Kind {
		case DockerdAbsent, DockerdLocal:
			return false, nil
		case DockerdForeign, DockerdHidden:
			return false, fmt.Errorf("the cgroup hook cannot reach containers of a dockerd in another container (%s)",
				s.Dockerd.Reason)
		case DockerdUnknown:
			return false, fmt.Errorf("in a private cgroup namespace beside an unidentified dockerd (%s)", s.Dockerd.Reason)
		default:
			return false, fmt.Errorf("dockerd kind %d has no hook-scope rule", s.Dockerd.Kind)
		}
	default:
		return false, fmt.Errorf("cgroup namespace kind %d has no hook-scope rule", s.CgroupNS)
	}
}

// LogArgs is every fact and probe error, as slog key-value pairs.
func (s Shape) LogArgs() []any {
	return []any{
		"cgroupns", s.CgroupNS.String(), "cgroupns_reason", s.CgroupNSReason,
		"cgroup", s.CgroupPath, "cgroup_reason", s.CgroupPathReason,
		"pidns", s.PidNS.String(), "pidns_reason", s.PidNSReason,
		"dockerd", s.Dockerd.Kind.String(), "dockerd_reason", s.Dockerd.Reason,
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
	if ino, err := nsInode("/proc/self/ns/pid"); err != nil {
		s.PidNSReason = err.Error()
	} else if ino == initPidNamespace {
		s.PidNS = PidNSHost
	} else {
		s.PidNS = PidNSPrivate
	}
	s.Dockerd = probeDockerd(dockerSocket)
	return s
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
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ECONNREFUSED) {
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
