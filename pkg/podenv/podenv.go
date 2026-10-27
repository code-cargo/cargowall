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
// in: whose cgroup tree its root-cgroup hooks land on, and whether the
// Docker daemon on the socket is one it can reconfigure. A runner VM, a
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

// initCgroupNamespace is the inode of the initial cgroup namespace, a fixed
// kernel constant (PROC_CGROUP_INIT_INO).
const initCgroupNamespace = 0xEFFFFFFB

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

// DockerdKind is what is behind the Docker socket.
type DockerdKind int

const (
	DockerdUnknown DockerdKind = iota // the probe failed
	DockerdAbsent                     // no socket, or nothing listening on it
	// DockerdLocal: the daemon shares our mount namespace, so its
	// daemon.json is ours and our service manager can restart it.
	DockerdLocal
	// DockerdForeign: the daemon runs in another container (its pid is
	// outside our pid namespace, or it has another mount namespace).
	DockerdForeign
)

func (k DockerdKind) String() string {
	switch k {
	case DockerdAbsent:
		return "absent"
	case DockerdLocal:
		return "local"
	case DockerdForeign:
		return "foreign"
	}
	return "unknown"
}

// Dockerd describes the daemon behind the Docker socket.
type Dockerd struct {
	Kind DockerdKind
	// Reason is the evidence for Foreign, or the probe error for Unknown.
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
	Dockerd    Dockerd
}

// HookScope is nil when a cgroup program attached at /sys/fs/cgroup would
// judge exactly this job's traffic, and otherwise says why it would not or
// why that cannot be shown:
//
//   - In a Kubernetes pod in the host cgroup namespace (a privileged pod
//     container), /sys/fs/cgroup is the node root: the hook would judge
//     every pod and node daemon, other tenants' jobs included.
//   - In a private cgroup namespace beside a foreign or unidentified
//     dockerd, the daemon's containers may live outside our subtree, where
//     the hook never sees them.
//   - A cgroup namespace or path that could not be read proves neither.
func (s Shape) HookScope() error {
	switch s.CgroupNS {
	case CgroupNSUnknown:
		return fmt.Errorf("cgroup namespace unknown (%s)", s.CgroupNSReason)
	case CgroupNSHost:
		if s.CgroupPath == "" {
			return errors.New("cgroup path unknown in the host cgroup namespace")
		}
		// kubelet names its tree kubepods under both the cgroupfs and
		// systemd drivers.
		if strings.Contains(s.CgroupPath, "/kubepods") {
			return errors.New("running in a Kubernetes pod in the host cgroup namespace: " +
				"the cgroup hook would attach at the node root and judge every pod on the node")
		}
	case CgroupNSPrivate:
		switch s.Dockerd.Kind {
		case DockerdForeign:
			return fmt.Errorf("the cgroup hook cannot reach containers of a dockerd in another container (%s)",
				s.Dockerd.Reason)
		case DockerdUnknown:
			return fmt.Errorf("in a private cgroup namespace beside an unidentified dockerd (%s)", s.Dockerd.Reason)
		}
	}
	return nil
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
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		s.CgroupPath = parseCgroupV2Path(data)
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
		return Dockerd{Kind: DockerdForeign, Reason: "its pid is outside our pid namespace"}
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
