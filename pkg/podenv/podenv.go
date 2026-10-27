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

// Shape is what Detect found. Zero values are the unprobed answers: a
// failed probe never claims a problem it could not see.
type Shape struct {
	// HostCgroupNS: our cgroup namespace is the initial one, so
	// /sys/fs/cgroup, where every cgroup program attaches, is the root of
	// the whole machine's tree rather than our own container's.
	HostCgroupNS bool
	// CgroupPath is our cgroup v2 path as /proc/self/cgroup reports it:
	// absolute in the host namespace, relative to our own root otherwise.
	CgroupPath string
	// Dockerd describes the daemon on the Docker socket.
	Dockerd Dockerd
}

// Dockerd describes the daemon behind the Docker socket.
type Dockerd struct {
	// Foreign: the daemon runs in another container (its pid is outside
	// our pid namespace, or it has another mount namespace), so its
	// daemon.json is not our /etc/docker/daemon.json and no service
	// manager here can restart it.
	Foreign bool
	// Reason is the evidence for Foreign, for the log line.
	Reason string
}

// InKubernetesPod reports whether our cgroup is one kubelet created. Only
// meaningful in the host cgroup namespace, where the path is absolute;
// kubelet names its tree kubepods under both the cgroupfs and systemd
// drivers.
func (s Shape) InKubernetesPod() bool {
	return strings.Contains(s.CgroupPath, "/kubepods")
}

// HookScopeProblem says why a cgroup program attached at /sys/fs/cgroup
// would not judge exactly this job's traffic, or "" when it would:
//
//   - In a Kubernetes pod with the host cgroup namespace (a privileged
//     pod container), /sys/fs/cgroup is the node root: the hook would
//     judge every pod and node daemon, other tenants' jobs included.
//   - In a private cgroup namespace beside a foreign dockerd, the
//     daemon's containers live outside our subtree and the hook never
//     sees them.
func (s Shape) HookScopeProblem() string {
	switch {
	case s.HostCgroupNS && s.InKubernetesPod():
		return "running in a Kubernetes pod in the host cgroup namespace: the cgroup hook would attach at the node root and judge every pod on the node"
	case !s.HostCgroupNS && s.Dockerd.Foreign:
		return "the cgroup hook cannot reach containers of a dockerd in another container (" + s.Dockerd.Reason + ")"
	}
	return ""
}

// Detect probes the environment. Each probe that fails leaves its field at
// the zero value and returns its error joined with the others, for a debug
// log; a Shape is always returned.
func Detect(dockerSocket string) (Shape, error) {
	var s Shape
	var errs []error
	if ino, err := nsInode("/proc/self/ns/cgroup"); err != nil {
		errs = append(errs, err)
	} else {
		s.HostCgroupNS = ino == initCgroupNamespace
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err != nil {
		errs = append(errs, err)
	} else {
		s.CgroupPath = parseCgroupV2Path(data)
	}
	if d, err := probeDockerd(dockerSocket); err != nil {
		errs = append(errs, err)
	} else {
		s.Dockerd = d
	}
	return s, errors.Join(errs...)
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
// host. No socket is not an error: there is no daemon to configure.
func probeDockerd(socket string) (Dockerd, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ECONNREFUSED) {
			return Dockerd{}, nil
		}
		return Dockerd{}, fmt.Errorf("dial %s: %w", socket, err)
	}
	defer conn.Close()
	pid, err := peerPid(conn.(*net.UnixConn))
	if err != nil {
		return Dockerd{}, err
	}
	if pid == 0 {
		return Dockerd{Foreign: true, Reason: "its pid is outside our pid namespace"}, nil
	}
	ours, err := nsInode("/proc/self/ns/mnt")
	if err != nil {
		return Dockerd{}, err
	}
	theirs, err := nsInode("/proc/" + strconv.Itoa(int(pid)) + "/ns/mnt")
	if err != nil {
		return Dockerd{}, err
	}
	if ours != theirs {
		return Dockerd{Foreign: true, Reason: fmt.Sprintf("pid %d has another mount namespace", pid)}, nil
	}
	return Dockerd{}, nil
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
