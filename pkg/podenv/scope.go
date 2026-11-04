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

// Whether a cgroup program attached at /sys/fs/cgroup judges exactly this
// job's traffic, and how: the hook's scope.

import (
	"errors"
	"fmt"
	"strings"
)

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

// HookScopeOrPending decides whether a cgroup program attached at
// /sys/fs/cgroup can judge exactly this job's traffic, and how: loading the
// hook and scoping it are one decision. A nil error with the zero Scope judges every socket
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
//
// Where the scope reads a daemon that has not answered (daemonPending),
// whose containers are still to come, it returns the scope every other rule
// gives, and pending: the daemon's rules are for the caller to decide again
// once it answers (Recheck). Every other rule decides as it would with the
// daemon answering, and its refusal is final. The scope given
// with a daemon pending never reaches a task outside our pid namespace that
// the daemon's rules would keep it from (privateScope), so a refusal once
// the daemon answers only leaves its containers unjudged.
func (s Shape) HookScopeOrPending() (scope Scope, pending bool, err error) {
	return s.hookScope(true)
}

// hookScope is HookScopeOrPending, deferring a daemon still to come up only
// when deferDaemon: otherwise it is judged as it stands, and refuses.
func (s Shape) hookScope(deferDaemon bool) (Scope, bool, error) {
	switch s.CgroupNS {
	case CgroupNSUnknown:
		return Scope{}, false, fmt.Errorf("cgroup namespace unknown (%s)", s.CgroupNSReason)
	case CgroupNSHost, CgroupNSPrivate:
	default:
		return Scope{}, false, fmt.Errorf("cgroup namespace kind %d has no hook-scope rule", s.CgroupNS)
	}
	if err := s.attachPointRefusal(); err != nil {
		return Scope{}, false, err
	}
	if s.CgroupNS == CgroupNSPrivate {
		return s.privateScope(deferDaemon)
	}
	// /sys/fs/cgroup is the machine's root, which every pod and daemon on
	// it shares.
	pod := s.inPod()
	if scope, done, err := s.sharedPidNS(pod, "the host cgroup namespace", "the host"); done {
		return scope, false, err // the host pid namespace outside a pod is machineFirewall
	}
	if err := s.partialRefusal(); err != nil {
		return Scope{}, false, err
	}
	scope, err := s.limitedScope(pod)
	if err != nil {
		return Scope{}, false, err
	}
	// Under the machine's root every daemon's containers reach the hook,
	// and those of one whose runtime is in our pid namespace are recorded
	// as they start.
	if deferDaemon && s.daemonPending() {
		return scope, true, nil
	}
	if err := s.daemonRefusal(false); err != nil {
		return Scope{}, false, err
	}
	return scope, false, nil
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
// container's namespace. A daemon deferred (deferDaemon, daemonPending)
// leaves every other rule to decide, and pending.
func (s Shape) privateScope(deferDaemon bool) (Scope, bool, error) {
	if err := s.partialRefusal(); err != nil {
		return Scope{}, false, err
	}
	pending := deferDaemon && s.daemonPending()
	if !pending {
		if err := s.daemonRefusal(true); err != nil {
			return Scope{}, false, err
		}
	}
	if s.CgroupPath == "/" {
		return Scope{}, pending, nil
	}
	pod := s.inPod()
	if scope, done, err := s.sharedPidNS(pod, "a cgroup namespace rooted above our cgroup", "the node's"); done {
		return scope, pending && err == nil, err
	}
	// A tree with no task outside our pid namespace anywhere in it is our
	// container's alone, below whose root it moved its own tasks (an
	// entrypoint making room for nested cgroups, or systemd as its init),
	// and the hook judges all of it, as at "/". A nested node always has
	// some: its kubelet and runtime are outside every pod's pid namespace.
	// That is read once, before a daemon still to come up has made any
	// container, and one whose runtime turns out outside our pid namespace
	// would make them in this tree with tasks outside it, which the whole
	// tree's hook would judge: with the daemon pending the scope is limited
	// as below, where such a daemon's containers are never recorded and
	// only go unjudged.
	if !pod && s.KubeletHostsReason == "" && s.CgroupTree == CgroupTreeOurs && !pending {
		return Scope{}, false, nil
	}
	scope, err := s.limitedScope(pod)
	if err != nil {
		return Scope{}, false, err
	}
	return scope, pending, nil
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
// id, through at most 31 parents, and past that records a cgroup the hook
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

// inPod reports whether we are shown to be in a Kubernetes pod: our cgroup
// is in kubelet's tree (kubepods), or /etc/hosts is kubelet's, the one sign
// a kubelet that makes no pod cgroups (cgroupsPerQOS=false) leaves. A pod
// is judged whole, by its cgroup, which outside kubelet's tree no path
// shows, so the hosts file alone only refuses. In the host pid namespace
// only a sign counts, as nothing else marks a machine single-tenant;
// where the hook would be scoped, a hosts file that could not be read
// refuses too (limitedScope).
func (s Shape) inPod() bool {
	return s.kubepods() || s.KubeletHosts
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
// job's subtree: the pod's cgroup in a pod, our own cgroup outside one,
// which must hold only our pid namespace's tasks: a container's does, but
// a pid namespace of our own made in a systemd service or a session (unshare
// -pf) is beside every other task there, which the subtree would judge.
func (s Shape) limitedScope(pod bool) (Scope, error) {
	if !pod && s.KubeletHostsReason != "" {
		return Scope{}, fmt.Errorf("whether this is a Kubernetes pod, whose other containers the cgroup hook "+
			"would have to judge too, is unknown: /etc/hosts could not be read (%s)", s.KubeletHostsReason)
	}
	sub := s.CgroupPath
	if pod {
		if sub = podCgroup(s.CgroupPath); sub == "" {
			return Scope{}, fmt.Errorf("in a Kubernetes pod whose cgroup %s is in no pod cgroup of kubelet's "+
				"(kubelet's /etc/hosts: %v): the cgroup hook would not judge the pod's other containers",
				s.CgroupPath, s.KubeletHosts)
		}
	} else if CgroupLevel(s.CgroupPath) == 0 {
		return Scope{}, errors.New("in the root cgroup outside the host pid namespace: no cgroup of this job's own " +
			"holds its tasks, and the root holds every task on the machine")
	} else if s.OwnTree != CgroupTreeOurs {
		return Scope{}, fmt.Errorf("outside a pod the cgroup hook would judge our cgroup %s whole, whoever enters it, "+
			"and it cannot be shown to hold only our pid namespace's tasks (%s: %s)", s.CgroupPath, s.OwnTree, s.OwnTreeReason)
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

// readsRuntime reports whether the scope reads the daemon's runtime: where
// the hook may load (egressHook) below the machine's root, in a private
// cgroup namespace, or scoped, outside the host pid namespace in the
// host's, and past the refusals that come first there and need nothing of
// the daemon's: an attach point not shown to be our tree, a docker CLI set
// to use another daemon, a kernel that can lose sockets' cgroups. Detect
// looks for the daemon's server, runtime and containers' tree only then.
func (s Shape) readsRuntime(egressHook bool) bool {
	return egressHook && (s.CgroupNS == CgroupNSPrivate || s.CgroupNS == CgroupNSHost && s.PidNS == PidNSPrivate) &&
		s.attachPointRefusal() == nil && s.partialRefusal() == nil
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
