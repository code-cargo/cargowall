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

//go:build ignore

// The pod scope of the cgroup egress hook. In a privileged pod the hook sits
// at the node's root cgroup and must judge only this job's sockets: those in
// the job's subtree (our pod's cgroup, or outside Kubernetes our own
// container's), which the hook checks itself and these programs leave
// alone, and those in the cgroups this job's tasks, the tasks of the
// daemon's pid namespace, have entered outside it, such as dind's containers at the node-root
// /docker/<id>. Every socket a job gives rise to lives in one, whether a
// thread of the job made it (an io_uring worker included), the kernel made
// it for the job (an MPTCP subflow takes its parent's cgroup, an SMC
// connection's TCP socket is made in the caller's context), or it predates
// cargowall. This collection records the entered cgroups in
// map_scope_cgroups, which pkg/origin loads into the origin collection in
// place of its stand-in, and forgets each when it is released. It is its
// own collection, loaded only in that shape, so a failure here costs the
// scope and nothing else.
//
// A cgroup is recorded once a task of ours enters it: moves there
// (scope_attach) or is created there by clone3's CLONE_INTO_CGROUP
// (scope_fork). It leaves the scope as soon as a task outside our pid
// namespace enters it the same way, such as a node service systemd
// restarts into the cgroup a job of ours was left in: it is no longer this
// job's alone. A cgroup a task of ours merely inherits is never recorded
// on that account. A container runtime that runs a process in a container
// (runc exec, kubectl exec) creates it in our pid namespace while it is
// still in the runtime's own cgroup, and only then moves it; recording that
// cgroup would judge every socket of containerd. Tasks that predate the
// tracepoints are listed by the startup walk (scope_task_iter), and
// pkg/origin records each cgroup it lists that no task outside our pid
// namespace is in. Membership is read from the task's own pid chain, and
// the root cgroup is never recorded (see scope_enter).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Inode of the daemon's pid namespace, written by userspace before load.
const volatile __u32 pidns_ino = 0;

// The cgroup whose whole subtree the hook judges (scope_subtree_cgroup in
// originbpf.c), written by userspace before load. Nothing in it is
// recorded or taken out: it is the job's whatever enters it.
const volatile __u64 subtree_cgroup = 0;

// cargowall's own process id in the daemon's pid namespace, written by
// userspace before load: the one process in the subtree that the walk
// lists (scope_task_iter).
const volatile __u32 self_tgid = 0;

#include "pidns.h"

#define ENOENT 2
#define E2BIG 7
#define EEXIST 17

// clone3's flag for creating the child in another cgroup (linux/sched.h).
#define CLONE_INTO_CGROUP 0x200000000ULL

// Cgroup v2 ids a task of ours has entered, and those the startup walk
// found only our tasks in. An entry lives until its cgroup is released
// (scope_release), which is after every socket made in it is gone, and a
// removed cgroup whose memory is still charged (page cache written to a
// volume, say) is not released until that memory is reclaimed. So the map
// is large and allocated as it fills. A hash, not an LRU: nothing is ever
// evicted, and a cgroup that finds the map full is counted
// (SCOPE_STAT_FULL) instead of displacing another.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_scope_cgroups SEC(".maps");

// What the scope could not record, for pkg/origin to report: each counts
// entries, so a cgroup entered twice that could not be recorded counts
// twice. Mirrored by Go constants and pinned by test.
#define SCOPE_STAT_FULL 0    // map_scope_cgroups was full
#define SCOPE_STAT_ROOT 1    // a task of ours entered the root cgroup
#define SCOPE_STAT_FAILED 2  // any other update or delete failure, such as a busy bucket
#define SCOPE_STAT_SHARED 3  // a task outside our pid namespace entered a recorded cgroup
#define SCOPE_STATS_MAX 4

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, SCOPE_STATS_MAX);
} map_scope_stats SEC(".maps");

static __always_inline void scope_count(__u32 slot)
{
    __u64 *n = bpf_map_lookup_elem(&map_scope_stats, &slot);
    if (n)
        __sync_fetch_and_add(n, 1);
}

static __always_inline struct cgroup *dfl_cgroup(struct task_struct *t)
{
    return BPF_CORE_READ(t, cgroups, dfl_cgrp);
}

// scope_id is cg's id for the scope, or 0 for none. The root cgroup holds
// the kernel's own sockets and the node's, never a pod's alone, so it is
// never in scope; a task of ours there (one that moved itself, which takes
// privilege) has sockets that are never judged, and the callers count it.
static __always_inline __u64 scope_id(struct cgroup *cg)
{
    if (!cg || BPF_CORE_READ(cg, level) == 0)
        return 0;
    return BPF_CORE_READ(cg, kn, id);
}

// How many of a cgroup's ancestors in_subtree looks at.
#define SUBTREE_MAX_DEPTH 32

// in_subtree reports whether cg is the job's subtree cgroup or below it,
// by its own and its parents' ids: a cgroup's self is its first member, so
// a parent css is the parent cgroup. By id, not by level: in a cgroup
// namespace rooted below the machine's (a nested node's) userspace sees a
// path, not a level. A cgroup more than SUBTREE_MAX_DEPTH below it reads as
// outside it, which only records a cgroup the hook judges anyway, and lists
// it in the walk, where pkg/origin matches by path, with no bound.
static __always_inline bool in_subtree(struct cgroup *cg)
{
    if (!subtree_cgroup)
        return false;
    for (int i = 0; i < SUBTREE_MAX_DEPTH && cg; i++) {
        if (BPF_CORE_READ(cg, kn, id) == subtree_cgroup)
            return true;
        cg = (struct cgroup *)BPF_CORE_READ(cg, self.parent);
    }
    return false;
}

// scope_enter records cg, which a task of ours has entered. The lookup
// first keeps an existing cgroup from costing a write.
static __always_inline void scope_enter(struct cgroup *cg)
{
    __u64 id = scope_id(cg);
    if (!id) {
        if (cg)
            scope_count(SCOPE_STAT_ROOT);
        return;
    }
    if (in_subtree(cg))
        return;
    if (bpf_map_lookup_elem(&map_scope_cgroups, &id))
        return;
    __u8 one = 1;
    long err = bpf_map_update_elem(&map_scope_cgroups, &id, &one, BPF_NOEXIST);
    if (err == -E2BIG)
        scope_count(SCOPE_STAT_FULL);
    else if (err && err != -EEXIST)
        scope_count(SCOPE_STAT_FAILED);
}

// scope_leave takes cg out of the scope, if it is in it, when a task
// outside our pid namespace enters it: judging the cgroup would judge that
// task. The job's own tasks there now pass, so it is counted, and so is a
// delete that fails other than to a concurrent one, which leaves the
// cgroup judged until pkg/origin's next walk.
static __always_inline void scope_leave(struct cgroup *cg)
{
    __u64 id = scope_id(cg);
    if (!id || !bpf_map_lookup_elem(&map_scope_cgroups, &id))
        return;
    long err = bpf_map_delete_elem(&map_scope_cgroups, &id);
    if (!err)
        scope_count(SCOPE_STAT_SHARED);
    else if (err != -ENOENT)
        scope_count(SCOPE_STAT_FAILED);
}

// A task created by clone3 in the cgroup CLONE_INTO_CGROUP named, before
// it runs: a task of ours enters it, any other leaves it out of the scope.
// The flag, not a comparison with the parent's cgroup: this fires
// once the fork has let go of the lock that keeps its parent from moving,
// so a parent moved in that instant would make an inherited cgroup look
// entered. Every other fork returns after one test.
SEC("tp_btf/task_newtask")
int BPF_PROG(scope_fork, struct task_struct *task, __u64 clone_flags)
{
    if (!(clone_flags & CLONE_INTO_CGROUP))
        return 0;
    if (ns_tgid_of(task))
        scope_enter(dfl_cgroup(task));
    else
        scope_leave(dfl_cgroup(task));
    return 0;
}

// A task moving into dst, such as runc placing a container's first process,
// or systemd starting a unit's: a task of ours enters it, any other leaves
// it out of the scope. Fires just after the move, once per migration, for the thread-group
// leader when a whole group moves, and for every hierarchy, of which only
// the default one decides socket cgroups. dst, not the leader's own cgroup:
// a leader that has exited stays where it was while its live threads move.
SEC("tp_btf/cgroup_attach_task")
int BPF_PROG(scope_attach, struct cgroup *dst, const char *path,
             struct task_struct *task, bool threadgroup)
{
    if (BPF_CORE_READ(dst, root, hierarchy_id) != 0)
        return 0;
    if (ns_tgid_of(task))
        scope_enter(dst);
    else
        scope_leave(dst);
    return 0;
}

// A cgroup being freed: its last task and its last socket are gone, so
// no packet can carry its id again, and cgroup ids are never reused. Fires
// for every hierarchy, and v1 ids can repeat v2 ones, so only the default
// hierarchy's are ours to delete.
SEC("tp_btf/cgroup_release")
int BPF_PROG(scope_release, struct cgroup *cg, const char *path)
{
    if (BPF_CORE_READ(cg, root, hierarchy_id) != 0)
        return 0;
    __u64 id = BPF_CORE_READ(cg, kn, id);
    bpf_map_delete_elem(&map_scope_cgroups, &id);
    return 0;
}

// The startup walk, run by pkg/origin after the tracepoints attach and
// before the hook does, for tasks that entered their cgroup before
// cargowall started. It records nothing, because a task's cgroup does not
// say whether it entered it: a job left running by a shell someone
// nsenter'd into our pid namespace from a node daemon's cgroup is still in
// that cgroup, adopted by our namespace's init. It writes each task of
// ours to the iterator's output instead, as its cgroup's id, its process
// id in our namespace and its cgroup's level, three u64s, and pkg/origin
// records each cgroup that no task outside our pid namespace is in. The
// level is the kernel's, which userspace cannot read from a path in a
// cgroup namespace rooted below the machine's; level 0 is the root, which
// pkg/origin reports rather than records. pkg/origin runs the walk at
// startup and again on every report tick, so it counts nothing here, and
// writes only what it acts on: a thread in its process's cgroup adds
// nothing to the process's own record, and a task in the subtree nothing
// at all, except cargowall itself, whose record gives pkg/origin the
// subtree's level. The kernel scopes the walk to the opener's pid
// namespace.
SEC("iter/task")
int scope_task_iter(struct bpf_iter__task *ctx)
{
    struct task_struct *t = ctx->task;
    if (!t)
        return 0;
    __u32 tgid = ns_tgid_of(t);
    if (!tgid)
        return 0;
    struct cgroup *cg = dfl_cgroup(t);
    if (!cg)
        return 0;
    __u64 id = BPF_CORE_READ(cg, kn, id);
    // The leader, even one that has exited, stays in its cgroup until its
    // process is reaped, and the walk writes its record there.
    struct task_struct *leader = BPF_CORE_READ(t, group_leader);
    if (leader && leader != t) {
        struct cgroup *lcg = dfl_cgroup(leader);
        if (lcg && BPF_CORE_READ(lcg, kn, id) == id)
            return 0;
    }
    if (tgid != self_tgid && in_subtree(cg))
        return 0;
    __u64 rec[3] = {id, tgid, BPF_CORE_READ(cg, level)};
    bpf_seq_write(ctx->meta->seq, rec, sizeof(rec));
    return 0;
}

char _license[] SEC("license") = "GPL";
