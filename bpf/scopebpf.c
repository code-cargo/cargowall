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
// at the node's root cgroup and must judge only this job's sockets. Those
// are the sockets in the cgroups this job's tasks, the tasks of the daemon's
// pid namespace, have entered: every socket a job gives rise to lives in
// one, whether a thread of the job made it (an io_uring worker included),
// the kernel made it for the job (an MPTCP subflow takes its parent's
// cgroup, an SMC connection's TCP socket is made in the caller's context),
// or it predates cargowall. This collection records those cgroups in
// map_scope_cgroups, which pkg/origin loads into the origin collection in
// place of its stand-in. It is its own collection, loaded only in that
// shape, so a failure here costs the scope and nothing else.
//
// A cgroup is in scope once a task of ours enters it: moves there
// (scope_attach), is created there by clone3's CLONE_INTO_CGROUP
// (scope_fork), or is found at startup in a cgroup its parent is not in
// (scope_task_iter). A cgroup a task of ours merely shares with its parent
// is never recorded on that account. A container runtime that runs a
// process in a container (runc exec, kubectl exec) creates it in our pid
// namespace while it is still in the runtime's own cgroup, and only then
// moves it; recording that cgroup would judge every socket of containerd.
// Membership is read from the task's own pid chain, and the root cgroup is
// never recorded (see scope_enter).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Inode of the daemon's pid namespace, written by userspace before load.
const volatile __u32 pidns_ino = 0;

#include "pidns.h"

#define EEXIST 17

// Cgroup v2 ids a task of ours has entered. Cgroup ids are never reused, so
// an entry that outlives its cgroup is harmless and nothing deletes one. A
// hash, not an LRU: nothing is ever evicted, and a cgroup that finds the
// map full is counted (SCOPE_STAT_FULL) instead of displacing another.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 8192);
} map_scope_cgroups SEC(".maps");

// What the scope could not record, for pkg/origin to report. Mirrored by
// Go constants and pinned by test.
#define SCOPE_STAT_FULL 0  // a cgroup we entered found map_scope_cgroups full
#define SCOPE_STAT_ROOT 1  // a task of ours entered the root cgroup
#define SCOPE_STATS_MAX 2

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

// scope_enter records cg, which a task of ours has entered. The root cgroup
// holds the kernel's own sockets and the node's, never a pod's alone, so it
// is counted rather than recorded: a task of ours there (one that moved
// itself, which takes privilege) has sockets the hook never judges. The
// lookup first keeps an existing cgroup from costing a write.
static __always_inline void scope_enter(struct cgroup *cg)
{
    if (!cg)
        return;
    if (BPF_CORE_READ(cg, level) == 0) {
        scope_count(SCOPE_STAT_ROOT);
        return;
    }
    __u64 id = BPF_CORE_READ(cg, kn, id);
    if (bpf_map_lookup_elem(&map_scope_cgroups, &id))
        return;
    __u8 one = 1;
    long err = bpf_map_update_elem(&map_scope_cgroups, &id, &one, BPF_NOEXIST);
    if (err && err != -EEXIST)
        scope_count(SCOPE_STAT_FULL);
}

// A task created in a cgroup other than its parent's, which only clone3's
// CLONE_INTO_CGROUP does, before the task runs. Every other fork inherits
// its parent's cgroup and returns after two reads.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(scope_fork, struct task_struct *parent, struct task_struct *child)
{
    struct cgroup *cg = dfl_cgroup(child);
    if (cg == dfl_cgroup(parent) || !ns_tgid_of(child))
        return 0;
    scope_enter(cg);
    return 0;
}

// A task moving into dst, such as runc placing a container's first process.
// Fires just after the move, once per migration, for the thread-group
// leader when a whole group moves, and for every hierarchy, of which only
// the default one decides socket cgroups. dst, not the leader's own cgroup:
// a leader that has exited stays where it was while its live threads move.
SEC("tp_btf/cgroup_attach_task")
int BPF_PROG(scope_attach, struct cgroup *dst, const char *path,
             struct task_struct *task, bool threadgroup)
{
    if (BPF_CORE_READ(dst, root, hierarchy_id) != 0 || !ns_tgid_of(task))
        return 0;
    scope_enter(dst);
    return 0;
}

// The startup walk, run by pkg/origin after the tracepoints attach and
// before the hook does, for tasks that entered their cgroup before
// cargowall started. A task in a cgroup its parent is not in entered it;
// one in its parent's inherited it, and is covered by whichever ancestor
// entered it, or by none when that ancestor is outside our pid namespace.
// The kernel scopes the walk to the opener's pid namespace. It writes no
// output.
SEC("iter/task")
int scope_task_iter(struct bpf_iter__task *ctx)
{
    struct task_struct *t = ctx->task;
    if (!t)
        return 0;
    struct cgroup *cg = dfl_cgroup(t);
    if (cg == dfl_cgroup(BPF_CORE_READ(t, real_parent)) || !ns_tgid_of(t))
        return 0;
    scope_enter(cg);
    return 0;
}

char _license[] SEC("license") = "GPL";
