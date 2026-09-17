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

// Step-attribution programs that require kernel BTF (tp_btf tracepoints,
// the cgroup/sock_create hook and the task iterator). Kept in a separate
// collection from tcbpf.c so a kernel without BTF degrades attribution
// only — the firewall proper loads and enforces unaffected. The shared maps
// below are declared with identical shapes in tcbpf.c, which owns them;
// this collection is loaded with MapReplacements pointing at the tcbpf map
// fds.
//
// Pid numbering. Everything the kernel compares or keys on in this file is
// a global (init-namespace) id: that is what the tracepoint arguments and
// bpf_get_current_pid_tgid() hand out. Userspace, however, only ever sees
// pids as numbered in the daemon's own pid namespace, and the two differ
// whenever cargowall runs inside a container (ARC runners are Kubernetes
// pods). map_task_nspid is the bridge — global tid → daemon-namespace
// tgid — seeded for pre-existing tasks by step_task_iter and kept current
// by step_fork/step_exit. It is what lets the reconciler read
// /proc/<tgid>/cmdline for a boundary event, lets userspace resolve the
// process behind a socket, and lets pkg/steps translate the /proc-numbered
// pids it discovers into the global ids the kernel needs.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Inode of the daemon's pid namespace (stat /proc/self/ns/pid), written by
// userspace before load. Picks the entry of a task's upid chain that is
// "the" pid userspace can act on. Zero disables translation outright
// rather than matching garbage.
const volatile __u32 pidns_ino = 0;

// ---- Shared with tcbpf.c (replaced at load time; shapes must match) ----

struct step_state {
    __u32 worker_tgid;   // Runner.Worker global tgid (0 = not discovered)
    __u32 enabled;       // 0 = feature off, all step hooks no-op
    __u64 next_ordinal;  // next step ordinal, atomically incremented
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct step_state);
    __uint(max_entries, 1);
} map_step_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 32768);
} map_task_step SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 65536);
} map_sock_step SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 32768);
} map_task_nspid SEC(".maps");

// ---- Owned by this collection ----

// New-step notifications for the userspace reconciler: emitted once per new
// direct child process of Runner.Worker, before the child runs user code.
// tgid is the child's pid as numbered in the daemon's namespace, so the
// reconciler can read its /proc entry directly (0 if untranslatable).
struct step_child_event {
    __u32 tgid;
    __u32 ordinal;
};

// BTF anchor — see the blocked_event anchor in tcbpf.c for rationale.
const struct step_child_event *btf_anchor_step_child_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} map_step_events SEC(".maps");

// One record per task in the daemon's pid-namespace subtree, streamed by
// step_task_iter. tid/tgid/ppid are global; ns_tgid is the process id
// userspace sees. pkg/steps builds its process-tree views from these
// instead of scanning /proc, which cannot reveal global ids from inside a
// namespace.
struct task_iter_rec {
    __u32 tid;
    __u32 tgid;
    __u32 ppid;
    __u32 ns_tgid;
};

const struct task_iter_rec *btf_anchor_task_iter_rec __attribute__((unused));

// MAX_PID_NS_LEVEL: a task's upid chain is at most this deep.
#define PIDNS_MAX_LEVEL 32

static __always_inline struct step_state *step_state(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&map_step_state, &key);
}

// ns_tgid_of returns t's process id as numbered in the daemon's pid
// namespace, or 0 when t lives outside that namespace's subtree (another
// pod, the host) or translation is disabled. Walks the group leader's upid
// chain from the innermost namespace outward: a task directly in the
// daemon's namespace matches on the first probe, a task inside a nested
// container (docker under the runner) one or two probes later.
static __always_inline __u32 ns_tgid_of(struct task_struct *t)
{
    if (!pidns_ino)
        return 0;
    struct pid *p = BPF_CORE_READ(t, group_leader, thread_pid);
    if (!p)
        return 0;
    unsigned int level = BPF_CORE_READ(p, level);
    for (unsigned int i = 0; i < PIDNS_MAX_LEVEL; i++) {
        if (i > level)
            break;
        unsigned int l = level - i;
        struct pid_namespace *ns = BPF_CORE_READ(p, numbers[l].ns);
        if (BPF_CORE_READ(ns, ns.inum) == pidns_ino)
            return BPF_CORE_READ(p, numbers[l].nr);
    }
    return 0;
}

// Tag propagation. Runs synchronously inside fork(), in the parent's
// context, so the child's tag exists before its first instruction — step
// attribution has no detection race for host processes.
//
// The namespace bridge is maintained first and unconditionally (not gated
// on enabled): userspace relies on map_task_nspid being complete from
// attach time onward, so the seeding iterator only has to cover tasks that
// predate the attach. A new thread copies its process's entry (one lookup);
// a new process walks its upid chain.
//
// Then two tagging cases:
//   1. New process (child tgid == child tid) whose parent process is
//      Runner.Worker → allocate the next step ordinal and notify userspace.
//      Worker *thread* creation deliberately falls through to case 2: a new
//      worker thread inherits the forking worker thread's tag (seeded as
//      STEP_ORD_RUNNER by the daemon) instead of minting a phantom step.
//   2. Anything else inherits the forking thread's tag, if it has one.
//      Untagged lineages stay untagged — absence is meaningful (pre-daemon
//      or non-runner processes).
SEC("tp_btf/sched_process_fork")
int BPF_PROG(step_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 parent_tid = parent->pid;
    __u32 parent_tgid = parent->tgid;
    __u32 child_tid = child->pid;
    __u32 child_tgid = child->tgid;

    __u32 ns_tgid = 0;
    if (child_tgid == parent_tgid) {
        __u32 *pns = bpf_map_lookup_elem(&map_task_nspid, &parent_tid);
        if (pns)
            ns_tgid = *pns;
    }
    if (!ns_tgid)
        ns_tgid = ns_tgid_of(child);
    if (ns_tgid)
        bpf_map_update_elem(&map_task_nspid, &child_tid, &ns_tgid, BPF_ANY);

    struct step_state *st = step_state();
    if (!st || !st->enabled)
        return 0;

    if (parent_tgid == st->worker_tgid && child_tgid == child_tid) {
        __u32 ord = (__u32)__sync_fetch_and_add(&st->next_ordinal, 1);
        bpf_map_update_elem(&map_task_step, &child_tid, &ord, BPF_ANY);
        struct step_child_event *ev =
            bpf_ringbuf_reserve(&map_step_events, sizeof(*ev), 0);
        if (ev) {
            ev->tgid = ns_tgid;
            ev->ordinal = ord;
            bpf_ringbuf_submit(ev, 0);
        }
        return 0;
    }

    __u32 *ord = bpf_map_lookup_elem(&map_task_step, &parent_tid);
    if (ord)
        bpf_map_update_elem(&map_task_step, &child_tid, ord, BPF_ANY);
    return 0;
}

// PID-reuse hygiene: drop the tag and the namespace entry when the task
// exits. Unconditional — a delete on an absent key is cheap, and gating on
// step_state would cost the same lookup.
SEC("tp_btf/sched_process_exit")
int BPF_PROG(step_exit, struct task_struct *task)
{
    __u32 tid = task->pid;
    bpf_map_delete_elem(&map_task_step, &tid);
    bpf_map_delete_elem(&map_task_nspid, &tid);
    return 0;
}

// Primary socket-tagging path: fires at socket() for every family/protocol
// in process context, so the cookie carries the creator's step for the
// socket's whole life. The connect/sendmsg hooks in tcbpf.c re-tag as a
// fallback for sockets created before attach.
SEC("cgroup/sock_create")
int cg_sock_create(struct bpf_sock *ctx)
{
    struct step_state *st = step_state();
    if (!st || !st->enabled)
        return 1;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 *ord = bpf_map_lookup_elem(&map_task_step, &tid);
    if (ord) {
        __u64 cookie = bpf_get_socket_cookie(ctx);
        bpf_map_update_elem(&map_sock_step, &cookie, ord, BPF_ANY);
    }
    return 1;
}

// Task walk for userspace. Two jobs in one pass: seed map_task_nspid for
// every task that predates the tracepoint attach, and stream the process
// tree (global ids plus the daemon-namespace tgid) so pkg/steps can seed
// step tags and tag container subtrees without /proc. The kernel already
// scopes the iteration to the opener's pid namespace — only the daemon's
// subtree is visited — and ns_tgid_of filters, defensively, anything it
// cannot map. Re-running it is idempotent, so container tagging takes a
// fresh pass per call.
SEC("iter/task")
int step_task_iter(struct bpf_iter__task *ctx)
{
    struct task_struct *t = ctx->task;
    if (!t)
        return 0;
    __u32 ns_tgid = ns_tgid_of(t);
    if (!ns_tgid)
        return 0;
    struct task_iter_rec rec = {
        .tid = t->pid,
        .tgid = t->tgid,
        .ppid = BPF_CORE_READ(t, real_parent, tgid),
        .ns_tgid = ns_tgid,
    };
    bpf_map_update_elem(&map_task_nspid, &rec.tid, &ns_tgid, BPF_ANY);
    bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
    return 0;
}

char _license[] SEC("license") = "GPL";
