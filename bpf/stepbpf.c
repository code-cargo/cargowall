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

#include "pidns.h"

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

// Event kinds on map_step_events; every event starts with its kind.
#define STEP_EV_FORK 1
#define STEP_EV_EXEC 2
#define STEP_EV_EXIT 3

// New-step notifications for the userspace reconciler, emitted once per new
// direct child process of Runner.Worker, before the child runs user code
// (STEP_EV_FORK). tgid is the child's pid as numbered in the daemon's
// namespace (0 if untranslatable).
struct step_child_event {
    __u32 kind;
    __u32 tgid;
    __u32 ordinal;
};

// BTF anchor — see the blocked_event anchor in tcbpf.c for rationale.
const struct step_child_event *btf_anchor_step_child_event __attribute__((unused));

// Bytes of a step's argument area its exec event carries: the cap
// userspace puts on a command line anyway.
#define STEP_ARGV_MAX 256

// What a step runs, from its root's first exec (STEP_EV_EXEC): argv is the
// start of the new program's argument area, NUL-separated, and argv_len
// the whole area's length (0 if unreadable), so a value over
// STEP_ARGV_MAX says argv was cut. A fork event cannot carry it: the child
// is still a copy of Runner.Worker, and a /proc read races the exec,
// reading empty mid-exec. A root that exits without exec'ing reports
// STEP_EV_EXIT, with no argv.
struct step_exec_event {
    __u32 kind;
    __u32 tgid;
    __u32 ordinal;
    __u32 argv_len;
    char argv[STEP_ARGV_MAX];
};

const struct step_exec_event *btf_anchor_step_exec_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} map_step_events SEC(".maps");

// Step roots between fork and their first exec: global tgid → ordinal.
// step_fork adds one, and step_exec or step_exit takes it out, so a
// recycled tgid never finds an entry. Steps run a few at a time.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} map_step_exec_pending SEC(".maps");

// One record per task in the daemon's pid-namespace subtree, streamed by
// step_task_iter. tid/tgid/ppid are global; ns_tgid is the process id
// userspace sees. pkg/steps builds its process-tree views from these
// instead of scanning /proc, which cannot reveal global ids from inside a
// namespace. exiting is 1 for a task already in do_exit: step_exit has run
// or is about to, so a tag written to it would outlive it.
struct task_iter_rec {
    __u32 tid;
    __u32 tgid;
    __u32 ppid;
    __u32 ns_tgid;
    __u32 exiting;
};

const struct task_iter_rec *btf_anchor_task_iter_rec __attribute__((unused));

// PF_EXITING from include/linux/sched.h (macros are not in BTF): set by
// exit_signals() at the top of do_exit, before sched_process_exit fires,
// and never cleared. A zombie still has it.
#define PF_EXITING 0x00000004

static __always_inline struct step_state *step_state(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&map_step_state, &key);
}

// clear_entry deletes key from map if it is there. A delete takes the
// bucket's lock even for an absent key, and step_fork clears an entry for
// most tasks the host creates; a lookup takes none.
static __always_inline void clear_entry(void *map, __u32 *key)
{
    if (bpf_map_lookup_elem(map, key))
        bpf_map_delete_elem(map, key);
}

// Tag propagation. Runs inside copy_process, in the creating thread's
// context, so the child's tag exists before its first instruction — step
// attribution has no detection race for host processes. task_newtask, not
// sched_process_fork: it fires for every task copy_process makes, io_uring
// and vhost workers included, which never reach sched_process_fork. Such
// a worker takes its creator's tag, as a thread does.
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
//
// The child's entries are set outright, cleared where there is nothing to
// copy and while attribution is off: the child's tid can be a recycled one
// that still holds an entry. Userspace tags tasks from a task walk, and a
// task that exits between the walk and the write keeps a tag step_exit has
// already run for; the iterator can likewise re-seed a namespace entry for
// a task it caught exiting.
SEC("tp_btf/task_newtask")
int BPF_PROG(step_fork, struct task_struct *child, __u64 clone_flags)
{
    __u64 parent = bpf_get_current_pid_tgid();
    __u32 parent_tid = (__u32)parent;
    __u32 parent_tgid = parent >> 32;
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
    else
        clear_entry(&map_task_nspid, &child_tid);

    struct step_state *st = step_state();
    if (!st || !st->enabled) {
        clear_entry(&map_task_step, &child_tid);
        return 0;
    }

    if (parent_tgid == st->worker_tgid && child_tgid == child_tid) {
        __u32 ord = (__u32)__sync_fetch_and_add(&st->next_ordinal, 1);
        bpf_map_update_elem(&map_task_step, &child_tid, &ord, BPF_ANY);
        bpf_map_update_elem(&map_step_exec_pending, &child_tgid, &ord, BPF_ANY);
        struct step_child_event *ev =
            bpf_ringbuf_reserve(&map_step_events, sizeof(*ev), 0);
        if (ev) {
            ev->kind = STEP_EV_FORK;
            ev->tgid = ns_tgid;
            ev->ordinal = ord;
            bpf_ringbuf_submit(ev, 0);
        }
        return 0;
    }

    __u32 *ord = bpf_map_lookup_elem(&map_task_step, &parent_tid);
    if (ord)
        bpf_map_update_elem(&map_task_step, &child_tid, ord, BPF_ANY);
    else
        clear_entry(&map_task_step, &child_tid);
    return 0;
}

// emit_step_exec reports a pending step root's first exec, or its exit
// before one, and takes it out of map_step_exec_pending. tgid is global;
// the event carries the daemon-namespace pid, which the caller still has
// in map_task_nspid.
static __always_inline void emit_step_exec(struct task_struct *task, __u32 tgid, __u32 kind)
{
    __u32 *ord = bpf_map_lookup_elem(&map_step_exec_pending, &tgid);
    if (!ord)
        return;
    struct step_exec_event *ev = bpf_ringbuf_reserve(&map_step_events, sizeof(*ev), 0);
    if (ev) {
        __u32 *ns = bpf_map_lookup_elem(&map_task_nspid, &tgid);
        ev->kind = kind;
        ev->tgid = ns ? *ns : 0;
        ev->ordinal = *ord;
        __u64 len = 0;
        if (kind == STEP_EV_EXEC) {
            __u64 start = BPF_CORE_READ(task, mm, arg_start);
            __u64 end = BPF_CORE_READ(task, mm, arg_end);
            if (end > start)
                len = end - start;
            __u64 n = len > STEP_ARGV_MAX ? STEP_ARGV_MAX : len;
            if (bpf_probe_read_user(ev->argv, n, (const void *)start))
                len = 0;
        }
        ev->argv_len = len > 0xffffffff ? 0xffffffff : len;
        bpf_ringbuf_submit(ev, 0);
    }
    bpf_map_delete_elem(&map_step_exec_pending, &tgid);
}

// A step root's first exec. At this tracepoint the new program's arguments
// are in place in its memory, which a /proc read from userspace can only
// race. One lookup per exec anywhere on the host.
SEC("tp_btf/sched_process_exec")
int BPF_PROG(step_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    emit_step_exec(p, p->tgid, STEP_EV_EXEC);
    return 0;
}

// PID-reuse hygiene: drop the tag and the namespace entry when the task
// exits. Unconditional — a delete on an absent key is cheap, and gating on
// step_state would cost the same lookup. A step root that exits without
// exec'ing reports it first, while its namespace entry is still there.
SEC("tp_btf/sched_process_exit")
int BPF_PROG(step_exit, struct task_struct *task)
{
    __u32 tid = task->pid;
    emit_step_exec(task, tid, STEP_EV_EXIT);
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
// fresh pass per call. A task already exiting is listed, flagged, but not
// seeded: step_exit may have deleted its entry already.
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
        .exiting = (t->flags & PF_EXITING) ? 1 : 0,
    };
    if (!rec.exiting)
        bpf_map_update_elem(&map_task_nspid, &rec.tid, &ns_tgid, BPF_ANY);
    bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
    return 0;
}

char _license[] SEC("license") = "GPL";
