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
// tgid — seeded for pre-existing tasks by cw_step_iter and kept current
// by cw_step_fork, cw_step_exec (a de_thread moves it) and cw_step_exit. It is what lets the reconciler read
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
enum step_event_kind {
    STEP_EV_FORK = 1,
    STEP_EV_EXEC = 2,
    STEP_EV_EXIT = 3,
    STEP_EV_END = 4,
};

const enum step_event_kind *btf_anchor_step_event_kind __attribute__((unused));

// New-step notifications for the userspace reconciler, emitted once per new
// direct child process of Runner.Worker, before the child runs user code
// (STEP_EV_FORK), and again when the child exits: before it execs
// (STEP_EV_EXIT), or after (STEP_EV_END), which ends its step. tgid is the
// child's pid as numbered in the daemon's namespace (0 if
// untranslatable). ktime is when the fork or exit happened, by
// bpf_ktime_get_ns (CLOCK_MONOTONIC): the reader can fall behind, and the
// step starts at its fork, not when the reader gets to it.
struct step_child_event {
    __u32 kind;
    __u32 tgid;
    __u32 ordinal;
    __u32 pad;
    __u64 ktime;
};

// BTF anchor — see the blocked_event anchor in tcbpf.c for rationale.
const struct step_child_event *btf_anchor_step_child_event __attribute__((unused));

// Bytes of a step's argument area its exec event carries: the cap
// userspace puts on a command line anyway.
#define STEP_ARGV_MAX 256

// Bytes of a step root's environment its exec event carries. The runner
// names the step there (GITHUB_ACTION), a few KB in: the step's and job's
// env: values can come before it. An environment cut before the name
// leaves the step unidentified.
#define STEP_ENV_MAX (32 * 1024)

// What a step runs, from its root's first exec (STEP_EV_EXEC): argv is the
// start of the new program's argument area, NUL-separated, and argv_len
// the whole area's length (0 if unreadable), so a value over
// STEP_ARGV_MAX says argv was cut; comm is the new program's name, for
// when it is. env and env_len are the same for the environment, which
// Runner.Worker wrote and which names the step; it holds secrets, so
// userspace takes the name and keeps nothing else. A fork event cannot
// carry these: the child is still a copy of Runner.Worker. Nor can /proc,
// whose read races the exec, and reads what the program may since have
// rewritten. A root that exits without exec'ing reports STEP_EV_EXIT in a
// step_child_event, which has room for none of them, so an exit record
// can't carry what an older record left in the ring.
struct step_exec_event {
    __u32 kind;
    __u32 tgid;
    __u32 ordinal;
    __u32 argv_len;
    char argv[STEP_ARGV_MAX];
    char comm[16];
    __u32 env_len;
    char env[STEP_ENV_MAX];
};

const struct step_exec_event *btf_anchor_step_exec_event __attribute__((unused));

// Room for about 60 exec events, each over STEP_ENV_MAX, so a reader that
// falls behind a burst of steps loses none; a lost one is still reported
// (from /proc), unidentified. Allocated only with step attribution on.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} map_step_events SEC(".maps");

// Step roots between fork and their first exec: global tgid → ordinal.
// cw_step_fork adds one, and cw_step_exec or cw_step_exit takes it out, so a
// recycled tgid never finds an entry. Steps run a few at a time.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} map_step_exec_pending SEC(".maps");

// Step roots from their first exec to their exit: global tgid → ordinal.
// emit_step_exec adds one, and cw_step_exit takes it out as it reports the
// step's end.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} map_step_live SEC(".maps");

// Step ends the ring had no room for, per CPU. A lost exec or exit event
// is made up for from /proc; a lost end leaves its step running as far as
// userspace knows, and userspace warns of it.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} map_step_ends_lost SEC(".maps");

// One record per task in the daemon's pid-namespace subtree, streamed by
// cw_step_iter. tid/tgid/ppid are global; ns_tgid is the process id
// userspace sees. pkg/steps builds its process-tree views from these
// instead of scanning /proc, which cannot reveal global ids from inside a
// namespace. exiting is 1 for a task already in do_exit: cw_step_exit has run
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
// bucket's lock even for an absent key, and cw_step_fork clears an entry for
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
// task that exits between the walk and the write keeps a tag cw_step_exit has
// already run for; the iterator can likewise re-seed a namespace entry for
// a task it caught exiting.
SEC("tp_btf/task_newtask")
int BPF_PROG(cw_step_fork, struct task_struct *child, __u64 clone_flags)
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
            ev->pad = 0;
            ev->ktime = bpf_ktime_get_ns();
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
// the event carries the daemon-namespace pid from map_task_nspid, 0 once
// the leader's own exit has deleted it (userspace has it from the fork).
static __always_inline void emit_step_exec(struct task_struct *task, __u32 tgid, __u32 kind)
{
    __u32 *pending = bpf_map_lookup_elem(&map_step_exec_pending, &tgid);
    if (!pending)
        return;
    __u32 ord = *pending;
    __u32 *ns = bpf_map_lookup_elem(&map_task_nspid, &tgid);
    __u32 ns_tgid = ns ? *ns : 0;
    if (kind == STEP_EV_EXIT) {
        struct step_child_event *ev = bpf_ringbuf_reserve(&map_step_events, sizeof(*ev), 0);
        if (ev) {
            ev->kind = kind;
            ev->tgid = ns_tgid;
            ev->ordinal = ord;
            ev->pad = 0;
            ev->ktime = bpf_ktime_get_ns();
            bpf_ringbuf_submit(ev, 0);
        }
        bpf_map_delete_elem(&map_step_exec_pending, &tgid);
        return;
    }
    struct step_exec_event *ev = bpf_ringbuf_reserve(&map_step_events, sizeof(*ev), 0);
    if (ev) {
        ev->kind = kind;
        ev->tgid = ns_tgid;
        ev->ordinal = ord;
        __u64 len = 0, env_len = 0;
        __u64 start = BPF_CORE_READ(task, mm, arg_start);
        __u64 end = BPF_CORE_READ(task, mm, arg_end);
        if (end > start)
            len = end - start;
        __u64 n = len > STEP_ARGV_MAX ? STEP_ARGV_MAX : len;
        if (bpf_probe_read_user(ev->argv, n, (const void *)start))
            len = 0;
        bpf_get_current_comm(ev->comm, sizeof(ev->comm));

        start = BPF_CORE_READ(task, mm, env_start);
        end = BPF_CORE_READ(task, mm, env_end);
        if (end > start)
            env_len = end - start;
        n = env_len > STEP_ENV_MAX ? STEP_ENV_MAX : env_len;
        if (bpf_probe_read_user(ev->env, n, (const void *)start))
            env_len = 0;
        ev->argv_len = len > 0xffffffff ? 0xffffffff : len;
        ev->env_len = env_len > 0xffffffff ? 0xffffffff : env_len;
        bpf_ringbuf_submit(ev, 0);
    }
    bpf_map_update_elem(&map_step_live, &tgid, &ord, BPF_ANY);
    bpf_map_delete_elem(&map_step_exec_pending, &tgid);
}

// emit_step_end reports the exit of a step root that has exec'd, the end
// of its step, and takes it out of map_step_live.
static __always_inline void emit_step_end(__u32 tgid)
{
    __u32 *live = bpf_map_lookup_elem(&map_step_live, &tgid);
    if (!live)
        return;
    __u32 ord = *live;
    __u32 *ns = bpf_map_lookup_elem(&map_task_nspid, &tgid);
    struct step_child_event *ev = bpf_ringbuf_reserve(&map_step_events, sizeof(*ev), 0);
    if (ev) {
        ev->kind = STEP_EV_END;
        ev->tgid = ns ? *ns : 0;
        ev->ordinal = ord;
        ev->pad = 0;
        ev->ktime = bpf_ktime_get_ns();
        bpf_ringbuf_submit(ev, 0);
    } else {
        __u32 k = 0;
        __u64 *lost = bpf_map_lookup_elem(&map_step_ends_lost, &k);
        if (lost)
            *lost += 1;
    }
    bpf_map_delete_elem(&map_step_live, &tgid);
}

// move_entry moves a task's entry in map from tid from to tid to, if it
// has one.
static __always_inline void move_entry(void *map, __u32 *from, __u32 *to)
{
    __u32 *v = bpf_map_lookup_elem(map, from);
    if (!v)
        return;
    __u32 val = *v;
    bpf_map_update_elem(map, to, &val, BPF_ANY);
    bpf_map_delete_elem(map, from);
}

// A task's exec. A thread other than the leader that execs takes the
// leader's tid (de_thread), and the leader's exit has already deleted the
// entries under it: the process's tag and namespace pid are the exec'ing
// thread's, still under old_pid, and move with it. Then a step root's
// first exec reports what the step runs: at this tracepoint the new
// program's arguments are in place in its memory, which a /proc read from
// userspace can only race. A lookup or two per exec anywhere on the host.
SEC("tp_btf/sched_process_exec")
int BPF_PROG(cw_step_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    __u32 tid = p->pid;
    __u32 old = old_pid;
    if (old != tid) {
        move_entry(&map_task_step, &old, &tid);
        move_entry(&map_task_nspid, &old, &tid);
    }
    emit_step_exec(p, p->tgid, STEP_EV_EXEC);
    return 0;
}

// PID-reuse hygiene: drop the tag and the namespace entry when the task
// exits. Unconditional — a delete on an absent key is cheap, and gating on
// step_state would cost the same lookup. A step root reports its exit
// first, when its last thread exits: the leader alone exiting is a
// pthread_exit, or a de_thread whose exec is still to come. do_exit
// counts the thread out of signal->live before this fires.
SEC("tp_btf/sched_process_exit")
int BPF_PROG(cw_step_exit, struct task_struct *task)
{
    __u32 tid = task->pid;
    if (BPF_CORE_READ(task, signal, live.counter) == 0) {
        emit_step_exec(task, task->tgid, STEP_EV_EXIT);
        emit_step_end(task->tgid);
    }
    bpf_map_delete_elem(&map_task_step, &tid);
    bpf_map_delete_elem(&map_task_nspid, &tid);
    return 0;
}

// Socket tagging at birth: cgroup/sock_create runs from inet_create and
// inet6_create, for each user socket of the inet families, in the creating
// thread's context, so the cookie carries that thread's step. The connect
// and sendmsg hooks in tcbpf.c re-tag it later, which also tags a socket
// made before attach once it is connected or sent on to an address: see
// step_tag_socket there for the rule.
SEC("cgroup/sock_create")
int cw_cg_sock_new(struct bpf_sock *ctx)
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
// seeded: cw_step_exit may have deleted its entry already.
SEC("iter/task")
int cw_step_iter(struct bpf_iter__task *ctx)
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
