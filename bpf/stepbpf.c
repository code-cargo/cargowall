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

// Step-attribution programs that require kernel BTF (tp_btf tracepoints and
// the cgroup/sock_create hook). Kept in a separate collection from tcbpf.c
// so a kernel without BTF degrades attribution only — the firewall proper
// loads and enforces unaffected. The three shared maps below are declared
// with identical shapes in tcbpf.c, which owns them; this collection is
// loaded with MapReplacements pointing at the tcbpf map fds.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ---- Shared with tcbpf.c (replaced at load time; shapes must match) ----

struct step_state {
    __u32 worker_tgid;   // Runner.Worker tgid (0 = not discovered)
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

// ---- Owned by this collection ----

// New-step notifications for the userspace reconciler: emitted once per new
// direct child process of Runner.Worker, before the child runs user code.
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

static __always_inline struct step_state *step_state(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&map_step_state, &key);
}

// Tag propagation. Runs synchronously inside fork(), in the parent's
// context, so the child's tag exists before its first instruction — step
// attribution has no detection race for host processes.
//
// Two cases:
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
    struct step_state *st = step_state();
    if (!st || !st->enabled)
        return 0;

    __u32 parent_tid = parent->pid;
    __u32 parent_tgid = parent->tgid;
    __u32 child_tid = child->pid;
    __u32 child_tgid = child->tgid;

    if (parent_tgid == st->worker_tgid && child_tgid == child_tid) {
        __u32 ord = (__u32)__sync_fetch_and_add(&st->next_ordinal, 1);
        bpf_map_update_elem(&map_task_step, &child_tid, &ord, BPF_ANY);
        struct step_child_event *ev =
            bpf_ringbuf_reserve(&map_step_events, sizeof(*ev), 0);
        if (ev) {
            ev->tgid = child_tgid;
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

// PID-reuse hygiene: drop the tag when the task exits. Unconditional — a
// delete on an absent key is cheap, and gating on step_state would cost the
// same lookup.
SEC("tp_btf/sched_process_exit")
int BPF_PROG(step_exit, struct task_struct *task)
{
    __u32 tid = task->pid;
    bpf_map_delete_elem(&map_task_step, &tid);
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

char _license[] SEC("license") = "GPL";
