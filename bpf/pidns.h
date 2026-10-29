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

// Pid-namespace membership, shared by stepbpf.c and scopebpf.c. The
// including file declares pidns_ino, the inode of the daemon's pid
// namespace that userspace sets before load, and includes this after it.

#ifndef __PIDNS_H__
#define __PIDNS_H__

// MAX_PID_NS_LEVEL: a task's upid chain is at most this deep.
#define PIDNS_MAX_LEVEL 32

// ns_tgid_of returns t's process id as numbered in the daemon's pid
// namespace, or 0 when t lives outside that namespace's subtree (another
// pod, the host) or translation is disabled. Walks the group leader's upid
// chain — numbers[0] is the init namespace, numbers[level] the task's own —
// looking for the namespace whose inode userspace passed in. The daemon's
// namespace appears at most once in a chain, so order is irrelevant; a
// plain bounded index keeps the flexible-array access simple.
static __always_inline __u32 ns_tgid_of(struct task_struct *t)
{
    if (!pidns_ino)
        return 0;
    struct pid *p = BPF_CORE_READ(t, group_leader, thread_pid);
    if (!p)
        return 0;
    unsigned int level = BPF_CORE_READ(p, level);
    if (level >= PIDNS_MAX_LEVEL)
        level = PIDNS_MAX_LEVEL - 1;
    for (unsigned int i = 0; i < PIDNS_MAX_LEVEL; i++) {
        if (i > level)
            break;
        struct upid up;
        if (bpf_core_read(&up, sizeof(up), &p->numbers[i]))
            break;
        if (BPF_CORE_READ(up.ns, ns.inum) == pidns_ino)
            return up.nr;
    }
    return 0;
}

#endif /* __PIDNS_H__ */
