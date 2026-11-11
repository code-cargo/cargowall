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

// Shared egress verdict surface (issue #106 phase 3b). The allow/deny
// decision and the maps that carry it are the single source of truth for
// BOTH enforcing hooks: cw_tc_egress (bpf/tcbpf.c) and cw_cg_egress
// (bpf/originbpf.c). A divergence between the primary hook and its backstop
// would be a security bug, so the decision lives here once, not copied.
//
// Both includers already pull in vmlinux.h + bpf/bpf_helpers.h before this
// header. This header owns only the pure decision — the rule/config maps,
// their key/value structs, and the lookup helpers. Each hook keeps its own
// packet parsing, event emission, and action constants (TC_ACT_* vs the
// cgroup_skb 1/0 and the mode ladder), because those genuinely differ.
//
// The maps below are declared identically here in whichever collection
// includes this header; userspace wires the non-owning collection's copies
// to the owning collection's fds via ebpf MapReplacements (see
// pkg/origin/origin.go), so all hooks read one set of kernel maps.

#pragma once

// The DNS proxy marks its own upstream queries with this SO_MARK
// (pkg/network/dns_redirect.go DNSProxyFWMark). The cgroup verdict hook
// reads skb->mark to exempt them, so the proxy can never self-block its
// upstream lookups during a policy race. Mirrored constant — pinned to the
// Go definition by a layout test.
#define DNS_PROXY_FW_MARK 0xCA12

// ---- Rule policies ----
//
// The rule maps hold rules by policy as well as by address, so one set of
// maps can carry more than one rule set. POLICY_JOB is the job's own rules.
// An LPM key's prefix length counts the policy field's RULE_POLICY_BITS ahead
// of the address bits, and every lookup asks for all of them: an entry can
// only ever answer a lookup made under its own policy, a 0.0.0.0/0 rule
// included. Port entries carry the policy in their key the same way.
#define POLICY_JOB 0
#define RULE_POLICY_BITS 32

// What a policy's rules decide about a packet. RULE_NONE is no rule
// deciding: no LPM match and no wildcard port, or a port-specific match
// whose port is not listed and no wildcard. The default action is then the
// caller's to apply.
#define RULE_NONE  0
#define RULE_DENY  1
#define RULE_ALLOW 2

// ---- IPv4 rule structs ----

// LPM trie key for CIDR matching. prefixlen is RULE_POLICY_BITS plus the
// rule's own prefix length.
struct rule_key {
    __u32 prefixlen;  // Must be first member for LPM trie
    __u32 policy;
    __u32 ip;
} __attribute__((packed));

// Value for LPM trie - action with optional port restrictions.
//
// host_bits is the address width the rule leaves open: 32 (128 for IPv6)
// minus its prefix length, so 0 is a host route. A port-specific rule's
// port entries are keyed by the rule's network address plus host_bits (see
// rule_port_key), and the LPM lookup returns only this value, not the key
// that matched — host_bits is how the verdict recovers which prefix that was.
struct lpm_val {
    __u8 action;      // 0 = deny, 1 = allow
    __u8 port_specific; // 0 = all ports, 1 = check port map
    __u8 host_bits;
    __u8 pad;
} __attribute__((packed));

// Key for port-specific rules: the owning rule's policy, network address and
// host_bits (see lpm_val), so a subnet's entries are found from any address
// inside it and a host route's from its own. The wildcard-port entries are
// ip 0 / host_bits 0, under their policy. For ICMP (proto=1) the port field
// is always 0; ICMP has no L4 port, so the protocol byte alone discriminates
// the rule.
struct rule_port_key {
    __u32 policy;
    __u32 ip;
    __u16 port;
    __u8 proto;           // IPPROTO_TCP (6), IPPROTO_UDP (17), or IPPROTO_ICMP (1)
    __u8 host_bits;
} __attribute__((packed));

// Value for port rules - just allow/deny
struct port_val {
    __u8 action;      // 0 = deny, 1 = allow
    __u8 pad[3];
} __attribute__((packed));

// ---- IPv6 rule structs ----

// IPv6 LPM trie key (128-bit IP), its prefix counted as in rule_key.
struct rule_key_v6 {
    __u32 prefixlen;
    __u32 policy;
    __u8 ip[16];
} __attribute__((packed));

// IPv6 port key — the policy, network address and host_bits of the owning
// rule, as in rule_port_key.
struct rule_port_key_v6 {
    __u32 policy;
    __u8 ip[16];
    __u16 port;
    __u8 proto;           // IPPROTO_TCP (6) or IPPROTO_UDP (17)
    __u8 host_bits;
} __attribute__((packed));

// ---- Shared rule/config maps ----
//
// The four rule maps hold the job's rules (POLICY_JOB) and every step's, so
// each is sized for both: userspace keeps 4096 entries of each for the job,
// what the whole map held before step policies, and lets the steps share
// the rest (pkg/firewall/policy.go).

// Default action map (0 = deny, 1 = allow)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} map_default_action SEC(".maps");

// LPM trie map for IPv4 CIDR-based allow/deny rules
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct rule_key);
    __type(value, struct lpm_val);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_cidrs SEC(".maps");

// Hash map for IPv4 port-specific rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rule_port_key);
    __type(value, struct port_val);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ports SEC(".maps");

// LPM trie map for IPv6 CIDR-based allow/deny rules
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct rule_key_v6);
    __type(value, struct lpm_val);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_cidrs_v6 SEC(".maps");

// Hash map for IPv6 port-specific rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rule_port_key_v6);
    __type(value, struct port_val);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ports_v6 SEC(".maps");

// Audit mode map (0 = enforce/block, 1 = audit/log only)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} map_audit_mode SEC(".maps");

// ---- Step policies ----
//
// A step's own allow rules live in the rule maps under a policy of their
// own, never under POLICY_JOB. map_step_policy binds a step's ordinal to
// that policy, written once, by userspace, when the step is identified, and
// a socket finds its step's ordinal in map_sock_step, by the rule
// step_tag_socket in tcbpf.c gives: in short, the last tagged thread to
// connect it or send on it as UDP to an address (or with IP-level control
// messages), and until then its creator. An ordinal
// with no binding (not identified yet, or never: a sentinel, a runner
// helper, an unknown step) and a socket with no tag have no step policy,
// and the job's rules alone judge them.

// Nonzero when the policy loaded at startup has steps with rules of their
// own. A load-time constant, so a job without step rules runs no step
// lookup at all: at zero the verifier prunes the branch.
const volatile __u8 step_rules_enabled = 0;

// socket cookie → step ordinal, written at socket creation (cw_cg_sock_new
// in stepbpf.c, which declares the same map) and again by the connect and
// sendmsg hooks in tcbpf.c (see step_tag_socket there).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 65536);
} map_sock_step SEC(".maps");

// step ordinal → the policy that holds the step's own allow rules.
// Requirement: a step may be bound here only while step installs are
// L7-scoped, or a step's own entries would open a shared edge IP to it on
// any SNI. They are: a step's DNS install scopes its address, and the L7
// oracle judges a punt's name by the step policy step_policy_judged gives.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_step_policy SEC(".maps");

// ---- Decision helpers ----

// audit_mode_active reports whether the run is in audit (log-only) posture.
// Both hooks force a pass when true.
static __always_inline __u8 audit_mode_active(void) {
    __u32 audit_key = 0;
    __u8 *audit_mode = bpf_map_lookup_elem(&map_audit_mode, &audit_key);
    return (audit_mode && *audit_mode == 1) ? 1 : 0;
}

// rule_net_v4 masks ip (network byte order) down to the network address of
// a rule leaving host_bits open — the address its port entries are keyed by.
// host_bits 0 (a host route) returns ip unchanged.
static __always_inline __u32 rule_net_v4(__u32 ip_nbo, __u8 host_bits) {
    if (host_bits >= 32)
        return 0;
    return ip_nbo & bpf_htonl(0xffffffffU << host_bits);
}

// rule_net_v6 is rule_net_v4 for a 16-byte address, worked as two 64-bit
// halves so the masking stays a few straight-line instructions.
static __always_inline void rule_net_v6(__u8 out[16], const __u8 ip[16], __u8 host_bits) {
    __u64 hi, lo;
    __builtin_memcpy(&hi, ip, 8);
    __builtin_memcpy(&lo, ip + 8, 8);
    __u64 hi_mask = ~0ULL;
    __u64 lo_mask = ~0ULL;
    if (host_bits >= 128) {
        hi_mask = 0;
        lo_mask = 0;
    } else if (host_bits >= 64) {
        hi_mask = ~0ULL << (host_bits - 64);
        lo_mask = 0;
    } else {
        lo_mask = ~0ULL << host_bits;
    }
    hi &= bpf_cpu_to_be64(hi_mask);
    lo &= bpf_cpu_to_be64(lo_mask);
    __builtin_memcpy(out, &hi, 8);
    __builtin_memcpy(out + 8, &lo, 8);
}

// rule_result maps a matched entry's action byte onto a RULE_* result.
static __always_inline int rule_result(__u8 action) {
    return action == 1 ? RULE_ALLOW : RULE_DENY;
}

// default_allows reports the job's default action, for a packet no rule
// decides: 1 for allow.
static __always_inline __u8 default_allows(void) {
    __u32 def_key = 0;
    __u8 *default_action = bpf_map_lookup_elem(&map_default_action, &def_key);
    return (default_action && *default_action == 1) ? 1 : 0;
}

// rules_v4 is what policy's rules decide about a packet to dst (network
// byte order) on dst_port (host order) / proto: the LPM rule match, then,
// for a port-specific rule, its port entry under the MATCHED rule's network
// address, so a subnet rule's ports cover every address inside it, then the
// 0.0.0.0 wildcard port. A no-LPM match consults only the wildcard-port
// entry, never a specific-IP port. RULE_NONE leaves the default action to
// the caller.
//
// A global function rather than an inlined one, so the verifier walks it
// once however many times a hook asks it. Global functions date from 5.6,
// under the 5.8 floor; before 5.12 one could take no pointer but its
// program's context, hence the scalar arguments.
__noinline int rules_v4(__u32 policy, __u32 dst_ip_nbo, __u32 dst_port, __u32 proto) {
    struct rule_key key = {
        .prefixlen = RULE_POLICY_BITS + 32,
        .policy = policy,
        .ip = dst_ip_nbo,
    };
    struct rule_port_key pkey = {
        .policy = policy,
        .port = (__u16)dst_port,
        .proto = (__u8)proto,
    };

    struct lpm_val *rule = bpf_map_lookup_elem(&map_cidrs, &key);
    if (rule) {
        if (rule->port_specific == 0)
            return rule_result(rule->action);
        pkey.ip = rule_net_v4(dst_ip_nbo, rule->host_bits);
        pkey.host_bits = rule->host_bits;
        struct port_val *pval = bpf_map_lookup_elem(&map_ports, &pkey);
        if (pval)
            return rule_result(pval->action);
        pkey.ip = 0;  // 0.0.0.0
        pkey.host_bits = 0;
    }

    struct port_val *wildcard = bpf_map_lookup_elem(&map_ports, &pkey);
    if (wildcard)
        return rule_result(wildcard->action);
    return RULE_NONE;
}

// rules_v6 is the IPv6 analogue of rules_v4. The destination comes as its
// two 8-byte halves, in network byte order, so the function keeps to scalar
// arguments.
__noinline int rules_v6(__u32 policy, __u64 dst_hi, __u64 dst_lo, __u32 dst_port, __u32 proto) {
    struct rule_key_v6 key;
    __builtin_memset(&key, 0, sizeof(key));
    key.prefixlen = RULE_POLICY_BITS + 128;
    key.policy = policy;
    __builtin_memcpy(key.ip, &dst_hi, 8);
    __builtin_memcpy(key.ip + 8, &dst_lo, 8);

    struct rule_port_key_v6 pkey;
    __builtin_memset(&pkey, 0, sizeof(pkey));
    pkey.policy = policy;
    pkey.port = (__u16)dst_port;
    pkey.proto = (__u8)proto;

    struct lpm_val *rule = bpf_map_lookup_elem(&map_cidrs_v6, &key);
    if (rule) {
        if (rule->port_specific == 0)
            return rule_result(rule->action);
        rule_net_v6(pkey.ip, key.ip, rule->host_bits);
        pkey.host_bits = rule->host_bits;
        struct port_val *pval = bpf_map_lookup_elem(&map_ports_v6, &pkey);
        if (pval)
            return rule_result(pval->action);
        __builtin_memset(pkey.ip, 0, 16);
        pkey.host_bits = 0;
    }

    struct port_val *wildcard = bpf_map_lookup_elem(&map_ports_v6, &pkey);
    if (wildcard)
        return rule_result(wildcard->action);
    return RULE_NONE;
}

// ---- Bridge stamp ----
//
// A bridge-networked container's packets reach TC past NAT with no socket,
// so TC cannot read their socket's step tag. cw_tc_br_stamp, at the ingress
// of each Docker bridge port (a container veth's host end), still sees the
// container's socket: the kernel takes it off the packet only later, as
// the bridge hands the packet to br_netfilter, or as it enters the IP
// layer. It writes the socket's step policy into skb->mark under
// STEP_STAMP_MAGIC; the mark rides the bridge, forwarding and NAT to the
// uplink, where step_policy_of reads it for a packet with no socket. A
// container cannot forge a stamp: a packet's mark is cleared as it leaves
// the container's network namespace, and the port program clears any
// stamp it did not write itself. Premises: no rule of the host's sets or
// changes a forwarded packet's mark in the 0xCA1B0000 range, and every
// other container path to the uplink clears the mark too or carries the
// container's socket (see "The bridge stamp" in design.md). The cgroup
// hook always has the socket, and never reads a stamp.
#define STEP_STAMP_MAGIC      0xCA1B0000u
#define STEP_STAMP_MASK       0xFFFF0000u
#define STEP_STAMP_POLICY_MAX 0xFFFFu

// stamp_step_policy is the step policy a bridge stamp in mark carries, or
// POLICY_JOB for a mark that is none.
static __always_inline __u32 stamp_step_policy(__u32 mark) {
    if ((mark & STEP_STAMP_MASK) != STEP_STAMP_MAGIC)
        return POLICY_JOB;
    return mark & STEP_STAMP_POLICY_MAX;
}

// cookie_step_policy is the policy holding the own rules of the step tagged
// on the socket with cookie, or POLICY_JOB for none: no tag, or no binding
// for the tag. The two lookups are not one atomic read: the tag map is an
// LRU, whose element a concurrent re-tag or eviction can recycle between
// them, judging the packet by another socket's step. TC reads its own way,
// so both hooks would have to lose that race on the same packet, and steps
// that race each other's sockets so are beyond the step rules: the job is
// the boundary between them.
static __always_inline __u32 cookie_step_policy(__u64 cookie) {
    __u32 *ordinal = bpf_map_lookup_elem(&map_sock_step, &cookie);
    if (!ordinal)
        return POLICY_JOB;
    __u32 *policy = bpf_map_lookup_elem(&map_step_policy, ordinal);
    return policy ? *policy : POLICY_JOB;
}

// step_policy_judged is the step policy the socket with cookie is judged
// by, or POLICY_JOB with step rules off. The L7 oracle judges a flow's name
// by the policy this read gives with the punt, never by one it reads later,
// which a binding landing in between would change. Policies fit 16 bits
// (STEP_STAMP_POLICY_MAX), as the punt carries them.
static __always_inline __u32 step_policy_judged(__u64 cookie) {
    if (!step_rules_enabled)
        return POLICY_JOB;
    return cookie_step_policy(cookie);
}

// step_policy_of is the step policy skb is judged by: that of the socket it
// was sent from, or, with no socket (TC, past NAT), its bridge stamp's.
static __always_inline __u32 step_policy_of(struct __sk_buff *skb) {
    __u64 cookie = bpf_get_socket_cookie(skb);
    if (!cookie)
        return stamp_step_policy(skb->mark);
    return cookie_step_policy(cookie);
}

// verdict_allowed_v4 returns 1 if a packet to dst (network byte order) on
// dst_port (host order) / proto is allowed, 0 if denied. The job's rules
// decide first. Where they decide nothing, the own rules of the step tagged
// on the socket (step_policy_of) may allow it, and the job's default action
// decides the rest. A step's rules only ever turn the job's silence into an
// allow, never into a deny, whatever the maps hold, so a step gets all the
// job gets and never less. *step_tier is set when a step's rules were asked.
static __always_inline __u8 verdict_allowed_v4(struct __sk_buff *skb, __u32 dst_ip_nbo,
                                               __u16 dst_port, __u8 proto, __u8 *step_tier) {
    *step_tier = 0;
    int r = rules_v4(POLICY_JOB, dst_ip_nbo, dst_port, proto);
    if (r == RULE_NONE && step_rules_enabled) {
        __u32 policy = step_policy_of(skb);
        if (policy != POLICY_JOB) {
            *step_tier = 1;
            if (rules_v4(policy, dst_ip_nbo, dst_port, proto) == RULE_ALLOW)
                return 1;
        }
    }
    if (r == RULE_NONE)
        return default_allows();
    return r == RULE_ALLOW;
}

// verdict_allowed_v6 is the IPv6 analogue of verdict_allowed_v4, dst_ip6 in
// network byte order.
static __always_inline __u8 verdict_allowed_v6(struct __sk_buff *skb, const __u8 dst_ip6[16],
                                               __u16 dst_port, __u8 proto, __u8 *step_tier) {
    __u64 hi, lo;
    __builtin_memcpy(&hi, dst_ip6, 8);
    __builtin_memcpy(&lo, dst_ip6 + 8, 8);
    *step_tier = 0;
    int r = rules_v6(POLICY_JOB, hi, lo, dst_port, proto);
    if (r == RULE_NONE && step_rules_enabled) {
        __u32 policy = step_policy_of(skb);
        if (policy != POLICY_JOB) {
            *step_tier = 1;
            if (rules_v6(policy, hi, lo, dst_port, proto) == RULE_ALLOW)
                return 1;
        }
    }
    if (r == RULE_NONE)
        return default_allows();
    return r == RULE_ALLOW;
}
