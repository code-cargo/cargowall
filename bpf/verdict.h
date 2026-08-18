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
// BOTH enforcing hooks: tc_egress (bpf/tcbpf.c) and cg_origin_egress
// (bpf/originbpf.c). A divergence between the primary hook and its backstop
// would be a security bug, so the decision lives here once, not copied.
//
// Both includers already pull in vmlinux.h + bpf/bpf_helpers.h before this
// header. This header owns only the pure decision — the rule/config maps,
// their key/value structs, and the lookup helpers. Each hook keeps its own
// packet parsing, event emission, and action constants (TC_ACT_* vs the
// cgroup_skb 1/0 and the mode ladder), because those genuinely differ.
//
// The six maps below are declared identically here in whichever collection
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

// ---- IPv4 rule structs ----

// LPM trie key for CIDR matching
struct lpm_key {
    __u32 prefixlen;  // Must be first member for LPM trie
    __u32 ip;
} __attribute__((packed));

// Value for LPM trie - action with optional port restrictions
struct lpm_val {
    __u8 action;      // 0 = deny, 1 = allow
    __u8 port_specific; // 0 = all ports, 1 = check port map
    __u16 pad;
} __attribute__((packed));

// Key for port-specific rules. For ICMP (proto=1) the port field is always 0;
// ICMP has no L4 port, so the protocol byte alone discriminates the rule.
struct port_key {
    __u32 ip;
    __u16 port;
    __u8 proto;           // IPPROTO_TCP (6), IPPROTO_UDP (17), or IPPROTO_ICMP (1)
    __u8 pad;
} __attribute__((packed));

// Value for port rules - just allow/deny
struct port_val {
    __u8 action;      // 0 = deny, 1 = allow
    __u8 pad[3];
} __attribute__((packed));

// ---- IPv6 rule structs ----

// IPv6 LPM trie key (128-bit IP)
struct lpm_key_v6 {
    __u32 prefixlen;
    __u8 ip[16];
} __attribute__((packed));

// IPv6 port key
struct port_key_v6 {
    __u8 ip[16];
    __u16 port;
    __u8 proto;           // IPPROTO_TCP (6) or IPPROTO_UDP (17)
    __u8 pad;
} __attribute__((packed));

// ---- Shared rule/config maps ----

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
    __type(key, struct lpm_key);
    __type(value, struct lpm_val);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_cidrs SEC(".maps");

// Hash map for IPv4 port-specific rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key);
    __type(value, struct port_val);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ports SEC(".maps");

// LPM trie map for IPv6 CIDR-based allow/deny rules
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_v6);
    __type(value, struct lpm_val);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_cidrs_v6 SEC(".maps");

// Hash map for IPv6 port-specific rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key_v6);
    __type(value, struct port_val);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ports_v6 SEC(".maps");

// Audit mode map (0 = enforce/block, 1 = audit/log only)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} map_audit_mode SEC(".maps");

// ---- Decision helpers ----

// audit_mode_active reports whether the run is in audit (log-only) posture.
// Both hooks force a pass when true.
static __always_inline __u8 audit_mode_active(void) {
    __u32 audit_key = 0;
    __u8 *audit_mode = bpf_map_lookup_elem(&map_audit_mode, &audit_key);
    return (audit_mode && *audit_mode == 1) ? 1 : 0;
}

// verdict_allowed_v4 returns 1 if a packet to dst (network byte order) on
// dst_port (host order) / proto is allowed, 0 if denied. This is the exact
// decision tc_egress made inline before phase 3b: LPM rule match →
// port-specific check → 0.0.0.0 wildcard port → default action. A no-LPM
// match consults only the wildcard-port entry, never a specific-IP port —
// preserving the original asymmetry.
static __always_inline __u8 verdict_allowed_v4(__u32 dst_ip_nbo, __u16 dst_port, __u8 proto) {
    struct lpm_key key = {
        .prefixlen = 32,
        .ip = dst_ip_nbo
    };

    struct lpm_val *rule = bpf_map_lookup_elem(&map_cidrs, &key);
    __u8 decision_made = 0;
    __u8 allowed = 0;

    if (rule) {
        if (rule->port_specific == 0) {
            decision_made = 1;
            if (rule->action == 1) {
                allowed = 1;
            }
        } else {
            struct port_key pkey = {
                .ip = dst_ip_nbo,
                .port = dst_port,
                .proto = proto,
                .pad = 0
            };
            struct port_val *pval = bpf_map_lookup_elem(&map_ports, &pkey);
            if (pval) {
                decision_made = 1;
                if (pval->action == 1) {
                    allowed = 1;
                }
            } else {
                pkey.ip = 0;  // 0.0.0.0
                pval = bpf_map_lookup_elem(&map_ports, &pkey);
                if (pval) {
                    decision_made = 1;
                    if (pval->action == 1) {
                        allowed = 1;
                    }
                }
            }
        }
    } else {
        struct port_key pkey = {
            .ip = 0,  // 0.0.0.0 wildcard
            .port = dst_port,
            .proto = proto,
            .pad = 0
        };
        struct port_val *pval = bpf_map_lookup_elem(&map_ports, &pkey);
        if (pval) {
            decision_made = 1;
            if (pval->action == 1) {
                allowed = 1;
            }
        }
    }

    if (!decision_made) {
        __u32 def_key = 0;
        __u8 *default_action = bpf_map_lookup_elem(&map_default_action, &def_key);
        if (default_action && *default_action == 1) {
            allowed = 1;
        }
    }
    return allowed;
}

// verdict_allowed_v6 is the IPv6 analogue of verdict_allowed_v4, dst_ip6 in
// network byte order.
static __always_inline __u8 verdict_allowed_v6(const __u8 dst_ip6[16], __u16 dst_port, __u8 proto) {
    struct lpm_key_v6 key;
    __builtin_memset(&key, 0, sizeof(key));
    key.prefixlen = 128;
    __builtin_memcpy(key.ip, dst_ip6, 16);

    struct lpm_val *rule = bpf_map_lookup_elem(&map_cidrs_v6, &key);
    __u8 decision_made = 0;
    __u8 allowed = 0;

    if (rule) {
        if (rule->port_specific == 0) {
            decision_made = 1;
            if (rule->action == 1) {
                allowed = 1;
            }
        } else {
            struct port_key_v6 pkey;
            __builtin_memset(&pkey, 0, sizeof(pkey));
            __builtin_memcpy(pkey.ip, dst_ip6, 16);
            pkey.port = dst_port;
            pkey.proto = proto;

            struct port_val *pval = bpf_map_lookup_elem(&map_ports_v6, &pkey);
            if (pval) {
                decision_made = 1;
                if (pval->action == 1) {
                    allowed = 1;
                }
            } else {
                __builtin_memset(pkey.ip, 0, 16);
                pval = bpf_map_lookup_elem(&map_ports_v6, &pkey);
                if (pval) {
                    decision_made = 1;
                    if (pval->action == 1) {
                        allowed = 1;
                    }
                }
            }
        }
    } else {
        struct port_key_v6 pkey;
        __builtin_memset(&pkey, 0, sizeof(pkey));
        pkey.port = dst_port;
        pkey.proto = proto;

        struct port_val *pval = bpf_map_lookup_elem(&map_ports_v6, &pkey);
        if (pval) {
            decision_made = 1;
            if (pval->action == 1) {
                allowed = 1;
            }
        }
    }

    if (!decision_made) {
        __u32 def_key = 0;
        __u8 *default_action = bpf_map_lookup_elem(&map_default_action, &def_key);
        if (default_action && *default_action == 1) {
            allowed = 1;
        }
    }
    return allowed;
}
