//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TC action return codes
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Ethernet protocols
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100   // 802.1Q VLAN tag
#define ETH_P_8021AD 0x88A8  // 802.1ad QinQ (double VLAN)

// IP protocol numbers
#define IPPROTO_ICMP 1
#define IPPROTO_IGMP 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_HOPOPTS 0    // IPv6 Hop-by-Hop Options
#define IPPROTO_ROUTING 43   // IPv6 Routing Header
#define IPPROTO_FRAGMENT 44  // IPv6 Fragment Header
#define IPPROTO_GRE 47
#define IPPROTO_ESP 50
#define IPPROTO_AH 51
#define IPPROTO_ICMPV6 58
#define IPPROTO_DSTOPTS 60   // IPv6 Destination Options
#define IPPROTO_MH 135       // IPv6 Mobility Header
#define IPPROTO_SCTP 132

// IPv6 header is always 40 bytes (no variable-length options like IPv4 IHL)
#define IPV6_HDR_LEN 40

// TCP flags (byte 13 of TCP header) - explicit masks for portability
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

// ---- IPv4 structs ----

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

// Key for port-specific rules
struct port_key {
    __u32 ip;
    __u16 port;
    __u16 pad;
} __attribute__((packed));

// Value for port rules - just allow/deny
struct port_val {
    __u8 action;      // 0 = deny, 1 = allow
    __u8 pad[3];
} __attribute__((packed));

// ---- IPv6 structs ----

// IPv6 LPM trie key (128-bit IP)
struct lpm_key_v6 {
    __u32 prefixlen;
    __u8 ip[16];
} __attribute__((packed));

// IPv6 port key
struct port_key_v6 {
    __u8 ip[16];
    __u16 port;
    __u16 pad;
} __attribute__((packed));

// ---- Event struct with version discriminator ----

struct blocked_event {
    __u8 ip_version;   // 4 or 6
    __u8 allowed;      // 0 = blocked, 1 = allowed
    __u8 pad1[2];
    __u32 src_ip;      // IPv4 (used when ip_version == 4)
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 src_ip6[16];  // IPv6 (used when ip_version == 6)
    __u8 dst_ip6[16];
    __u64 timestamp;
    __u32 pid;         // process ID (looked up via /proc in userspace)
    __u32 _pad2;       // align to 64 bytes to match Go struct layout
} __attribute__((packed));


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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} map_events SEC(".maps");

// Audit mode map (0 = enforce/block, 1 = audit/log only)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} map_audit_mode SEC(".maps");

// LRU hash map: socket cookie → PID (populated by cgroup programs, read by TC)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 65536);
} map_sock_pid SEC(".maps");


// Helper: check audit mode and return appropriate action
static __always_inline int check_audit_or_block(void) {
    __u32 audit_key = 0;
    __u8 *audit_mode = bpf_map_lookup_elem(&map_audit_mode, &audit_key);
    if (audit_mode && *audit_mode == 1) {
        return TC_ACT_OK;  // Audit mode: log but don't block
    }
    return TC_ACT_SHOT;  // Enforce mode: block
}

// Helper: submit an event for IPv4
static __always_inline void submit_event_v4(struct __sk_buff *skb, __u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 is_allowed) {
    struct blocked_event *evt = bpf_ringbuf_reserve(&map_events, sizeof(*evt), 0);
    if (evt) {
        __builtin_memset(evt, 0, sizeof(*evt));
        evt->ip_version = 4;
        evt->allowed = is_allowed;
        evt->src_ip = src_ip;
        evt->dst_ip = dst_ip;
        evt->src_port = src_port;
        evt->dst_port = dst_port;
        evt->timestamp = bpf_ktime_get_ns();
        __u64 cookie = bpf_get_socket_cookie(skb);
        __u32 *pid = bpf_map_lookup_elem(&map_sock_pid, &cookie);
        evt->pid = pid ? *pid : 0;
        bpf_ringbuf_submit(evt, 0);
    }
}

// Helper: check if nexthdr is an IPv6 extension header
static __always_inline int is_ipv6_ext_hdr(__u8 nexthdr) {
    return nexthdr == IPPROTO_HOPOPTS ||
           nexthdr == IPPROTO_ROUTING ||
           nexthdr == IPPROTO_FRAGMENT ||
           nexthdr == IPPROTO_DSTOPTS ||
           nexthdr == IPPROTO_MH;
}

// Helper: submit an event for IPv6
static __always_inline void submit_event_v6(struct __sk_buff *skb, __u8 src_ip6[16], __u8 dst_ip6[16], __u16 src_port, __u16 dst_port, __u8 is_allowed) {
    struct blocked_event *evt = bpf_ringbuf_reserve(&map_events, sizeof(*evt), 0);
    if (evt) {
        __builtin_memset(evt, 0, sizeof(*evt));
        evt->ip_version = 6;
        evt->allowed = is_allowed;
        evt->src_port = src_port;
        evt->dst_port = dst_port;
        __builtin_memcpy(evt->src_ip6, src_ip6, 16);
        __builtin_memcpy(evt->dst_ip6, dst_ip6, 16);
        evt->timestamp = bpf_ktime_get_ns();
        __u64 cookie = bpf_get_socket_cookie(skb);
        __u32 *pid = bpf_map_lookup_elem(&map_sock_pid, &cookie);
        evt->pid = pid ? *pid : 0;
        bpf_ringbuf_submit(evt, 0);
    }
}

// Handle IPv4 egress traffic
static __always_inline int handle_ipv4(struct __sk_buff *skb, __u32 l3_offset) {
    // Parse IP header - use load_bytes to avoid issues
    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, l3_offset, &ip_hdr, sizeof(ip_hdr)) < 0)
        return check_audit_or_block();  // Block malformed packets

    // Network byte order for map lookups: LPM trie prefix matching compares raw
    // bytes from lowest address, so the most significant octet must come first.
    __u32 dst_ip_nbo = ip_hdr.daddr;
    // Host byte order for event reporting
    __u32 src_ip = bpf_ntohl(ip_hdr.saddr);
    __u32 dst_ip = bpf_ntohl(ip_hdr.daddr);
    __u8 ip_proto = ip_hdr.protocol;

    // Only allow TCP and UDP protocols - block everything else
    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
        // Log blocked non-TCP/UDP protocol (store protocol number in dst_port)
        submit_event_v4(skb, src_ip, dst_ip, 0, ip_proto, 0);
        return check_audit_or_block();
    }

    // Calculate actual IP header length
    __u32 ip_hlen = (ip_hdr.ihl & 0x0F) * 4;
    if (ip_hlen < sizeof(struct iphdr))
        return check_audit_or_block();  // Block invalid header length
    if (ip_hlen > 60) // Max IP header length
        return check_audit_or_block();  // Block invalid header length

    // Check for IP fragmentation. The frag_off field contains:
    // - Bits 0-12: Fragment offset (in 8-byte units)
    // - Bit 13: MF (More Fragments)
    // - Bit 14: DF (Don't Fragment)
    // - Bit 15: Reserved
    // Non-first fragments (offset > 0) don't have L4 headers at the expected offset.
    __u16 frag_off = bpf_ntohs(ip_hdr.frag_off);
    __u8 is_non_first_fragment = (frag_off & 0x1FFF) != 0;

    // Initialize ports
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 is_tcp_syn = 0;

    // Only parse L4 headers for non-fragmented packets or first fragments.
    // Non-first fragments don't contain L4 headers, so we skip parsing and
    // rely on IP-level CIDR rules (port-specific rules won't match with port=0).
    if (!is_non_first_fragment) {
        // For TC programs, we need to use load_bytes for variable offsets
        __u32 l4_offset = l3_offset + ip_hlen;

        if (ip_proto == IPPROTO_TCP) {
            struct tcphdr tcp_hdr;
            if (bpf_skb_load_bytes(skb, l4_offset, &tcp_hdr, sizeof(tcp_hdr)) < 0)
                return check_audit_or_block();  // Block malformed TCP packets
            src_port = bpf_ntohs(tcp_hdr.source);
            dst_port = bpf_ntohs(tcp_hdr.dest);
            // Read flags byte directly (offset 13 in TCP header) for portability.
            // Bitfield layout is architecture-dependent, explicit masks are not.
            __u8 tcp_flags;
            if (bpf_skb_load_bytes(skb, l4_offset + 13, &tcp_flags, 1) < 0)
                return check_audit_or_block();
            if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
                is_tcp_syn = 1;
            }
        } else if (ip_proto == IPPROTO_UDP) {
            struct udphdr udp_hdr;
            if (bpf_skb_load_bytes(skb, l4_offset, &udp_hdr, sizeof(udp_hdr)) < 0)
                return check_audit_or_block();  // Block malformed UDP packets
            src_port = bpf_ntohs(udp_hdr.source);
            dst_port = bpf_ntohs(udp_hdr.dest);
        }
    }

    // Check firewall rules using LPM trie (network byte order key)
    struct lpm_key key = {
        .prefixlen = 32,
        .ip = dst_ip_nbo
    };

    struct lpm_val *rule = bpf_map_lookup_elem(&map_cidrs, &key);
    __u8 decision_made = 0;
    __u8 allowed = 0;

    if (rule) {
        // We have a matching rule
        if (rule->port_specific == 0) {
            // Rule applies to all ports
            decision_made = 1;
            if (rule->action == 1) {
                allowed = 1;
            }
        } else {
            // Rule has specific ports - check port map
            struct port_key pkey = {
                .ip = dst_ip_nbo,
                .port = dst_port,
                .pad = 0
            };
            struct port_val *pval = bpf_map_lookup_elem(&map_ports, &pkey);
            if (pval) {
                // Specific rule for this IP:port
                decision_made = 1;
                if (pval->action == 1) {
                    allowed = 1;
                }
            } else {
                // Check for wildcard 0.0.0.0:port entries
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
        // No LPM match - check for wildcard port rules
        struct port_key pkey = {
            .ip = 0,  // 0.0.0.0 wildcard
            .port = dst_port,
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

    // If no specific rule made a decision, use default action
    if (!decision_made) {
        __u32 def_key = 0;
        __u8 *default_action = bpf_map_lookup_elem(&map_default_action, &def_key);
        if (default_action && *default_action == 1) {
            allowed = 1;
        }
    }

    if (!allowed) {
        if (is_tcp_syn || ip_proto == IPPROTO_UDP) {
            submit_event_v4(skb, src_ip, dst_ip, src_port, dst_port, 0);
        }
        return check_audit_or_block();
    }

    if (is_tcp_syn) {
        submit_event_v4(skb, src_ip, dst_ip, src_port, dst_port, 1);
    }
    return TC_ACT_OK;
}

// Handle IPv6 egress traffic
static __always_inline int handle_ipv6(struct __sk_buff *skb, __u32 l3_offset) {
    // Parse IPv6 header (fixed 40 bytes, no variable IHL like IPv4)
    struct ipv6hdr ip6_hdr;
    if (bpf_skb_load_bytes(skb, l3_offset, &ip6_hdr, sizeof(ip6_hdr)) < 0)
        return check_audit_or_block();  // Block malformed packets

    // Extract addresses (kept in network byte order for map lookups)
    __u8 src_ip6[16];
    __u8 dst_ip6[16];
    __builtin_memcpy(src_ip6, &ip6_hdr.addrs.saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(dst_ip6, &ip6_hdr.addrs.daddr.in6_u.u6_addr8, 16);

    // Always allow IPv6 multicast (ff00::/8). This includes:
    // - NDP (neighbor discovery, router solicitation) to ff02::1, ff02::2
    // - MLD/MLDv2 (multicast listener discovery) to ff02::16
    // - Other link-local multicast infrastructure traffic
    // These often use ICMPv6 wrapped in Hop-by-Hop extension headers,
    // making protocol-based checks unreliable. Multicast is never
    // routable egress traffic, so it's safe to always allow.
    if (dst_ip6[0] == 0xff)
        return TC_ACT_OK;

    __u8 nexthdr = ip6_hdr.nexthdr;
    __u32 l4_offset = l3_offset + IPV6_HDR_LEN;
    __u8 is_non_first_fragment = 0;

    // Walk IPv6 extension header chain (max 6 iterations for verifier).
    // Extension headers we handle: Hop-by-Hop (0), Routing (43), Fragment (44),
    // Destination Options (60), Mobility (135).
    // We must walk ALL extension headers before checking the final protocol.
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (!is_ipv6_ext_hdr(nexthdr))
            break;

        if (nexthdr == IPPROTO_FRAGMENT) {
            // Fragment header is 8 bytes: nexthdr(1) + reserved(1) + frag_off(2) + id(4)
            __u8 frag_hdr[8];
            if (bpf_skb_load_bytes(skb, l4_offset, frag_hdr, sizeof(frag_hdr)) < 0)
                return check_audit_or_block();
            nexthdr = frag_hdr[0];
            // Fragment offset is in bytes 2-3, bits 0-12 contain offset (in 8-byte units)
            // Layout: [offset:13 bits][res:2 bits][M:1 bit]
            __u16 frag_off = ((__u16)frag_hdr[2] << 8) | frag_hdr[3];
            if ((frag_off & 0xFFF8) != 0)
                is_non_first_fragment = 1;
            l4_offset += 8;
        } else {
            // Standard extension header: next_hdr(1) + len(1) + data
            // Length field = number of 8-byte units after first 8 bytes
            // Total length = (len + 1) * 8
            __u8 ext_hdr[2];
            if (bpf_skb_load_bytes(skb, l4_offset, ext_hdr, 2) < 0)
                return check_audit_or_block();
            nexthdr = ext_hdr[0];
            l4_offset += (ext_hdr[1] + 1) * 8;
        }
    }

    // Always allow ICMPv6 — it's required for IPv6 NDP (neighbor discovery,
    // router solicitation, etc.) which is the IPv6 equivalent of ARP.
    // Blocking it breaks basic IPv6 connectivity.
    // Check AFTER extension header walking to handle fragmented ICMPv6.
    if (nexthdr == IPPROTO_ICMPV6)
        return TC_ACT_OK;

    // Only allow TCP and UDP - block other protocols
    if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP) {
        submit_event_v6(skb, src_ip6, dst_ip6, 0, nexthdr, 0);
        return check_audit_or_block();
    }

    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 is_tcp_syn = 0;

    // Only parse L4 headers for non-fragmented packets or first fragments.
    // Non-first fragments don't contain L4 headers at this offset.
    if (!is_non_first_fragment) {
        if (nexthdr == IPPROTO_TCP) {
            struct tcphdr tcp_hdr;
            if (bpf_skb_load_bytes(skb, l4_offset, &tcp_hdr, sizeof(tcp_hdr)) < 0)
                return check_audit_or_block();  // Block malformed TCP packets
            src_port = bpf_ntohs(tcp_hdr.source);
            dst_port = bpf_ntohs(tcp_hdr.dest);
            // Read flags byte directly (offset 13 in TCP header) for portability.
            // Bitfield layout is architecture-dependent, explicit masks are not.
            __u8 tcp_flags;
            if (bpf_skb_load_bytes(skb, l4_offset + 13, &tcp_flags, 1) < 0)
                return check_audit_or_block();
            if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
                is_tcp_syn = 1;
            }
        } else if (nexthdr == IPPROTO_UDP) {
            struct udphdr udp_hdr;
            if (bpf_skb_load_bytes(skb, l4_offset, &udp_hdr, sizeof(udp_hdr)) < 0)
                return check_audit_or_block();  // Block malformed UDP packets
            src_port = bpf_ntohs(udp_hdr.source);
            dst_port = bpf_ntohs(udp_hdr.dest);
        }
    }

    // Check firewall rules using IPv6 LPM trie
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
            // Check IPv6 port map
            struct port_key_v6 pkey;
            __builtin_memset(&pkey, 0, sizeof(pkey));
            __builtin_memcpy(pkey.ip, dst_ip6, 16);
            pkey.port = dst_port;

            struct port_val *pval = bpf_map_lookup_elem(&map_ports_v6, &pkey);
            if (pval) {
                decision_made = 1;
                if (pval->action == 1) {
                    allowed = 1;
                }
            } else {
                // Check for wildcard [::]:port entries
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
        // No LPM match - check for wildcard port rules
        struct port_key_v6 pkey;
        __builtin_memset(&pkey, 0, sizeof(pkey));
        pkey.port = dst_port;

        struct port_val *pval = bpf_map_lookup_elem(&map_ports_v6, &pkey);
        if (pval) {
            decision_made = 1;
            if (pval->action == 1) {
                allowed = 1;
            }
        }
    }

    // If no specific rule made a decision, use default action
    if (!decision_made) {
        __u32 def_key = 0;
        __u8 *default_action = bpf_map_lookup_elem(&map_default_action, &def_key);
        if (default_action && *default_action == 1) {
            allowed = 1;
        }
    }

    if (!allowed) {
        if (is_tcp_syn || nexthdr == IPPROTO_UDP) {
            submit_event_v6(skb, src_ip6, dst_ip6, src_port, dst_port, 0);
        }
        return check_audit_or_block();
    }

    if (is_tcp_syn) {
        submit_event_v6(skb, src_ip6, dst_ip6, src_port, dst_port, 1);
    }
    return TC_ACT_OK;
}

// Cgroup programs to track socket cookie → PID mapping
// These fire on connect() and have process context available
SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&map_sock_pid, &cookie, &pid, BPF_ANY);
    return 1;
}

SEC("cgroup/connect6")
int cg_connect6(struct bpf_sock_addr *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&map_sock_pid, &cookie, &pid, BPF_ANY);
    return 1;
}

// sendmsg hooks for UDP sockets that use sendto()/sendmsg() without connect().
// Without these, connectionless UDP traffic won't have a cookie→PID entry.
SEC("cgroup/sendmsg4")
int cg_sendmsg4(struct bpf_sock_addr *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&map_sock_pid, &cookie, &pid, BPF_ANY);
    return 1;
}

SEC("cgroup/sendmsg6")
int cg_sendmsg6(struct bpf_sock_addr *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&map_sock_pid, &cookie, &pid, BPF_ANY);
    return 1;
}

SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return check_audit_or_block();  // Block malformed packets

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    __u32 l3_offset = sizeof(struct ethhdr);

    // Handle VLAN tags (802.1Q and 802.1ad QinQ)
    // VLAN header is 4 bytes: TPID (2) + TCI (2), inner protocol in bytes 2-3
    if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
        __u8 vlan_hdr[4];
        if (bpf_skb_load_bytes(skb, l3_offset, vlan_hdr, 4) < 0)
            return check_audit_or_block();
        eth_proto = ((__u16)vlan_hdr[2] << 8) | vlan_hdr[3];
        l3_offset += 4;

        // Handle QinQ (double VLAN) - second tag after first
        if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
            if (bpf_skb_load_bytes(skb, l3_offset, vlan_hdr, 4) < 0)
                return check_audit_or_block();
            eth_proto = ((__u16)vlan_hdr[2] << 8) | vlan_hdr[3];
            l3_offset += 4;
        }
    }

    if (eth_proto == ETH_P_IP)
        return handle_ipv4(skb, l3_offset);

    if (eth_proto == ETH_P_IPV6)
        return handle_ipv6(skb, l3_offset);

    // Allow non-IP protocols (ARP, etc.) - required for basic networking
    return TC_ACT_OK;
}

// Handle ingress traffic - currently just allows everything
SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *skb) {
    // Allow all ingress traffic
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
