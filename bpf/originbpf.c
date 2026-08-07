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

// Flow-origin observer (issue #106, phase 3a). Bridge-networked container
// packets cross a netns and NAT before tc_egress sees them, so the
// cookie→pid/step lookup there finds nothing — container traffic arrives
// unattributed. cgroup_skb/egress runs in socket context inside the
// originating netns, before NAT, where the cookie is real; this program
// records each flow's pre-NAT origin so userspace can join it back onto the
// post-NAT TC verdict events (pkg/origin) and classify container traffic
// (pkg/containers).
//
// Observer ONLY: every packet returns 1 (pass). The parse/emit helpers
// return void so no code path can reach the program's return value — the
// zero-enforcement-risk property is structural, and pinned by
// TestOriginEgressAlwaysAllows. TC remains the sole enforcer in 3a; phase 3b
// may add a verdict path here (which is why the parser is self-contained
// rather than shared with tcbpf.c — that file stays untouched).
//
// Standalone collection on purpose: a verifier rejection here must degrade
// attribution only, never enforcement, so nothing is shared with the tcbpf
// collection — not even maps. Records carry the socket cookie and userspace
// resolves pid/step against map_sock_pid/map_sock_step at read time, which
// also sidesteps the MapReplacements size-matching hazard with the
// step-attribution map shrink in cmd/start.go. Helpers used
// (bpf_get_socket_cookie 4.12, bpf_skb_cgroup_id 5.7, ringbuf 5.8) are all
// within the 5.8 kernel floor. Unlike TC, skb data here starts at the IP
// header: no Ethernet header, no VLAN tags, l3 offset is always 0. Dispatch
// is on the IP version nibble, not skb->protocol, because PROG_TEST_RUN
// cannot set skb->protocol for cgroup_skb programs and the nibble works
// identically live.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// IP protocol numbers (subset needed here)
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_HOPOPTS 0    // IPv6 Hop-by-Hop Options
#define IPPROTO_ROUTING 43   // IPv6 Routing Header
#define IPPROTO_FRAGMENT 44  // IPv6 Fragment Header
#define IPPROTO_ICMPV6 58
#define IPPROTO_DSTOPTS 60   // IPv6 Destination Options
#define IPPROTO_MH 135       // IPv6 Mobility Header

// IPv6 header is always 40 bytes (no variable-length options like IPv4 IHL)
#define IPV6_HDR_LEN 40

// TCP flags (byte 13 of TCP header) - explicit masks for portability
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

// origin_event.flags bits
#define ORIGIN_FLAG_TCP_SYN 0x1  // record was emitted for a connection-opening SYN

// One record per observed flow origin. 8-byte fields first so the packed C
// layout equals Go's natural layout (72 bytes, no hidden padding); addresses
// follow blocked_event's convention (v4 host byte order, v6 raw bytes). Go
// mirror: originEvent in pkg/origin; layout pinned by
// TestOriginEventLayoutMatchesBTF in originbpf_test.go.
struct origin_event {
    __u64 cookie;      // socket cookie — userspace join key to map_sock_pid / map_sock_step
    __u64 cgroup_id;   // socket cgroup id — container identity seam for pkg/containers
    __u64 timestamp;   // bpf_ktime_get_ns(), same clock domain as blocked_event.timestamp
    __u32 src_ip;      // IPv4, host byte order — pre-NAT, so a container's own address
    __u32 dst_ip;      // IPv4, host byte order (MASQUERADE never rewrites dst)
    __u8 src_ip6[16];  // IPv6 (used when ip_version == 6)
    __u8 dst_ip6[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 ip_version;   // 4 or 6
    __u8 ip_proto;     // L4 protocol; non-TCP/UDP records carry ports 0 (joins TC protocol blocks)
    __u8 flags;        // ORIGIN_FLAG_* bits
    __u8 pad;
} __attribute__((packed));

// BTF anchor — see the blocked_event anchor in tcbpf.c for rationale.
const struct origin_event *btf_anchor_origin_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} map_origin_events SEC(".maps");

// Emission dedup key: one record per socket/destination tuple per interval.
struct origin_seen_key {
    __u64 cookie;
    __u8 dst[16];       // v4 address in bytes 0-3 (host order), rest zero
    __u16 dst_port;
    __u8 ip_proto;
    __u8 ip_version;
} __attribute__((packed));

// Re-emit interval: suppresses SYN retransmits of blocked flows and repeated
// DNS queries while refreshing the userspace join store for long-lived
// flows. Same pattern and 10s rationale as map_midstream_seen in tcbpf.c;
// LRU eviction under pressure costs a duplicate record, never a lost one.
#define ORIGIN_EMIT_INTERVAL_NS (10ULL * 1000000000ULL)

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct origin_seen_key);
    __type(value, __u64);   // last emit, bpf_ktime_get_ns()
    __uint(max_entries, 4096);
} map_origin_seen SEC(".maps");

// Dedup-then-emit one origin record. A concurrent lookup/update race across
// CPUs costs at most one duplicate record — not worth an atomic. Ringbuf
// reservation failure just drops the record: attribution degrades, nothing
// else does.
static __always_inline void origin_emit(struct __sk_buff *skb, __u8 ip_version,
                                        __u8 ip_proto, __u8 flags,
                                        __u32 src_ip, __u32 dst_ip,
                                        const __u8 src_ip6[16], const __u8 dst_ip6[16],
                                        __u16 src_port, __u16 dst_port) {
    __u64 cookie = bpf_get_socket_cookie(skb);

    struct origin_seen_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.cookie = cookie;
    if (ip_version == 4)
        __builtin_memcpy(key.dst, &dst_ip, 4);
    else
        __builtin_memcpy(key.dst, dst_ip6, 16);
    key.dst_port = dst_port;
    key.ip_proto = ip_proto;
    key.ip_version = ip_version;

    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&map_origin_seen, &key);
    if (last && now - *last < ORIGIN_EMIT_INTERVAL_NS)
        return;
    bpf_map_update_elem(&map_origin_seen, &key, &now, BPF_ANY);

    struct origin_event *evt = bpf_ringbuf_reserve(&map_origin_events, sizeof(*evt), 0);
    if (!evt)
        return;
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->cookie = cookie;
    evt->cgroup_id = bpf_skb_cgroup_id(skb);
    evt->timestamp = now;
    evt->ip_version = ip_version;
    evt->ip_proto = ip_proto;
    evt->flags = flags;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    if (ip_version == 4) {
        evt->src_ip = src_ip;
        evt->dst_ip = dst_ip;
    } else {
        __builtin_memcpy(evt->src_ip6, src_ip6, 16);
        __builtin_memcpy(evt->dst_ip6, dst_ip6, 16);
    }
    bpf_ringbuf_submit(evt, 0);
}

// Emission policy, chosen to shadow what tc_egress can emit so every TC
// verdict event has a joinable origin record and little else is produced:
//   - TCP: connection-opening SYNs only (mirrors TC's allowed-event policy;
//     blocked-flow SYN retransmits re-emit past the dedup interval, which
//     keeps the join store fresh). Established-flow segments exit after two
//     header loads — that is the hot path whose cost the 3a telemetry
//     measures.
//   - UDP: every packet is a candidate (dedup collapses repeats).
//   - Other protocols: candidate with ports 0, matching the shape of TC
//     protocol-block events.
//   - Skipped entirely: non-first fragments (no L4 header; the flow's
//     opening packet already produced a record) and, for v6, multicast and
//     ICMPv6 (TC allows both silently — nothing to join).

static __always_inline void origin_observe_v4(struct __sk_buff *skb) {
    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, 0, &ip_hdr, sizeof(ip_hdr)) < 0)
        return;

    __u16 frag_off = bpf_ntohs(ip_hdr.frag_off);
    if ((frag_off & 0x1FFF) != 0)
        return;

    __u32 ip_hlen = (ip_hdr.ihl & 0x0F) * 4;
    if (ip_hlen < sizeof(struct iphdr) || ip_hlen > 60)
        return;

    __u32 src_ip = bpf_ntohl(ip_hdr.saddr);
    __u32 dst_ip = bpf_ntohl(ip_hdr.daddr);
    __u8 ip_proto = ip_hdr.protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 flags = 0;

    if (ip_proto == IPPROTO_TCP) {
        struct tcphdr tcp_hdr;
        if (bpf_skb_load_bytes(skb, ip_hlen, &tcp_hdr, sizeof(tcp_hdr)) < 0)
            return;
        __u8 tcp_flags;
        if (bpf_skb_load_bytes(skb, ip_hlen + 13, &tcp_flags, 1) < 0)
            return;
        if (!(tcp_flags & TCP_FLAG_SYN) || (tcp_flags & TCP_FLAG_ACK))
            return;
        flags = ORIGIN_FLAG_TCP_SYN;
        src_port = bpf_ntohs(tcp_hdr.source);
        dst_port = bpf_ntohs(tcp_hdr.dest);
    } else if (ip_proto == IPPROTO_UDP) {
        struct udphdr udp_hdr;
        if (bpf_skb_load_bytes(skb, ip_hlen, &udp_hdr, sizeof(udp_hdr)) < 0)
            return;
        src_port = bpf_ntohs(udp_hdr.source);
        dst_port = bpf_ntohs(udp_hdr.dest);
    }

    __u8 zero16[16] = {};
    origin_emit(skb, 4, ip_proto, flags, src_ip, dst_ip, zero16, zero16,
                src_port, dst_port);
}

static __always_inline int is_ipv6_ext_hdr(__u8 nexthdr) {
    return nexthdr == IPPROTO_HOPOPTS ||
           nexthdr == IPPROTO_ROUTING ||
           nexthdr == IPPROTO_FRAGMENT ||
           nexthdr == IPPROTO_DSTOPTS ||
           nexthdr == IPPROTO_MH;
}

static __always_inline void origin_observe_v6(struct __sk_buff *skb) {
    struct ipv6hdr ip6_hdr;
    if (bpf_skb_load_bytes(skb, 0, &ip6_hdr, sizeof(ip6_hdr)) < 0)
        return;

    __u8 src_ip6[16];
    __u8 dst_ip6[16];
    __builtin_memcpy(src_ip6, &ip6_hdr.addrs.saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(dst_ip6, &ip6_hdr.addrs.daddr.in6_u.u6_addr8, 16);

    if (dst_ip6[0] == 0xff)
        return;

    __u8 nexthdr = ip6_hdr.nexthdr;
    __u32 l4_offset = IPV6_HDR_LEN;

    // Walk the extension header chain — same discipline and 6-iteration
    // bound as handle_ipv6 in tcbpf.c.
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (!is_ipv6_ext_hdr(nexthdr))
            break;

        if (nexthdr == IPPROTO_FRAGMENT) {
            __u8 frag_hdr[8];
            if (bpf_skb_load_bytes(skb, l4_offset, frag_hdr, sizeof(frag_hdr)) < 0)
                return;
            nexthdr = frag_hdr[0];
            __u16 frag_off = ((__u16)frag_hdr[2] << 8) | frag_hdr[3];
            if ((frag_off & 0xFFF8) != 0)
                return;  // non-first fragment
            l4_offset += 8;
        } else {
            __u8 ext_hdr[2];
            if (bpf_skb_load_bytes(skb, l4_offset, ext_hdr, 2) < 0)
                return;
            nexthdr = ext_hdr[0];
            l4_offset += (ext_hdr[1] + 1) * 8;
        }
    }

    if (nexthdr == IPPROTO_ICMPV6)
        return;

    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 flags = 0;

    if (nexthdr == IPPROTO_TCP) {
        struct tcphdr tcp_hdr;
        if (bpf_skb_load_bytes(skb, l4_offset, &tcp_hdr, sizeof(tcp_hdr)) < 0)
            return;
        __u8 tcp_flags;
        if (bpf_skb_load_bytes(skb, l4_offset + 13, &tcp_flags, 1) < 0)
            return;
        if (!(tcp_flags & TCP_FLAG_SYN) || (tcp_flags & TCP_FLAG_ACK))
            return;
        flags = ORIGIN_FLAG_TCP_SYN;
        src_port = bpf_ntohs(tcp_hdr.source);
        dst_port = bpf_ntohs(tcp_hdr.dest);
    } else if (nexthdr == IPPROTO_UDP) {
        struct udphdr udp_hdr;
        if (bpf_skb_load_bytes(skb, l4_offset, &udp_hdr, sizeof(udp_hdr)) < 0)
            return;
        src_port = bpf_ntohs(udp_hdr.source);
        dst_port = bpf_ntohs(udp_hdr.dest);
    }

    origin_emit(skb, 6, nexthdr, flags, 0, 0, src_ip6, dst_ip6,
                src_port, dst_port);
}

SEC("cgroup_skb/egress")
int cg_origin_egress(struct __sk_buff *skb) {
    __u8 first_byte;
    if (bpf_skb_load_bytes(skb, 0, &first_byte, 1) == 0) {
        __u8 version = first_byte >> 4;
        if (version == 4)
            origin_observe_v4(skb);
        else if (version == 6)
            origin_observe_v6(skb);
    }
    // Observer: pass unconditionally. Under BPF_F_ALLOW_MULTI the effective
    // egress verdict is the AND of every attached program, and constant 1 is
    // its identity — coexisting cgroup programs are unaffected.
    return 1;
}

char _license[] SEC("license") = "GPL";
