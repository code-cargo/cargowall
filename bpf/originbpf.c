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

// Flow-origin recorder and primary egress verdict (issue #106).
// Bridge-networked container packets cross a netns and NAT before tc_egress
// sees them, so the cookie→pid/step lookup there finds nothing — container
// traffic arrives unattributed, and no per-step policy could ever select on
// it. cgroup_skb/egress runs in socket context inside the originating netns,
// before NAT, where the cookie is real: this program records each flow's
// pre-NAT origin and, once raised out of observe mode, decides its fate.
//
// WHAT THIS PROGRAM DOES depends on map_origin_config (ORIGIN_MODE_*):
//   observe  — phase-3a behavior: pass everything, record origins only.
//   shadow   — compute the verdict, record would-blocks, still pass.
//   enforce  — DROP denied traffic here (return 0). This program is then the
//              primary egress enforcement point for traffic with a local
//              socket; tc_egress remains attached as the fail-closed
//              backstop for traffic that never traversed one (AF_PACKET,
//              non-IP frames, forwarded packets, TCP minisockets) and for
//              the case where this program fails to load or attach.
// Userspace raises the mode only AFTER the allowlist is programmed, so
// attaching early can never run this live against empty maps.
//
// The allow/deny decision and its rule maps are SHARED with tc_egress via
// verdict.h, wired to one set of kernel maps by MapReplacements. That
// deliberately reverses phase 3a's standalone-collection isolation (whose
// point was that a verifier rejection could only cost attribution): a
// divergence between the primary hook and its backstop would be a security
// bug, so the decision must exist exactly once. The blast radius is bounded
// instead by the mode gate and by TC staying attached.
//
// Helpers used (bpf_get_socket_cookie 4.12, bpf_skb_cgroup_id 5.7, ringbuf
// 5.8) are all within the 5.8 kernel floor. Unlike TC, skb data here starts
// at the IP header: no Ethernet header, no VLAN tags, l3 offset is always 0.
// Dispatch is on the IP version nibble, not skb->protocol, because
// PROG_TEST_RUN cannot set skb->protocol for cgroup_skb programs and the
// nibble works identically live.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The allow/deny decision and its rule maps are shared with tc_egress so the
// enforcing hook and its backstop can never diverge. See bpf/verdict.h.
#include "verdict.h"

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
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

// The loopback device is ifindex 1 in every network namespace (it is
// registered first, by loopback_net_init). Traffic egressing it never leaves
// the host, whatever address it carries.
#define LOOPBACK_IFINDEX 1

// origin_event.flags bits
#define ORIGIN_FLAG_TCP_SYN 0x1        // record was emitted for a connection-opening SYN
#define ORIGIN_FLAG_TCP_MIDSTREAM 0x2  // segment of an established flow: ACK set, no
                                       // SYN/RST — the same guard as is_tcp_midstream in
                                       // tcbpf.c, so kernel RST replies to inbound port
                                       // scans and SYN-ACK replies to inbound handshakes
                                       // are never reported as killed egress connections

// origin_event.verdict values — what this hook decided about the flow.
#define ORIGIN_VERDICT_NONE        0  // observe mode: no verdict computed
#define ORIGIN_VERDICT_ALLOW       1  // policy allows
#define ORIGIN_VERDICT_WOULD_BLOCK 2  // policy denies, but the packet was passed
                                      // (shadow mode, or audit posture in enforce)
#define ORIGIN_VERDICT_BLOCK       3  // policy denies and the packet was dropped here

// Enforcement mode, read per packet from map_origin_config. Userspace flips
// this AFTER the allowlist, DNS/infra auto-allows, and existing-connection
// gating are programmed — never at attach — so the program can be attached
// early (the observer and join store need it) without ever running the
// attach-before-program race that cmd/start.go's TC ordering avoids.
#define ORIGIN_MODE_OBSERVE 0  // phase 3a: always pass, emit origin records
#define ORIGIN_MODE_SHADOW  1  // compute the verdict, emit would-blocks, still pass
#define ORIGIN_MODE_ENFORCE 2  // authoritative: drop denied traffic here

// map_origin_config keys.
#define ORIGIN_CFG_KEY_MODE 0         // ORIGIN_MODE_*
#define ORIGIN_CFG_KEY_LO_CARVEOUT 1  // 1 = carve out skb->ifindex == lo (see below)

// One record per observed flow origin. 8-byte fields first so the packed C
// layout equals Go's natural layout (72 bytes, no hidden padding); addresses
// follow blocked_event's convention (v4 host byte order, v6 raw bytes). Go
// mirror: OriginEvent in bpf/origin_event.go — the ONE mirror, cast over
// ringbuf bytes by pkg/origin and pinned by TestOriginEventLayoutMatchesBTF
// in originbpf_test.go, so the production reader can never drift from the
// layout the test validates.
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
    __u8 verdict;      // ORIGIN_VERDICT_* — occupies the former pad byte, layout unchanged
} __attribute__((packed));

// BTF anchor — see the blocked_event anchor in tcbpf.c for rationale.
const struct origin_event *btf_anchor_origin_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} map_origin_events SEC(".maps");

// Runtime mode gate (ORIGIN_MODE_*), owned by this collection and written by
// userspace. Same "loaded but inert until seeded" pattern as
// map_step_state.enabled and map_audit_mode.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 2);
} map_origin_config SEC(".maps");

static __always_inline __u8 origin_mode(void) {
    __u32 key = ORIGIN_CFG_KEY_MODE;
    __u8 *mode = bpf_map_lookup_elem(&map_origin_config, &key);
    return mode ? *mode : ORIGIN_MODE_OBSERVE;  // absent = inert
}

// origin_lo_carveout gates the "egressing the loopback device" carve-out.
// pkg/origin sets it unconditionally at load, before attach, so it is always
// on in production. It exists as a config byte ONLY because PROG_TEST_RUN
// attaches every cgroup_skb test packet to the loopback device (test_run.c
// uses the netns loopback_dev), so a hardwired ifindex check would carve out
// every packet the test suite sends and leave the verdict path unprovable.
// Tests exercise verdicts with it off and the carve-out with it on.
static __always_inline __u8 origin_lo_carveout(void) {
    __u32 key = ORIGIN_CFG_KEY_LO_CARVEOUT;
    __u8 *on = bpf_map_lookup_elem(&map_origin_config, &key);
    return on ? *on : 0;
}

// verdict_action maps a policy decision onto this hook's return value.
// Denied traffic is dropped ONLY in enforce mode and only outside audit
// posture — audit mode is the run's single source of truth for "log, never
// block" (config.Manager.IsAuditMode → map_audit_mode) and must hold here
// exactly as it does at TC.
static __always_inline int verdict_action(__u8 mode, __u8 allowed) {
    if (allowed)
        return 1;
    if (mode != ORIGIN_MODE_ENFORCE)
        return 1;
    if (audit_mode_active())
        return 1;
    return 0;
}

// verdict_label records what actually happened, for the audit stream.
static __always_inline __u8 verdict_label(__u8 mode, __u8 allowed) {
    if (mode == ORIGIN_MODE_OBSERVE)
        return ORIGIN_VERDICT_NONE;
    if (allowed)
        return ORIGIN_VERDICT_ALLOW;
    if (mode == ORIGIN_MODE_ENFORCE && !audit_mode_active())
        return ORIGIN_VERDICT_BLOCK;
    return ORIGIN_VERDICT_WOULD_BLOCK;
}

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

// What the tuple last emitted. The verdict is part of the dedup decision, not
// just the timestamp: a verdict CHANGE re-emits immediately, however recent
// the last record. Otherwise a tuple that emitted verdict-NONE/ALLOW just
// before the mode was raised (or a policy reload flipped allow→deny) would
// have its first denial suppressed for the rest of the interval — in enforce
// mode that is a drop with no record, no audit event, and no late-allow
// reconciliation.
struct origin_seen_val {
    __u64 last_emit;  // bpf_ktime_get_ns()
    __u8 verdict;     // ORIGIN_VERDICT_* carried by the last emitted record
    __u8 pad[7];      // explicit padding for a deterministic value layout
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct origin_seen_key);
    __type(value, struct origin_seen_val);
    __uint(max_entries, 4096);
} map_origin_seen SEC(".maps");

// Dedup-then-emit one origin record. A concurrent lookup/update race across
// CPUs costs at most one duplicate record — not worth an atomic. Ringbuf
// reservation failure just drops the record: attribution degrades, nothing
// else does.
static __always_inline void origin_emit(struct __sk_buff *skb, __u8 ip_version,
                                        __u8 ip_proto, __u8 flags, __u8 verdict,
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
    struct origin_seen_val *last = bpf_map_lookup_elem(&map_origin_seen, &key);
    if (last && last->verdict == verdict && now - last->last_emit < ORIGIN_EMIT_INTERVAL_NS)
        return;
    struct origin_seen_val val = { .last_emit = now, .verdict = verdict };
    bpf_map_update_elem(&map_origin_seen, &key, &val, BPF_ANY);

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
    evt->verdict = verdict;
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

// Carve-outs — traffic this hook never adjudicates, because it sees traffic
// tc_egress never did and denying it would break the host:
//   - Local-only traffic, i.e. the class "never leaves the machine". Matched
//     two ways: by egress device (skb->ifindex == lo, gated by
//     origin_lo_carveout — this is what catches a flow to the host's OWN
//     non-loopback address, which Linux also routes over lo and which TC
//     therefore never adjudicated either) and by destination literal (127/8,
//     ::1 — kept as the ungated second net, and because the address is known
//     before the routing-dependent device check matters). The DNS redirect
//     DNATs port 53 to 127.0.0.1 BEFORE this hook runs, so we also see the
//     proxy's own inbound-side loopback. Belt-and-suspenders with the
//     userspace 127.0.0.0/8 allow (cmd/start.go).
//   - ICMP / ICMPv6: path-MTU discovery and NDP. tc_egress treats ICMPv4 as
//     a protocol-block candidate and always allows ICMPv6; dropping either
//     here would break connectivity for traffic that is otherwise allowed.
static __always_inline int origin_handle_v4(struct __sk_buff *skb, __u8 mode) {
    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, 0, &ip_hdr, sizeof(ip_hdr)) < 0)
        return verdict_action(mode, 0);  // malformed: fail-closed, as tc_egress does

    __u32 ip_hlen = (ip_hdr.ihl & 0x0F) * 4;
    if (ip_hlen < sizeof(struct iphdr) || ip_hlen > 60)
        return verdict_action(mode, 0);  // invalid header length: fail-closed

    __u32 src_ip = bpf_ntohl(ip_hdr.saddr);
    __u32 dst_ip = bpf_ntohl(ip_hdr.daddr);
    __u8 ip_proto = ip_hdr.protocol;

    __u16 frag_off = bpf_ntohs(ip_hdr.frag_off);
    __u8 non_first_frag = (frag_off & 0x1FFF) != 0;

    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 flags = 0;
    __u8 emit = 1;

    if (non_first_frag) {
        // No L4 header: ports stay 0 and the verdict falls to the LPM/default
        // path, exactly as in tc_egress. The flow's opening packet already
        // produced a record, so nothing new to emit.
        emit = 0;
    } else if (ip_proto == IPPROTO_TCP) {
        struct tcphdr tcp_hdr;
        if (bpf_skb_load_bytes(skb, ip_hlen, &tcp_hdr, sizeof(tcp_hdr)) < 0)
            return verdict_action(mode, 0);
        __u8 tcp_flags;
        if (bpf_skb_load_bytes(skb, ip_hlen + 13, &tcp_flags, 1) < 0)
            return verdict_action(mode, 0);
        src_port = bpf_ntohs(tcp_hdr.source);
        dst_port = bpf_ntohs(tcp_hdr.dest);
        if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
            flags = ORIGIN_FLAG_TCP_SYN;
        } else {
            // Established-flow segment: still adjudicated (an allowlist
            // change must be able to kill a live flow, as at TC), but not
            // re-emitted — this is the hot path.
            emit = 0;
            if ((tcp_flags & TCP_FLAG_ACK) && !(tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_RST)))
                flags = ORIGIN_FLAG_TCP_MIDSTREAM;
        }
    } else if (ip_proto == IPPROTO_UDP) {
        struct udphdr udp_hdr;
        if (bpf_skb_load_bytes(skb, ip_hlen, &udp_hdr, sizeof(udp_hdr)) < 0)
            return verdict_action(mode, 0);
        src_port = bpf_ntohs(udp_hdr.source);
        dst_port = bpf_ntohs(udp_hdr.dest);
    }

    __u8 allowed = 1;
    __u8 verdict = ORIGIN_VERDICT_NONE;
    if (mode != ORIGIN_MODE_OBSERVE) {
        // Carve-out evaluated only when a verdict would be, so observe mode
        // never pays for it; operand order keeps the config-map lookup
        // confined to packets actually on the loopback device.
        __u8 carve_out = ((dst_ip >> 24) == 127) || (ip_proto == IPPROTO_ICMP) ||
                         (skb->ifindex == LOOPBACK_IFINDEX && origin_lo_carveout());
        if (!carve_out) {
            allowed = verdict_allowed_v4(ip_hdr.daddr, dst_port, ip_proto);
            verdict = verdict_label(mode, allowed);
            // Surface our own denials (dedup still applies), for exactly the
            // shapes tc_egress reports for the same denial: connection
            // attempts (SYN), killed established flows (midstream), UDP, and
            // other protocols. Deliberately silent, as at TC: kernel RST
            // replies to inbound port scans and SYN-ACK replies to inbound
            // handshakes (TCP with flags 0 — constant noise on a public CI
            // runner), and non-first fragments (the flow's first packet
            // already carried this verdict).
            if (!allowed && !non_first_frag && (ip_proto != IPPROTO_TCP || flags != 0))
                emit = 1;
        }
    }

    if (emit) {
        __u8 zero16[16] = {};
        origin_emit(skb, 4, ip_proto, flags, verdict, src_ip, dst_ip, zero16, zero16,
                    src_port, dst_port);
    }
    return verdict_action(mode, allowed);
}

static __always_inline int is_ipv6_ext_hdr(__u8 nexthdr) {
    return nexthdr == IPPROTO_HOPOPTS ||
           nexthdr == IPPROTO_ROUTING ||
           nexthdr == IPPROTO_FRAGMENT ||
           nexthdr == IPPROTO_DSTOPTS ||
           nexthdr == IPPROTO_MH;
}

// is_ipv6_loopback reports whether ip6 is ::1. A constant-size memcmp, not
// an unrolled byte loop: loop-unrolling heuristics vary between clang host
// builds, which made the generated object differ between an arm64 developer
// machine and CI's x86_64 runner even though the source was identical
// (verify-bpf-generated-code compares object checksums).
static __always_inline int is_ipv6_loopback(const __u8 ip6[16]) {
    const __u8 loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return __builtin_memcmp(ip6, loopback, 16) == 0;
}

static __always_inline int origin_handle_v6(struct __sk_buff *skb, __u8 mode) {
    struct ipv6hdr ip6_hdr;
    if (bpf_skb_load_bytes(skb, 0, &ip6_hdr, sizeof(ip6_hdr)) < 0)
        return verdict_action(mode, 0);  // malformed: fail-closed

    __u8 src_ip6[16];
    __u8 dst_ip6[16];
    __builtin_memcpy(src_ip6, &ip6_hdr.addrs.saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(dst_ip6, &ip6_hdr.addrs.daddr.in6_u.u6_addr8, 16);

    // Multicast (NDP/MLD) and loopback: always allowed, never emitted —
    // matching tc_egress's unconditional multicast pass.
    if (dst_ip6[0] == 0xff || is_ipv6_loopback(dst_ip6))
        return 1;

    __u8 nexthdr = ip6_hdr.nexthdr;
    __u32 l4_offset = IPV6_HDR_LEN;
    __u8 non_first_frag = 0;

    // Walk the extension header chain — same discipline and 6-iteration
    // bound as handle_ipv6 in tcbpf.c.
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (!is_ipv6_ext_hdr(nexthdr))
            break;

        if (nexthdr == IPPROTO_FRAGMENT) {
            __u8 frag_hdr[8];
            if (bpf_skb_load_bytes(skb, l4_offset, frag_hdr, sizeof(frag_hdr)) < 0)
                return verdict_action(mode, 0);
            nexthdr = frag_hdr[0];
            __u16 frag_off = ((__u16)frag_hdr[2] << 8) | frag_hdr[3];
            if ((frag_off & 0xFFF8) != 0)
                non_first_frag = 1;
            l4_offset += 8;
        } else {
            __u8 ext_hdr[2];
            if (bpf_skb_load_bytes(skb, l4_offset, ext_hdr, 2) < 0)
                return verdict_action(mode, 0);
            nexthdr = ext_hdr[0];
            l4_offset += (ext_hdr[1] + 1) * 8;
        }
    }

    // ICMPv6 is required for NDP — tc_egress allows it unconditionally and
    // pkg/firewall stripICMPForV6 depends on that invariant.
    if (nexthdr == IPPROTO_ICMPV6)
        return 1;

    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 flags = 0;
    __u8 emit = 1;

    if (non_first_frag) {
        emit = 0;
    } else if (nexthdr == IPPROTO_TCP) {
        struct tcphdr tcp_hdr;
        if (bpf_skb_load_bytes(skb, l4_offset, &tcp_hdr, sizeof(tcp_hdr)) < 0)
            return verdict_action(mode, 0);
        __u8 tcp_flags;
        if (bpf_skb_load_bytes(skb, l4_offset + 13, &tcp_flags, 1) < 0)
            return verdict_action(mode, 0);
        src_port = bpf_ntohs(tcp_hdr.source);
        dst_port = bpf_ntohs(tcp_hdr.dest);
        if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
            flags = ORIGIN_FLAG_TCP_SYN;
        } else {
            emit = 0;  // established segment — see the IPv4 branch
            if ((tcp_flags & TCP_FLAG_ACK) && !(tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_RST)))
                flags = ORIGIN_FLAG_TCP_MIDSTREAM;
        }
    } else if (nexthdr == IPPROTO_UDP) {
        struct udphdr udp_hdr;
        if (bpf_skb_load_bytes(skb, l4_offset, &udp_hdr, sizeof(udp_hdr)) < 0)
            return verdict_action(mode, 0);
        src_port = bpf_ntohs(udp_hdr.source);
        dst_port = bpf_ntohs(udp_hdr.dest);
    }

    __u8 allowed = 1;
    __u8 verdict = ORIGIN_VERDICT_NONE;
    if (mode != ORIGIN_MODE_OBSERVE) {
        // Local-only traffic that used a non-loopback v6 address (the host's
        // own global address over lo): same carve-out class and same
        // evaluation-order rationale as the IPv4 handler; ::1 itself
        // returned above.
        __u8 carve_out = (skb->ifindex == LOOPBACK_IFINDEX) && origin_lo_carveout();
        if (!carve_out) {
            allowed = verdict_allowed_v6(dst_ip6, dst_port, nexthdr);
            verdict = verdict_label(mode, allowed);
            // Same denial-surfacing policy as the IPv4 branch: silent for
            // RST / SYN-ACK replies and non-first fragments, emitted for
            // everything else this hook denies.
            if (!allowed && !non_first_frag && (nexthdr != IPPROTO_TCP || flags != 0))
                emit = 1;
        }
    }

    if (emit) {
        origin_emit(skb, 6, nexthdr, flags, verdict, 0, 0, src_ip6, dst_ip6,
                    src_port, dst_port);
    }
    return verdict_action(mode, allowed);
}

SEC("cgroup_skb/egress")
int cg_origin_egress(struct __sk_buff *skb) {
    // The DNS proxy marks its own upstream queries; never adjudicate them,
    // so a policy race can't make the proxy self-block the very lookups that
    // populate the allowlist. Checked before anything else, including parse —
    // the exemption must also cover fragments of large (EDNS0) replies, which
    // carry no L4 header to recognize the proxy by.
    //
    // Threat model, so nobody re-litigates or silently weakens this:
    //   - Setting SO_MARK requires CAP_NET_ADMIN, i.e. a --privileged
    //     container or host root. pkg/containers documents privileged
    //     containers as host-root equivalent and OUT OF SCOPE (they could as
    //     easily detach this program); post-NAT traffic still meets the TC
    //     backstop regardless.
    //   - The comparison is exact equality BY CONTRACT: the mark is an
    //     identity, not a bitfield. Never give DNS_PROXY_FW_MARK bit/mask
    //     semantics (e.g. an iptables `--mark 0xCA12/0xFFFF` rule or ORing in
    //     a second-purpose bit) — a composed mark stops matching here and
    //     every proxy reply is then dropped under enforce, killing name
    //     resolution with nothing in the logs pointing at the mark. The value
    //     is pinned to pkg/network.DNSProxyFWMark by
    //     TestDNSProxyFWMarkMatchesGoConstant.
    if (skb->mark == DNS_PROXY_FW_MARK)
        return 1;

    __u8 mode = origin_mode();

    __u8 first_byte;
    if (bpf_skb_load_bytes(skb, 0, &first_byte, 1) != 0)
        return 1;  // unreadable: not IP-shaped, and tc_egress passes non-IP too

    __u8 version = first_byte >> 4;
    if (version == 4)
        return origin_handle_v4(skb, mode);
    if (version == 6)
        return origin_handle_v6(skb, mode);

    // Non-IP (ARP etc.) — allowed, matching tc_egress. Under ALLOW_MULTI the
    // effective egress verdict is the AND of every attached program, so a 1
    // here is the identity element and never overrides a peer's decision;
    // conversely our 0 in enforce mode cannot be vetoed by a peer, which is
    // why every drop of a connection attempt or established flow emits a
    // record (userspace turns it into a blocked audit event) — otherwise
    // cargowall would inherit blame for drops it did not make. The only
    // drops deliberately left silent mirror tc_egress's own reporting
    // policy: kernel RST / SYN-ACK replies to inbound scans, and non-first
    // fragments of an already-reported flow.
    return 1;
}

char _license[] SEC("license") = "GPL";
