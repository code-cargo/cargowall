//go:build ignore

// L7 destination-identity enforcement (TLS SNI / HTTP Host / QUIC): the
// narrowing layer that closes the shared-edge-IP hole, where an allowed
// hostname resolving to a CDN edge opens that /32 for every tenant behind it.
// It can only turn an L4-allowed flow into a deny, never widen one.
//
// #included by originbpf.c AFTER verdict.h, reusing that program's mode ladder
// (ORIGIN_MODE_*), audit posture (audit_mode_active()), and config map.
//
// SPLIT OF WORK with the userspace oracle (pkg/origin.L7): the kernel decides
// WHETHER a segment needs adjudication (scope, identity gate, flow state,
// punt); userspace is the only name matcher. There is deliberately no
// in-kernel name match — design-l7.md records why.

#ifndef __SNI_H__
#define __SNI_H__

#include "sni_bytes.h"
#include "sni_quic.h"

// L7 rollout gate, independent of ORIGIN_MODE so L7 can be dark-launched.
#define L7_MODE_OFF     0  // no L7 work at all
#define L7_MODE_OBSERVE 1  // parse, punt, count — never drop
#define L7_MODE_ENFORCE 2  // fail closed: drop until a name is adjudicated

// map_origin_config key 2 (0 and 1 belong to originbpf.c; 3 is reserved).
#define ORIGIN_CFG_KEY_L7_MODE 2

// Which L7 dimension applies to a destination IP. Mirrored by pkg/bpf's Go
// constants and pinned to this source by test.
#define L7_SCOPE_TLS  0x01  // TCP 443 (+ the alternate HTTPS ports) — pin the SNI
#define L7_SCOPE_HTTP 0x02  // TCP 80  (+ the alternate HTTP ports)  — pin the Host
#define L7_SCOPE_QUIC 0x04  // UDP 443 — pin the QUIC SNI

// Per-flow adjudication state.
#define L7_STATE_NEED_HELLO 0  // flow seen (SYN); awaiting its first data segment
#define L7_STATE_PENDING    1  // punted to userspace; awaiting a verdict
#define L7_STATE_ALLOWED    2  // adjudicated: pass
#define L7_STATE_DENIED     3  // adjudicated: drop

// Punt-event flags.
#define L7_PUNT_F_NO_STATE  0x01  // no flow entry (LRU eviction / attach race / pre-existing)
#define L7_PUNT_F_OBSERVE   0x02  // observe/audit posture: the packet was passed, not dropped
#define L7_PUNT_F_TRUNCATED 0x04  // payload longer than the sample could carry
#define L7_PUNT_F_QUIC      0x08  // a QUIC Initial datagram, not a TCP segment
#define L7_PUNT_F_REPIN     0x10  // a new QUIC Initial DCID superseded the flow's
                                  // identity: the oracle resets its assembler
                                  // rather than dropping the sample as stale
#define L7_PUNT_F_REFUSED   0x20  // an identity-gate refusal RECORD, not an
                                  // adjudication punt: report-only, opens no
                                  // cycle and writes no flow state

// A flow undecided after this many punts never will be, so the cap bounds a
// segment flood to O(flows) ringbuf traffic. Each re-pinned QUIC cycle re-arms
// it, priced at one attacker datagram per punt and failing closed under enforce.
#define L7_MAX_PUNTS 8

// Stats slots (PERCPU_ARRAY indices) — only outcomes the kernel itself
// distinguishes. Mirrored by logStats in pkg/origin and pinned by test.
#define L7_STAT_PUNT          0  // sample sent to userspace
#define L7_STAT_PUNT_DROPPED  1  // ringbuf full — fail closed in enforce
#define L7_STAT_QUIC          2  // QUIC Initial punted
#define L7_STAT_BUDGET        3  // punt budget exhausted for a flow
#define L7_STAT_ALLOWED       4  // passed on a userspace ALLOWED verdict
#define L7_STAT_DENIED        5  // dropped on a userspace DENIED verdict
#define L7_STAT_GATE_REFUSED  6  // a FIRST FLIGHT with no usable identity — the
                                 // number the observe-first rollout is read on
#define L7_STAT_PENDING_NO_ID 7  // no-identity packet on a flow mid-adjudication
                                 // (0-RTT racing its Initial): expected, counted
                                 // apart so it cannot inflate GATE_REFUSED
#define L7_STAT_GATE_NO_STATE 8  // no-state bytes that are not the protocol —
                                 // mostly evicted flows' mid-record ciphertext,
                                 // counted apart for the same reason
#define L7_STAT_ALT_UNGATED   9  // a packet on an ALTERNATE HTTPS/HTTP port
                                 // carrying no TLS/HTTP identity: passed, not
                                 // refused (see l7_alt_https_port)
#define L7_STATS_MAX          16

// Bytes of payload a punt carries. A GSO/TSO super-skb delivers a whole first
// flight as one skb, and an initial congestion window (10 x MSS ~ 14.6KB) is
// the most a client can send before an ACK — so this covers every legitimate
// flight and matches sni.MaxAssembly. Beyond it, truncation is anomalous: the
// parse can never complete and the flow is denied, which the client's
// retransmit reproduces identically.
#define L7_PUNT_PAYLOAD 16384

// Bytes of the refused payload a refusal record carries — enough to classify
// the refusal (a TLS record byte, a QUIC version), and no more: refusals have
// no per-flow budget, so the copy must stay cheap under a garbage flood.
#define L7_REFUSAL_SNIPPET 64

// Per-flow key, shaped like origin_seen_key. Binding the verdict to the socket
// cookie AND the destination stops a raw socket laundering an allow from one
// destination onto another; ip_proto keeps TCP and UDP flows distinct.
struct l7_flow_key {
    __u64 cookie;
    __u8 dst[16];       // v4 address in bytes 0-3 (host order), rest zero
    __u16 dst_port;
    __u8 ip_proto;
    __u8 ip_version;
} __attribute__((packed));

struct l7_flow_val {
    __u8 state;          // L7_STATE_*
    __u8 punts;          // punt budget consumed
    __u16 last_punt_len; // dedup half 2: payload length of the last punt
    __u32 last_punt_seq; // dedup half 1: TCP sequence. Dedup ONLY, never identity.
    __u64 ts;
    // The cycle's QUIC connection-attempt identity, compared in every state;
    // zero on TCP. Stamped here when a punt opens a cycle, and by the oracle
    // with both terminal verdicts.
    __u8 dcid_len;
    __u8 dcid[20];
} __attribute__((packed));

// One punted sample. Fixed size so bpf_ringbuf_reserve takes a constant; the
// leading fields mirror origin_event's byte-order convention (v4 host order,
// v6 raw bytes) so userspace reuses the same cookie->pid/step join. Go mirror:
// L7Event in bpf/l7_event.go, pinned by TestL7EventLayoutMatchesBTF.
struct l7_event {
    __u64 cookie;
    __u64 cgroup_id;
    __u64 timestamp;
    __u32 src_ip;       // v4 host byte order
    __u32 dst_ip;       // v4 host byte order
    __u8 src_ip6[16];
    __u8 dst_ip6[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 ip_version;    // 4 or 6
    __u8 ip_proto;      // IPPROTO_TCP or IPPROTO_UDP
    __u8 flags;         // L7_PUNT_F_*
    __u8 scope;         // the ONE L7_SCOPE_* bit that applied
    __u32 seq;          // TCP sequence (punt dedup); 0 for QUIC
    __u16 payload_len;  // valid bytes in payload[]
    __u16 pad;
    // The Initial's exact DCID (0 for TCP): the kernel already walked the long
    // header, so the oracle stamps THIS into the verdict rather than running a
    // second decoder over the payload.
    __u8 dcid_len;
    __u8 dcid[20];
    __u8 pad2[3];
    // INVARIANT: only payload[0 .. payload_len) belongs to this sample. The
    // tail is NOT cleared (zeroing 16KB per punt would cost more than the copy
    // itself), so a consumer reading past payload_len sees another flow's bytes.
    __u8 payload[L7_PUNT_PAYLOAD];
} __attribute__((packed));

// BTF anchor — see the blocked_event anchor in tcbpf.c for rationale.
const struct l7_event *btf_anchor_l7_event __attribute__((unused));

// Scope maps. Entries are reclaimed only by the reload rebuild, and a full map
// is FAIL-OPEN for new destinations (see scopeFull in pkg/origin), so capacity
// is deliberately generous.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IPv4 destination, network byte order (as in the packet)
    __type(value, __u8); // L7_SCOPE_* bits
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_l7_scope SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[16]);
    __type(value, __u8);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_l7_scope_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct l7_flow_key);
    __type(value, struct l7_flow_val);
    __uint(max_entries, 16384);
} map_l7_flow SEC(".maps");

struct {
    // ~120 in-flight 16KB samples. Fewer would make a handshake burst hit
    // L7_STAT_PUNT_DROPPED sooner, and a dropped punt fails closed under enforce.
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} map_l7_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, L7_STATS_MAX);
} map_l7_stats SEC(".maps");

static __always_inline void l7_stat(__u32 slot) {
    __u64 *c = bpf_map_lookup_elem(&map_l7_stats, &slot);
    if (c)
        (*c)++;
}

static __always_inline __u8 l7_mode(void) {
    __u32 key = ORIGIN_CFG_KEY_L7_MODE;
    __u8 *m = bpf_map_lookup_elem(&map_origin_config, &key);
    return m ? *m : L7_MODE_OFF;  // absent = inert
}

// ---- TLS / HTTP identity gate ----

#define TLS_REC_HANDSHAKE 22
#define TLS_HS_CLIENT_HELLO 1

// l7_http_tok matches the payload's first bytes against ONE method token,
// INCLUDING its delimiting space. It succeeds on a complete token, or on a
// payload that ENDS mid-token while agreeing on every byte seen — a proper
// prefix, undecidable without more bytes.
static __always_inline int l7_http_tok(const __u8 *b, __u32 n, const char *tok, __u32 len) {
    for (__u32 i = 0; i < len; i++) {
        if (i >= n)
            return 1;  // payload exhausted mid-token: undecidable prefix
        if (b[i] != (__u8)tok[i])
            return 0;
    }
    return 1;
}

// l7_http_request_line reports whether the window begins with an HTTP/1.x
// request line, or a prefix of one cut short by the segment boundary.
// INVARIANT: a short first flight that may still become a request line must
// return 1, because the NEED_HELLO gate turns a 0 into a fail-closed drop. A
// prefix of a LONGER payload never matches — body bytes diverge from every
// token before its space. Token table pinned to pkg/sni's by
// TestKernelHTTPMethodsMatchParser.
static __always_inline int l7_http_request_line(struct __sk_buff *skb, __u32 off, __u32 end) {
    __u8 b[8] = {};
    // VERIFIER: branch on n itself, not off vs end — there is no relational
    // tracking, so `off >= end` proves nothing about the range of end - off,
    // and a load length whose range includes zero is rejected. The mask then
    // pins [1,8] STRUCTURALLY, because branch-derived bounds regress across
    // unrelated clang inlining changes.
    __u32 n = end - off;
    if (n == 0)
        return 0;
    if (n > 8)
        n = 8;
    n = ((n - 1) & 7) + 1;
    if (bpf_skb_load_bytes(skb, off, b, n) < 0)
        return 0;
    return l7_http_tok(b, n, "GET ", 4) || l7_http_tok(b, n, "PUT ", 4) ||
           l7_http_tok(b, n, "POST ", 5) || l7_http_tok(b, n, "HEAD ", 5) ||
           l7_http_tok(b, n, "PATCH ", 6) || l7_http_tok(b, n, "TRACE ", 6) ||
           l7_http_tok(b, n, "DELETE ", 7) ||
           l7_http_tok(b, n, "OPTIONS ", 8) || l7_http_tok(b, n, "CONNECT ", 8);
}

// ---- Flow adjudication ----

struct l7_ctx {
    __u64 cookie;
    __u64 cgroup_id;
    __be32 dst_key;    // v4 destination, network order — the map_l7_scope key
    __u32 dst_ip;      // v4 host byte order — for the punt event (0 for v6)
    __u32 src_ip;      // v4 host byte order
    __u8 dst6[16];     // v6 destination raw bytes (also the map_l7_scope_v6 key)
    __u8 src6[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 ip_version;
    __u8 ip_proto;
    __u32 payload_off; // absolute skb offset of the L4 payload
    __u32 payload_len;
    __u32 seq;         // TCP dedup key; always 0 for QUIC
    __u8 is_syn;
    __u8 alt_port;     // set by l7_narrow_scope: this is an ALTERNATE HTTPS/HTTP
                       // port, where a packet with no identity passes instead of
                       // being refused (see l7_alt_https_port)
    struct l7_quic_id quic;  // filled by the coalesced walk; zero on TCP
};

static __always_inline __u8 l7_scope_for(struct l7_ctx *c) {
    if (c->ip_version == 4) {
        __u8 *s = bpf_map_lookup_elem(&map_l7_scope, &c->dst_key);
        return s ? *s : 0;
    }
    __u8 *s = bpf_map_lookup_elem(&map_l7_scope_v6, c->dst6);
    return s ? *s : 0;
}

static __always_inline void l7_flow_key_init(struct l7_flow_key *k, struct l7_ctx *c) {
    __builtin_memset(k, 0, sizeof(*k));
    k->cookie = c->cookie;
    if (c->ip_version == 4)
        __builtin_memcpy(k->dst, &c->dst_ip, 4);  // host order, mirrors origin_seen_key
    else
        __builtin_memcpy(k->dst, c->dst6, 16);
    k->dst_port = c->dst_port;
    k->ip_proto = c->ip_proto;
    k->ip_version = c->ip_version;
}

// l7_pass maps the fail-closed decision onto the L7 mode AND the run-wide
// audit posture: observe never drops, enforce defers to audit_mode_active()
// exactly as verdict_action does.
static __always_inline int l7_pass(__u8 l7mode) {
    if (l7mode != L7_MODE_ENFORCE)
        return 1;
    if (audit_mode_active())
        return 1;
    return 0;
}

// l7_gate_refused is a refusal that emits no record — the transient
// PENDING_NO_ID and high-volume no-state arms, where records would be noise.
// Genuine refusals go through l7_refuse.
static __always_inline int l7_gate_refused(__u8 l7mode, __u32 slot) {
    l7_stat(slot);
    return l7_pass(l7mode);
}

// l7_commit_pending persists a PENDING punt state, unless the oracle's verdict
// raced in between this program's snapshot and now — writing PENDING over a
// terminal state would strand the flow (the racing punt is tombstone-dropped
// and the retransmit dedup swallows the rest).
//
// A raced verdict is honored only when its stored DCID matches this attempt's,
// because QUIC identity is per ATTEMPT: a verdict written for a different
// attempt on this socket must neither admit nor sentence this one. TCP carries
// no DCID on either side, so it always honors. honor_terminal is false only
// for a REPIN, which deliberately moves ALLOWED back to PENDING.
//
// Returns -1 when it committed (caller falls through to l7_pass), else the
// return value for the honored terminal verdict.
static __always_inline int l7_commit_pending(struct l7_flow_key *key, struct l7_flow_val *v,
                                             int honor_terminal, __u8 l7mode) {
    struct l7_flow_val *cur = bpf_map_lookup_elem(&map_l7_flow, key);
    if (honor_terminal && cur &&
        (cur->state == L7_STATE_ALLOWED || cur->state == L7_STATE_DENIED) &&
        l7_dcid_bytes_eq(cur->dcid, cur->dcid_len, v->dcid, v->dcid_len)) {
        if (cur->state == L7_STATE_ALLOWED) {
            l7_stat(L7_STAT_ALLOWED);
            return 1;
        }
        l7_stat(L7_STAT_DENIED);
        return l7_pass(l7mode);
    }
    bpf_map_update_elem(&map_l7_flow, key, v, BPF_ANY);
    return -1;
}

// l7_fill_event stamps a sample's header fields, shared by the adjudication
// punt and the refusal record so the cookie->pid/step join reads the same off
// both.
static __always_inline void l7_fill_event(struct l7_event *e, struct l7_ctx *c,
                                          __u8 scope, __u8 flags) {
    e->cookie = c->cookie;
    e->cgroup_id = c->cgroup_id;
    e->timestamp = bpf_ktime_get_ns();
    e->src_ip = c->src_ip;
    e->dst_ip = c->dst_ip;
    __builtin_memcpy(e->src_ip6, c->src6, 16);
    __builtin_memcpy(e->dst_ip6, c->dst6, 16);
    e->src_port = c->src_port;
    e->dst_port = c->dst_port;
    e->ip_version = c->ip_version;
    e->ip_proto = c->ip_proto;
    e->flags = flags;
    e->scope = scope;
    e->seq = c->seq;
    e->pad = 0;
    e->dcid_len = c->quic.dcid_len;
    __builtin_memcpy(e->dcid, c->quic.dcid, 20);
    __builtin_memset(e->pad2, 0, sizeof(e->pad2));
}

// l7_refuse is the identity gate's fail-closed answer plus its audit record: a
// counter and a report-only sample carrying a snippet, so userspace can
// classify the refusal and attribute it to a pid/step. It opens no
// adjudication and writes no flow state. A lost record (full ring) is
// tolerated — the counter still carries the aggregate.
static __always_inline int l7_refuse(struct __sk_buff *skb, struct l7_ctx *c,
                                     __u8 scope, __u8 l7mode, __u32 slot) {
    l7_stat(slot);
    int pass = l7_pass(l7mode);
    struct l7_event *e = bpf_ringbuf_reserve(&map_l7_events, sizeof(*e), 0);
    if (!e)
        return pass;
    __u8 flags = L7_PUNT_F_REFUSED;
    if (pass)
        flags |= L7_PUNT_F_OBSERVE;
    l7_fill_event(e, c, scope, flags);
    __u32 n = c->payload_len;
    if (n > L7_REFUSAL_SNIPPET)
        n = L7_REFUSAL_SNIPPET;
    e->payload_len = (__u16)n;
    // VERIFIER: the branch above bounds n, but branch-derived bounds regress
    // across unrelated clang inlining changes — which is why l7_http_request_line
    // and the QUIC DCID loader both pin their lengths structurally instead. Do
    // the same here. The (n-1)+1 form is load-bearing: a plain
    // `n & (SIZE-1)` maps a full-size copy to zero.
    if (n > 0 &&
        bpf_skb_load_bytes(skb, c->payload_off, e->payload,
                           ((n - 1) & (L7_REFUSAL_SNIPPET - 1)) + 1) < 0) {
        bpf_ringbuf_discard(e, 0);
        return pass;
    }
    bpf_ringbuf_submit(e, 0);
    return pass;
}

static __always_inline int l7_punt(struct __sk_buff *skb, struct l7_ctx *c,
                                   __u8 scope, __u8 flags) {
    struct l7_event *e = bpf_ringbuf_reserve(&map_l7_events, sizeof(*e), 0);
    if (!e) {
        l7_stat(L7_STAT_PUNT_DROPPED);
        return 0;
    }
    l7_fill_event(e, c, scope, flags);

    // VERIFIER: the branch clamp alone gives the bound (umax becomes the exact
    // buffer size). Deliberately NOT a (SIZE-1) mask — that maps a full-window
    // payload to zero, punting no bytes and parking the flow forever.
    __u32 n = c->payload_len;
    if (n > L7_PUNT_PAYLOAD) {
        n = L7_PUNT_PAYLOAD;
        e->flags |= L7_PUNT_F_TRUNCATED;
    }
    e->payload_len = (__u16)n;
    // Structural pin, same reasoning as l7_refuse: the clamp above is what
    // decides truncation, this is what proves the length to the verifier.
    if (n > 0 &&
        bpf_skb_load_bytes(skb, c->payload_off, e->payload,
                           ((n - 1) & (L7_PUNT_PAYLOAD - 1)) + 1) < 0) {
        bpf_ringbuf_discard(e, 0);
        l7_stat(L7_STAT_PUNT_DROPPED);
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    l7_stat(L7_STAT_PUNT);
    return 1;
}

// The alternate HTTPS/HTTP ports the big CDNs terminate the SAME shared edge
// on. Leaving them unscoped left the tenant swap this layer exists to close
// reachable on :8443 — an all-ports hostname allow opens the edge /32 on every
// port, and a flow that presented an attacker's SNI there was never
// adjudicated. Kept equal to pkg/bpf's AltHTTPSPorts/AltHTTPPorts (which
// pkg/dns derives scope bits from) by TestKernelAltPortsMatchScopeTables.
static __always_inline int l7_alt_https_port(__u16 port) {
    return port == 2053 || port == 2083 || port == 2087 || port == 2096 ||
           port == 8443;
}

static __always_inline int l7_alt_http_port(__u16 port) {
    return port == 2052 || port == 2082 || port == 2086 || port == 2095 ||
           port == 8080 || port == 8880;
}

// l7_narrow_scope reduces the destination's scope bits to the ONE dimension
// this packet's proto+port selects, returning 0 when no L7 dimension applies
// and the L4 verdict governs alone. A scoped edge IP still serves protocols
// this layer cannot parse (ssh:22, SMTP, DNS), and adjudicating those as TLS
// would fail-close traffic the rule deliberately allows.
//
// On an alternate port it also sets c->alt_port, which softens the identity
// gate there from fail-closed to pass-through: those ports are governed to pin
// the SNI/Host of flows that DO speak TLS/HTTP, and a non-TLS service on :8443
// is the same L4-governed residual as ssh:22. UDP alt ports are deliberately
// absent — QUIC's walk fails closed on an uncertain datagram in every state,
// and design-l7.md records that residual rather than carving a hole in it.
static __always_inline __u8 l7_narrow_scope(struct l7_ctx *c, __u8 scope) {
    if (c->ip_proto == IPPROTO_UDP)
        return (c->dst_port == 443 && (scope & L7_SCOPE_QUIC)) ? L7_SCOPE_QUIC : 0;
    if (c->ip_proto != IPPROTO_TCP)
        return 0;
    if (scope & L7_SCOPE_TLS) {
        if (c->dst_port == 443)
            return L7_SCOPE_TLS;
        if (l7_alt_https_port(c->dst_port)) {
            c->alt_port = 1;
            return L7_SCOPE_TLS;
        }
    }
    if (scope & L7_SCOPE_HTTP) {
        if (c->dst_port == 80)
            return L7_SCOPE_HTTP;
        if (l7_alt_http_port(c->dst_port)) {
            c->alt_port = 1;
            return L7_SCOPE_HTTP;
        }
    }
    return 0;
}

// l7_no_identity answers a packet whose leading bytes carry no destination
// identity to adjudicate. Three inputs decide it:
//
//   alt_port — an ALTERNATE HTTPS/HTTP port passes. Those ports are L7-governed
//     to pin the SNI/Host of flows that DO speak TLS/HTTP; a non-TLS service on
//     :8443 is the same L4-governed residual as ssh:22, and refusing it would
//     fail-close traffic the rule deliberately allows. Counted, so the widened
//     scope stays measurable. The canonical ports keep their fail-closed
//     posture — this softens nothing that was already covered.
//   fresh — this flow's SYN was seen, so these bytes ARE its first flight:
//     refuse, with a per-flow record.
//   ride — bytes that are established-session traffic by shape (a non-hello TLS
//     record, an HTTP body) ride the L4 verdict. Without it the bytes are not
//     the protocol at all and take the counter-only no-state arm.
static __always_inline int l7_no_identity(struct __sk_buff *skb, struct l7_ctx *c,
                                          __u8 scope, __u8 l7mode, __u8 fresh, int ride) {
    if (c->alt_port) {
        l7_stat(L7_STAT_ALT_UNGATED);
        return 1;
    }
    if (fresh)
        return l7_refuse(skb, c, scope, l7mode, L7_STAT_GATE_REFUSED);
    if (ride)
        return 1;
    return l7_gate_refused(l7mode, L7_STAT_GATE_NO_STATE);
}

// l7_identity_gate decides what a packet's leading bytes mean for a flow in
// state st. It returns 1 to punt for adjudication, or writes *ret with the
// pass/drop answer and returns 0 — L7 only adjudicates bytes that carry a
// destination identity, and what a non-identity byte means depends on the
// protocol and the flow's state.
static __always_inline int l7_identity_gate(struct __sk_buff *skb, struct l7_ctx *c,
                                            struct l7_flow_val *st, __u8 scope,
                                            __u8 l7mode, int *ret) {
    if (c->ip_proto == IPPROTO_UDP) {
        // Uncertain datagrams were refused before the state machine, so only a
        // walk that found a known-version Initial reaches a punt: every QUIC
        // sample the oracle receives carries an identity it can decrypt.
        if (c->quic.dcid_len == 0) {
            // No first-flight identity (short header, a lone Handshake/0-RTT).
            // On PENDING the attempt is still unadjudicated, so fail closed
            // without spending budget; with no state it rides as established
            // traffic — the no-state residual, documented in design-l7.md.
            if (st && st->state == L7_STATE_PENDING)
                *ret = l7_gate_refused(l7mode, L7_STAT_PENDING_NO_ID);
            else
                *ret = 1;
            return 0;
        }
        return 1;
    }

    // PENDING skips the gate entirely: the second half of a split ClientHello
    // starts mid-record and must reach the assembler.
    if (st && st->state == L7_STATE_PENDING)
        return 1;

    // `fresh` (this flow's SYN was seen) splits two things. The COUNTER:
    // no-state non-protocol bytes are mostly evicted flows' mid-record
    // ciphertext, so folding them into GATE_REFUSED would make the number the
    // enforce rollout is decided on unreadable. The RECORD: a fresh refusal is
    // a low-volume, actionable first flight and gets one; a no-state refusal
    // is high-volume noise and stays counter-only.
    __u8 fresh = st && st->state == L7_STATE_NEED_HELLO;
    __u8 b0;
    if (!l7_load_u8(skb, c->payload_off, c->payload_off + c->payload_len, &b0)) {
        *ret = l7_no_identity(skb, c, scope, l7mode, fresh, /*ride=*/0);
        return 0;
    }

    if (scope & L7_SCOPE_TLS) {
        if (b0 == TLS_REC_HANDSHAKE) {
            // Only a ClientHello (msg type 1, at byte 5) opens adjudication;
            // any other handshake record is established-session traffic.
            __u8 msg = TLS_HS_CLIENT_HELLO;  // <6 bytes: a hello prefix, punt it
            if (c->payload_len >= 6)
                l7_load_u8(skb, c->payload_off + 5,
                           c->payload_off + c->payload_len, &msg);
            if (msg == TLS_HS_CLIENT_HELLO)
                return 1;
            // A non-hello handshake record: established-session traffic.
            *ret = l7_no_identity(skb, c, scope, l7mode, fresh, /*ride=*/1);
            return 0;
        }
        if (b0 == 0x14 || b0 == 0x15 || b0 == 0x17) {
            // change_cipher_spec / alert / application_data.
            *ret = l7_no_identity(skb, c, scope, l7mode, fresh, /*ride=*/1);
            return 0;
        }
        // Not TLS at all (e.g. SSH-on-443): fail closed in every state.
        *ret = l7_no_identity(skb, c, scope, l7mode, fresh, /*ride=*/0);
        return 0;
    }

    // HTTP: body bytes on an established flow ride; a first flight that is not
    // a request line fails closed.
    if (l7_http_request_line(skb, c->payload_off, c->payload_off + c->payload_len))
        return 1;
    *ret = l7_no_identity(skb, c, scope, l7mode, fresh, /*ride=*/1);
    return 0;
}

// l7_adjudicate is the whole L7 decision for one packet, called from
// origin_handle_v4/v6 AFTER the L4 verdict has already passed it. Returns 1 to
// pass and 0 to drop; it can only ever turn a pass into a drop.
static __always_inline int l7_adjudicate(struct __sk_buff *skb, __u8 l7mode, struct l7_ctx *c) {
    __u8 scope = l7_narrow_scope(c, l7_scope_for(c));
    if (!scope)
        return 1;  // not L7-scoped on this port: the L4 pass stands

    if (c->ip_proto == IPPROTO_UDP) {
        if (c->payload_len == 0)
            return 1;
        // Recover the connection-attempt identity. c->seq stays 0: dedup is
        // TCP-only, because QUIC loss recovery never repeats a datagram
        // byte-identically and the offset-indexed assembler absorbs re-sent
        // CRYPTO.
        __u32 end = c->payload_off + c->payload_len;
        __u32 walked_to = c->payload_off;
        l7_quic_find_initial(skb, c->payload_off, end, &c->quic, &walked_to);
        // A GSO batch is several datagrams in one skb; the walk above modelled
        // only the first. Everything it did not reach has to be cleared too.
        l7_quic_gso_tail(skb, c->payload_off, end, skb->gso_size, skb->gso_segs,
                         walked_to, &c->quic);
    }

    // Past the narrowing this destination really is L7-governed, so it is now
    // worth the socket identity. Packets to unscoped destinations returned
    // above having paid one hash lookup.
    c->cookie = bpf_get_socket_cookie(skb);
    c->cgroup_id = bpf_skb_cgroup_id(skb);

    // BEFORE any flow state: an uncertain walk must fail closed in every
    // state, or an ALLOWED flow rides one (it leaves dcid_len 0, so nothing
    // re-pins). Refusing writes no state — parking PENDING on a sample the
    // oracle may resolve to "no Initial" would strand the socket.
    if (c->ip_proto == IPPROTO_UDP && c->quic.uncertain)
        return l7_refuse(skb, c, scope, l7mode, L7_STAT_GATE_REFUSED);

    struct l7_flow_key key;
    l7_flow_key_init(&key, c);
    // SNAPSHOT the value rather than mutating through the map pointer.
    // map_l7_flow is an LRU hash: a concurrent userspace Update frees the old
    // node to the freelist, where it can be recycled for a DIFFERENT flow, so
    // an in-place write through a stale pointer would stamp this flow's state
    // onto that one. Every mutation below goes through bpf_map_update_elem.
    struct l7_flow_val *stp = bpf_map_lookup_elem(&map_l7_flow, &key);
    struct l7_flow_val stv = {};
    struct l7_flow_val *st = NULL;
    if (stp) {
        stv = *stp;
        st = &stv;
    }

    // QUIC identity check, BEFORE the state machine: one UDP socket can carry
    // several connections the flow key cannot tell apart, so the Initial DCID
    // is the identity in every state. A matching DCID is the same attempt and
    // falls through to the ladder below; anything else opens a fresh cycle
    // (fresh budget, oracle assembler reset via REPIN) whatever the prior
    // verdict was — ALLOWED must not admit an unadjudicated SNI, and DENIED
    // (an entry with no TTL) must sentence ONE attempt, not the socket. TCP
    // never reaches here: dcid_len is 0.
    __u8 repin = 0;
    if (st && c->quic.dcid_len > 0 &&
        !(st->dcid_len > 0 &&
          l7_dcid_bytes_eq(c->quic.dcid, c->quic.dcid_len, st->dcid, st->dcid_len))) {
        // Applied to the snapshot; the update at the punt persists it, so a
        // failed punt leaves the old state and the next datagram retries.
        repin = 1;
        st->punts = 0;
        st->last_punt_seq = 0;
        st->last_punt_len = 0;
        st->dcid_len = c->quic.dcid_len;
        __builtin_memcpy(st->dcid, c->quic.dcid, 20);
    }
    if (st && !repin) {
        if (st->state == L7_STATE_ALLOWED) {
            l7_stat(L7_STAT_ALLOWED);
            return 1;
        }
        if (st->state == L7_STATE_DENIED) {
            l7_stat(L7_STAT_DENIED);
            return l7_pass(l7mode);
        }
    }

    if (c->is_syn && c->payload_len == 0) {
        struct l7_flow_val v = {};
        v.state = L7_STATE_NEED_HELLO;
        v.ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&map_l7_flow, &key, &v, BPF_ANY);
        return 1;
    }
    if (c->payload_len == 0)
        return 1;  // pure ACK / empty datagram

    int gated;
    if (!l7_identity_gate(skb, c, st, scope, l7mode, &gated))
        return gated;

    // Punt. There is no in-kernel admit — userspace is the only name matcher —
    // so every segment reaching here goes to the oracle, bounded by budget and
    // dedup so a segment flood costs O(flows).
    __u8 flags = 0;
    if (!st)
        flags |= L7_PUNT_F_NO_STATE;
    if (repin)
        flags |= L7_PUNT_F_REPIN;
    if (c->ip_proto == IPPROTO_UDP) {
        flags |= L7_PUNT_F_QUIC;
        l7_stat(L7_STAT_QUIC);
    }
    if (l7_pass(l7mode))
        flags |= L7_PUNT_F_OBSERVE;

    __u16 plen = c->payload_len > 0xffff ? 0xffff : (__u16)c->payload_len;

    if (st) {
        if (st->punts >= L7_MAX_PUNTS) {
            l7_stat(L7_STAT_BUDGET);
            return l7_pass(l7mode);
        }
        // Dedup on (seq, LENGTH), not seq alone: a retransmit that TCP
        // collapsed with the following segment (tcp_collapse_retrans) carries
        // the same seq but MORE bytes, which the oracle has never seen. QUIC
        // never dedups (seq is 0).
        if (st->last_punt_seq == c->seq && st->last_punt_len == plen && c->seq != 0)
            return l7_pass(l7mode);  // identical retransmit: already queued
        // Dedup/budget advance ONLY on a punt that reached the ringbuf.
        // Stamping first would let a full ring silently lose the sample while
        // the stamp swallowed every retransmit — a permanent unaudited black
        // hole under enforce.
        if (l7_punt(skb, c, scope, flags)) {
            st->punts++;
            st->last_punt_seq = c->seq;
            st->last_punt_len = plen;
            st->state = L7_STATE_PENDING;
            int r = l7_commit_pending(&key, st, !repin, l7mode);
            if (r >= 0)
                return r;
        }
    } else if (l7_punt(skb, c, scope, flags)) {
        struct l7_flow_val v = {};
        v.state = L7_STATE_PENDING;
        v.punts = 1;
        v.last_punt_seq = c->seq;
        v.last_punt_len = plen;
        v.dcid_len = c->quic.dcid_len;  // the cycle's identity (zero for TCP)
        __builtin_memcpy(v.dcid, c->quic.dcid, 20);
        v.ts = bpf_ktime_get_ns();
        int r = l7_commit_pending(&key, &v, 1, l7mode);
        if (r >= 0)
            return r;
    }
    return l7_pass(l7mode);
}

// l7_tcp_doff_ok bounds the caller's data offset to the [5,15] words a real
// TCP header can hold. The value arrives from a header the caller already
// parsed, but it was never range-checked, and payload_off = l4_off + doff*4
// then landed INSIDE the TCP header for a doff below 5 — the identity gate
// read header bytes as L7 payload, and a source port whose high byte is 0x17
// reads as a TLS application_data record, so the packet rode through as
// established traffic with L7 never having looked at the real payload.
//
// Rejected rather than clamped, deliberately. Clamping keeps a payload offset
// for a header that has none, and the verifier then range-tracks payload_off
// through every downstream bounds check — 56k instructions, a quarter of this
// program's entire budget, to reason about a packet no TCP stack will accept.
// The caller passes such a packet to its L4 verdict instead, exactly as it
// does every packet L7 does not narrow.
static __always_inline int l7_tcp_doff_ok(__u8 tcp_doff) {
    return tcp_doff >= 5 && tcp_doff <= 15;
}

// l7_gate_open is THE definition of "may this hook deny this packet at L7",
// asked identically by both address families so a third one cannot acquire a
// subtly different copy. L4 must already have ALLOWED the packet, and it must
// be a non-fragmented TCP or UDP segment.
//
// It keys off `allowed`, not verdict_action's return: under audit posture the
// latter passes L4-DENIED packets, which L7 has nothing to say about. The
// caller's `pass` is deliberately not an input — verdict_action opens with
// `if (allowed) return 1`, so `pass && allowed` is just `allowed`, and taking
// both would invite a future edit to disagree with itself.
//
// The carve-out is deliberately NOT here: it is family-specific
// (origin_carved_v4/v6), and those are defined after this header is included.
// Callers short-circuit on it LAST, so an unscoped packet never pays that
// lookup. The carve-outs define traffic this hook never denies, L7 included —
// a hostname rule resolving to loopback or bridge-local (DNS rebinding) would
// otherwise scope an IP they promised to pass.
static __always_inline int l7_gate_open(__u8 l7mode, __u8 allowed,
                                        __u8 non_first_frag, __u8 ip_proto) {
    return allowed && l7mode != L7_MODE_OFF && !non_first_frag &&
           (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP);
}

// l7_payload_window resolves the L4 payload the identity gate reads, from the
// L4 base offset each family computed (past the IP header, or past the v6
// extension-header chain). Returns 0 when the header offers no payload window
// to trust — see l7_tcp_doff_ok.
static __always_inline int l7_payload_window(struct l7_ctx *c, __u32 skb_len, __u32 l4_off,
                                             __u8 tcp_doff, __u32 tcp_seq) {
    if (c->ip_proto == IPPROTO_TCP) {
        if (!l7_tcp_doff_ok(tcp_doff))
            return 0;
        c->payload_off = l4_off + (__u32)tcp_doff * 4;
        c->seq = tcp_seq;
    } else {
        c->payload_off = l4_off + 8;  // fixed UDP header
    }
    c->payload_len = skb_len > c->payload_off ? skb_len - c->payload_off : 0;
    return 1;
}

// l7_hook_v4 / l7_hook_v6 are the entry points the two origin handlers call
// once their L4 verdict has passed a packet. All they still own is the
// FAMILY-SPECIFIC part — which addresses to key on and where L4 starts;
// the gate, the payload window and the adjudication are shared above.
//
// tcp_doff/tcp_seq come from the header the caller already parsed: re-reading
// them here had a failure branch that silently fail-opened.
//
// NB: cookie/cgroup_id are fetched lazily inside l7_adjudicate, after the scope
// check — most packets go to unscoped destinations and must not pay two helper
// calls to learn that.
static __always_inline int l7_hook_v4(struct __sk_buff *skb, __u8 l7mode, __u32 ip_hlen,
                                      __be32 daddr_net, __u32 saddr_host, __u32 daddr_host,
                                      __u8 ip_proto, __u16 src_port, __u16 dst_port,
                                      __u8 is_syn, __u8 tcp_doff, __u32 tcp_seq) {
    struct l7_ctx c = {};
    c.dst_key = daddr_net;
    c.dst_ip = daddr_host;
    c.src_ip = saddr_host;
    c.src_port = src_port;
    c.dst_port = dst_port;
    c.ip_version = 4;
    c.ip_proto = ip_proto;
    c.is_syn = is_syn;
    if (!l7_payload_window(&c, skb->len, ip_hlen, tcp_doff, tcp_seq))
        return 1;  // no window L7 can trust; the L4 verdict governs
    return l7_adjudicate(skb, l7mode, &c);
}

static __always_inline int l7_hook_v6(struct __sk_buff *skb, __u8 l7mode, __u32 l4_off,
                                      const __u8 dst6[16], const __u8 src6[16],
                                      __u8 ip_proto, __u16 src_port, __u16 dst_port,
                                      __u8 is_syn, __u8 tcp_doff, __u32 tcp_seq) {
    struct l7_ctx c = {};
    __builtin_memcpy(c.dst6, dst6, 16);
    __builtin_memcpy(c.src6, src6, 16);
    c.src_port = src_port;
    c.dst_port = dst_port;
    c.ip_version = 6;
    c.ip_proto = ip_proto;
    c.is_syn = is_syn;
    if (!l7_payload_window(&c, skb->len, l4_off, tcp_doff, tcp_seq))
        return 1;
    return l7_adjudicate(skb, l7mode, &c);
}

#endif /* __SNI_H__ */
