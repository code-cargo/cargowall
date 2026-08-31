//go:build ignore

// The QUIC half of L7 identity: walk a (possibly coalesced) UDP datagram to
// the client Initial that carries the SNI, and recover its Destination
// Connection ID — the connection-attempt identity, since one UDP socket can
// carry several QUIC connections that the flow key cannot tell apart.
//
// It knows nothing about scope maps, flow state, or punting — the adjudication
// side calls in, never the reverse. #included by sni.h. design-l7.md holds the
// rationale (why the exact DCID and not a hash, why the walk fails closed).

#ifndef __SNI_QUIC_H__
#define __SNI_QUIC_H__

#include "sni_bytes.h"

// QUIC versions the userspace decryptor supports, with their long-header
// packet-type bits (bits 5-4 of byte 0). Pinned equal to pkg/sni's
// initialVersions table by TestKernelQUICVersionsMatchParser and
// TestKernelQUICVersionTypeBitsMatchParser: a version this table misses (or
// whose bits drift) yields no connection-attempt identity, so a second
// connection would ride the first's verdict with its SNI never parsed.
#define QUIC_VER_1       0x00000001  // RFC 9000/9001
#define QUIC_VER_2       0x6b3343cf  // RFC 9369 — rotated the type bits
#define QUIC_VER_DRAFT29 0xff00001d  // draft-29: v1 layout

#define QUIC_V1_INITIAL_TYPE 0  // v1/draft-29: Initial 00, 0-RTT 01, Handshake 10, Retry 11
#define QUIC_V1_RETRY_TYPE   3
#define QUIC_V2_INITIAL_TYPE 1  // v2: Initial 01, 0-RTT 10, Handshake 11, Retry 00
#define QUIC_V2_RETRY_TYPE   0

// The coalesced walk is capped because the verifier forbids unbounded loops.
//
// INVARIANT FOR ANYONE RAISING THIS: the cap is set by VERIFIER BUDGET, not by
// protocol shape — roughly 20k of cg_origin_egress's 1M instructions per rung.
// Measure on CI's kernel before changing it (a 6.8 kernel under-reports by
// ~3x), because busting the limit does not fail this feature, it fails the
// whole program to load and takes L4 enforcement down with it. design-l7.md
// records the incident and the GSO batching this depth does not cover.
#define L7_QUIC_MAX_COALESCED 4

#define L7_QPKT_INITIAL  1   // known-version Initial: id->dcid filled
#define L7_QPKT_SKIP     0   // known-version 0-RTT/Handshake: *next advanced
#define L7_QPKT_STOP    (-1) // short header / clean end: no Initial can follow
#define L7_QPKT_UNSURE  (-2) // unskippable long header (unknown version, Retry,
                             // malformed) — meaning depends on position; see
                             // l7_quic_find_initial

// l7_quic_id is what the walk recovers: the datagram's Initial DCID, or
// uncertain when the walk could not rule out a reachable Initial it did not
// adjudicate. Callers MUST fail closed on uncertain, in every flow state.
struct l7_quic_id {
    __u8 dcid_len;  // 0 when the datagram carries no Initial
    __u8 dcid[20];
    __u8 uncertain;
};

// l7_dcid_bytes_eq compares two connection IDs exactly. The client picks the
// DCID, so a folded/hashed identity would be forgeable by search.
static __always_inline int l7_dcid_bytes_eq(const __u8 *a, __u8 alen,
                                            const __u8 *b, __u8 blen) {
    if (alen != blen)
        return 0;
    for (__u32 i = 0; i < 20; i++) {
        if (i >= alen)
            break;
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

// l7_read_varint decodes a QUIC variable-length integer (RFC 9000 §16) at off,
// returning its byte width in *nbytes, or 0 on truncation.
//
// VERIFIER: it reads ONE byte at a time. A single variable-length
// bpf_skb_load_bytes of `1 << (b>>6)` is rejected — the verifier cannot bound a
// shift-by-variable, and clang proves any structural mask on a power-of-two
// length is a no-op and deletes it.
static __always_inline int l7_read_varint(struct __sk_buff *skb, __u32 off, __u32 end,
                                          __u64 *val, __u32 *nbytes) {
    __u8 b;
    if (!l7_load_u8(skb, off, end, &b))
        return 0;
    __u32 len = 1u << (b >> 6);  // a loop bound, never a load length
    __u64 v = b & 0x3f;
    for (__u32 i = 1; i < 8; i++) {
        if (i >= len)
            break;
        __u8 nb;
        if (!l7_load_u8(skb, off + i, end, &nb))
            return 0;
        v = (v << 8) | nb;
    }
    *val = v;
    *nbytes = len;
    return 1;
}

// l7_quic_one classifies the long-header packet at off, filling *pkt with THAT
// packet's DCID (every long header carries one; a zero length is legal for a
// non-Initial) and setting *next to the following coalesced packet on INITIAL
// and SKIP. The skippable-header rules below are stated once, for both walks,
// at skipLongHeader in pkg/sni/quic.go.
static __always_inline int l7_quic_one(struct __sk_buff *skb, __u32 off, __u32 end,
                                       struct l7_quic_id *pkt, __u32 *next) {
    __u8 b0;
    if (!l7_load_u8(skb, off, end, &b0) || !(b0 & 0x80))
        return L7_QPKT_STOP;  // short header / end
    __u8 vb[4];
    if (off + 6 > end || bpf_skb_load_bytes(skb, off + 1, vb, 4) < 0)
        return L7_QPKT_STOP;  // no room for a header — no Initial fits
    __u32 ver = ((__u32)vb[0] << 24) | ((__u32)vb[1] << 16) | ((__u32)vb[2] << 8) | vb[3];
    __u8 type = (b0 >> 4) & 0x3;
    __u8 initial_type, retry_type;
    if (ver == QUIC_VER_1 || ver == QUIC_VER_DRAFT29) {
        initial_type = QUIC_V1_INITIAL_TYPE;
        retry_type = QUIC_V1_RETRY_TYPE;
    } else if (ver == QUIC_VER_2) {
        initial_type = QUIC_V2_INITIAL_TYPE;
        retry_type = QUIC_V2_RETRY_TYPE;
    } else {
        return L7_QPKT_UNSURE;  // unknown version: cannot size it to skip past
    }
    __u8 dlen;
    if (!l7_load_u8(skb, off + 5, end, &dlen) || dlen > 20)
        return L7_QPKT_UNSURE;

    if (type == retry_type)
        return L7_QPKT_UNSURE;  // Retry has no Length field

    // Load this packet's DCID, whatever its type. RFC 9000 §12.2 forbids
    // coalescing packets with different connection IDs, so the caller can hold
    // every packet in the datagram to one identity instead of adjudicating the
    // Initial and passing whatever else rode along.
    //
    // VERIFIER: load into a 32-byte scratch so the length is pinned to [1,32]
    // structurally (dlen is not a power of two, so clang cannot delete the
    // mask), then copy a CONSTANT 20 out.
    if (dlen >= 1) {
        __u8 scratch[32] = {};
        __u32 n = ((__u32)(dlen - 1) & 31) + 1;
        if (off + 6 + n > end || bpf_skb_load_bytes(skb, off + 6, scratch, n) < 0)
            return L7_QPKT_UNSURE;  // truncated
        pkt->dcid_len = dlen;
        __builtin_memcpy(pkt->dcid, scratch, 20);
    }

    if (type != initial_type) {
        // 0-RTT / Handshake: skip past dcid, scid, and the Length-delimited
        // body (non-Initials carry no Token).
        __u32 p = off + 6 + dlen;
        __u8 slen;
        if (!l7_load_u8(skb, p, end, &slen) || slen > 20)
            return L7_QPKT_UNSURE;
        p = p + 1 + slen;
        __u64 length;
        __u32 vn;
        if (!l7_read_varint(skb, p, end, &length, &vn))
            return L7_QPKT_UNSURE;
        __u64 nx = (__u64)p + vn + length;  // u64: a crafted Length cannot wrap
        if (nx <= off || nx > end)
            return L7_QPKT_UNSURE;
        *next = (__u32)nx;
        return L7_QPKT_SKIP;
    }

    // The fixed bit is required on a client Initial (RFC 9287 greasing is
    // negotiated, so it cannot apply here), and userspace rejects a clear bit
    // as not-QUIC — punting one would only park a flow the oracle must refuse.
    // A conformant client Initial DCID is 8..20, never empty.
    if (!(b0 & 0x40) || dlen < 1)
        return L7_QPKT_UNSURE;

    // Size this Initial so the walk can continue to a second one behind it. A
    // sizing failure degrades to *next = end, ending the walk: a receiver that
    // cannot parse a coalesced packet cannot reach anything past it either, so
    // an unsizable tail hides nothing reachable.
    *next = end;
    __u32 p = off + 6 + dlen;
    __u8 slen;
    if (!l7_load_u8(skb, p, end, &slen) || slen > 20)
        return L7_QPKT_INITIAL;
    p += 1 + slen;  // Token length varint (Initials carry a Token)
    __u64 tlen, length;
    __u32 tn, ln;
    if (!l7_read_varint(skb, p, end, &tlen, &tn))
        return L7_QPKT_INITIAL;
    __u64 tend = (__u64)p + tn + tlen;  // u64: a crafted token len cannot wrap
    if (tend > end)
        return L7_QPKT_INITIAL;
    p = (__u32)tend;
    if (!l7_read_varint(skb, p, end, &length, &ln))
        return L7_QPKT_INITIAL;
    __u64 nx = (__u64)p + ln + length;
    if (nx <= off || nx > end)
        return L7_QPKT_INITIAL;
    *next = (__u32)nx;
    return L7_QPKT_INITIAL;
}

// l7_quic_find_initial walks the coalesced datagram (RFC 9000 §12.2) and
// records the Initial's DCID in *id. Three rules, each load-bearing:
//
//   It does NOT stop at the first Initial. A receiver processes every packet
//   it can reach, so anything coalesced behind an adjudicated Initial would
//   otherwise ride that verdict.
//
//   Every long-header packet must carry the SAME connection ID, which §12.2
//   already requires of senders — so no conformant client is refused, while a
//   smuggled second attempt and a 0-RTT for another connection both fail.
//
//   Uncertainty is POSITIONAL. An unskippable packet before any Initial could
//   hide the only one, so it fails closed; behind a found Initial it hides
//   nothing reachable and ends the walk, which is what lets real clients grease
//   with a trailing reserved-version packet. Skippable packets past the cap are
//   reachable, so they are uncertain wherever they appear.
//
// design-l7.md has the rationale; this comment is the contract.
static __always_inline void l7_quic_find_initial(struct __sk_buff *skb, __u32 off, __u32 end,
                                                 struct l7_quic_id *id, __u32 *walked_to) {
    __u8 first[20] = {};
    __u8 first_len = 0;
    __u8 saw_first = 0;
    __u8 saw_initial = 0;
    for (int i = 0; i < L7_QUIC_MAX_COALESCED; i++) {
        __u32 next = off;
        struct l7_quic_id pkt = {};
        int r = l7_quic_one(skb, off, end, &pkt, &next);
        if (r == L7_QPKT_STOP)
            break;
        if (r == L7_QPKT_UNSURE) {
            if (!saw_initial)
                id->uncertain = 1;  // the only Initial may hide behind it
            break;
        }
        // One datagram, one connection.
        if (!saw_first) {
            saw_first = 1;
            first_len = pkt.dcid_len;
            __builtin_memcpy(first, pkt.dcid, 20);
        } else if (!l7_dcid_bytes_eq(first, first_len, pkt.dcid, pkt.dcid_len)) {
            id->uncertain = 1;
            break;
        }
        if (r == L7_QPKT_INITIAL)
            saw_initial = 1;
        off = next;  // INITIAL falls through like SKIP: keep walking
        if (off >= end)
            break;
        if (i == L7_QUIC_MAX_COALESCED - 1)
            id->uncertain = 1;  // reachable packets past the cap
    }
    // Every break above leaves off at the packet that stopped the walk, so
    // this is the exact boundary between classified and unclassified bytes.
    *walked_to = off;
    // The identity is reported only when an Initial actually carried it: a
    // datagram of non-Initials alone has no first-flight identity to pin.
    if (saw_initial) {
        id->dcid_len = first_len;
        __builtin_memcpy(id->dcid, first, 20);
    }
}

// Datagrams a single GSO send can hold. Linux caps UDP_SEGMENT at
// UDP_MAX_SEGMENTS (64), and a 64KB batch of QUIC's 1200-byte minimum
// datagrams reaches 54, so this clears every batch a conformant sender can
// build. A batch beyond it is refused rather than partly checked — the
// unscanned segments are exactly the hole this closes.
#define L7_GSO_MAX_SEGS 64

// l7_quic_gso_tail closes the GSO fail-open.
//
// cgroup_skb/egress runs in ip_finish_output, BEFORE ip_finish_output_gso
// splits a UDP_SEGMENT send — so ONE skb here can hold several datagrams that
// the stack emits independently a moment later. The coalesced walk models one
// datagram, and a short header legitimately ENDS a datagram (RFC 9000 §17.3:
// it carries no Length and runs to the end of the packet). A batch whose first
// segment starts with a short header therefore stopped the walk with no
// Initial AND no uncertainty, the identity gate read that as established 1-RTT
// traffic, and every later segment shipped unadjudicated — an identity-bearing
// first flight reaching an allowed edge with its name never checked, which is
// the bypass this whole layer exists to stop.
//
// So every segment boundary the walk did NOT reach must itself start with a
// short header. One long header past the walk means the "no Initial" answer
// described only part of the send: uncertain, and the caller fails closed.
// Bulk 1-RTT GSO (every segment a short header) is untouched, and a first
// flight whose Initials the walk DID cover keeps its existing adjudication —
// the walk steps datagram to datagram there, because a padded Initial's Length
// spans its whole datagram.
static __always_inline void l7_quic_gso_tail(struct __sk_buff *skb, __u32 start, __u32 end,
                                             __u32 seg, __u32 segs, __u32 walked_to,
                                             struct l7_quic_id *id) {
    if (seg == 0 || segs <= 1)
        return;  // one datagram: the walk already saw all of it
    if (segs > L7_GSO_MAX_SEGS) {
        id->uncertain = 1;  // more datagrams than this scan can clear
        return;
    }
    __u32 off = start + seg;
    for (__u32 i = 1; i < L7_GSO_MAX_SEGS; i++) {
        if (i >= segs || off >= end)
            return;
        if (off >= walked_to) {
            __u8 b0;
            if (!l7_load_u8(skb, off, end, &b0) || (b0 & 0x80)) {
                id->uncertain = 1;
                return;
            }
        }
        off += seg;
    }
}

#endif /* __SNI_QUIC_H__ */
