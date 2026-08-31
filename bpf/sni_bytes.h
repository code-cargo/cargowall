//go:build ignore

// Bounded skb reads shared by the L7 identity gate (sni.h) and the QUIC
// coalesced walk (sni_quic.h). Neither owns the other's primitives.

#ifndef __SNI_BYTES_H__
#define __SNI_BYTES_H__

// l7_load_u8 reads one byte at off, refusing to read at or past end.
static __always_inline int l7_load_u8(struct __sk_buff *skb, __u32 off, __u32 end, __u8 *out) {
    if (off + 1 > end)
        return 0;
    if (bpf_skb_load_bytes(skb, off, out, 1) < 0)
        return 0;
    return 1;
}

#endif /* __SNI_BYTES_H__ */
