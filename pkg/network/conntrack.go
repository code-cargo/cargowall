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

//go:build linux

package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Conntrack flush for the DNS redirect, via ctnetlink (NETLINK_NETFILTER).
// CTA_* constants are from include/uapi/linux/netfilter/nfnetlink_conntrack.h
// (x/sys/unix carries the nfnetlink subsystem/version constants but not the
// CTA_* space). Dump-then-delete-per-entry is deliberate: the kernel's flush
// path rejects CTA_FILTER with EOPNOTSUPP (filters are dump-only), so a
// port-scoped flush has no single-call form. Full rationale and
// measurements: design.md, "DNS redirect".

const (
	// nfnetlink message subtypes (enum ctnl_msg_types); dump replies
	// arrive as IPCTNL_MSG_CT_NEW.
	ipctnlMsgCtNew    = 0 // IPCTNL_MSG_CT_NEW
	ipctnlMsgCtGet    = 1 // IPCTNL_MSG_CT_GET
	ipctnlMsgCtDelete = 2 // IPCTNL_MSG_CT_DELETE

	// Top-level attributes (enum ctattr_type). CTA_ZONE is a big-endian
	// u16; a conntrack zone (`-j CT --zone`, used by OVS) namespaces the
	// tuple, and a delete that fails to echo it addresses zone 0 instead —
	// ENOENT for an entry that plainly exists.
	ctaTupleOrig = 1  // CTA_TUPLE_ORIG
	ctaZone      = 18 // CTA_ZONE

	// Nested under CTA_TUPLE_ORIG (enum ctattr_tuple).
	ctaTupleIP    = 1 // CTA_TUPLE_IP
	ctaTupleProto = 2 // CTA_TUPLE_PROTO

	// Nested under CTA_TUPLE_IP (enum ctattr_ip).
	ctaIPv4Src = 1 // CTA_IP_V4_SRC
	ctaIPv4Dst = 2 // CTA_IP_V4_DST
	ctaIPv6Src = 3 // CTA_IP_V6_SRC
	ctaIPv6Dst = 4 // CTA_IP_V6_DST

	// Nested under CTA_TUPLE_PROTO (enum ctattr_l4proto). Ports are wire
	// (big-endian) u16 without the NLA_F_NET_BYTEORDER flag, so they are
	// converted explicitly rather than via the encoder/decoder byte order.
	ctaProtoNum     = 1 // CTA_PROTO_NUM (u8)
	ctaProtoSrcPort = 2 // CTA_PROTO_SRC_PORT
	ctaProtoDstPort = 3 // CTA_PROTO_DST_PORT

	// struct nfgenmsg: family (u8), version (u8), res_id (be16).
	sizeofNfgenmsg = 4
)

// ctFlushTimeout bounds each netlink socket's operations so a lost reply
// cannot stall startup or shutdown.
const ctFlushTimeout = 2 * time.Second

// ctFlushAttempts bounds the whole-attempt retry in FlushDNSConntrack: each
// attempt is a complete dial→dump→delete pass on a fresh socket, so one
// transient failure anywhere — the all-or-nothing dump (mdlayher aggregates
// the full multipart reply or fails) or a mid-delete deadline — cannot
// leave stale DNS flows in place. Permanent refusals (EPERM, EOPNOTSUPP)
// short-circuit instead of retrying.
const ctFlushAttempts = 3

// ctMsgType composes an nfnetlink header type from the conntrack subsystem
// and a message subtype.
func ctMsgType(subtype uint16) netlink.HeaderType {
	return netlink.HeaderType(uint16(unix.NFNL_SUBSYS_CTNETLINK)<<8 | subtype)
}

// nfgenmsg returns the nfgenmsg header for a conntrack request on family's
// table.
func nfgenmsg(family uint8) []byte {
	return []byte{family, unix.NFNETLINK_V0, 0, 0}
}

// ctTuple is one flow's original-direction identity plus its conntrack
// zone — exactly the fields ctnetlink needs to address the entry for
// deletion. The addresses are of one family, which is the entry's table.
// Ports and zone are host order.
type ctTuple struct {
	src     netip.Addr
	dst     netip.Addr
	proto   uint8
	srcPort uint16
	dstPort uint16
	zone    uint16
}

// family is the conntrack table the tuple lives in.
func (t ctTuple) family() uint8 {
	if t.src.Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

// isDNS reports whether the flow is one the DNS redirect claims: TCP or UDP
// with original destination port 53. NAT does not rewrite the original-
// direction tuple, so entries already DNAT'd to the proxy match too.
func (t ctTuple) isDNS() bool {
	return t.dstPort == 53 && (t.proto == unix.IPPROTO_TCP || t.proto == unix.IPPROTO_UDP)
}

func be16(p uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, p)
	return b
}

// marshalDeleteAttrs encodes the attribute tree addressing one conntrack
// entry for deletion: CTA_TUPLE_ORIG, plus CTA_ZONE when the entry lives in
// a non-default zone.
func marshalDeleteAttrs(t ctTuple) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	if t.zone != 0 {
		ae.Bytes(ctaZone, be16(t.zone))
	}
	ae.Nested(ctaTupleOrig, func(nae *netlink.AttributeEncoder) error {
		nae.Nested(ctaTupleIP, func(iae *netlink.AttributeEncoder) error {
			if t.src.Is4() {
				iae.Bytes(ctaIPv4Src, t.src.AsSlice())
				iae.Bytes(ctaIPv4Dst, t.dst.AsSlice())
			} else {
				iae.Bytes(ctaIPv6Src, t.src.AsSlice())
				iae.Bytes(ctaIPv6Dst, t.dst.AsSlice())
			}
			return nil
		})
		nae.Nested(ctaTupleProto, func(pae *netlink.AttributeEncoder) error {
			pae.Uint8(ctaProtoNum, t.proto)
			pae.Bytes(ctaProtoSrcPort, be16(t.srcPort))
			pae.Bytes(ctaProtoDstPort, be16(t.dstPort))
			return nil
		})
		return nil
	})
	return ae.Encode()
}

// parseConntrackTupleOrig extracts the original-direction tuple, IPv4 or
// IPv6, from one conntrack message payload (nfgenmsg + attributes). ok is
// true only when every field a delete needs was present, both addresses of
// one family, and the payload decoded cleanly — a truncated message parses
// as !ok and is skipped.
func parseConntrackTupleOrig(data []byte) (ctTuple, bool) {
	var t ctTuple
	if len(data) < sizeofNfgenmsg {
		return t, false
	}
	ad, err := netlink.NewAttributeDecoder(data[sizeofNfgenmsg:])
	if err != nil {
		return t, false
	}
	var haveSrc, haveDst, haveNum, haveSport, haveDport bool
	for ad.Next() {
		if ad.Type() == ctaZone {
			if b := ad.Bytes(); len(b) >= 2 {
				t.zone = binary.BigEndian.Uint16(b)
			}
			continue
		}
		if ad.Type() != ctaTupleOrig {
			continue
		}
		ad.Nested(func(nad *netlink.AttributeDecoder) error {
			for nad.Next() {
				switch nad.Type() {
				case ctaTupleIP:
					nad.Nested(func(iad *netlink.AttributeDecoder) error {
						for iad.Next() {
							b := iad.Bytes()
							switch {
							case iad.Type() == ctaIPv4Src && len(b) == 4,
								iad.Type() == ctaIPv6Src && len(b) == 16:
								t.src, haveSrc = netip.AddrFromSlice(b)
							case iad.Type() == ctaIPv4Dst && len(b) == 4,
								iad.Type() == ctaIPv6Dst && len(b) == 16:
								t.dst, haveDst = netip.AddrFromSlice(b)
							}
						}
						return nil
					})
				case ctaTupleProto:
					nad.Nested(func(pad *netlink.AttributeDecoder) error {
						for pad.Next() {
							b := pad.Bytes()
							switch {
							case pad.Type() == ctaProtoNum && len(b) >= 1:
								t.proto = b[0]
								haveNum = true
							case pad.Type() == ctaProtoSrcPort && len(b) >= 2:
								t.srcPort = binary.BigEndian.Uint16(b)
								haveSport = true
							case pad.Type() == ctaProtoDstPort && len(b) >= 2:
								t.dstPort = binary.BigEndian.Uint16(b)
								haveDport = true
							}
						}
						return nil
					})
				}
			}
			return nil
		})
	}
	return t, ad.Err() == nil && haveSrc && haveDst && t.src.Is4() == t.dst.Is4() &&
		haveNum && haveSport && haveDport
}

// dialCt opens a NETLINK_NETFILTER socket with a bounded deadline so a lost
// reply cannot stall startup or shutdown.
func dialCt() (*netlink.Conn, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("dial netfilter netlink: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(ctFlushTimeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set netlink deadline: %w", err)
	}
	return conn, nil
}

// dumpTuples dumps family's conntrack table over conn, AF_UNSPEC for both
// families' entries, keeping the tuples keep() accepts (nil keeps all). Best-effort by design: ctnetlink dumps
// carry no consistency signal (the conntrack dump path never stamps
// NLM_F_DUMP_INTR), so an entry that moves during the walk can be missed —
// the flush makes no completeness claim. Unparseable entries are skipped,
// not fatal: an entry we cannot address for deletion is one we could not
// act on anyway.
func dumpTuples(conn *netlink.Conn, family uint8, keep func(ctTuple) bool) ([]ctTuple, error) {
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  ctMsgType(ipctnlMsgCtGet),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: nfgenmsg(family),
	})
	if err != nil {
		return nil, fmt.Errorf("conntrack dump: %w", err)
	}
	var tuples []ctTuple
	for _, m := range msgs {
		if m.Header.Type != ctMsgType(ipctnlMsgCtNew) {
			continue
		}
		if t, ok := parseConntrackTupleOrig(m.Data); ok && (keep == nil || keep(t)) {
			tuples = append(tuples, t)
		}
	}
	return tuples, nil
}

// deleteTuple removes one conntrack entry, addressed by its original-
// direction tuple (and zone). ENOENT is not an error — the entry expired or
// was replaced between dump and delete — but it is reported distinctly
// (deleted=false) so the caller can tell a benign race from a systematic
// failure to address entries.
func deleteTuple(conn *netlink.Conn, t ctTuple) (bool, error) {
	attrs, err := marshalDeleteAttrs(t)
	if err != nil {
		return false, fmt.Errorf("marshal conntrack tuple: %w", err)
	}
	_, err = conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  ctMsgType(ipctnlMsgCtDelete),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(nfgenmsg(t.family()), attrs...),
	})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENOENT):
		return false, nil
	default:
		return false, fmt.Errorf("conntrack delete: %w", err)
	}
}

// flushAttempt is one complete dial→dump→delete pass over the dport-53
// entries, IPv6 ones too with ipv6. Re-running it is convergent: a re-dump
// no longer contains what a prior pass already deleted. A delete-phase
// error returns partial progress as "flushed N of M" so the eventual error
// names how far the flush got.
func flushAttempt(logger *slog.Logger, ipv6 bool) error {
	conn, err := dialCt()
	if err != nil {
		return err
	}
	defer conn.Close()

	tuples, err := dumpTuples(conn, unix.AF_UNSPEC, func(t ctTuple) bool {
		return t.isDNS() && (ipv6 || t.src.Is4())
	})
	if err != nil {
		return err
	}

	// Fresh deadline for the deletes: a slow dump would otherwise leave
	// them only the attempt's remainder.
	if err := conn.SetDeadline(time.Now().Add(ctFlushTimeout)); err != nil {
		return fmt.Errorf("set netlink deadline: %w", err)
	}
	deleted, gone := 0, 0
	var lastErr error
	for _, t := range tuples {
		ok, err := deleteTuple(conn, t)
		if err != nil {
			lastErr = err
			// The deadline covers the whole delete loop; once it expires
			// every remaining delete fails the same way, so stop instead
			// of burning through the tail.
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			continue
		}
		if ok {
			deleted++
		} else {
			gone++
		}
	}
	if lastErr != nil {
		return fmt.Errorf("flushed %d of %d DNS conntrack entries: %w", deleted, len(tuples), lastErr)
	}
	if deleted > 0 || gone > 0 {
		// already_gone counts ENOENT acks. A handful is the benign
		// dump→delete race; already_gone dominating deleted is the
		// signal that deletes are failing to address entries.
		logger.Info("Flushed pre-existing DNS conntrack entries", "count", deleted, "already_gone", gone)
	}
	return nil
}

// FlushDNSConntrack deletes every conntrack entry whose original-direction
// destination port is 53 (TCP or UDP): IPv4 ones, and IPv6 ones with ipv6,
// when the redirect covers IPv6 too. One it does not cover keeps its flows. nat is evaluated only on a
// flow's first packet and the verdict replayed from its conntrack entry, so
// DNS flow state predating the redirect bypasses the proxy — and state
// surviving teardown keeps DNAT'ing to the dead proxy — until deleted.
// Scoped to port 53 (a full flush would churn unrelated NAT state) and
// best-effort: the redirect stands regardless, and a returned error
// names how far the flush got. Mechanics, collateral analysis, and
// measurements: design.md.
func FlushDNSConntrack(logger *slog.Logger, ipv6 bool) error {
	var lastErr error
	for range ctFlushAttempts {
		err := flushAttempt(logger, ipv6)
		if err == nil {
			return nil
		}
		lastErr = err
		// A fresh attempt gets a fresh socket (discarding any stale queued
		// replies a timed-out one left behind), but permanent refusals are
		// not retried: EPERM (no CAP_NET_ADMIN) and EOPNOTSUPP (no
		// nf_conntrack_netlink) won't change on a new socket.
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) {
			return lastErr
		}
	}
	return lastErr
}
