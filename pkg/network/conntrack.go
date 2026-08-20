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

// nfgenmsgV4 returns the nfgenmsg header for AF_INET — the redirect is
// v4-only (iptables rules, udp4/tcp4 proxy listeners), so v4 is the only
// table with entries to flush.
func nfgenmsgV4() []byte {
	return []byte{unix.AF_INET, unix.NFNETLINK_V0, 0, 0}
}

// ctTuple is one flow's original-direction identity plus its conntrack
// zone — exactly the fields ctnetlink needs to address the entry for
// deletion. Ports and zone are host order.
type ctTuple struct {
	srcIP   [4]byte
	dstIP   [4]byte
	proto   uint8
	srcPort uint16
	dstPort uint16
	zone    uint16
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
			iae.Bytes(ctaIPv4Src, t.srcIP[:])
			iae.Bytes(ctaIPv4Dst, t.dstIP[:])
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

// parseConntrackTupleOrig extracts the original-direction v4 tuple from one
// conntrack message payload (nfgenmsg + attributes). ok is true only when
// every field a delete needs was present and the payload decoded cleanly —
// a v6 entry (no CTA_IP_V4_*) or a truncated message parses as !ok and is
// skipped.
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
							case iad.Type() == ctaIPv4Src && len(b) == 4:
								copy(t.srcIP[:], b)
								haveSrc = true
							case iad.Type() == ctaIPv4Dst && len(b) == 4:
								copy(t.dstIP[:], b)
								haveDst = true
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
	return t, ad.Err() == nil && haveSrc && haveDst && haveNum && haveSport && haveDport
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

// dumpTuples dumps the IPv4 conntrack table over conn, keeping the tuples
// keep() accepts (nil keeps all). Best-effort by design: ctnetlink dumps
// carry no consistency signal (the conntrack dump path never stamps
// NLM_F_DUMP_INTR), so an entry that moves during the walk can be missed —
// the flush makes no completeness claim. Unparseable entries are skipped,
// not fatal: an entry we cannot address for deletion is one we could not
// act on anyway.
func dumpTuples(conn *netlink.Conn, keep func(ctTuple) bool) ([]ctTuple, error) {
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  ctMsgType(ipctnlMsgCtGet),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: nfgenmsgV4(),
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
		Data: append(nfgenmsgV4(), attrs...),
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
// entries. Re-running it is convergent: a re-dump no longer contains what a
// prior pass already deleted. A delete-phase error returns partial progress
// as "flushed N of M" so the eventual error names how far the flush got.
func flushAttempt(logger *slog.Logger) error {
	conn, err := dialCt()
	if err != nil {
		return err
	}
	defer conn.Close()

	tuples, err := dumpTuples(conn, ctTuple.isDNS)
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

// FlushDNSConntrack deletes every IPv4 conntrack entry whose original-
// direction destination port is 53 (TCP or UDP). nat is evaluated only on a
// flow's first packet and the verdict replayed from its conntrack entry, so
// DNS flow state predating the redirect bypasses the proxy — and state
// surviving teardown keeps DNAT'ing to the dead proxy — until deleted.
// Scoped to port 53 (a full flush would churn unrelated NAT state) and
// best-effort: the iptables rules stand regardless, and a returned error
// names how far the flush got. Mechanics, collateral analysis, and
// measurements: design.md.
func FlushDNSConntrack(logger *slog.Logger) error {
	var lastErr error
	for range ctFlushAttempts {
		err := flushAttempt(logger)
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
