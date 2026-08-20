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
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Conntrack flush for the DNS redirect, via ctnetlink (NETLINK_NETFILTER).
// Attribute constants are from include/uapi/linux/netfilter/
// nfnetlink_conntrack.h — x/sys/unix carries the nfnetlink subsystem and
// version constants but not the CTA_* space.
//
// Dump-then-delete-per-entry is the only mechanism the kernel offers for a
// port-scoped flush: IPCTNL_MSG_CT_DELETE takes either a full tuple or a
// whole-table flush, and the flush path rejects CTA_FILTER with EOPNOTSUPP
// (filters are dump-only; verified on 6.8) — the same reason
// conntrack-tools' `conntrack -D --dport` iterates in userspace. Dumps are
// flow-controlled (the kernel produces one batch per recv), so the default
// rcvbuf handles arbitrarily large tables; a 5k-entry table dumps in ~5ms.

const (
	// nfnetlink message subtypes (enum ctnl_msg_types); dump replies
	// arrive as IPCTNL_MSG_CT_NEW.
	ipctnlMsgCtNew    = 0 // IPCTNL_MSG_CT_NEW
	ipctnlMsgCtGet    = 1 // IPCTNL_MSG_CT_GET
	ipctnlMsgCtDelete = 2 // IPCTNL_MSG_CT_DELETE

	ctaTupleOrig = 1 // CTA_TUPLE_ORIG (enum ctattr_type)

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

// ctDumpAttempts bounds the dump retry. mdlayher's Receive is
// all-or-nothing across a multipart dump — a mid-dump failure yields no
// partial results to act on — so retrying on a fresh socket is what keeps a
// transient hiccup from leaving every stale DNS flow in place.
const ctDumpAttempts = 3

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

// ctTuple is one flow's original-direction identity — exactly the fields
// ctnetlink needs to address the entry for deletion. Ports are host order.
type ctTuple struct {
	srcIP   [4]byte
	dstIP   [4]byte
	proto   uint8
	srcPort uint16
	dstPort uint16
}

// isDNS reports whether the flow is one the DNS redirect claims: TCP or UDP
// with original destination port 53. NAT does not rewrite the original-
// direction tuple, so entries already DNAT'd to the proxy match too.
func (t ctTuple) isDNS() bool {
	return t.dstPort == 53 && (t.proto == unix.IPPROTO_TCP || t.proto == unix.IPPROTO_UDP)
}

func bePort(p uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, p)
	return b
}

// marshalTupleOrig encodes a CTA_TUPLE_ORIG attribute tree addressing one
// conntrack entry.
func marshalTupleOrig(t ctTuple) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	ae.Nested(ctaTupleOrig, func(nae *netlink.AttributeEncoder) error {
		nae.Nested(ctaTupleIP, func(iae *netlink.AttributeEncoder) error {
			iae.Bytes(ctaIPv4Src, t.srcIP[:])
			iae.Bytes(ctaIPv4Dst, t.dstIP[:])
			return nil
		})
		nae.Nested(ctaTupleProto, func(pae *netlink.AttributeEncoder) error {
			pae.Uint8(ctaProtoNum, t.proto)
			pae.Bytes(ctaProtoSrcPort, bePort(t.srcPort))
			pae.Bytes(ctaProtoDstPort, bePort(t.dstPort))
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

// dumpConntrackTuples dumps the IPv4 conntrack table, retrying on a fresh
// socket per attempt (see ctDumpAttempts; a fresh dial also discards any
// stale queued replies from a timed-out attempt). Unparseable entries are
// skipped, not fatal — an entry we cannot address for deletion is one the
// caller could not act on anyway. Table churn during the dump can set
// NLM_F_DUMP_INTR, which mdlayher ignores; an entry missed that way is a
// post-redirect flow that already carries the right NAT verdict. Returns
// the successful attempt's conn for the caller's follow-up deletes; the
// caller closes it.
func dumpConntrackTuples() (*netlink.Conn, []ctTuple, error) {
	var lastErr error
	for range ctDumpAttempts {
		conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("dial netfilter netlink: %w", err)
		}
		if err := conn.SetDeadline(time.Now().Add(ctFlushTimeout)); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("set netlink deadline: %w", err)
		}
		msgs, err := conn.Execute(netlink.Message{
			Header: netlink.Header{
				Type:  ctMsgType(ipctnlMsgCtGet),
				Flags: netlink.Request | netlink.Dump,
			},
			Data: nfgenmsgV4(),
		})
		if err != nil {
			conn.Close()
			lastErr = fmt.Errorf("conntrack dump: %w", err)
			continue
		}
		var tuples []ctTuple
		for _, m := range msgs {
			if m.Header.Type != ctMsgType(ipctnlMsgCtNew) {
				continue
			}
			if t, ok := parseConntrackTupleOrig(m.Data); ok {
				tuples = append(tuples, t)
			}
		}
		return conn, tuples, nil
	}
	return nil, nil, lastErr
}

// deleteConntrackEntry removes one entry, addressed by its original-
// direction tuple. ENOENT is success: the entry expired or was replaced
// between dump and delete, which is the outcome the delete wanted anyway.
func deleteConntrackEntry(conn *netlink.Conn, t ctTuple) error {
	attrs, err := marshalTupleOrig(t)
	if err != nil {
		return fmt.Errorf("marshal conntrack tuple: %w", err)
	}
	_, err = conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  ctMsgType(ipctnlMsgCtDelete),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(nfgenmsgV4(), attrs...),
	})
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("conntrack delete: %w", err)
	}
	return nil
}

// FlushDNSConntrack deletes every IPv4 conntrack entry whose original-
// direction destination port is 53 (TCP or UDP). The nat table is evaluated
// only on a flow's first packet — the verdict is stamped into its conntrack
// entry and replayed for every later packet — so DNS flow state predating
// the redirect keeps steering queries straight to the (allow-listed)
// upstream resolver, silently bypassing the proxy's rule matching and IP
// allowlisting; state surviving teardown keeps DNAT'ing queries to the
// now-dead proxy. Deleting the entries makes the next packet of every DNS
// flow re-traverse the nat OUTPUT chain and land on the current rules.
//
// Scoped to port 53 rather than a full table flush, which would churn
// unrelated NAT state (Docker MASQUERADE bindings, established flows). The
// scoped delete is collateral-free: loopback stub traffic (127.0.0.53) is
// outside the DNAT anyway, the proxy's own marked upstream flows re-match
// the mark RETURN rules, and an in-flight transaction costs at most one
// retry. Callers treat failure as best-effort — the iptables rules stand
// either way, and idle entries age out on their own in 30-120s — but an
// actively-used flow (e.g. an open DNS-over-TCP stream) keeps refreshing
// its entry and can bypass indefinitely, hence the Warn at both call sites.
func FlushDNSConntrack(logger *slog.Logger) error {
	conn, tuples, err := dumpConntrackTuples()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Fresh deadline for the deletes: the dump may have consumed most of
	// its attempt's budget.
	if err := conn.SetDeadline(time.Now().Add(ctFlushTimeout)); err != nil {
		return fmt.Errorf("set netlink deadline: %w", err)
	}

	deleted := 0
	var lastErr error
	for _, t := range tuples {
		if !t.isDNS() {
			continue
		}
		if err := deleteConntrackEntry(conn, t); err != nil {
			lastErr = err
			continue
		}
		deleted++
	}
	if deleted > 0 {
		logger.Info("Flushed pre-existing DNS conntrack entries", "count", deleted)
	}
	return lastErr
}
