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
	"fmt"
	"net"
	"time"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The redirect table's nf_tables encoding: the expression helpers its rules
// are written in (dns_redirect.go holds the rules themselves), and its
// messages, framed here on a socket the redirect keeps. google/nftables
// encodes the rule expressions, but its
// released Conn cannot carry this table: it writes every table with no
// flags, and it hides the socket, while an owned table must be created,
// changed and deleted from the one socket that owns it.

// nftTableFOwner is NFT_TABLE_F_OWNER (include/uapi/linux/netfilter/
// nf_tables.h, kernel 5.12; x/sys/unix does not carry it). An owned table
// can be changed or deleted only from the netlink socket that created it,
// and the kernel deletes it when that socket closes. An older kernel
// refuses the flag.
const nftTableFOwner = 0x2

// nftTimeout bounds each transaction's wait for the kernel's answers, so a
// lost reply cannot stall startup or shutdown.
const nftTimeout = 2 * time.Second

// Expression helpers. A match loads into register 1 and compares it; dnat
// loads its address into register 1 and its port into register 2.

// udpAndTCP is rule twice, given the UDP match and then the TCP one: DNS
// rides both.
func udpAndTCP(rule func(proto []expr.Any) []expr.Any) [][]expr.Any {
	return [][]expr.Any{rule(l4proto(unix.IPPROTO_UDP)), rule(l4proto(unix.IPPROTO_TCP))}
}

func l4proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// Offsets of the source and destination ports, which TCP and UDP place
// alike at the head of their headers.
const (
	srcPort = 0
	dstPort = 2
)

func port(offset uint32, p uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(p)},
	}
}

// daddr compares the leading len(addr) bytes of the IPv4 destination, which
// sits 16 bytes into the header, so a byte-aligned prefix is its own bytes.
func daddr(op expr.CmpOp, addr []byte) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: uint32(len(addr))},
		&expr.Cmp{Op: op, Register: 1, Data: addr},
	}
}

func markIs(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
	}
}

// iifname compares the whole interface name, NUL padding included, so
// "lo" does not also match "lo0".
func iifname(op expr.CmpOp, name string) []expr.Any {
	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, name)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: op, Register: 1, Data: padded},
	}
}

// iifnamePrefix compares only the prefix's bytes: nft's "br-*", iptables'
// "br-+".
func iifnamePrefix(prefix string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(prefix)},
	}
}

func ctStateNew() []expr.Any {
	zero := binaryutil.NativeEndian.PutUint32(0)
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW), Xor: zero,
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zero},
	}
}

func dnat(addr net.IP, p uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: addr},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(p)},
		&expr.NAT{
			Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4,
			RegAddrMin: 1, RegProtoMin: 2, Specified: true,
		},
	}
}

func verdict(kind expr.VerdictKind) []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: kind}}
}

// redirectChain is one base chain of the redirect table and its rules, in
// order.
type redirectChain struct {
	name     string
	kind     string // nft chain type: "nat" or "filter"
	hook     uint32 // NF_INET_*
	priority int32
	rules    [][]expr.Any
}

// nftMsg is one nf_tables request on the redirect table's family. Every
// request asks for an ack, which is how transact learns each one's fate.
func nftMsg(msgType uint16, flags netlink.HeaderFlags, attrs func(ae *netlink.AttributeEncoder)) (netlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian // nf_tables attributes are network order
	attrs(ae)
	data, err := ae.Encode()
	if err != nil {
		return netlink.Message{}, err
	}
	return netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | msgType),
			Flags: netlink.Request | netlink.Acknowledge | flags,
		},
		Data: append(nfgenmsgV4(), data...),
	}, nil
}

func newTableMsg(flags uint32) (netlink.Message, error) {
	return nftMsg(unix.NFT_MSG_NEWTABLE, netlink.Create, func(ae *netlink.AttributeEncoder) {
		ae.String(unix.NFTA_TABLE_NAME, RedirectTable)
		ae.Uint32(unix.NFTA_TABLE_FLAGS, flags)
	})
}

func delTableMsg() (netlink.Message, error) {
	return nftMsg(unix.NFT_MSG_DELTABLE, 0, func(ae *netlink.AttributeEncoder) {
		ae.String(unix.NFTA_TABLE_NAME, RedirectTable)
	})
}

// chainMsgs is the chain followed by its rules, appended in order.
func chainMsgs(c redirectChain) ([]netlink.Message, error) {
	chain, err := nftMsg(unix.NFT_MSG_NEWCHAIN, netlink.Create, func(ae *netlink.AttributeEncoder) {
		ae.String(unix.NFTA_CHAIN_TABLE, RedirectTable)
		ae.String(unix.NFTA_CHAIN_NAME, c.name)
		ae.Nested(unix.NFTA_CHAIN_HOOK, func(hook *netlink.AttributeEncoder) error {
			hook.Uint32(unix.NFTA_HOOK_HOOKNUM, c.hook)
			hook.Uint32(unix.NFTA_HOOK_PRIORITY, uint32(c.priority))
			return nil
		})
		ae.String(unix.NFTA_CHAIN_TYPE, c.kind)
	})
	if err != nil {
		return nil, fmt.Errorf("chain %s: %w", c.name, err)
	}
	msgs := []netlink.Message{chain}
	for i, exprs := range c.rules {
		rule, err := nftMsg(unix.NFT_MSG_NEWRULE, netlink.Create|netlink.Append, func(ae *netlink.AttributeEncoder) {
			ae.String(unix.NFTA_RULE_TABLE, RedirectTable)
			ae.String(unix.NFTA_RULE_CHAIN, c.name)
			ae.Nested(unix.NFTA_RULE_EXPRESSIONS, func(list *netlink.AttributeEncoder) error {
				for _, e := range exprs {
					b, err := expr.Marshal(unix.NFPROTO_IPV4, e)
					if err != nil {
						return err
					}
					list.Bytes(netlink.Nested|unix.NFTA_LIST_ELEM, b)
				}
				return nil
			})
		})
		if err != nil {
			return nil, fmt.Errorf("chain %s rule %d: %w", c.name, i, err)
		}
		msgs = append(msgs, rule)
	}
	return msgs, nil
}

// transact sends msgs as one nf_tables transaction, which the kernel
// applies whole or not at all, and waits for its answer to each. The first
// error ends the wait: a transaction refused as a whole, for want of
// CAP_NET_ADMIN or of nf_tables, is answered with one error and no acks.
// The caller closes the socket after an error, dropping whatever answers
// are still queued.
//
// The kernel runs the whole transaction inside the send, module loads for
// the nat chain type and expressions included, which on a cold host can
// take seconds; by the time the send returns, every answer is queued. So
// the deadline bounds only the wait for them, set once the send is done: a
// deadline running from before it could expire during a transaction that
// committed and refuse to read its answers.
func transact(conn *netlink.Conn, msgs []netlink.Message) error {
	// The batch markers carry the subsystem the transaction is for in
	// nfgenmsg's resource id.
	marker := func(t netlink.HeaderType) netlink.Message {
		return netlink.Message{
			Header: netlink.Header{Type: t, Flags: netlink.Request},
			Data:   []byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, 0, unix.NFNL_SUBSYS_NFTABLES},
		}
	}
	batch := make([]netlink.Message, 0, len(msgs)+2)
	batch = append(batch, marker(unix.NFNL_MSG_BATCH_BEGIN))
	batch = append(batch, msgs...)
	batch = append(batch, marker(unix.NFNL_MSG_BATCH_END))
	if _, err := conn.SendMessages(batch); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(nftTimeout)); err != nil {
		return err
	}
	for acked := 0; acked < len(msgs); {
		replies, err := conn.Receive()
		if err != nil {
			return err
		}
		acked += len(replies)
	}
	return nil
}
