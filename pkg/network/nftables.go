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
	"time"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nf_tables messages for the redirect table, framed here on a socket the
// redirect keeps. google/nftables encodes the rule expressions, but its
// released Conn cannot carry this table: it writes every table with no
// flags, and it hides the socket, while an owned table must be created,
// changed and deleted from the one socket that owns it.

// nftTableFOwner is NFT_TABLE_F_OWNER (include/uapi/linux/netfilter/
// nf_tables.h, kernel 5.12; x/sys/unix does not carry it). An owned table
// can be changed or deleted only from the netlink socket that created it,
// and the kernel deletes it when that socket closes.
const nftTableFOwner = 0x2

// nftTimeout bounds each transaction's wait for the kernel's answers, so a
// lost reply cannot stall startup or shutdown.
const nftTimeout = 2 * time.Second

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
func nftMsg(msgType uint16, flags netlink.HeaderFlags, attrs func(ae *netlink.AttributeEncoder) error) (netlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian // nf_tables attributes are network order
	if err := attrs(ae); err != nil {
		return netlink.Message{}, err
	}
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
	return nftMsg(unix.NFT_MSG_NEWTABLE, netlink.Create, func(ae *netlink.AttributeEncoder) error {
		ae.String(unix.NFTA_TABLE_NAME, RedirectTable)
		ae.Uint32(unix.NFTA_TABLE_FLAGS, flags)
		return nil
	})
}

func delTableMsg() (netlink.Message, error) {
	return nftMsg(unix.NFT_MSG_DELTABLE, 0, func(ae *netlink.AttributeEncoder) error {
		ae.String(unix.NFTA_TABLE_NAME, RedirectTable)
		return nil
	})
}

// chainMsgs is the chain followed by its rules, appended in order.
func chainMsgs(c redirectChain) ([]netlink.Message, error) {
	chain, err := nftMsg(unix.NFT_MSG_NEWCHAIN, netlink.Create, func(ae *netlink.AttributeEncoder) error {
		ae.String(unix.NFTA_CHAIN_TABLE, RedirectTable)
		ae.String(unix.NFTA_CHAIN_NAME, c.name)
		ae.Nested(unix.NFTA_CHAIN_HOOK, func(hook *netlink.AttributeEncoder) error {
			hook.Uint32(unix.NFTA_HOOK_HOOKNUM, c.hook)
			hook.Uint32(unix.NFTA_HOOK_PRIORITY, uint32(c.priority))
			return nil
		})
		ae.String(unix.NFTA_CHAIN_TYPE, c.kind)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("chain %s: %w", c.name, err)
	}
	msgs := []netlink.Message{chain}
	for i, exprs := range c.rules {
		rule, err := nftMsg(unix.NFT_MSG_NEWRULE, netlink.Create|netlink.Append, func(ae *netlink.AttributeEncoder) error {
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
			return nil
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
func transact(conn *netlink.Conn, msgs []netlink.Message) error {
	if err := conn.SetDeadline(time.Now().Add(nftTimeout)); err != nil {
		return err
	}
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
	for acked := 0; acked < len(msgs); {
		replies, err := conn.Receive()
		if err != nil {
			return err
		}
		acked += len(replies)
	}
	return nil
}
