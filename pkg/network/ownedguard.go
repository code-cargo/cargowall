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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// GuardTable names the tables that guard the container DNS addresses
// cargowall adds to lo, one for each address it holds, of the address's
// family: ip for ContainerDNSIPv4, ip6 for ContainerDNSIPv6. A guard comes
// and goes with its address (OwnedAddrs), whether or not the DNS redirect
// is in place, and is owned, like the redirect's table, by the socket that
// made it, so it dies with the process however that ends.
const GuardTable = "cargowall_guard"

// guardChains is addr's guard. The address is on lo, but the kernel
// delivers a packet for a local address whichever interface it arrives on,
// and answers ARP for one on every link (arp_ignore 0): a neighbour on the
// uplink could use the proxy as its resolver through it. So input, a filter
// hook, drops what arrives for addr on anything but lo or a docker bridge
// (docker0, or a user-defined br-*, which also matches bridges created
// later). And forward drops whatever would be forwarded to addr, which
// happens only were the address gone while cargowall runs: container DNS
// sent to it, by daemon.json or the redirect's DNAT, would then leave by
// the uplink, to whatever answers for the address there. A table of one
// family needs no family match.
func guardChains(addr netip.Addr) []redirectChain {
	dst := daddr(expr.CmpOpEq, addr.AsSlice())
	if addr.Is6() {
		dst = daddr6(expr.CmpOpEq, net.IP(addr.AsSlice()))
	}
	notBridgeOrLo := slices.Concat(iifname(expr.CmpOpNeq, "lo"), iifname(expr.CmpOpNeq, "docker0"),
		iifnamePrefix(expr.CmpOpNeq, "br-"))
	return []redirectChain{
		{
			name: "input", kind: "filter", hook: unix.NF_INET_LOCAL_IN, priority: filterPriority,
			rules: [][]expr.Any{slices.Concat(dst, notBridgeOrLo, verdict(expr.VerdictDrop))},
		},
		{
			name: "forward", kind: "filter", hook: unix.NF_INET_FORWARD, priority: filterPriority,
			rules: [][]expr.Any{slices.Concat(dst, verdict(expr.VerdictDrop))},
		},
	}
}

// ownedGuard is one address's guard table and the socket that made it.
type ownedGuard struct {
	conn  *netlink.Conn
	fam   tableFamily
	owned bool // the kernel took the owner flag
}

// installGuard installs addr's guard table, asking for it owned with
// ownerFlag (zero for unowned): a kernel that refuses the flag, before
// 5.12, gets it unowned, which a run that dies without removing it leaves
// until the next run's replaces it. A table of the name another live socket
// owns refuses the install.
func installGuard(addr netip.Addr, ownerFlag uint32, logger *slog.Logger) (*ownedGuard, error) {
	fam := familyIP
	if addr.Is6() {
		fam = familyIP6
	}
	var msgs []netlink.Message
	for _, c := range guardChains(addr) {
		m, err := chainMsgs(fam, GuardTable, c)
		if err != nil {
			return nil, fmt.Errorf("nftables: %w", err)
		}
		msgs = append(msgs, m...)
	}
	conn, owned, refused, err := installOwnedTable(fam, GuardTable, ownerFlag, msgs)
	if err != nil {
		return nil, err
	}
	if refused != nil {
		logger.Debug("The kernel refused an owned guard table, so it went in unowned", "table", fam.String()+" "+GuardTable,
			"refusal", refused)
	}
	return &ownedGuard{conn: conn, fam: fam, owned: owned}, nil
}

// remove deletes the guard table and closes the socket that made it. An
// owned table goes with its socket, so its failed delete is no error. An
// unowned one's is retried once on a new socket, and is then the error,
// unless the table is gone.
func (g *ownedGuard) remove() error {
	msg, err := delTableMsg(g.fam, GuardTable)
	if err == nil {
		err = transact(g.conn, []netlink.Message{msg})
	}
	_ = g.conn.Close()
	if err == nil || g.owned || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err = deleteTable(g.fam, GuardTable); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("nftables: deleting table %s %s: %w (nft delete table %s %s)", g.fam, GuardTable, err,
			g.fam, GuardTable)
	}
	return nil
}
