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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// DNSProxyFWMark is the firewall mark applied to the DNS proxy's own upstream
// queries so that the redirect's return rules can exempt them from it.
const DNSProxyFWMark = 0xCA12

// MarkDNSProxySocket is a net Control function (Dialer.Control or
// ListenConfig.Control) that stamps DNSProxyFWMark on the socket, so its
// traffic matches the return exemptions in redirectChains instead of
// being DNAT'd back into the proxy. Every socket cargowall itself uses on
// the port-53 path — the proxy's upstream client, its listeners, and the
// startup stub peek — must carry the mark.
func MarkDNSProxySocket(_, _ string, c syscall.RawConn) error {
	var sErr error
	if err := c.Control(func(fd uintptr) {
		sErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, DNSProxyFWMark)
	}); err != nil {
		return err
	}
	return sErr
}

// RedirectTable names the nftables table that holds the whole redirect, of
// family inet, or ip where it covers IPv4 alone (see RedirectSpec). One table
// of cargowall's own, rather than rules spliced into
// the host's nat and filter tables, is what makes the redirect atomic: it
// is built in one transaction and deleted in one, so no packet meets half
// of it, and it never touches rules Docker or the host own. It needs only
// the kernel's nf_tables, not an iptables or nft binary, which container
// runner images such as ARC's do not carry. The table is owned by the
// socket that created it (see DNSRedirect).
const RedirectTable = "cargowall"

// Chain priorities. Both nat chains run one ahead of dstnat
// (NF_IP_PRI_NAT_DST), where iptables' nat table, and with it Docker's and
// kube-proxy's DNAT, sit. The first NAT binding a flow gets is the one it
// keeps, so DNS bound for a published container port or a service address
// still reaches the proxy, and the proxy's own marked queries, which the
// chain returns unbound, still get the host's DNAT after it. At the same
// priority the order would hang on which table registered first, which
// the kernel resolves newest first. The input guard filters at
// NF_IP_PRI_FILTER; a drop anywhere is a drop, so its order is moot.
const (
	natPriority    = -100 - 1
	filterPriority = 0
)

// ProxyAddrIPv6 is the proxy listener the redirect sends IPv6 DNS to: the
// address the DNAT names (proxyIPv6) and the listener cmd binds are this one
// value.
const ProxyAddrIPv6 = "[::1]:53"

var proxyIPv6 = netip.MustParseAddrPort(ProxyAddrIPv6)

// RedirectSpec is what Install redirects.
type RedirectSpec struct {
	// IPv6 covers IPv6 DNS as well, sending it to the proxy's listener at
	// ProxyAddrIPv6, in a table of family inet. Without it the table is of
	// family ip, IPv4 only.
	IPv6 bool
	// BridgeIP is the proxy's container listener on the docker bridge, ""
	// for none.
	BridgeIP string
}

// HostIPv6 reports whether this network namespace has an IPv6 address
// other than loopback's, link-local included, since DNS to an on-link
// resolver leaves by one: whether IPv6 DNS can leave it, and so whether a
// redirect that does not cover IPv6 leaves a way around the proxy. Addresses
// that cannot be listed count as IPv6, the side that leaves no gap
// unreported.
func HostIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() == nil && !ipnet.IP.IsLoopback() {
			return true
		}
	}
	return false
}

// redirectChains is the redirect for traffic this netns originates, plus,
// with a docker bridge IP, for DNS that containers send through a docker
// bridge. With ipv6 the table is inet, and a rule that reads an address, or
// rewrites to one, first matches the packet's family (nfproto): there an
// IPv4 offset read on an IPv6 packet would compare bytes of its source
// address instead. An ip table's packets are all IPv4, so it needs no match.
//
// output, the nat hook for locally generated packets:
//   - the DNS proxy's own sockets (DNSProxyFWMark: its upstream client, its
//     listeners, the startup stub peeks) return first, before any DNAT;
//   - systemd-resolved's stubs are DNAT'd too, 127.0.0.53 and the proxy-mode
//     127.0.0.54 (systemd 247 and later): a stub-following client otherwise
//     reaches resolved, which re-queries upstream from its OWN socket,
//     laundering the querying process away from the sockdiag join and
//     serving warm cache hits the proxy never sees;
//   - every other DNS leaving for a non-loopback address goes to the proxy.
//     127.0.0.1, the proxy's listen address, is never DNAT'd;
//   - with ipv6, IPv6 DNS likewise goes to the proxy at ProxyAddrIPv6, all
//     but what is sent to ::1 itself. IPv6 has no resolved stub to send to.
//     DNS for a link-local resolver gets no answer at all: a socket
//     connected to one is bound to its interface, which keeps the DNAT'd
//     packet from ::1 (ENETUNREACH at once), and an unbound socket's query
//     reaches the proxy, whose answer, to a link-local source seen on
//     loopback, cannot be routed back, so the client times out. That is DNS
//     that reaches no resolver, not one around the proxy.
//
// input, a filter hook: an inbound sport-53 packet off loopback must not
// CREATE a flow. A reply racing the conntrack flush would re-create it
// reversed, with a null NAT binding no later flush can see (design.md, "DNS
// redirect"). Replies on ESTABLISHED entries never match. Loopback is
// exempt: a reversed 127.x entry has loopback addresses on both sides, so it
// can only ever match loopback tuples and never capture a later external
// query, and dropping a stub or proxy reply mid-transaction would cost the
// client its full resolver timeout. Its rules read no address, so in an inet
// table they guard IPv6 as well.
//
// prerouting, only with a bridge IP: DNS arriving on docker0 or a
// user-defined br-* bridge (which also matches bridges created later) goes
// to the proxy's container listener on that IP. That traffic is forwarded,
// not originated here, so the output chain never sees it: a container that
// names its own resolver (--dns, a hard-coded 8.8.8.8, a dockerd whose
// daemon.json cargowall cannot rewrite) would otherwise resolve around the
// proxy. DNAT keeps the source address, so the proxy still attributes the
// query by container IP. With ipv6, IPv6 DNS arriving there is dropped:
// daemon.json points containers at the IPv4 listener, so only a container
// naming an IPv6 resolver of its own sends any, and there is no IPv6
// listener to send it to. A bridge's IPv6 address is not one cargowall can
// count on holding, and DNAT to an address it does not hold hands the query
// to whatever does.
func redirectChains(ipv6 bool, bridgeIP net.IP) []redirectChain {
	var v4, v6 []expr.Any
	if ipv6 {
		v4, v6 = nfproto(unix.NFPROTO_IPV4), nfproto(unix.NFPROTO_IPV6)
	}
	proxy := net.IPv4(127, 0, 0, 1).To4()
	output := udpAndTCP(func(proto []expr.Any) []expr.Any {
		return slices.Concat(proto, port(dstPort, 53), markIs(DNSProxyFWMark), verdict(expr.VerdictReturn))
	})
	for _, stub := range []net.IP{net.IPv4(127, 0, 0, 53).To4(), net.IPv4(127, 0, 0, 54).To4()} {
		output = append(output, udpAndTCP(func(proto []expr.Any) []expr.Any {
			return slices.Concat(v4, proto, daddr(expr.CmpOpEq, stub), port(dstPort, 53), dnat(proxy, 53))
		})...)
	}
	output = slices.Concat(output,
		// One byte of the address is the /8: 127.0.0.0/8 is every address
		// whose first byte is 127.
		udpAndTCP(func(proto []expr.Any) []expr.Any {
			return slices.Concat(v4, proto, port(dstPort, 53), daddr(expr.CmpOpNeq, []byte{127}), dnat(proxy, 53))
		}),
	)
	if ipv6 {
		proxy6 := net.IP(proxyIPv6.Addr().AsSlice())
		output = slices.Concat(output, udpAndTCP(func(proto []expr.Any) []expr.Any {
			return slices.Concat(v6, proto, port(dstPort, 53), daddr6(expr.CmpOpNeq, proxy6),
				dnat(proxy6, proxyIPv6.Port()))
		}))
	}
	input := udpAndTCP(func(proto []expr.Any) []expr.Any {
		return slices.Concat(proto, iifname(expr.CmpOpNeq, "lo"), port(srcPort, 53), ctStateNew(), verdict(expr.VerdictDrop))
	})
	chains := []redirectChain{
		{name: "output", kind: "nat", hook: unix.NF_INET_LOCAL_OUT, priority: natPriority, rules: output},
		{name: "input", kind: "filter", hook: unix.NF_INET_LOCAL_IN, priority: filterPriority, rules: input},
	}
	if bridgeIP == nil {
		return chains
	}
	bridges := [][]expr.Any{iifname(expr.CmpOpEq, "docker0"), iifnamePrefix("br-")}
	var prerouting [][]expr.Any
	for _, bridge := range bridges {
		prerouting = append(prerouting, udpAndTCP(func(proto []expr.Any) []expr.Any {
			return slices.Concat(v4, bridge, proto, port(dstPort, 53), dnat(bridgeIP, 53))
		})...)
	}
	if ipv6 {
		for _, bridge := range bridges {
			prerouting = append(prerouting, udpAndTCP(func(proto []expr.Any) []expr.Any {
				return slices.Concat(v6, bridge, proto, port(dstPort, 53), verdict(expr.VerdictDrop))
			})...)
		}
	}
	return append(chains, redirectChain{
		name: "prerouting", kind: "nat", hook: unix.NF_INET_PRE_ROUTING, priority: natPriority, rules: prerouting,
	})
}

// DNSRedirect is the redirect. Once installed it keeps the netlink socket
// that created the table, and where the kernel allows (5.12 and later) that
// socket owns it:
// no other socket can change or delete the table, and the kernel deletes it
// when the socket closes, which the process's exit does however it ends. A
// cargowall killed outright therefore takes the redirect with it rather
// than leaving the host's DNS DNAT'd to a proxy that is gone; only the
// conntrack flush Teardown would have run is lost. The socket is
// close-on-exec, so no child keeps the table alive.
//
// A kernel that refuses the ownership flag gets the table unowned: the same
// redirect, but one that outlives a process that dies without Teardown,
// until the next Install replaces it, and one another process can delete.
//
// Install and Teardown may run concurrently: a forced shutdown tears down
// from another goroutine while startup is still installing. Teardown then
// waits for the transaction and removes what it installed, and an Install
// after Teardown refuses.
type DNSRedirect struct {
	logger *slog.Logger
	// ownerFlag is the table flag Install asks for first: NFT_TABLE_F_OWNER,
	// or a flag the kernel refuses when a test stands in for a kernel
	// without owned tables. Zero asks for an unowned table outright.
	ownerFlag uint32
	// inet is the family Install asks for first with spec.IPv6:
	// familyInet when zero, or one the kernel refuses when a test stands in
	// for a kernel without inet tables.
	inet tableFamily

	mu     sync.Mutex
	conn   *netlink.Conn // the socket that made the table, while installed
	family tableFamily   // the table's, while installed
	owned  bool          // the kernel took the owner flag
	done   bool          // torn down
	// ipv6Refused is why the kernel took no inet table, when spec.IPv6 asked
	// for one and the redirect went in IPv4 only.
	ipv6Refused error
	// ownerRefused remembers the kernel refusing the owner flag, so a second
	// family's install does not ask again.
	ownerRefused bool
}

// NewDNSRedirect returns a redirect to Install. Register its Teardown
// first.
func NewDNSRedirect(logger *slog.Logger) *DNSRedirect {
	return &DNSRedirect{logger: logger, ownerFlag: nftTableFOwner, inet: familyInet}
}

// Install installs the redirect table (see redirectChains): outbound DNS
// (UDP+TCP port 53) goes to the local proxy at 127.0.0.1:53, and with
// spec.IPv6 IPv6 DNS to ProxyAddrIPv6, except the proxy's own marked
// queries, and the input guard keeps flushed flows from being re-picked-up
// in reverse. A bridge IP in spec, where the proxy has a container
// listener, also redirects container DNS crossing a docker bridge.
//
// One transaction builds the table, so a failure leaves the host as it
// was. It first replaces a table of the same name that no socket owns (add,
// delete, add: the first add makes the delete safe when there is none). A
// table another live socket owns, such as a cargowall already running in
// this network namespace, refuses that add, and Install fails. Once the
// table is in, a leftover of the other family, from a run with or without
// IPv6, is removed the same way, in a transaction of its own, so a kernel
// that has no such family does not fail the install; a refusal there takes
// the new table back out (see installFamily).
//
// The table is asked for owned, and the kernel's answer decides rather
// than its version: one that refuses the flag, as kernels before 5.12 do
// (EINVAL there, EOPNOTSUPP for a flag a later kernel does not know), gets
// the same transaction again with the table unowned. Likewise a kernel that
// will not take the inet table, for any reason but another process holding
// the redirect (EPERM), gets the IPv4-only one, and IPv6Refused says why: an
// IPv4 redirect is never lost to a part of the kernel only IPv6 needs. When
// the ip table fails the same way, that is the error returned.
func (r *DNSRedirect) Install(spec RedirectSpec) error {
	var bridge net.IP
	if spec.BridgeIP != "" {
		if bridge = net.ParseIP(spec.BridgeIP).To4(); bridge == nil {
			return fmt.Errorf("docker bridge IP %q is not an IPv4 address", spec.BridgeIP)
		}
	}

	r.mu.Lock()
	switch {
	case r.done:
		r.mu.Unlock()
		return errors.New("DNS redirect already torn down")
	case r.conn != nil:
		r.mu.Unlock()
		return errors.New("DNS redirect already installed")
	}
	fam, ipv6 := familyIP, false
	if spec.IPv6 {
		fam, ipv6 = r.inet, true
		if fam == 0 {
			fam = familyInet
		}
	}
	conn, owned, err := r.installFamily(fam, ipv6, bridge)
	if err != nil && ipv6 && !errors.Is(err, unix.EPERM) && !errors.Is(err, errLeftover) {
		r.ipv6Refused = err
		fam, ipv6 = familyIP, false
		conn, owned, err = r.installFamily(fam, ipv6, bridge)
	}
	if err != nil {
		r.mu.Unlock()
		return err
	}
	r.conn, r.family, r.owned = conn, fam, owned
	r.logger.Info("DNS redirect installed", "nftables_table", fam.String()+" "+RedirectTable, "owned", r.owned,
		"ipv6", ipv6, "container_bridge_redirect", bridge != nil)
	r.mu.Unlock()

	// Purge DNS flow state predating the redirect — nat verdicts are
	// per-flow, so those flows would keep bypassing the proxy (see
	// FlushDNSConntrack). The input guard is already in place, so a reply in
	// flight across this flush cannot resurrect a deleted flow in reverse.
	// Outside the lock, so a forced Teardown does not wait out a slow flush;
	// one that runs first deletes the table and flushes itself, and this
	// flush then only repeats it.
	if err := FlushDNSConntrack(r.logger, ipv6); err != nil {
		r.logger.Warn("Failed to flush DNS conntrack entries; pre-existing DNS flows may bypass the proxy until they expire",
			"error", err)
	}
	return nil
}

// IPv6Refused is why the kernel took no inet table, when Install was asked
// to cover IPv6 and the redirect went in IPv4 only; nil otherwise.
func (r *DNSRedirect) IPv6Refused() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ipv6Refused
}

// inetRefused reports whether an install of the inet table failed for want
// of the family itself: the family refused (EAFNOSUPPORT, or EOPNOTSUPP
// before 6.8 rejected unknown families outright), or its nat chain type
// missing (ENOENT). It picks the error's hint.
func inetRefused(err error) bool {
	return errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOENT)
}

// errLeftover marks a failure to remove the other family's leftover, which
// says nothing of whether the kernel takes the install's own family.
var errLeftover = errors.New("other family's table")

// installFamily installs the table as family fam, owned where the kernel
// allows, and then removes a leftover of the other family, so that a
// failed install leaves the host as it was and a refusal there can only be
// another process's table. That refusal takes the new table back out: on
// the socket that made it, and failing that on a new one, since an unowned
// table outlives its socket. One that still stands is named in the error.
func (r *DNSRedirect) installFamily(fam tableFamily, ipv6 bool, bridge net.IP) (*netlink.Conn, bool, error) {
	conn, owned, err := r.installOwned(fam, ipv6, bridge)
	if err != nil {
		return nil, false, err
	}
	if err := removeLeftover(fam.other()); err != nil {
		undo, uerr := delTableMsg(fam)
		if uerr == nil {
			uerr = transact(conn, []netlink.Message{undo})
		}
		_ = conn.Close()
		if uerr != nil && !owned {
			if uerr = deleteTable(fam); errors.Is(uerr, unix.ENOENT) {
				uerr = nil
			}
		}
		if uerr != nil && !owned {
			return nil, false, fmt.Errorf("%w; and the table installed before it stays until removed "+
				"(nft delete table %s %s): %v", err, fam, RedirectTable, uerr)
		}
		return nil, false, err
	}
	return conn, owned, nil
}

// installOwned installs the table as family fam, owned unless the kernel
// refuses the flag, which it then is not asked for again.
func (r *DNSRedirect) installOwned(fam tableFamily, ipv6 bool, bridge net.IP) (*netlink.Conn, bool, error) {
	var chains []netlink.Message
	for _, c := range redirectChains(ipv6, bridge) {
		msgs, err := chainMsgs(fam, c)
		if err != nil {
			return nil, false, fmt.Errorf("nftables: %w", err)
		}
		chains = append(chains, msgs...)
	}
	if r.ownerFlag == 0 || r.ownerRefused {
		conn, err := installTable(fam, 0, chains)
		return conn, false, err
	}
	conn, err := installTable(fam, r.ownerFlag, chains)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		refused := err
		if conn, err = installTable(fam, 0, chains); err == nil {
			r.ownerRefused = true
			r.logger.Info("The kernel refused an owned DNS redirect table (owned tables need 5.12), so it went in unowned: "+
				"if cargowall dies without tearing it down, it stays until the next run replaces it", "refusal", refused)
		}
		return conn, false, err
	}
	return conn, err == nil, err
}

// removeLeftover removes a table of family fam that no socket owns (add,
// delete), one an earlier run that did or did not cover IPv6 left. A kernel
// that has no such family (EAFNOSUPPORT, or EOPNOTSUPP before 6.8) has no
// leftover to remove. Any other failure, a live socket's table refusing
// (EPERM) above all, fails the install, as it would for the install's own
// family: a leftover kept would be a second redirect. It runs on a socket of
// its own: a refused batch leaves the delete's answer queued, which on the
// redirect's socket a later transaction would read as its own.
func removeLeftover(fam tableFamily) error {
	create, errCreate := newTableMsg(fam, 0)
	del, errDel := delTableMsg(fam)
	if err := errors.Join(errCreate, errDel); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return fmt.Errorf("nftables: %w: %w%s", errLeftover, err, installHint(err))
	}
	defer conn.Close()
	err = transact(conn, []netlink.Message{create, del})
	if err == nil || errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return fmt.Errorf("nftables: removing %w %s %s: %w%s", errLeftover, fam, RedirectTable, err, installHint(err))
}

// installTable runs one install transaction, the table of family fam with
// the given flags and then chains, on a new socket, and returns the socket
// that made it.
func installTable(fam tableFamily, flags uint32, chains []netlink.Message) (*netlink.Conn, error) {
	create, errCreate := newTableMsg(fam, 0)
	del, errDel := delTableMsg(fam)
	table, errTable := newTableMsg(fam, flags)
	if err := errors.Join(errCreate, errDel, errTable); err != nil {
		return nil, fmt.Errorf("nftables: %w", err)
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("nftables: %w%s", err, installHint(err))
	}
	if err := transact(conn, slices.Concat([]netlink.Message{create, del, table}, chains)); err != nil {
		_ = conn.Close()
		hint := installHint(err)
		if fam == familyInet && inetRefused(err) {
			hint = " (the kernel may lack inet tables or IPv6 nat: CONFIG_NF_TABLES_INET, or nf_nat for IPv6)"
		}
		return nil, fmt.Errorf("nftables: installing table %s %s: %w%s", fam, RedirectTable, err, hint)
	}
	return conn, nil
}

// deleteTable deletes the table of family fam from a new socket: an
// unowned table is anyone's to delete.
func deleteTable(fam tableFamily) error {
	msg, err := delTableMsg(fam)
	if err != nil {
		return err
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	return transact(conn, []netlink.Message{msg})
}

// installHint names what an install error most likely means, since under
// an enforcing policy it becomes the reason startup failed, and the bare
// errno does not say which part of the kernel is missing.
func installHint(err error) string {
	switch {
	case errors.Is(err, unix.EPERM):
		return " (another process owns the table, such as a cargowall already running in this " +
			"network namespace, or CAP_NET_ADMIN is missing)"
	case errors.Is(err, unix.EPROTONOSUPPORT):
		return " (the kernel has no nfnetlink: CONFIG_NETFILTER_NETLINK)"
	case errors.Is(err, unix.EOPNOTSUPP):
		return " (nf_tables refused the operation: the kernel may have no nf_tables, CONFIG_NF_TABLES, or be unable to load it)"
	case errors.Is(err, unix.ENOENT):
		return " (the kernel lacks a part of nf_tables the redirect uses and cannot load it: " +
			"the nat chain type, nft_chain_nat, or the nat, ct or meta expressions)"
	}
	return ""
}

// resolvedRuntimeDir exists only while systemd-resolved is running. Its
// presence is the signal that tells "resolved not in use" (a quiet skip) apart
// from "resolved running but the flush genuinely failed" (surfaced to the
// caller). A var so tests can point it at a controllable path.
var resolvedRuntimeDir = "/run/systemd/resolve"

// flushResolvedTimeout bounds the resolvectl call so a wedged systemd-resolved
// (or its D-Bus endpoint) cannot stall startup before the eBPF program
// attaches and the firewall begins enforcing. A var so tests can shorten it.
var flushResolvedTimeout = 5 * time.Second

// FlushResolvedCache clears systemd-resolved's DNS cache via
// `resolvectl flush-caches`. Client packets to the stub are DNAT'd to the
// proxy by the redirect (redirectChains), so the residual warm-cache exposure is lookups
// that reach resolved WITHOUT a client DNS packet — nss-resolve's
// D-Bus/varlink path — plus resolved's own upstream re-queries: a warm
// cache hit there is served invisibly, the proxy never sees the name, and
// the connection lands as an unallowed bare IP. Flushing forces those
// lookups upstream, through the redirect.
//
// Best-effort with two quiet skips (return nil, log at Debug): resolvectl not
// installed, or systemd-resolved not running — in both cases there is no stub
// cache to flush and the redirect alone suffices. Everything else is surfaced
// to the caller: a non-not-found lookup error (e.g. a non-executable resolvectl
// on PATH), a non-zero flush exit, or the bounded call timing out.
func FlushResolvedCache(ctx context.Context, logger *slog.Logger) error {
	path, err := exec.LookPath("resolvectl")
	if err != nil {
		// Only genuine not-installed is benign; a permission or other PATH
		// resolution failure is real and must not silently skip the flush.
		if errors.Is(err, exec.ErrNotFound) {
			logger.Debug("resolvectl not found; skipping systemd-resolved cache flush")
			return nil
		}
		return fmt.Errorf("locating resolvectl failed: %w", err)
	}

	// resolvectl can be installed on hosts that don't actually run
	// systemd-resolved (a different resolver is in use); its runtime dir is
	// absent there, so skip quietly rather than warn on every startup. Only a
	// genuine "not there" is benign — a stat failure such as EACCES/EIO is real
	// and surfaced, mirroring the LookPath classification above (otherwise a
	// host where resolved *is* running would be misreported as a correct skip).
	if _, err := os.Stat(resolvedRuntimeDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Debug("systemd-resolved not running; skipping cache flush", "probe", resolvedRuntimeDir)
			return nil
		}
		return fmt.Errorf("probing %s failed: %w", resolvedRuntimeDir, err)
	}

	flushCtx, cancel := context.WithTimeout(ctx, flushResolvedTimeout)
	defer cancel()
	flush := exec.CommandContext(flushCtx, path, "flush-caches")
	// WaitDelay bounds CombinedOutput's Wait after the deadline kills the
	// process: without it, Wait blocks until every inheritor of the stdout/
	// stderr pipes exits, so the timeout would rest on resolvectl never leaving
	// a lingering child holding them.
	flush.WaitDelay = time.Second
	if out, err := flush.CombinedOutput(); err != nil {
		// Name the deadline rather than surfacing a bare "signal: killed".
		if ctxErr := flushCtx.Err(); ctxErr != nil {
			return fmt.Errorf("resolvectl flush-caches timed out after %s: %w", flushResolvedTimeout, ctxErr)
		}
		return fmt.Errorf("resolvectl flush-caches failed: %w (output: %s)", err, out)
	}
	logger.Info("Flushed systemd-resolved DNS cache")
	return nil
}

// Teardown deletes the redirect table and closes the socket that made it,
// then flushes the DNS flows still DNAT'd to the proxy. For an owned table,
// closing the socket alone would delete it too, so a failed delete only
// warns and the table is gone before the flush either way. An unowned table
// stays unless the delete succeeds, so there a failed delete is the error,
// and so is finding it already gone: another process deleted it during the
// run, and DNS went around the proxy from then on. A redirect never
// installed has nothing to remove. Safe to call more than once, and
// nil-safe.
func (r *DNSRedirect) Teardown() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = true
	if r.conn == nil {
		return nil
	}
	msg, delErr := delTableMsg(r.family)
	if delErr == nil {
		delErr = transact(r.conn, []netlink.Message{msg})
	}
	closeErr := r.conn.Close()
	r.conn = nil
	var err error
	switch {
	case delErr == nil:
	case !r.owned && errors.Is(delErr, unix.ENOENT):
		// Only an unowned table can be deleted by another process, and
		// whenever that happened, DNS went around the proxy from then on.
		err = fmt.Errorf("table %s %s was already gone at teardown: another process deleted it during the run, "+
			"and DNS went around the proxy from then on", r.family, RedirectTable)
	case r.owned:
		r.logger.Warn("Deleting the DNS redirect table failed; closing the socket that owns it removes it",
			"error", delErr)
		if closeErr != nil {
			err = fmt.Errorf("nftables: closing the socket that owns table %s %s: %w", r.family, RedirectTable, closeErr)
		}
	default:
		// Nothing else removes an unowned table: one more try on a new
		// socket, in case the first died with a lost reply. Gone by then
		// means the first try deleted it.
		if delErr = deleteTable(r.family); delErr != nil && !errors.Is(delErr, unix.ENOENT) {
			err = fmt.Errorf("nftables: deleting table %s %s: %w; host DNS stays redirected to the stopped proxy "+
				"until it is removed (nft delete table %s %s)", r.family, RedirectTable, delErr, r.family, RedirectTable)
		}
	}
	if err == nil {
		r.logger.Info("DNS redirect removed")
	}

	// Purge flows still DNAT'd to the now-dead proxy, so client DNS recovers
	// immediately instead of at conntrack expiry (see FlushDNSConntrack).
	if err := FlushDNSConntrack(r.logger, r.family == familyInet); err != nil {
		r.logger.Warn("Failed to flush DNS conntrack entries on teardown; client DNS may stall until entries expire",
			"error", err)
	}
	return err
}
