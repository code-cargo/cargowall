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

package steps

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/events"
)

// sockdiag resolves a local socket's kernel cookie from its source address,
// via NETLINK_SOCK_DIAG. The DNS proxy uses this to attribute a query to
// the step whose process sent it: source address → cookie → map_sock_step.
//
// A dump (matched client-side by source) is used instead of an exact
// 4-tuple lookup deliberately: the iptables DNAT that steers DNS to the
// proxy rewrites the packet, not the client socket, so the client's socket
// still names the ORIGINAL resolver as its peer — the proxy-side 4-tuple
// doesn't exist in the client's socket table.
//
// The pipeline is split in three: dumpSocketTable walks one (family, proto)
// table into rows, matchCookie is a pure source-address match over those
// rows, and diagBatcher coalesces concurrent lookups so a burst of clients
// costs one dump, not one each.

// inetDiagReqV2 documents struct inet_diag_req_v2 — the dump request body
// serialized in dumpSocketTable. The embedded sock id (ports/addrs
// big-endian) stays zero for a dump.
type inetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       [48]byte // struct inet_diag_sockid, zeroed
}

// Responses are struct inet_diag_msg: 4 header bytes, then the sock id
// (ports big-endian at 4..8, src at 8..24, dst at 24..40, ifindex at
// 40..44, cookie at 44..52), then counters — parsed by offset below and
// pinned against SO_COOKIE in TestDumpSocketTable_*.
const (
	sizeofInetDiagReqV2 = 56
	sizeofInetDiagMsg   = 72
)

// diagDumpTimeout bounds the netlink exchange: this runs on the DNS query
// path, and a lost reply (e.g. ENOBUFS under memory pressure) must not
// park a handler goroutine indefinitely.
const diagDumpTimeout = 500 * time.Millisecond

// sockRow is one socket from a table dump: everything the source match needs.
type sockRow struct {
	sport  uint16
	src    [16]byte
	cookie uint64
}

// wantBytes renders a source IP the way the kernel's socket table shows it:
// AF_INET entries carry the 4 address bytes at offset 0, everything else is
// the 16-byte form (which for a v4 address is its v4-mapped ::ffff:a.b.c.d —
// exactly what a dual-stack socket's v6-table entry holds).
func wantBytes(family uint8, srcIP net.IP) [16]byte {
	var want [16]byte
	if ip4 := srcIP.To4(); ip4 != nil && family == unix.AF_INET {
		copy(want[:4], ip4)
	} else {
		copy(want[:], srcIP.To16())
	}
	return want
}

// dumpSocketTable dumps the kernel's socket table for (family, proto) into
// rows, on the same mdlayher/netlink contract as the conntrack flush
// (Execute aggregates the multipart dump and surfaces NLMSG_ERROR). A
// non-nil error means the dump itself failed (netlink unavailable — e.g. a
// kernel without CONFIG_INET_DIAG — or the deadline fired), as opposed to a
// clean dump, so callers can surface systemic breakage instead of
// conflating it with "socket not found".
func dumpSocketTable(family, proto uint8) ([]sockRow, error) {
	conn, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return nil, fmt.Errorf("dial sock_diag netlink: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(diagDumpTimeout)); err != nil {
		return nil, fmt.Errorf("set netlink deadline: %w", err)
	}

	req := inetDiagReqV2{
		Family:   family,
		Protocol: proto,
		States:   ^uint32(0),
	}
	data := make([]byte, sizeofInetDiagReqV2)
	data[0], data[1], data[2], data[3] = req.Family, req.Protocol, req.Ext, req.Pad
	binary.NativeEndian.PutUint32(data[4:8], req.States)
	// req.ID stays zero for a dump.

	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.SOCK_DIAG_BY_FAMILY),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	})
	if err != nil {
		return nil, fmt.Errorf("sock_diag dump: %w", err)
	}

	rows := make([]sockRow, 0, len(msgs))
	for _, m := range msgs {
		if len(m.Data) < sizeofInetDiagMsg {
			continue
		}
		d := m.Data
		var row sockRow
		row.sport = uint16(d[4])<<8 | uint16(d[5]) // big-endian in the sock id
		copy(row.src[:], d[8:24])
		cookieLo := binary.NativeEndian.Uint32(d[44:48])
		cookieHi := binary.NativeEndian.Uint32(d[48:52])
		row.cookie = uint64(cookieLo) | uint64(cookieHi)<<32
		rows = append(rows, row)
	}
	return rows, nil
}

// matchCookie resolves a source address against dumped rows. An exact
// source match wins immediately (ephemeral ports make it unique in
// practice). An unconnected client (bare sendto, e.g. dig or dnspython —
// glibc/musl/Go resolvers all connect) is auto-bound to the wildcard
// address, so the table shows 0.0.0.0/:: where the wire carried the routed
// source; such a socket is accepted by port alone, but only with exactly
// one wildcard candidate — misattribution is worse than none, so two or
// more report ambiguous instead. (A bound-then-connected socket gets a
// concrete source from the route, so an all-zero source reliably means
// unconnected.)
func matchCookie(rows []sockRow, port uint16, want [16]byte) (cookie uint64, found, ambiguous bool) {
	var wildCookie uint64
	wildCount := 0
	for _, r := range rows {
		if r.sport != port {
			continue
		}
		if r.src == want {
			return r.cookie, true, false
		}
		if r.src == [16]byte{} {
			wildCookie = r.cookie
			wildCount++
		}
	}
	switch wildCount {
	case 1:
		return wildCookie, true, false
	case 0:
		return 0, false, false
	default:
		return 0, false, true
	}
}

// ClientStep is the resolved attribution of one DNS client address.
type ClientStep struct {
	Ordinal uint32                 // step ordinal, 0 unless Outcome is StepAttrOK
	Outcome events.StepAttrOutcome // why the lookup resolved the way it did
	PID     uint32                 // socket owner's pid from map_sock_pid, 0 if unknown
	Process string                 // owner's /proc comm, "" if unknown
}

// stepCacheTTL bounds reuse of a client-address resolution. A cookie is
// stable for its socket's lifetime; the risk is the ephemeral (ip, port)
// being reused by a NEW socket inside the window, which the size of the
// ephemeral range makes unlikely within seconds even under churn. Kept
// short regardless: the cache exists to shed query floods (many blocked
// queries from one client socket), not for steady-state savings.
const stepCacheTTL = 2 * time.Second

// stepCacheCap bounds the cache map — a flood of one-query client sockets
// would otherwise grow it without limit. Reset-on-full is crude, but the
// cache is purely a load shed and repopulates immediately.
const stepCacheCap = 4096

// diagPendingCap bounds how many lookups may wait on a table's next dump.
// One dump serves the whole batch, so this is purely a goroutine/memory
// guard against a flood of one-query client sockets; beyond it a lookup
// sheds to StepAttrShed (uncached, so a quieter moment can still resolve
// that client).
const diagPendingCap = 512

type stepCacheKey struct {
	ip    [16]byte
	port  uint16
	proto uint8
}

type stepCacheEntry struct {
	step    ClientStep
	expires time.Time
}

// diagTable identifies one kernel socket table — the granularity of a dump.
type diagTable struct {
	family uint8
	proto  uint8
}

// diagCall is one waiter for a table snapshot. Every call in a batch shares
// the same dump: the drainer fills rows/err and closes done.
type diagCall struct {
	rows []sockRow
	err  error
	done chan struct{}
}

// diagQueue is one table's coalescing state: the calls awaiting its next
// dump, and whether a drainer goroutine is currently serving them.
type diagQueue struct {
	pending []*diagCall
	active  bool
}

// diagBatcher coalesces sock_diag dumps per socket table: callers waiting
// on the same table share one dump, and a call that arrives while a dump is
// in flight is served by the NEXT round — its socket may not have existed
// when the running dump started.
type diagBatcher struct {
	mu     sync.Mutex
	queues map[diagTable]*diagQueue
	closed bool
	wg     sync.WaitGroup
}

func newDiagBatcher() *diagBatcher {
	return &diagBatcher{queues: make(map[diagTable]*diagQueue)}
}

// rows returns a snapshot of one socket table. The first arrival starts a
// drainer that dumps the table once per waiting batch, so a burst of N
// clients costs one dump, not N. shed reports a full batch (or a closed
// batcher); err a failed dump.
func (b *diagBatcher) rows(table diagTable) (rows []sockRow, shed bool, err error) {
	b.mu.Lock()
	q := b.queues[table]
	if q == nil {
		q = &diagQueue{}
		b.queues[table] = q
	}
	if b.closed || len(q.pending) >= diagPendingCap {
		b.mu.Unlock()
		return nil, true, nil
	}
	c := &diagCall{done: make(chan struct{})}
	q.pending = append(q.pending, c)
	if !q.active {
		q.active = true
		b.wg.Add(1)
		go b.drain(table, q)
	}
	b.mu.Unlock()
	<-c.done
	return c.rows, false, c.err
}

// drain serves a table's pending calls, one dump per batch, until none
// remain. close joins these goroutines after closed stops new work.
func (b *diagBatcher) drain(table diagTable, q *diagQueue) {
	defer b.wg.Done()
	for {
		b.mu.Lock()
		calls := q.pending
		if len(calls) == 0 {
			q.active = false
			b.mu.Unlock()
			return
		}
		q.pending = nil
		b.mu.Unlock()

		rows, err := dumpSocketTable(table.family, table.proto)
		for _, c := range calls {
			c.rows, c.err = rows, err
			close(c.done)
		}
	}
}

// close stops new dumps (later rows calls shed) and joins the drainers, so
// no dump goroutine outlives the owner.
func (b *diagBatcher) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.wg.Wait()
}

// resolveCookie resolves one client source address against its socket
// table — one shared snapshot, one pure match — folding the whole
// dump/match state into the outcome taxonomy the event carries: an empty
// outcome means cookie is a unique hit; otherwise shed / dump_error (with
// the underlying error) / ambiguous_wildcard / not_found. A clean AF_INET
// miss retries the AF_INET6 table before concluding not_found: a
// dual-stack [::]:port socket sending v4-mapped traffic lives there.
func (t *Tracker) resolveCookie(family, proto uint8, ip net.IP, port uint16) (uint64, events.StepAttrOutcome, error) {
	rows, shed, err := t.diag.rows(diagTable{family: family, proto: proto})
	if shed {
		return 0, events.StepAttrShed, nil
	}
	if err != nil {
		return 0, events.StepAttrDumpError, err
	}
	cookie, found, ambiguous := matchCookie(rows, port, wantBytes(family, ip))
	switch {
	case found:
		return cookie, "", nil
	case ambiguous:
		return 0, events.StepAttrAmbiguous, nil
	case family == unix.AF_INET:
		return t.resolveCookie(unix.AF_INET6, proto, ip, port)
	default:
		return 0, events.StepAttrNotFound, nil
	}
}

// AttributeClient resolves the step attribution of the process owning the
// local socket behind addr and writes it onto the audit event — the DNS
// proxy's dns_blocked path installs this as its step lookup, so a new
// attribution field means a new line here, not a re-threaded callback type.
func (t *Tracker) AttributeClient(addr net.Addr, ev *events.AuditEvent) {
	cs := t.StepForClient(addr)
	ev.StepOrdinal = cs.Ordinal
	ev.StepAttrOutcome = cs.Outcome
	ev.PID = cs.PID
	ev.Process = cs.Process
}

// StepForClient resolves the attribution of the process owning the local
// socket behind addr (a DNS client seen by the proxy). Ordinal 0 with a
// non-ok Outcome means no ordinal was resolved — the Outcome says why, and
// PID/Process name the owner when the socket was found at all.
//
// The blocked-query path is adversarial by definition (query floods are
// what filtering exists for), so the dump is guarded twice: a short-TTL
// cache absorbs repeat queries from the same client socket, and lookups
// beyond a batch cap shed to StepAttrShed (uncached) rather than growing
// the pending set without bound.
func (t *Tracker) StepForClient(addr net.Addr) ClientStep {
	var ip net.IP
	var port int
	var proto uint8
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, port, proto = a.IP, a.Port, unix.IPPROTO_UDP
	case *net.TCPAddr:
		ip, port, proto = a.IP, a.Port, unix.IPPROTO_TCP
	default:
		return ClientStep{Outcome: events.StepAttrUnsupported}
	}
	family := uint8(unix.AF_INET6)
	if ip.To4() != nil {
		family = unix.AF_INET
	}

	var key stepCacheKey
	copy(key.ip[:], ip.To16())
	key.port = uint16(port)
	key.proto = proto

	now := time.Now()
	t.stepCacheMu.Lock()
	if e, ok := t.stepCache[key]; ok && now.Before(e.expires) {
		t.stepCacheMu.Unlock()
		return e.step
	}
	t.stepCacheMu.Unlock()

	cookie, outcome, err := t.resolveCookie(family, proto, ip, uint16(port))
	if outcome == events.StepAttrShed {
		return ClientStep{Outcome: outcome} // uncached: a quieter moment can still resolve this client
	}

	var cs ClientStep
	switch {
	case outcome == events.StepAttrDumpError:
		// Warn once per DISTINCT failure, not once ever: a transient
		// first error (one recv timeout) must not permanently mask a
		// later systemic one (EOPNOTSUPP on a CONFIG_INET_DIAG-less
		// kernel), while identical repeats stay suppressed.
		msg := err.Error()
		t.diagWarnMu.Lock()
		changed := msg != t.diagLastWarn
		t.diagLastWarn = msg
		t.diagWarnMu.Unlock()
		if changed {
			t.logger.Warn("Step attribution: socket-cookie lookup failed; DNS events will carry step_attr_outcome=dump_error",
				"error", err)
		}
		cs.Outcome = outcome
	case outcome != "":
		cs.Outcome = outcome
	default:
		// nil sockMap only in unit tests (no loaded BPF); a lookup error on
		// the real map means the cookie was never tagged.
		var ordinal uint32
		if t.sockMap == nil || t.sockMap.Lookup(cookie, &ordinal) != nil {
			cs.Outcome = events.StepAttrUntagged
		} else {
			cs.Ordinal, cs.Outcome = ordinal, events.StepAttrOK
		}
		// Name the socket's owner either way — untagged is exactly where a
		// name (systemd-resolved, apt-news, ...) tells the reader who the
		// unattributed client actually was. Best-effort: the connect/sendmsg
		// hooks may not have seen a pre-attach socket, and the pid can be
		// gone by the time /proc is read.
		var pid uint32
		if t.pidMap != nil && t.pidMap.Lookup(cookie, &pid) == nil && pid != 0 {
			cs.PID = pid
			cs.Process = readComm(int(pid))
		}
	}

	// Cache every resolved outcome, dump errors and negatives included —
	// unattributable floods are the hot case, and a systemic dump failure
	// (EOPNOTSUPP, persistent timeouts) must not turn every blocked query
	// into a fresh dump; the TTL keeps transient errors recoverable. Only
	// shed stays uncached (nothing was resolved). Expiry from a fresh
	// clock, not the pre-dump `now`: the dump itself can take a large
	// fraction of the TTL, and stamping from before it would shorten — or
	// entirely consume — the shed window exactly where dumps are slowest.
	t.stepCacheMu.Lock()
	if len(t.stepCache) >= stepCacheCap {
		clear(t.stepCache)
	}
	t.stepCache[key] = stepCacheEntry{step: cs, expires: time.Now().Add(stepCacheTTL)}
	t.stepCacheMu.Unlock()
	return cs
}
