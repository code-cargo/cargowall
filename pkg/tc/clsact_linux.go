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

package tc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TC handle/parent constants. These are spelled out explicitly (rather than
// computed via TC_H_MAKE-style macros) because the exact values are the part
// that trips people up.
const (
	// clsactParent is TC_H_CLSACT — the parent under which a clsact qdisc lives.
	clsactParent = 0xFFFFFFF1
	// clsactHandle is the clsact qdisc handle: major 0xFFFF, minor 0.
	clsactHandle = 0xFFFF0000
	// egressParent is TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS) — the egress hook.
	egressParent = 0xFFFFFFF3

	// cwFilterPrio is a distinctive filter priority so teardown can target
	// exactly cargowall's filter without disturbing anything else on the qdisc.
	cwFilterPrio = 0xC150
	// cwFilterHandle is the filter handle within the priority.
	cwFilterHandle = 1
	// cwFilterName is surfaced by `tc filter show` via TCA_BPF_NAME.
	cwFilterName = "cargowall_egress"

	// TCA_BPF_* attribute types are stable kernel UAPI (linux/pkt_cls.h) but are
	// not exported by x/sys/unix, so we define them here.
	tcaBPFFD    = 6 // TCA_BPF_FD
	tcaBPFName  = 7 // TCA_BPF_NAME
	tcaBPFFlags = 8 // TCA_BPF_FLAGS

	// bpfFlagActDirect is TCA_BPF_FLAG_ACT_DIRECT: run the program in
	// direct-action mode so its return code (TC_ACT_OK / TC_ACT_SHOT) is the
	// verdict. Without it, cls_bpf treats the return value as a classid and
	// TC_ACT_SHOT would NOT drop — i.e. the firewall would silently fail open.
	// TCX is always direct-action, which is why the TCX path sets no flag.
	bpfFlagActDirect = 1
)

// tcMsg is the netlink tcmsg header (struct tcmsg, linux/rtnetlink.h): 20 bytes.
type tcMsg struct {
	family  uint8
	ifindex int32
	handle  uint32
	parent  uint32
	info    uint32
}

// marshal encodes the tcmsg in native byte order. Bytes 1-3 are padding.
func (m tcMsg) marshal() []byte {
	b := make([]byte, 20)
	b[0] = m.family
	binary.NativeEndian.PutUint32(b[4:8], uint32(m.ifindex))
	binary.NativeEndian.PutUint32(b[8:12], m.handle)
	binary.NativeEndian.PutUint32(b[12:16], m.parent)
	binary.NativeEndian.PutUint32(b[16:20], m.info)
	return b
}

// htons converts v from host to network byte order (identity on big-endian).
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)     // network order
	return binary.NativeEndian.Uint16(b[:]) // reinterpret in host order
}

// makeFilterInfo packs a tcmsg info field for a filter: priority in the high 16
// bits, protocol (network byte order) in the low 16 bits.
func makeFilterInfo(prio, proto uint16) uint32 {
	return uint32(prio)<<16 | uint32(htons(proto))
}

// encodeEgressFilterAttrs builds the rtnetlink attributes for a direct-action
// cls_bpf egress filter referencing the program file descriptor fd. Extracted
// so the (security-critical) direct-action encoding is unit-testable.
func encodeEgressFilterAttrs(fd uint32) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.TCA_KIND, "bpf")
	ae.Nested(unix.TCA_OPTIONS, func(nae *netlink.AttributeEncoder) error {
		nae.Uint32(tcaBPFFD, fd)
		nae.String(tcaBPFName, cwFilterName)
		nae.Uint32(tcaBPFFlags, bpfFlagActDirect)
		return nil
	})
	return ae.Encode()
}

// execTC sends a single tc netlink request and waits for the kernel's ack,
// returning the (possibly errno-wrapping) error. Request|Acknowledge are always
// set; flags adds the per-operation bits (Create/Excl/Replace).
func execTC(conn *netlink.Conn, typ uint16, flags netlink.HeaderFlags, m tcMsg, attrs []byte) error {
	_, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(typ),
			Flags: netlink.Request | netlink.Acknowledge | flags,
		},
		Data: append(m.marshal(), attrs...),
	})
	return err
}

// attachClsactEgress attaches prog to the interface's egress hook via the legacy
// clsact qdisc + direct-action cls_bpf filter (the pre-TCX mechanism, kernel
// 4.5+). It is the fallback used by AttachEgress on kernels without TCX (< 6.6).
//
// The clsact qdisc is created only if absent, and we record whether we created
// it so teardown removes only a qdisc we own (libbpf-style) — a qdisc installed
// by another tool (e.g. Cilium) is left in place.
func attachClsactEgress(ifindex int, prog *ebpf.Program, logger *slog.Logger) (io.Closer, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, fmt.Errorf("dial netlink: %w", err)
	}
	defer conn.Close()

	// 1. Ensure the clsact qdisc exists (create-if-missing via CREATE|EXCL).
	clsactAttrs := netlink.NewAttributeEncoder()
	clsactAttrs.String(unix.TCA_KIND, "clsact")
	clsactData, err := clsactAttrs.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode clsact qdisc attrs: %w", err)
	}
	qmsg := tcMsg{family: unix.AF_UNSPEC, ifindex: int32(ifindex), handle: clsactHandle, parent: clsactParent}

	createdQdisc := false
	switch err := execTC(conn, unix.RTM_NEWQDISC, netlink.Create|netlink.Excl, qmsg, clsactData); {
	case err == nil:
		createdQdisc = true
	case errors.Is(err, unix.EEXIST):
		// A clsact qdisc is already present (prior run or another tool); reuse it.
	default:
		return nil, fmt.Errorf("create clsact qdisc: %w", err)
	}

	// 2. Attach the program as a direct-action cls_bpf egress filter. REPLACE
	//    makes a restart idempotent over a stale filter from a crashed run.
	filterData, err := encodeEgressFilterAttrs(uint32(prog.FD()))
	if err != nil {
		return nil, fmt.Errorf("encode egress filter attrs: %w", err)
	}
	fmsg := tcMsg{
		family:  unix.AF_UNSPEC,
		ifindex: int32(ifindex),
		handle:  cwFilterHandle,
		parent:  egressParent,
		info:    makeFilterInfo(cwFilterPrio, unix.ETH_P_ALL),
	}
	err = execTC(conn, unix.RTM_NEWTFILTER, netlink.Create|netlink.Replace, fmsg, filterData)
	runtime.KeepAlive(prog) // keep the program fd valid across the syscall
	if err != nil {
		if createdQdisc {
			_ = execTC(conn, unix.RTM_DELQDISC, 0, qmsg, nil) // best-effort rollback of our qdisc
		}
		return nil, fmt.Errorf("attach egress bpf filter: %w", err)
	}

	return &tcLegacyLink{ifindex: ifindex, createdQdisc: createdQdisc, logger: logger}, nil
}

// tcLegacyLink is the io.Closer returned by attachClsactEgress. Close removes
// cargowall's egress filter and, if attachClsactEgress created the clsact qdisc,
// the qdisc as well.
type tcLegacyLink struct {
	ifindex      int
	createdQdisc bool
	logger       *slog.Logger
}

// Close detaches the egress filter (and our clsact qdisc, if we created it).
// It is best-effort: benign races (ENOENT — already gone; ENODEV — interface
// removed, e.g. netns teardown) are ignored, and other failures are logged
// rather than returned, matching cargowall's shutdown-defer conventions.
func (t *tcLegacyLink) Close() error {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		t.logger.Warn("Failed to dial netlink for legacy TC teardown", "ifindex", t.ifindex, "error", err)
		return nil
	}
	defer conn.Close()

	// Remove exactly our egress filter (matched by parent + priority + handle).
	fmsg := tcMsg{
		family:  unix.AF_UNSPEC,
		ifindex: int32(t.ifindex),
		handle:  cwFilterHandle,
		parent:  egressParent,
		info:    makeFilterInfo(cwFilterPrio, unix.ETH_P_ALL),
	}
	if err := execTC(conn, unix.RTM_DELTFILTER, 0, fmsg, nil); err != nil && !isBenignDetachErr(err) {
		t.logger.Warn("Failed to remove legacy TC egress filter", "ifindex", t.ifindex, "error", err)
	}

	// Only remove the clsact qdisc if we created it, so we never tear down a
	// qdisc another tool installed.
	if t.createdQdisc {
		qmsg := tcMsg{family: unix.AF_UNSPEC, ifindex: int32(t.ifindex), handle: clsactHandle, parent: clsactParent}
		if err := execTC(conn, unix.RTM_DELQDISC, 0, qmsg, nil); err != nil && !isBenignDetachErr(err) {
			t.logger.Warn("Failed to remove clsact qdisc", "ifindex", t.ifindex, "error", err)
		}
	}
	return nil
}

// isBenignDetachErr reports whether a teardown error means there is nothing left
// to clean up: the object is already gone (ENOENT) or the interface itself has
// been removed (ENODEV), in which case the kernel reclaimed the qdisc/filter.
func isBenignDetachErr(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV)
}
