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
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TestHtons verifies htons produces network (big-endian) byte order on any host.
func TestHtons(t *testing.T) {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], htons(0x0102))
	if b[0] != 0x01 || b[1] != 0x02 {
		t.Errorf("htons(0x0102) bytes = %#v, want network order {0x01, 0x02}", b)
	}
}

// TestMakeFilterInfo verifies the tcmsg info packing: priority in the high 16
// bits, protocol in network byte order in the low 16 bits. Host-independent.
func TestMakeFilterInfo(t *testing.T) {
	info := makeFilterInfo(cwFilterPrio, unix.ETH_P_ALL)

	if got := uint16(info >> 16); got != cwFilterPrio {
		t.Errorf("priority = %#x, want %#x", got, cwFilterPrio)
	}

	var low [2]byte
	binary.NativeEndian.PutUint16(low[:], uint16(info))
	if got := binary.BigEndian.Uint16(low[:]); got != uint16(unix.ETH_P_ALL) {
		t.Errorf("protocol = %#x, want %#x (ETH_P_ALL in network order)", got, unix.ETH_P_ALL)
	}
}

// TestEncodeEgressFilterAttrs decodes the encoded cls_bpf filter attributes and
// asserts the direct-action flag is set. This guards the most dangerous failure
// mode: without TCA_BPF_FLAG_ACT_DIRECT the program's return code is treated as
// a classid rather than a verdict, so TC_ACT_SHOT would not drop and the
// firewall would silently fail open.
func TestEncodeEgressFilterAttrs(t *testing.T) {
	const fd = 42
	data, err := encodeEgressFilterAttrs(fd)
	if err != nil {
		t.Fatalf("encodeEgressFilterAttrs: %v", err)
	}

	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	var (
		kind       string
		gotFD      uint32
		gotName    string
		gotFlags   uint32
		sawOptions bool
	)
	for ad.Next() {
		switch ad.Type() {
		case unix.TCA_KIND:
			kind = ad.String()
		case unix.TCA_OPTIONS:
			sawOptions = true
			// Nested has no error return: it folds both fn's returned nad.Err()
			// and any nested-decode failure into ad.err, which the ad.Err()
			// check below surfaces — so a malformed nested attr still fails.
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					switch nad.Type() {
					case tcaBPFFD:
						gotFD = nad.Uint32()
					case tcaBPFName:
						gotName = nad.String()
					case tcaBPFFlags:
						gotFlags = nad.Uint32()
					}
				}
				return nad.Err()
			})
		}
	}
	if err := ad.Err(); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if kind != "bpf" {
		t.Errorf("TCA_KIND = %q, want \"bpf\"", kind)
	}
	if !sawOptions {
		t.Error("missing TCA_OPTIONS")
	}
	if gotFD != fd {
		t.Errorf("TCA_BPF_FD = %d, want %d", gotFD, fd)
	}
	if gotName != cwFilterName {
		t.Errorf("TCA_BPF_NAME = %q, want %q", gotName, cwFilterName)
	}
	if gotFlags != bpfFlagActDirect {
		t.Errorf("TCA_BPF_FLAGS = %#x, want %#x (direct-action) — without this the firewall fails open", gotFlags, bpfFlagActDirect)
	}
}

// TestAttachClsactEgressIntegration exercises the real netlink round-trip
// (create clsact qdisc, attach a direct-action bpf filter, then detach) against
// the loopback interface. It requires root (CAP_NET_ADMIN) so it is skipped in
// the unprivileged test pass and runs under the sudo lane (see Makefile).
func TestAttachClsactEgressIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN) to manage tc qdiscs/filters")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

	// Minimal SCHED_CLS program returning TC_ACT_OK; enough to attach a filter.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0), // TC_ACT_OK
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("load SCHED_CLS program: %v", err)
	}
	defer prog.Close()

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lookup lo: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	closer, err := attachClsactEgress(lo.Index, prog, logger)
	if err != nil {
		t.Fatalf("attachClsactEgress: %v", err)
	}
	// Safety net in case an assertion below fails before the explicit Close.
	defer func() { _ = closer.Close() }()

	if out, ok := tcFilterShow(t, "lo"); ok {
		if !strings.Contains(out, cwFilterName) {
			t.Errorf("tc filter show did not list %q:\n%s", cwFilterName, out)
		}
		if !strings.Contains(out, "direct-action") {
			t.Errorf("tc filter show missing direct-action:\n%s", out)
		}
	}

	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if out, ok := tcFilterShow(t, "lo"); ok && strings.Contains(out, cwFilterName) {
		t.Errorf("filter %q still present after Close:\n%s", cwFilterName, out)
	}
}

// tcFilterShow runs `tc filter show dev <ifname> egress` and returns its output.
// ok is false when the iproute2 `tc` binary is unavailable, in which case the
// caller should skip the inspection (the attach/detach round-trip itself
// already validated the netlink path).
func tcFilterShow(t *testing.T, ifname string) (string, bool) {
	t.Helper()
	bin, err := exec.LookPath("tc")
	if err != nil {
		return "", false
	}
	out, err := exec.Command(bin, "filter", "show", "dev", ifname, "egress").CombinedOutput()
	if err != nil {
		t.Logf("tc filter show failed: %v\n%s", err, out)
		return "", false
	}
	return string(out), true
}
