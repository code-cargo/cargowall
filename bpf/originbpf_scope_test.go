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

package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// loadOriginObjectsStampedOnly loads the origin collection the way
// origin.Start does in a privileged pod: stamped_only set before load. The
// collection keeps its own stand-in map_sock_scope, which a test stamps
// directly.
func loadOriginObjectsStampedOnly(t *testing.T) *OriginBpfObjects {
	t.Helper()
	requireBPF(t)
	spec, err := LoadOriginBpf()
	require.NoError(t, err)
	require.NoError(t, spec.Variables[OriginBpfVarStampedOnly].Set(uint8(1)))
	var objs OriginBpfObjects
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// map_sock_scope is declared twice: stepbpf.c owns it and originbpf.c
// carries a stand-in the step collection's map replaces. cilium/ebpf rejects
// a replacement whose spec differs, and the replacement happens only in the
// scoped shape (a privileged pod), which no CI job runs, so a drift would
// ship and then fail ARC startup. Compared from the specs: no kernel needed.
func TestSockScopeMapSpecsMatch(t *testing.T) {
	stepSpec, err := LoadStepBpf()
	require.NoError(t, err)
	originSpec, err := LoadOriginBpf()
	require.NoError(t, err)
	owner := stepSpec.Maps[StepBpfMapMapSockScope]
	standIn := originSpec.Maps[OriginBpfMapMapSockScope]
	require.NotNil(t, owner, "stepbpf.c must declare map_sock_scope")
	require.NotNil(t, standIn, "originbpf.c must declare map_sock_scope")
	require.Equal(t, owner.Type, standIn.Type, "map type")
	require.Equal(t, owner.KeySize, standIn.KeySize, "key size")
	require.Equal(t, owner.ValueSize, standIn.ValueSize, "value size")
	require.Equal(t, owner.MaxEntries, standIn.MaxEntries, "max entries")
	require.Equal(t, owner.Flags, standIn.Flags, "flags")
}

// With stamped_only set the hook judges only sockets in map_sock_scope. A
// PROG_TEST_RUN socket is fresh and never stamped, so packets the default
// program drops must pass, and leave no record.
func TestOriginScopeStampedPassesUnstampedSockets(t *testing.T) {
	all := loadOriginObjects(t)
	stamped := loadOriginObjectsStampedOnly(t)
	for _, objs := range []*OriginBpfObjects{all, stamped} {
		seedOriginRules(t, objs)
		setOriginMode(t, objs, originModeEnforce)
	}

	denied := []struct {
		name   string
		packet []byte
	}{
		{"v4 TCP SYN", craftIPv4TCP(t, "93.184.216.34", 443)},
		{"v4 UDP", craftIPv4UDP(t, "93.184.216.34", 9999)},
		{"v6 TCP SYN", craftIPv6TCP(t, "2001:db8::1", 443)},
		{"invalid IHL", craftInvalidIHLIPv4(t)},
	}
	// The default program first, so a pass below can only be the scope.
	for _, d := range denied {
		ret, _, err := all.CgOriginEgress.Test(d.packet)
		require.NoError(t, err)
		require.Equal(t, uint32(0), ret, "%s: the default program must drop it", d.name)
	}

	rd, err := ringbuf.NewReader(stamped.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })
	for _, d := range denied {
		ret, _, err := stamped.CgOriginEgress.Test(d.packet)
		require.NoError(t, err)
		require.Equal(t, uint32(1), ret, "%s: an unstamped socket must pass a stamped_only program", d.name)
	}
	require.Empty(t, collectOriginRecords(t, rd, 200*time.Millisecond),
		"an out-of-scope socket must leave no record")
}

// enterTestCgroup creates a cgroup, moves the test process into it, and
// returns its path. A program attached there sees only this process's
// sockets, so a deny-all enforce policy can never affect the rest of the
// host, whatever the program under test gets wrong. Cleanup moves the
// process back to the root and removes the cgroup.
func enterTestCgroup(t *testing.T) string {
	t.Helper()
	cgRoot := "/sys/fs/cgroup"
	cgPath := filepath.Join(cgRoot, fmt.Sprintf("cargowall-bpf-test-%d", os.Getpid()))
	if err := os.Mkdir(cgPath, 0o755); err != nil {
		t.Skipf("cannot create test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cgPath) })
	self := []byte(strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"), self, 0); err != nil {
		t.Skipf("cannot enter test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(cgRoot, "cgroup.procs"), self, 0) })
	return cgPath
}

// TestOriginScopeRealSocket covers the stamped half, which PROG_TEST_RUN's
// unknowable cookies cannot: with real sockets, only the one whose cookie is
// stamped is judged. The deny-all enforce policy attaches to a private
// cgroup this process moves into, never the host root, so a broken scope
// check can only fail this test. The destination is the host's own address,
// which rides lo and is adjudicated with the loopback carve-out off, as it
// is in tests, so nothing leaves the machine.
func TestOriginScopeRealSocket(t *testing.T) {
	objs := loadOriginObjectsStampedOnly(t)
	seedOriginRules(t, objs) // deny by default
	setOriginMode(t, objs, originModeEnforce)

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    enterTestCgroup(t),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgOriginEgress,
	})
	if err != nil {
		t.Skipf("cannot attach cgroup_skb/egress at test cgroup: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	rd, err := ringbuf.NewReader(objs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	hostIP := hostOwnIPv4(t)
	ln, err := net.Listen("tcp4", hostIP.String()+":0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	conn, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err, "an unstamped socket must connect past the enforcing hook")
	conn.Close()

	// Stamp between socket() and connect(), where cg_sock_create would.
	var cookie uint64
	d := net.Dialer{Timeout: 1500 * time.Millisecond, Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			cookie, serr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
			if serr == nil {
				serr = objs.MapSockScope.Put(cookie, uint8(1))
			}
		}); err != nil {
			return err
		}
		return serr
	}}
	if conn, err := d.Dial("tcp4", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("a stamped socket to a denied destination must not connect")
	}
	require.NotZero(t, cookie)

	wantDst := binary.BigEndian.Uint32(hostIP)
	rd.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		record, err := rd.Read()
		require.NoError(t, err, "the stamped socket's drop must leave a record")
		require.GreaterOrEqual(t, len(record.RawSample), int(unsafe.Sizeof(OriginEvent{})))
		r := *(*OriginEvent)(unsafe.Pointer(&record.RawSample[0]))
		if r.Cookie != cookie {
			continue
		}
		require.Equal(t, uint8(originVerdictBlock), r.Verdict)
		require.Equal(t, wantDst, r.DstIp)
		break
	}
}
