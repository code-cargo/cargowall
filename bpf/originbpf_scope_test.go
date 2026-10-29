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
	"errors"
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

// loadOriginObjectsScoped loads the origin collection the way origin.Start
// does in a privileged pod: scoped set before load. The collection keeps
// its own stand-in map_scope_cgroups, which a test fills directly.
func loadOriginObjectsScoped(t *testing.T) *OriginBpfObjects {
	t.Helper()
	requireBPF(t)
	spec, err := LoadOriginBpf()
	require.NoError(t, err)
	require.NoError(t, spec.Variables[OriginBpfVarScoped].Set(uint8(1)))
	var objs OriginBpfObjects
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// map_scope_cgroups is declared twice: scopebpf.c owns it and originbpf.c
// carries a stand-in the scope collection's map replaces. cilium/ebpf rejects
// a replacement whose spec differs, and the replacement happens only in the
// scoped shape (a privileged pod), which no CI job runs, so a drift would
// ship and then fail ARC startup. The size is the exception: origin.Start
// gives the stand-in the replacement's. Compared from the specs: no kernel
// needed.
func TestScopeCgroupsMapSpecsMatch(t *testing.T) {
	scopeSpec, err := LoadScopeBpf()
	require.NoError(t, err)
	originSpec, err := LoadOriginBpf()
	require.NoError(t, err)
	owner := scopeSpec.Maps[ScopeBpfMapMapScopeCgroups]
	standIn := originSpec.Maps[OriginBpfMapMapScopeCgroups]
	require.NotNil(t, owner, "scopebpf.c must declare map_scope_cgroups")
	require.NotNil(t, standIn, "originbpf.c must declare map_scope_cgroups")
	require.Equal(t, owner.Type, standIn.Type, "map type")
	require.Equal(t, owner.KeySize, standIn.KeySize, "key size")
	require.Equal(t, owner.ValueSize, standIn.ValueSize, "value size")
	require.Equal(t, owner.Flags, standIn.Flags, "flags")
}

// With scoped set the hook judges only sockets in a cgroup recorded in
// map_scope_cgroups. Nothing is recorded here, so packets the default
// program drops must pass, and leave no record.
func TestOriginScopedPassesOtherCgroups(t *testing.T) {
	all := loadOriginObjects(t)
	scoped := loadOriginObjectsScoped(t)
	for _, objs := range []*OriginBpfObjects{all, scoped} {
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

	rd, err := ringbuf.NewReader(scoped.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })
	for _, d := range denied {
		ret, _, err := scoped.CgOriginEgress.Test(d.packet)
		require.NoError(t, err)
		require.Equal(t, uint32(1), ret, "%s: a socket outside the recorded cgroups must pass a scoped program", d.name)
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

// cgroupID is the id bpf_skb_cgroup_id reports for the cgroup at path: its
// cgroupfs inode, on 64-bit kernels.
func cgroupID(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	return fi.Sys().(*syscall.Stat_t).Ino
}

// TestOriginScopeRealSocket covers the recorded half, which PROG_TEST_RUN
// cannot: with real sockets, those in a recorded cgroup are judged, MPTCP's
// included, whose packets travel on a subflow socket the kernel creates
// itself and which only the cgroup ties to its creator. The deny-all
// enforce policy attaches to a private cgroup this process moves into,
// never the host root, so a broken scope check can only fail this test.
// The destination is the host's own address, which rides lo and is
// adjudicated with the loopback carve-out off, as it is in tests, so
// nothing leaves the machine.
func TestOriginScopeRealSocket(t *testing.T) {
	objs := loadOriginObjectsScoped(t)
	seedOriginRules(t, objs) // deny by default
	setOriginMode(t, objs, originModeEnforce)

	cg := enterTestCgroup(t)
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cg,
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
	require.NoError(t, err, "a socket in an unrecorded cgroup must connect past the enforcing hook")
	conn.Close()

	require.NoError(t, objs.MapScopeCgroups.Put(cgroupID(t, cg), uint8(1)))
	var cookie uint64
	d := net.Dialer{Timeout: 1500 * time.Millisecond, Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			cookie, serr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		}); err != nil {
			return err
		}
		return serr
	}}
	if conn, err := d.Dial("tcp4", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("a socket in a recorded cgroup to a denied destination must not connect")
	}
	require.NotZero(t, cookie)

	wantDst := binary.BigEndian.Uint32(hostIP)
	rd.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		record, err := rd.Read()
		require.NoError(t, err, "the recorded cgroup's drop must leave a record")
		require.GreaterOrEqual(t, len(record.RawSample), int(unsafe.Sizeof(OriginEvent{})))
		r := *(*OriginEvent)(unsafe.Pointer(&record.RawSample[0]))
		if r.Cookie != cookie {
			continue
		}
		require.Equal(t, uint8(originVerdictBlock), r.Verdict)
		require.Equal(t, wantDst, r.DstIp)
		break
	}

	t.Run("MPTCP", func(t *testing.T) {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_MPTCP)
		if errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EINVAL) {
			t.Skipf("no MPTCP on this kernel: %v", err)
		}
		require.NoError(t, err)
		defer unix.Close(fd)
		sa := &unix.SockaddrInet4{Port: ln.Addr().(*net.TCPAddr).Port}
		copy(sa.Addr[:], hostIP)
		if err := unix.Connect(fd, sa); err != nil && !errors.Is(err, unix.EINPROGRESS) {
			t.Fatalf("connect: %v", err)
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(pfd, 1500)
		require.NoError(t, err)
		if n > 0 {
			soErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			require.NoError(t, err)
			require.NotZero(t, soErr, "an MPTCP connection from a recorded cgroup to a denied destination must not connect")
		}
	})
}
