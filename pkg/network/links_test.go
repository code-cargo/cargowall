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
	"log/slog"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// linkReport is one report a LinkWatcher made: a link, or the index of
// one gone.
type linkReport struct {
	link Link
	gone int
}

// watchReports starts a LinkWatcher whose reports go to the channel it
// returns.
func watchReports(t *testing.T) (*LinkWatcher, chan linkReport) {
	t.Helper()
	reports := make(chan linkReport, 256)
	w, err := WatchLinks(
		func(l Link) { reports <- linkReport{link: l} },
		func(index int) { reports <- linkReport{gone: index} },
		slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })
	return w, reports
}

// awaitReport reads reports until one that match accepts.
func awaitReport(t *testing.T, reports chan linkReport, what string, match func(linkReport) bool) linkReport {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case r := <-reports:
			if match(r) {
				return r
			}
		case <-deadline:
			t.Fatalf("no report of %s", what)
		}
	}
}

func linkIndex(t *testing.T, name string) int {
	t.Helper()
	ifi, err := net.InterfaceByName(name)
	require.NoError(t, err)
	return ifi.Index
}

// release takes the interface named port off its master.
func release(t *testing.T, port string) {
	t.Helper()
	ifi := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(ifi[4:], uint32(linkIndex(t, port)))
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(unix.IFLA_MASTER, 0)
	attrs, err := ae.Encode()
	require.NoError(t, err)
	_, err = rtnetlink(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_NEWLINK, Flags: netlink.Request | netlink.Acknowledge},
		Data:   append(ifi, attrs...),
	})
	require.NoError(t, err)
}

// deleteLink removes the interface named name.
func deleteLink(t *testing.T, name string) {
	t.Helper()
	ifi := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(ifi[4:], uint32(linkIndex(t, name)))
	_, err := rtnetlink(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_DELLINK, Flags: netlink.Request | netlink.Acknowledge},
		Data:   ifi,
	})
	require.NoError(t, err)
}

// The watch lists the namespace's interfaces before it returns, and then
// reports each change, from a goroutine of its own, as the namespace's:
// an interface's kind, its master as it is enslaved and released, and its
// removal.
func TestWatchLinks(t *testing.T) {
	enterNetns(t)
	newBridge(t, "br-0123456789ab")
	_, reports := watchReports(t)
	lo := linkIndex(t, "lo")
	br := linkIndex(t, "br-0123456789ab")
	listed := map[int]Link{}
	for len(reports) > 0 {
		r := <-reports
		listed[r.link.Index] = r.link
	}
	assert.Equal(t, "lo", listed[lo].Name)
	assert.Equal(t, Link{Index: br, Name: "br-0123456789ab", Kind: "bridge"}, listed[br])

	require.NoError(t, newLink("p0", "dummy", "", nil))
	p0 := linkIndex(t, "p0")
	awaitReport(t, reports, "p0 added", func(r linkReport) bool {
		return r.link == Link{Index: p0, Name: "p0", Kind: "dummy"}
	})
	enslave(t, "p0", "br-0123456789ab")
	awaitReport(t, reports, "p0 enslaved", func(r linkReport) bool { return r.link.Index == p0 && r.link.Master == br })
	release(t, "p0")
	awaitReport(t, reports, "p0 released", func(r linkReport) bool {
		return r.link.Index == p0 && r.link.Master == 0 && r.link.Kind == "dummy"
	})
	deleteLink(t, "p0")
	awaitReport(t, reports, "p0 gone", func(r linkReport) bool { return r.gone == p0 })
}

// A listing after dropped events reports what went in the gap as gone,
// and everything there as it is.
func TestWatchLinks_ResyncReportsTheGap(t *testing.T) {
	enterNetns(t)
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	lo := linkIndex(t, "lo")
	var got []linkReport
	resync := &LinkWatcher{
		list:   conn,
		known:  map[int]bool{lo: true, 4242: true},
		onLink: func(l Link) { got = append(got, linkReport{link: l}) },
		onGone: func(index int) { got = append(got, linkReport{gone: index}) },
	}
	require.NoError(t, resync.resync())
	require.Len(t, got, 2)
	assert.Equal(t, 4242, got[0].gone, "gone in the gap")
	assert.Equal(t, lo, got[1].link.Index)
	assert.Equal(t, map[int]bool{lo: true}, resync.known)
}

func TestGoneLinks(t *testing.T) {
	gone := goneLinks(map[int]bool{1: true, 5: true, 9: true}, []Link{{Index: 1}, {Index: 7}})
	slices.Sort(gone)
	assert.Equal(t, []int{5, 9}, gone)
	assert.Empty(t, goneLinks(map[int]bool{}, []Link{{Index: 1}}))
}

func TestParseLink(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.IFLA_IFNAME, "veth1")
	ae.Uint32(unix.IFLA_MASTER, 3)
	ae.Nested(unix.IFLA_LINKINFO, func(info *netlink.AttributeEncoder) error {
		info.String(unix.IFLA_INFO_KIND, "veth")
		return nil
	})
	attrs, err := ae.Encode()
	require.NoError(t, err)
	ifi := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(ifi[4:], 12)
	l, ok := parseLink(append(ifi, attrs...))
	require.True(t, ok)
	assert.Equal(t, Link{Index: 12, Name: "veth1", Kind: "veth", Master: 3}, l)

	bridging := append(append([]byte{}, ifi...), attrs...)
	bridging[0] = unix.AF_BRIDGE
	_, ok = parseLink(bridging)
	assert.False(t, ok, "a bridge's report of its port")
	_, ok = parseLink(ifi[:8])
	assert.False(t, ok, "short")
	_, ok = parseLink(make([]byte, unix.SizeofIfInfomsg))
	assert.False(t, ok, "no index")
}
