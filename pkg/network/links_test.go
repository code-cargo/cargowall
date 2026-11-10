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
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// gatedReports is a LinkWatcher's callbacks that, once held, stop the
// watcher at its next report until let go, and say when it is stopped.
type gatedReports struct {
	mu      sync.Mutex
	links   map[int]Link
	held    atomic.Bool
	gate    chan struct{}
	stopped chan struct{}
}

func newGatedReports() *gatedReports {
	return &gatedReports{links: map[int]Link{}, gate: make(chan struct{}), stopped: make(chan struct{}, 1)}
}

func (g *gatedReports) wait() {
	if g.held.Load() {
		select {
		case g.stopped <- struct{}{}:
		default:
		}
		<-g.gate
	}
}

func (g *gatedReports) onLink(l Link) {
	g.wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.links[l.Index] = l
}

func (g *gatedReports) onGone(index int) {
	g.wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.links, index)
}

func (g *gatedReports) named(prefix string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, l := range g.links {
		if strings.HasPrefix(l.Name, prefix) {
			n++
		}
	}
	return n
}

// lockedLog is a log the watcher's goroutine writes while a test reads.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Events that overrun the socket while the reports are held up are
// dropped by the kernel; the watcher lists the interfaces again, and
// reports every one of them.
func TestWatchLinks_ListsAgainAfterDroppedEvents(t *testing.T) {
	enterNetns(t)
	saved := linkEventsBuffer
	linkEventsBuffer = 1024
	t.Cleanup(func() { linkEventsBuffer = saved })
	g := newGatedReports()
	log := &lockedLog{}
	w, err := WatchLinks(g.onLink, g.onGone, slog.New(slog.NewTextHandler(log, nil)))
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })

	g.held.Store(true)
	const burst = 200
	for i := range burst {
		require.NoError(t, newLink(fmt.Sprintf("burst%d", i), "dummy", "", nil))
	}
	<-g.stopped
	g.held.Store(false)
	close(g.gate)
	require.Eventually(t, func() bool { return g.named("burst") == burst }, 5*time.Second, 10*time.Millisecond,
		"every interface reported, dropped events or not")
	assert.Contains(t, log.String(), "Interface events dropped; listing the interfaces again")
}

// Close returns once the report being made is done, and none comes after.
func TestWatchLinks_CloseWaitsForTheLastReport(t *testing.T) {
	enterNetns(t)
	g := newGatedReports()
	w, err := WatchLinks(g.onLink, g.onGone, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	g.held.Store(true)
	require.NoError(t, newLink("p0", "dummy", "", nil))
	<-g.stopped
	var closed atomic.Bool
	go func() {
		_ = w.Close()
		closed.Store(true)
	}()
	require.Never(t, closed.Load, 200*time.Millisecond, 10*time.Millisecond, "Close waits for the report being made")
	g.held.Store(false)
	close(g.gate)
	require.Eventually(t, closed.Load, 5*time.Second, 10*time.Millisecond)
}

// A listing made after dropped events leaves nothing out, though more come
// while its reports are made: the kernel queues and reports none of those
// until the queue is read empty, and relist lists again for as long as
// events came while it listed.
func TestWatchLinks_RelistConverges(t *testing.T) {
	enterNetns(t)
	events, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{Groups: unix.RTMGRP_LINK})
	require.NoError(t, err)
	t.Cleanup(func() { events.Close() })
	require.NoError(t, events.SetReadBuffer(1024))
	list, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	require.NoError(t, err)
	t.Cleanup(func() { list.Close() })

	g := newGatedReports()
	more := 0
	w := &LinkWatcher{
		events: events, list: list, known: map[int]bool{}, logger: slog.New(slog.DiscardHandler),
		onLink: func(l Link) {
			// Events that come while the first listing's reports are made.
			if more < 40 {
				more++
				require.NoError(t, newLink(fmt.Sprintf("late%d", more), "dummy", "", nil))
			}
			g.onLink(l)
		},
		onGone: g.onGone,
	}
	for i := range 40 {
		require.NoError(t, newLink(fmt.Sprintf("early%d", i), "dummy", "", nil))
	}
	w.relist()
	assert.Equal(t, 40, g.named("early"))
	assert.Equal(t, 40, g.named("late"), "the events that came while a listing's reports were made")
}
