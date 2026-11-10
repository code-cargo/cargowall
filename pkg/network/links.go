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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync/atomic"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Link is a network interface as rtnetlink reports it.
type Link struct {
	Index  int
	Name   string
	Kind   string // its driver's IFLA_INFO_KIND ("veth", "bridge", ...); "" for none
	Master int    // the index of the device it is a port of; 0 for none
}

// linkEventsBuffer is the event socket's receive buffer: room for a burst
// of containers starting at once. Past it the kernel drops events, and the
// listing after makes up for them.
var linkEventsBuffer = 1 << 20

// LinkWatcher reports the interfaces of a network namespace as they come,
// change and go: see WatchLinks.
type LinkWatcher struct {
	events *netlink.Conn // subscribed to RTMGRP_LINK
	list   *netlink.Conn // for listings, made in the same namespace
	netns  *os.File      // that namespace
	onLink func(Link)
	onGone func(index int)
	logger *slog.Logger

	known   map[int]bool // what the reports so far leave there
	closing atomic.Bool
	done    chan struct{}
}

// WatchLinks reports every interface in the calling thread's network
// namespace to onLink before it returns, and then, on a goroutine of its
// own that runs in that namespace, each change: onLink again for an
// interface added or changed, onGone for one removed. Should the kernel
// drop events, as it does when they come faster than they are read, it
// lists the interfaces again and reports the difference, the ones that
// went in the gap among it.
func WatchLinks(onLink func(Link), onGone func(index int), logger *slog.Logger) (*LinkWatcher, error) {
	netns, err := os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
	if err != nil {
		return nil, fmt.Errorf("open network namespace: %w", err)
	}
	events, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{Groups: unix.RTMGRP_LINK})
	if err != nil {
		netns.Close()
		return nil, fmt.Errorf("subscribe to interface events: %w", err)
	}
	_ = events.SetReadBuffer(linkEventsBuffer)
	list, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		events.Close()
		netns.Close()
		return nil, fmt.Errorf("dial rtnetlink: %w", err)
	}
	w := &LinkWatcher{
		events: events, list: list, netns: netns,
		onLink: onLink, onGone: onGone, logger: logger,
		known: map[int]bool{},
		done:  make(chan struct{}),
	}
	// Subscribed first, so nothing that changes during the listing is
	// missed: its event comes after, and reports it again.
	if err := w.resync(); err != nil {
		w.closeConns()
		return nil, err
	}
	go w.run()
	return w, nil
}

// Close stops the reports, and returns once the last has been made.
func (w *LinkWatcher) Close() error {
	if w.closing.Swap(true) {
		return nil
	}
	_ = w.events.Close()
	<-w.done
	_ = w.list.Close()
	return w.netns.Close()
}

func (w *LinkWatcher) closeConns() {
	_ = w.events.Close()
	_ = w.list.Close()
	_ = w.netns.Close()
}

func (w *LinkWatcher) run() {
	defer close(w.done)
	// The reports are made from here, and act on interfaces by index,
	// which means something only in the namespace the watch began in. A
	// thread of another one (a caller that entered a namespace of its own)
	// joins it, locked for good: the thread exits with this goroutine
	// rather than carry the namespace back into the scheduler's pool.
	runtime.LockOSThread()
	if !sameNetns(w.netns) {
		if err := unix.Setns(int(w.netns.Fd()), unix.CLONE_NEWNET); err != nil {
			w.logger.Warn("Cannot enter the interfaces' network namespace; their changes go unreported", "error", err)
			return
		}
	} else {
		runtime.UnlockOSThread()
	}
	for {
		msgs, err := w.events.Receive()
		switch {
		case w.closing.Load():
			return
		case errors.Is(err, unix.ENOBUFS):
			w.logger.Warn("Interface events dropped; listing the interfaces again")
			w.relist()
			continue
		case err != nil:
			w.logger.Warn("Interface events stopped; their changes go unreported", "error", err)
			return
		}
		for _, m := range msgs {
			l, ok := parseLink(m.Data)
			if !ok {
				continue
			}
			switch m.Header.Type {
			case unix.RTM_NEWLINK:
				w.known[l.Index] = true
				w.onLink(l)
			case unix.RTM_DELLINK:
				delete(w.known, l.Index)
				w.onGone(l.Index)
			}
		}
	}
}

// relistPasses bounds relist's listings.
const relistPasses = 5

// relist makes up for events the kernel dropped: it discards what is
// queued, lists the interfaces and reports the difference, and does it
// again while events came during a listing, up to relistPasses listings
// and while the watch is not closing. Once it has dropped an event, the
// kernel queues none and reports no other drop until a read finds the
// queue empty, so a listing made before that leaves out what came while
// its reports were made: only one with no event during it is known to
// leave nothing out. The last listing's events are left queued, the queue
// read empty before it, for the watch to take as it does any.
func (w *LinkWatcher) relist() {
	w.drain()
	for pass := 1; !w.closing.Load(); pass++ {
		if err := w.resync(); err != nil {
			w.logger.Warn("Cannot list the interfaces; their changes go unreported until the next one", "error", err)
			return
		}
		if pass == relistPasses {
			w.logger.Warn("Interface events kept coming while the interfaces were listed; taking the rest as they come",
				"listings", pass)
			return
		}
		if !w.drain() {
			return
		}
	}
}

// drain reads and discards the events queued, down to the read that
// finds none, which also lets the kernel queue and report again. It
// reports whether there were any: a listing after reports their
// interfaces as they are by then. The reads don't wait, and go past
// Conn's: a read deadline already past would skip the read. A socket that
// can't be read, closed by Close, has nothing to drain.
func (w *LinkWatcher) drain() bool {
	rc, err := w.events.SyscallConn()
	if err != nil {
		return false
	}
	any := false
	buf := make([]byte, 64<<10)
	if err := rc.Read(func(fd uintptr) bool {
		for {
			_, _, err := unix.Recvfrom(int(fd), buf, unix.MSG_DONTWAIT)
			switch {
			case err == nil, errors.Is(err, unix.ENOBUFS):
				any = true
			case errors.Is(err, unix.EINTR):
			default:
				return true
			}
		}
	}); err != nil {
		return false
	}
	return any
}

// sameNetns reports whether the calling thread is in the namespace ns is.
func sameNetns(ns *os.File) bool {
	var a, b unix.Stat_t
	if unix.Fstat(int(ns.Fd()), &a) != nil {
		return false
	}
	if unix.Stat(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), &b) != nil {
		return false
	}
	return a.Dev == b.Dev && a.Ino == b.Ino
}

// resync lists the interfaces and reports the difference from what the
// reports so far leave there: onGone for each one not listed, onLink for
// each one listed.
func (w *LinkWatcher) resync() error {
	links, err := w.listLinks()
	if err != nil {
		return err
	}
	for _, index := range goneLinks(w.known, links) {
		delete(w.known, index)
		w.onGone(index)
	}
	for _, l := range links {
		w.known[l.Index] = true
		w.onLink(l)
	}
	return nil
}

// goneLinks is the indexes in known that links does not list.
func goneLinks(known map[int]bool, links []Link) []int {
	listed := make(map[int]bool, len(links))
	for _, l := range links {
		listed[l.Index] = true
	}
	var gone []int
	for index := range known {
		if !listed[index] {
			gone = append(gone, index)
		}
	}
	return gone
}

func (w *LinkWatcher) listLinks() ([]Link, error) {
	msgs, err := w.list.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETLINK, Flags: netlink.Request | netlink.Dump},
		Data:   make([]byte, unix.SizeofIfInfomsg),
	})
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var links []Link
	for _, m := range msgs {
		if l, ok := parseLink(m.Data); ok {
			links = append(links, l)
		}
	}
	return links, nil
}

// parseLink reads an RTM_NEWLINK or RTM_DELLINK message's interface: its
// struct ifinfomsg (family, pad, type, index, flags, change) and the
// attributes after it. Only the interface's own messages are, family
// AF_UNSPEC: a bridge also reports a port's bridging state on the same
// group as AF_BRIDGE, its delete included as a port leaves, with no kind,
// and that is not the interface coming or going.
func parseLink(data []byte) (Link, bool) {
	if len(data) < unix.SizeofIfInfomsg || data[0] != unix.AF_UNSPEC {
		return Link{}, false
	}
	l := Link{Index: int(int32(binary.NativeEndian.Uint32(data[4:8])))}
	ad, err := netlink.NewAttributeDecoder(data[unix.SizeofIfInfomsg:])
	if err != nil {
		return Link{}, false
	}
	for ad.Next() {
		switch ad.Type() {
		case unix.IFLA_IFNAME:
			l.Name = ad.String()
		case unix.IFLA_MASTER:
			l.Master = int(ad.Uint32())
		case unix.IFLA_LINKINFO:
			ad.Nested(func(info *netlink.AttributeDecoder) error {
				for info.Next() {
					if info.Type() == unix.IFLA_INFO_KIND {
						l.Kind = info.String()
					}
				}
				return info.Err()
			})
		}
	}
	return l, ad.Err() == nil && l.Index > 0
}
