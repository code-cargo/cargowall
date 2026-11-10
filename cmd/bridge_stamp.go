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

package cmd

import (
	"io"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/tc"
)

// bridgeStamp keeps cw_tc_br_stamp attached at the TC ingress of every
// port of a Docker bridge: the host end of each container's veth. There a
// container's packet still has its socket, which br_netfilter drops as the
// bridge takes the packet, so the program can write the socket's step
// policy into the packet's mark for the uplink's TC egress
// (stamp_step_policy in verdict.h).
//
// The ports come from the kernel (network.WatchLinks): a veth whose master
// is a Docker bridge, by Docker's names (network.DockerBridge) or a name
// the container tracker reports. Everything is keyed by interface index,
// which a removal names exactly.
//
// A port it can't attach to is warned and left unstamped: its container's
// traffic gets the job's rules alone, the stricter outcome. So do a port's
// packets before the attach lands.
//
// Nil (step rules off) is the disabled feature, and every method no-ops:
// the program would stamp nothing, and no watch starts.
type bridgeStamp struct {
	prog   *ebpf.Program
	attach func(ifindex int, name string, prog *ebpf.Program, logger *slog.Logger) (tc.Attachment, error)
	watch  func(onLink func(network.Link), onGone func(int), logger *slog.Logger) (io.Closer, error)
	logger *slog.Logger

	mu      sync.Mutex
	links   map[int]network.Link  // the namespace's interfaces, by index
	named   map[string]bool       // Docker bridges the tracker reported
	ports   map[int]tc.Attachment // where the program is attached, by index
	failed  map[int]bool          // ports the attach failed on, warned of once each
	watcher io.Closer
	closed  bool
}

// newBridgeStamp is the stamp for objs' program, nil with no objects or
// with step rules off.
func newBridgeStamp(objs *bpf.TcBpfObjects, logger *slog.Logger) *bridgeStamp {
	if objs == nil || !objs.StepRules() {
		return nil
	}
	return &bridgeStamp{
		prog:   objs.CwTcBrStamp,
		attach: tc.AttachIngress,
		watch:  watchLinks,
		logger: logger,
		links:  make(map[int]network.Link),
		named:  make(map[string]bool),
		ports:  make(map[int]tc.Attachment),
		failed: make(map[int]bool),
	}
}

func watchLinks(onLink func(network.Link), onGone func(int), logger *slog.Logger) (io.Closer, error) {
	return network.WatchLinks(onLink, onGone, logger)
}

// start watches the namespace's interfaces, attaching to each Docker
// bridge port there is and each one that comes.
func (b *bridgeStamp) start() {
	if b == nil {
		return
	}
	// Not under b.mu: the watch reports the interfaces there are before it
	// returns.
	w, err := b.watch(b.link, b.linkGone, b.logger)
	if err != nil {
		b.logger.Warn("Cannot watch interfaces for Docker bridge ports; container traffic gets the job's rules, "+
			"not its steps'", "error", err)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		_ = w.Close()
		return
	}
	b.watcher = w
}

// link takes an interface's report: a port to attach to or detach from,
// or a bridge whose ports are looked at again when it is new or renamed.
func (b *bridgeStamp) link(l network.Link) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	old, had := b.links[l.Index]
	b.links[l.Index] = l
	b.sync(l.Index)
	if !had || old.Name != l.Name {
		b.syncPortsOf(l.Index)
	}
}

// linkGone drops a removed interface's attachment, and those of its ports
// if it was a bridge.
func (b *bridgeStamp) linkGone(index int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	delete(b.links, index)
	b.sync(index)
	b.syncPortsOf(index)
}

// up is the tracker's report of a Docker bridge, which may carry a name of
// its network's choosing (com.docker.network.bridge.name): its ports are
// stamped.
func (b *bridgeStamp) up(dev string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.named[dev] {
		return
	}
	b.named[dev] = true
	for index, l := range b.links {
		if l.Name == dev {
			b.syncPortsOf(index)
		}
	}
}

// gone is the tracker's report that a Docker bridge's network was
// destroyed. While a device by its name is still there, which is a bridge
// recreated behind the name, reported before this, the name stays
// Docker's. A removed bridge's ports have gone with it.
func (b *bridgeStamp) gone(dev string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, l := range b.links {
		if l.Name == dev {
			return
		}
	}
	delete(b.named, dev)
}

// syncPortsOf syncs the ports of the interface at index, with b.mu held.
func (b *bridgeStamp) syncPortsOf(index int) {
	for i, l := range b.links {
		if l.Master == index {
			b.sync(i)
		}
	}
}

// sync attaches to or detaches from the interface at index as it now is,
// with b.mu held: attached if it is a Docker bridge's veth port, and
// attached afresh if an attachment there has gone dead. A port the attach
// fails on is tried again on its next report, and warned of once, until
// an attach there works or it is no Docker port.
func (b *bridgeStamp) sync(index int) {
	l, ok := b.links[index]
	want := ok && b.dockerPort(l)
	a, have := b.ports[index]
	if !want {
		delete(b.failed, index)
	}
	switch {
	case want && have && a.Attached():
	case want:
		if have {
			_ = a.Close()
			delete(b.ports, index)
		}
		na, err := b.attach(index, l.Name, b.prog, b.logger)
		if err != nil {
			if !b.failed[index] {
				b.failed[index] = true
				b.logger.Warn("Docker bridge port left unstamped; its container's traffic gets the job's rules, "+
					"not its step's", "port", l.Name, "bridge", b.links[l.Master].Name, "error", err)
			}
			return
		}
		delete(b.failed, index)
		b.ports[index] = na
	case have:
		_ = a.Close()
		delete(b.ports, index)
	}
}

// dockerPort reports whether l is a veth port of a Docker bridge, with
// b.mu held.
func (b *bridgeStamp) dockerPort(l network.Link) bool {
	if l.Kind != "veth" || l.Master == 0 {
		return false
	}
	m, ok := b.links[l.Master]
	return ok && m.Kind == "bridge" && (network.DockerBridge(m.Name) || b.named[m.Name])
}

// onBridge and onBridgeGone are the tracker's Options.OnBridge and
// OnBridgeGone: nil with the feature off, so the tracker does no bridge
// work at all.
func (b *bridgeStamp) onBridge() func(string) {
	if b == nil {
		return nil
	}
	return b.up
}

func (b *bridgeStamp) onBridgeGone() func(string) {
	if b == nil {
		return nil
	}
	return b.gone
}

// Close stops the watch and detaches from every port, and attaches to
// none after.
func (b *bridgeStamp) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.closed = true
	w := b.watcher
	b.watcher = nil
	b.mu.Unlock()
	// Unlocked: the watch's last report may be waiting on b.mu.
	if w != nil {
		_ = w.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for index, a := range b.ports {
		_ = a.Close()
		delete(b.ports, index)
	}
}
