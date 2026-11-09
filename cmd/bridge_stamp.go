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
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/tc"
)

// bridgeStamp keeps cw_tc_br_stamp attached at the TC ingress of every
// Docker bridge the container tracker reports, so a container's traffic
// forwarded through one reaches the uplink's TC egress with its socket's
// step policy in the packet's mark (stamp_step_policy in verdict.h). The
// container's socket is gone from the packet by then.
//
// A bridge it can't attach to is warned and left unstamped: its
// containers' traffic gets the job's rules alone, the stricter outcome. So
// does a bridge's traffic before the attach lands, a bridge created and
// used at once among it.
//
// Nil (step rules off) is the disabled feature, and every method no-ops:
// the program would stamp nothing.
type bridgeStamp struct {
	prog    *ebpf.Program
	attach  func(dev string, prog *ebpf.Program, logger *slog.Logger) (tc.Attachment, error)
	ifindex func(dev string) (int, error)
	logger  *slog.Logger

	mu      sync.Mutex
	bridges map[string]stampedBridge // by device
	closed  bool
}

// stampedBridge is the attachment on one bridge, and the index the device
// had then.
type stampedBridge struct {
	ifindex int
	link    tc.Attachment
}

// newBridgeStamp is the stamp for objs' program, nil with no objects or
// with step rules off.
func newBridgeStamp(objs *bpf.TcBpfObjects, logger *slog.Logger) *bridgeStamp {
	if objs == nil || !objs.StepRules() {
		return nil
	}
	return &bridgeStamp{
		prog:    objs.CwTcBrStamp,
		attach:  tc.AttachIngress,
		ifindex: ifindexOf,
		logger:  logger,
		bridges: make(map[string]stampedBridge),
	}
}

func ifindexOf(dev string) (int, error) {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// up attaches to dev, unless the program is attached there already: to the
// same device, still. A device recreated behind the name, at any index, is
// attached afresh, and the dead one's attachment dropped.
func (b *bridgeStamp) up(dev string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	idx, err := b.ifindex(dev)
	if err != nil {
		b.drop(dev)
		b.logger.Warn("Docker bridge not found; its containers' traffic gets the job's rules, not their steps'",
			"bridge", dev, "error", err)
		return
	}
	if s, ok := b.bridges[dev]; ok {
		if s.ifindex == idx && s.link.Attached() {
			return
		}
		b.drop(dev)
	}
	l, err := b.attach(dev, b.prog, b.logger)
	if err != nil {
		b.logger.Warn("Docker bridge left unstamped; its containers' traffic gets the job's rules, not their steps'",
			"bridge", dev, "error", err)
		return
	}
	b.bridges[dev] = stampedBridge{ifindex: idx, link: l}
}

// gone drops dev's attachment: its network was destroyed.
func (b *bridgeStamp) gone(dev string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.drop(dev)
}

// drop detaches from dev, if attached there, with b.mu held.
func (b *bridgeStamp) drop(dev string) {
	if s, ok := b.bridges[dev]; ok {
		_ = s.link.Close()
		delete(b.bridges, dev)
	}
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

// Close detaches from every bridge, and attaches to none after.
func (b *bridgeStamp) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for dev := range b.bridges {
		b.drop(dev)
	}
}
