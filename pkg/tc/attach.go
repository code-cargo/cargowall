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

// Package tc attaches cargowall's eBPF classifiers to a network interface's
// egress or ingress hook, preferring the modern TCX hook and transparently
// falling back to the legacy clsact qdisc on older kernels.
package tc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Attachment is a program attached to an interface's TC hook.
type Attachment interface {
	io.Closer
	// Attached reports whether the program is still attached to the
	// interface it was attached to: false once that interface is gone, as a
	// bridge Docker removes is, whatever index a later interface takes.
	Attached() bool
}

// AttachEgress attaches prog to the named interface's egress TC hook.
//
// It prefers TCX (the modern bpf_link TC hook, kernel 6.6+). On older kernels
// link.AttachTCX reports ebpf.ErrNotSupported, and we fall back to the legacy
// clsact qdisc + direct-action cls_bpf filter (kernel 4.5+). The returned
// io.Closer detaches the program on Close, regardless of which path was taken.
func AttachEgress(ifname string, prog *ebpf.Program, logger *slog.Logger) (io.Closer, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", ifname, err)
	}
	return attach(iface.Index, ifname, prog, egress, logger)
}

// AttachIngress attaches prog to the ingress TC hook of the interface at
// ifindex, the same two ways as AttachEgress, and logs it under name.
// Under TCX the program joins any others there, after them.
func AttachIngress(ifindex int, name string, prog *ebpf.Program, logger *slog.Logger) (Attachment, error) {
	return attach(ifindex, name, prog, ingress, logger)
}

// attach attaches prog to the hook in direction d of the interface at
// ifindex, called ifname.
func attach(ifindex int, ifname string, prog *ebpf.Program, d direction, logger *slog.Logger) (Attachment, error) {
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    d.tcx,
	})
	if err == nil {
		logger.Log(context.Background(), d.level, "Attached TC "+d.name+" program", "interface", ifname, "method", "tcx")
		return tcxAttachment{l}, nil
	}
	if !errors.Is(err, ebpf.ErrNotSupported) {
		// AttachTCX runs cilium's haveTCX() feature probe on failure and returns
		// ebpf.ErrNotSupported whenever TCX is absent (kernels <6.6). A raw
		// EOPNOTSUPP/EINVAL reaching here therefore means TCX *is* supported but
		// the attach genuinely failed (permissions, bad program, busy interface) —
		// surface it rather than silently falling back to clsact.
		return nil, fmt.Errorf("attach TCX %s: %w", d.name, err)
	}

	logger.Log(context.Background(), d.level, "TCX unsupported on this kernel, falling back to legacy clsact", "interface", ifname)
	a, err := attachClsact(ifindex, prog, d, logger)
	if err != nil {
		return nil, fmt.Errorf("attach legacy clsact %s: %w", d.name, err)
	}
	logger.Log(context.Background(), d.level, "Attached TC "+d.name+" program", "interface", ifname, "method", "clsact")
	return a, nil
}

// tcxAttachment is a TCX link. The kernel detaches it when its interface
// goes, and then reports no interface for it.
type tcxAttachment struct{ link.Link }

func (a tcxAttachment) Attached() bool {
	info, err := a.Info()
	if err != nil {
		return false
	}
	tcx := info.TCX()
	return tcx != nil && tcx.Ifindex != 0
}
