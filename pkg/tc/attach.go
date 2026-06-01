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

// Package tc attaches cargowall's egress eBPF classifier to a network
// interface, preferring the modern TCX hook and transparently falling back to
// the legacy clsact qdisc on older kernels.
package tc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

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

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err == nil {
		logger.Info("Attached TC egress program", "interface", ifname, "method", "tcx")
		return l, nil
	}
	if !errors.Is(err, ebpf.ErrNotSupported) {
		// AttachTCX runs cilium's haveTCX() feature probe on failure and returns
		// ebpf.ErrNotSupported whenever TCX is absent (kernels <6.6). A raw
		// EOPNOTSUPP/EINVAL reaching here therefore means TCX *is* supported but
		// the attach genuinely failed (permissions, bad program, busy interface) —
		// surface it rather than silently falling back to clsact.
		return nil, fmt.Errorf("attach TCX egress: %w", err)
	}

	logger.Info("TCX unsupported on this kernel, falling back to legacy clsact", "interface", ifname)
	closer, err := attachClsactEgress(iface.Index, prog, logger)
	if err != nil {
		return nil, fmt.Errorf("attach legacy clsact egress: %w", err)
	}
	logger.Info("Attached TC egress program", "interface", ifname, "method", "clsact")
	return closer, nil
}
