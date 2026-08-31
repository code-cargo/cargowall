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
	"net/netip"
	"unsafe"
)

// L7 scope bits, mirroring L7_SCOPE_* in sni.h: which L7 dimension governs a
// destination IP. THE Go mirror — pkg/dns derives them from a rule's ports and
// pkg/origin reads the one the kernel stamped into each sample, so a second
// copy in either would let a renumbering mis-scope silently. Pinned to the C
// source by TestL7KernelConstantsMatchSniSource.
const (
	L7ScopeTLS  uint8 = 0x01 // TCP 443 + AltHTTPSPorts
	L7ScopeHTTP uint8 = 0x02 // TCP 80 + AltHTTPPorts
	L7ScopeQUIC uint8 = 0x04 // UDP 443
)

// AltHTTPSPorts and AltHTTPPorts are the alternate ports the big CDNs
// terminate the SAME shared edge on. They carry the same L7 dimension as
// 443/80 — pinning only the canonical pair left the tenant swap this layer
// exists to close reachable on :8443, because an all-ports hostname allow
// opens the edge /32 on every port while the kernel adjudicated none of them.
//
// THE Go mirror of l7_alt_https_port/l7_alt_http_port in bpf/sni.h, pinned to
// that source by TestKernelAltPortsMatchScopeTables. They live here, beside
// the scope bits, because two consumers need the same list: pkg/dns derives a
// rule's scope bits from it, and the kernel narrows a packet's scope by it —
// and a port in one list but not the other is a silent hole (scoped but never
// adjudicated) or a silent fail-close (adjudicated but never scoped).
var (
	AltHTTPSPorts = []uint16{2053, 2083, 2087, 2096, 8443}
	AltHTTPPorts  = []uint16{2052, 2082, 2086, 2095, 8080, 8880}
)

// IsAltHTTPSPort reports whether port is an alternate HTTPS port (TLS).
func IsAltHTTPSPort(port uint16) bool { return containsPort(AltHTTPSPorts, port) }

// IsAltHTTPPort reports whether port is an alternate cleartext-HTTP port.
func IsAltHTTPPort(port uint16) bool { return containsPort(AltHTTPPorts, port) }

func containsPort(ports []uint16, port uint16) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// L7Event mirrors struct l7_event in sni.h — one punted TLS/HTTP/QUIC handshake
// sample (16488 bytes packed; 8-byte fields first, so the packed C layout equals
// Go's natural layout). The leading fields deliberately match OriginEvent's
// byte-order convention (v4 addresses host order, v6 raw bytes) so the same
// cookie->pid/step join serves both.
//
// This is the ONE Go view of the wire layout: pkg/origin's punt reader casts
// ringbuf bytes to it, and TestL7EventLayoutMatchesBTF pins this struct
// against the compiled BTF, so a C-side layout change cannot pass the test
// while userspace misparses.
type L7Event struct {
	Cookie     uint64
	CgroupID   uint64
	Timestamp  uint64
	SrcIp      uint32
	DstIp      uint32
	SrcIp6     [16]byte
	DstIp6     [16]byte
	SrcPort    uint16
	DstPort    uint16
	IpVersion  uint8
	IpProto    uint8
	Flags      uint8
	Scope      uint8
	Seq        uint32
	PayloadLen uint16
	Pad        uint16
	DcidLen    uint8    // QUIC Initial's DCID length, 0 for TCP
	Dcid       [20]byte // the connection-attempt identity the verdict pins
	Pad2       [3]byte
	// Payload is valid ONLY for [0:PayloadLen] — always slice it. The kernel
	// does not clear the tail (see the invariant on struct l7_event), so the
	// remaining bytes are whatever the ringbuf slot last held, typically
	// another flow's punted handshake.
	Payload [16384]byte // L7_PUNT_PAYLOAD — pinned by TestL7EventLayoutMatchesBTF
}

// L7EventFromBytes reinterprets a ringbuf sample as an *L7Event. It returns
// ok=false when the sample is shorter than the struct (the same length guard
// the origin reader applies before its unsafe cast) or when a wire-supplied
// length (PayloadLen, DcidLen) exceeds its buffer — consumers slice
// Payload[:PayloadLen] and Dcid[:DcidLen], so an unvalidated length from a
// drifted or corrupted sample would panic the punt-reader goroutine and
// black-hole every pending flow under enforce.
func L7EventFromBytes(raw []byte) (*L7Event, bool) {
	if len(raw) < int(unsafe.Sizeof(L7Event{})) {
		return nil, false
	}
	ev := (*L7Event)(unsafe.Pointer(&raw[0]))
	if int(ev.PayloadLen) > len(ev.Payload) || int(ev.DcidLen) > len(ev.Dcid) {
		return nil, false
	}
	return ev, true
}

// SrcAddr returns the punt's pre-NAT source address, decoding the wire
// convention stated on L7Event (v4 host order, v6 raw bytes) exactly as
// pkg/origin's insert decodes an OriginEvent. This is the ONE place that
// convention becomes an address: the per-IP binding (NameResolvedToIP) and
// the audit sink both consume these, and a second hand-rolled copy drifting
// (endianness, v4-mapped spelling) would silently break the pin-ip match
// while audit records kept printing the other form.
func (e *L7Event) SrcAddr() netip.Addr {
	if e.IpVersion == 6 {
		return netip.AddrFrom16(e.SrcIp6)
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], e.SrcIp)
	return netip.AddrFrom4(b)
}

// DstAddr returns the punt's destination address; see SrcAddr.
func (e *L7Event) DstAddr() netip.Addr {
	if e.IpVersion == 6 {
		return netip.AddrFrom16(e.DstIp6)
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], e.DstIp)
	return netip.AddrFrom4(b)
}

// FlowKey builds the map_l7_flow key the kernel wrote for this flow, so a
// userspace verdict lands on the exact entry sni.h's l7_flow_key_init created.
// For v4 the destination is the host-order address in the low 4 bytes, matching
// the kernel's memcpy of its host-order __u32.
func (e *L7Event) FlowKey() OriginBpfL7FlowKey {
	var k OriginBpfL7FlowKey
	k.Cookie = e.Cookie
	if e.IpVersion == 4 {
		binary.NativeEndian.PutUint32(k.Dst[0:4], e.DstIp)
	} else {
		copy(k.Dst[:], e.DstIp6[:])
	}
	k.DstPort = e.DstPort
	k.IpProto = e.IpProto
	k.IpVersion = e.IpVersion
	return k
}
