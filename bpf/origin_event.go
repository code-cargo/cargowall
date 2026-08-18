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

// OriginEvent mirrors struct origin_event in originbpf.c (72 bytes packed;
// 8-byte fields first so the packed C layout equals Go's natural layout).
// This is the ONE Go view of the wire layout: pkg/origin casts ringbuf bytes
// to it in production, and TestOriginEventLayoutMatchesBTF pins this same
// struct against the compiled BTF — so the reader the test validates is the
// reader that runs, and a C-side layout change cannot pass the test while
// production misparses.
type OriginEvent struct {
	Cookie    uint64
	CgroupID  uint64
	Timestamp uint64
	SrcIp     uint32
	DstIp     uint32
	SrcIp6    [16]byte
	DstIp6    [16]byte
	SrcPort   uint16
	DstPort   uint16
	IpVersion uint8
	IpProto   uint8
	Flags     uint8
	Verdict   uint8
}

// OriginEvent.Flags bits, mirroring ORIGIN_FLAG_* in originbpf.c (pinned by
// TestOriginConstantsMatchBpfSource in pkg/origin).
const (
	// OriginFlagTCPSyn marks a record emitted for a connection-opening SYN.
	OriginFlagTCPSyn = 0x1
	// OriginFlagTCPMidstream marks a segment of an established flow (ACK set,
	// no SYN/RST) — the same guard as is_tcp_midstream in tcbpf.c, so kernel
	// RST replies to inbound port scans and SYN-ACK replies to inbound
	// handshakes are never reported as killed egress connections.
	OriginFlagTCPMidstream = 0x2
)
