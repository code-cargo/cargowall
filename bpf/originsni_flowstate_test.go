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
	"testing"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// The per-flow state machine: NEED_HELLO -> PENDING -> terminal, the punt
// budget and dedup, and how a verdict is re-asserted or superseded.

// TestOriginL7FlowStateMachine pins what the kernel RECORDS, not just what it
// returns: the verdict-only tests above would stay green if map_l7_flow or the
// punt ring silently stopped being written, and the whole oracle loop hangs
// off those. Each Test() call mints a fresh socket cookie, so each step here
// is its own flow; where a step needs its key, the sample's FlowKey() recovers
// it. Same-flow sequencing rides a real socket in
// TestOriginL7RealSocketSplitHello.
func TestOriginL7FlowStateMachine(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.19"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeTLS)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	// A SYN passes AND must record NEED_HELLO — that entry is what later makes
	// a non-hello first flight fail closed instead of riding the no-state
	// established-traffic pass.
	require.Equal(t, 1, run(craftIPv4TCPWithFlags(t, edgeIP, 443, tcpFlagSYN)))
	flows := dumpL7Flows(t, objs)
	require.Len(t, flows, 1, "the SYN must create exactly one flow entry")
	for k, v := range flows {
		require.Equal(t, uint8(l7StateNeedHello), v.State, "a SYN must park the flow in NEED_HELLO")
		require.Equal(t, uint16(443), k.DstPort)
	}
	requireNoL7Sample(t, rd) // a SYN carries no payload and must never punt

	// A ClientHello: dropped pending, and the handoff to the oracle must be
	// complete — a ringbuf sample carrying the bytes verbatim, plus a PENDING
	// entry under the sample's own flow key with one punt of the budget
	// consumed.
	hello := snitest.BuildClientHello("auth.docker.io")
	mid := len(hello) / 2
	require.Equal(t, 0, run(craftIPv4TLSData(edgeIP, "auth.docker.io")),
		"a hello must drop pending")
	ev := readL7Sample(t, rd)
	require.NotZero(t, ev.Flags&l7PuntFlagNoState, "a fresh Test cookie has no flow entry")
	require.Zero(t, ev.Flags&l7PuntFlagObserve, "enforce posture must not stamp OBSERVE")
	require.Equal(t, hello, append([]byte(nil), ev.Payload[:ev.PayloadLen]...),
		"the sample must carry the hello verbatim")
	var fv OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &fv),
		"the punt must be recorded under the sample's own flow key")
	require.Equal(t, uint8(l7StatePending), fv.State, "a punted flow must park PENDING")
	require.Equal(t, uint8(1), fv.Punts, "one punt of the budget is consumed")

	// A truncated hello prefix behaves identically (punt + PENDING): the
	// oracle, not the kernel, decides what incomplete bytes mean.
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 443, hello[:mid])),
		"an incomplete hello must drop pending")
	ev = readL7Sample(t, rd)
	require.Equal(t, uint16(mid), ev.PayloadLen)
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &fv))
	require.Equal(t, uint8(l7StatePending), fv.State)

	// Mid-record continuation bytes (the second half of a split hello) on a
	// flow with NO state: not a record start, so the identity gate fails the
	// segment closed — and must do so WITHOUT punting or writing state. This
	// is the counterpart that makes the PENDING gate-skip load-bearing: the
	// same bytes are punted in TestOriginL7RealSocketSplitHello because state
	// says PENDING, and refused here because nothing says this flow is
	// mid-handshake.
	cont := hello[mid:]
	require.NotContains(t, []byte{0x14, 0x15, 0x16, 0x17}, cont[0],
		"test premise: the continuation must not start on a TLS record-type byte")
	before := dumpL7Flows(t, objs)
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 443, cont)),
		"a stateless mid-record segment must fail closed")
	requireNoL7Sample(t, rd)
	require.Equal(t, before, dumpL7Flows(t, objs),
		"a gate drop must neither punt nor write flow state")
}

// TestOriginL7HTTPStateMachine gives the HTTP dimension its own kernel state
// proof — the TLS arm had all the PROG_TEST_RUN coverage of what the flow map
// records. A request line always punts, and the identity gate's classifier is
// the request-line check instead of the TLS record grammar.
func TestOriginL7HTTPStateMachine(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	const edgeIP = "140.82.114.23"
	require.NoError(t, objs.MapOriginConfig.Put(uint32(l7CfgKeyMode), uint8(l7ModeEnforce)))
	require.NoError(t, objs.MapL7Scope.Put(ipToU32(edgeIP), uint8(L7ScopeHTTP)))

	rd, err := ringbuf.NewReader(objs.MapL7Events)
	require.NoError(t, err)
	defer rd.Close()

	run := func(frame []byte) int {
		ret, _, err := objs.CgOriginEgress.Test(frame)
		require.NoError(t, err)
		return int(ret)
	}

	// SYN to the scoped :80 → NEED_HELLO recorded.
	require.Equal(t, 1, run(craftIPv4TCPWithFlags(t, edgeIP, 80, tcpFlagSYN)))
	flows := dumpL7Flows(t, objs)
	require.Len(t, flows, 1, "the SYN must create exactly one flow entry")
	for _, v := range flows {
		require.Equal(t, uint8(l7StateNeedHello), v.State, "the HTTP SYN must park NEED_HELLO")
	}

	// A request line on a stateless flow opens adjudication: dropped pending,
	// punted with the bytes verbatim, PENDING under the sample's key.
	req := []byte("GET /v2/ HTTP/1.1\r\nHost: registry.example\r\n\r\n")
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 80, req)),
		"a stateless request line must be adjudicated (dropped pending)")
	ev := readL7Sample(t, rd)
	require.NotZero(t, ev.Flags&l7PuntFlagNoState)
	require.Equal(t, req, append([]byte(nil), ev.Payload[:ev.PayloadLen]...))
	var fv OriginBpfL7FlowVal
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &fv))
	require.Equal(t, uint8(l7StatePending), fv.State)

	// Body bytes on a stateless flow are an established connection mid-stream:
	// pass, no punt, no state written.
	before := dumpL7Flows(t, objs)
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 80, []byte("chunk of body, no request line"))),
		"stateless non-request bytes must pass as established traffic")
	requireNoL7Sample(t, rd)
	require.Equal(t, before, dumpL7Flows(t, objs), "an established-pass must not write state")

	// A SHORT segment carrying a complete method token ("GET /he", 7 bytes)
	// must open adjudication exactly like a full request line — anything the
	// classifier fails on a fresh flow is dropped with no punt and no audit
	// record, so the classifier must accept every first flight that IS (or
	// may still become) a request line, whatever the segment length.
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 80, []byte("GET /he"))),
		"a short request-line segment must be adjudicated (dropped pending)")
	ev = readL7Sample(t, rd)
	require.Equal(t, uint16(7), ev.PayloadLen)
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &fv))
	require.Equal(t, uint8(l7StatePending), fv.State,
		"a short request line must punt and park PENDING, not fail closed unpunted")

	// A segment cut MID-TOKEN ("GE"): undecidable, so it must also punt — the
	// request-line analogue of the TLS arm punting a <6-byte hello prefix.
	require.Equal(t, 0, run(craftIPv4TCPData(edgeIP, 80, []byte("GE"))),
		"an undecidable method prefix must be adjudicated, not silently dropped")
	ev = readL7Sample(t, rd)
	require.Equal(t, uint16(2), ev.PayloadLen)
	require.NoError(t, objs.MapL7Flow.Lookup(ev.FlowKey(), &fv))
	require.Equal(t, uint8(l7StatePending), fv.State)

	// Short NON-prefix bytes stay body traffic: "HEADER:" (7 bytes) diverges
	// from HEAD at the byte where its space belongs — only a segment SHORTER
	// than a method token may classify as an undecidable prefix.
	before = dumpL7Flows(t, objs)
	require.Equal(t, 1, run(craftIPv4TCPData(edgeIP, 80, []byte("HEADER:"))),
		"short body bytes that are not a method prefix must pass")
	requireNoL7Sample(t, rd)
	require.Equal(t, before, dumpL7Flows(t, objs), "an established-pass must not write state")
}
