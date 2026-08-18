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

// The cgroup hook's protocol gate and unparsed (parse-fail) paths — the
// two places where cg_origin_egress must agree with tc_egress about
// traffic neither can fully parse or does not speak TCP/UDP.

package bpf

import (
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
)

func craftGREv4(dst string) []byte {
	eth := craftEthHeader(ethPIP)
	gre := make([]byte, 4)
	ip := craftIPv4Header(dst, 47, len(gre))
	return append(append(eth, ip...), gre...)
}

func craftGREv6(dst string) []byte {
	eth := craftEthHeader(ethPIPv6)
	gre := make([]byte, 4)
	ip6 := craftIPv6Header(dst, 47, len(gre))
	return append(append(eth, ip6...), gre...)
}

// The protocol gate must match tc_egress: everything that is not
// TCP/UDP/ICMP(v6) is denied before any map lookup, even to an
// allowed-CIDR destination — TC drops those packets wherever it sees them,
// and on paths TC does not cover this gate is the only one. Without it an
// allowed-CIDR GRE flow passes here and drops at TC: the hooks contradict
// each other. GRE (47) stands in for the class.
func TestOriginProtocolGateMatchesTC(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)

	rd, err := ringbuf.NewReader(objs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	setOriginMode(t, objs, originModeEnforce)

	ret, _, err := objs.CgOriginEgress.Test(craftGREv4("140.82.114.3")) // allowed CIDR
	require.NoError(t, err)
	require.Equal(t, uint32(0), ret, "GRE to an allowed v4 CIDR must drop, as at TC")

	ret, _, err = objs.CgOriginEgress.Test(craftGREv6("2606:4700::1")) // allowed CIDR
	require.NoError(t, err)
	require.Equal(t, uint32(0), ret, "GRE to an allowed v6 CIDR must drop, as at TC")

	// Carved classes are exempt: GRE to loopback is local-only traffic TC
	// never adjudicated, and the gate must not newly deny it.
	ret, _, err = objs.CgOriginEgress.Test(craftGREv4("127.0.0.1"))
	require.NoError(t, err)
	require.Equal(t, uint32(1), ret, "the protocol gate must not override the carve-outs")

	// Both enforced drops surfaced records (ports 0, protocol preserved) —
	// under enforce these records are the drops' only evidence.
	recs := collectOriginRecords(t, rd, 500*time.Millisecond)
	require.Len(t, recs, 2)
	for _, rec := range recs {
		require.Equal(t, uint8(47), rec.IpProto)
		require.Zero(t, rec.DstPort)
		require.Equal(t, uint8(originVerdictBlock), rec.Verdict)
	}

	// Shadow: passed, recorded as a would-block for the same shape.
	setOriginMode(t, objs, originModeShadow)
	ret, _, err = objs.CgOriginEgress.Test(craftGREv4("140.82.114.4"))
	require.NoError(t, err)
	require.Equal(t, uint32(1), ret, "shadow never drops")
	recs = collectOriginRecords(t, rd, 500*time.Millisecond)
	require.Len(t, recs, 1)
	require.Equal(t, uint8(47), recs[0].IpProto)
	require.Equal(t, uint8(originVerdictWouldBlock), recs[0].Verdict)
}

// Fail-closed parse paths: outside the carve-outs, a packet whose L4
// header cannot be read drops WITH a record (ports 0) — under enforce that
// record is the drop's only evidence anywhere (the packet dies before the
// TC qdisc). Inside a carve-out the same malformed packet passes:
// loopback traffic TC never adjudicated must not become newly-denied just
// because it is malformed (CAP_NET_RAW + IP_HDRINCL crafts this shape).
func TestOriginUnparsedDropEmitsRecordAndHonorsCarveOuts(t *testing.T) {
	objs := loadOriginObjects(t)
	seedOriginRules(t, objs)
	setOriginMode(t, objs, originModeEnforce)

	rd, err := ringbuf.NewReader(objs.MapOriginEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	// Truncated TCP to a non-carved destination (140.82.114.3 — allowed,
	// which must not matter: unparseable fails closed as at tc_egress).
	ret, _, err := objs.CgOriginEgress.Test(craftTruncatedTCP(t))
	require.NoError(t, err)
	require.Equal(t, uint32(0), ret)
	recs := collectOriginRecords(t, rd, 500*time.Millisecond)
	require.Len(t, recs, 1, "an unparsed enforce-mode drop must leave a record")
	require.Equal(t, uint8(ipprotoTCP), recs[0].IpProto)
	require.Zero(t, recs[0].SrcPort)
	require.Zero(t, recs[0].DstPort)
	require.Equal(t, uint8(originVerdictBlock), recs[0].Verdict)

	// The same truncated-TCP shape to 127.0.0.1: carved, passes, silent.
	eth := craftEthHeader(ethPIP)
	ip := craftIPv4Header("127.0.0.1", ipprotoTCP, 10)
	loopbackTruncated := append(append(eth, ip...), make([]byte, 10)...)
	ret, _, err = objs.CgOriginEgress.Test(loopbackTruncated)
	require.NoError(t, err)
	require.Equal(t, uint32(1), ret, "carve-outs are honored even for malformed packets")
	require.Empty(t, collectOriginRecords(t, rd, 300*time.Millisecond))

	// Invalid IHL (dst 0.0.0.0 — not carved): drop + record.
	ret, _, err = objs.CgOriginEgress.Test(craftInvalidIHLIPv4(t))
	require.NoError(t, err)
	require.Equal(t, uint32(0), ret)
	recs = collectOriginRecords(t, rd, 500*time.Millisecond)
	require.Len(t, recs, 1)
	require.Equal(t, uint8(originVerdictBlock), recs[0].Verdict)
}
