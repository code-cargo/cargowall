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
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// tupleOrigPayload builds the nfgenmsg+attributes payload a dump reply (or
// delete request) carries for the given tuple, so the parser can be
// exercised against the marshaller.
func tupleOrigPayload(t *testing.T, ct ctTuple) []byte {
	t.Helper()
	attrs, err := marshalTupleOrig(ct)
	if err != nil {
		t.Fatalf("marshal tuple: %v", err)
	}
	return append(nfgenmsgV4(), attrs...)
}

// TestParseConntrackTupleOrig_RoundTrip: a tuple written by the marshaller
// parses back identically — pinning both to the same attribute layout
// (nesting, byte order).
func TestParseConntrackTupleOrig_RoundTrip(t *testing.T) {
	want := ctTuple{
		srcIP:   [4]byte{10, 1, 0, 223},
		dstIP:   [4]byte{168, 63, 129, 16},
		proto:   unix.IPPROTO_UDP,
		srcPort: 40732,
		dstPort: 53,
	}
	got, ok := parseConntrackTupleOrig(tupleOrigPayload(t, want))
	if !ok {
		t.Fatal("round-trip parse reported incomplete tuple")
	}
	if got != want {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
	if !got.isDNS() {
		t.Fatal("udp/53 tuple not classified as DNS")
	}
}

// TestParseConntrackTupleOrig_Incomplete: payloads missing required fields
// (or too short to carry any) must report !ok, never a zero-filled tuple a
// delete would then aim at the wrong flow.
func TestParseConntrackTupleOrig_Incomplete(t *testing.T) {
	// Tuple with only the IP half: CTA_TUPLE_ORIG carrying CTA_TUPLE_IP but
	// no CTA_TUPLE_PROTO.
	ae := netlink.NewAttributeEncoder()
	ae.Nested(ctaTupleOrig, func(nae *netlink.AttributeEncoder) error {
		nae.Nested(ctaTupleIP, func(iae *netlink.AttributeEncoder) error {
			iae.Bytes(ctaIPv4Src, []byte{1, 2, 3, 4})
			iae.Bytes(ctaIPv4Dst, []byte{5, 6, 7, 8})
			return nil
		})
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, ok := parseConntrackTupleOrig(append(nfgenmsgV4(), attrs...)); ok {
		t.Fatal("tuple without CTA_TUPLE_PROTO parsed as complete")
	}

	for name, data := range map[string][]byte{
		"empty":          {},
		"nfgenmsg-only":  nfgenmsgV4(),
		"short-nfgenmsg": {0},
	} {
		if _, ok := parseConntrackTupleOrig(data); ok {
			t.Fatalf("%s payload parsed as complete", name)
		}
	}
}

// TestParseConntrackTupleOrig_MalformedAttr: attribute lengths that lie
// (shorter than a header, longer than the buffer) must not panic and must
// not fabricate a complete tuple.
func TestParseConntrackTupleOrig_MalformedAttr(t *testing.T) {
	tooShort := append(nfgenmsgV4(), 2, 0, ctaTupleOrig, 0) // nla_len=2 < NLA_HDRLEN
	if _, ok := parseConntrackTupleOrig(tooShort); ok {
		t.Fatal("undersized attribute parsed as complete")
	}

	tooLong := append(nfgenmsgV4(), 0xFF, 0, ctaTupleOrig, 0) // nla_len=255 > buffer
	if _, ok := parseConntrackTupleOrig(tooLong); ok {
		t.Fatal("oversized attribute parsed as complete")
	}
}

// TestCtTupleIsDNS pins the flush scope: TCP/UDP to port 53 and nothing
// else — not other ports, not other protocols.
func TestCtTupleIsDNS(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tuple ctTuple
		want  bool
	}{
		{"udp53", ctTuple{proto: unix.IPPROTO_UDP, dstPort: 53}, true},
		{"tcp53", ctTuple{proto: unix.IPPROTO_TCP, dstPort: 53}, true},
		{"udp443", ctTuple{proto: unix.IPPROTO_UDP, dstPort: 443}, false},
		{"tcp443", ctTuple{proto: unix.IPPROTO_TCP, dstPort: 443}, false},
		{"sport53", ctTuple{proto: unix.IPPROTO_UDP, srcPort: 53, dstPort: 5353}, false},
		{"icmp", ctTuple{proto: unix.IPPROTO_ICMP}, false},
	} {
		if got := tc.tuple.isDNS(); got != tc.want {
			t.Errorf("%s: isDNS() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// sendUDP fires one datagram at addr from an ephemeral port, creating a
// conntrack entry when tracking is active, and returns the local port.
func sendUDP(t *testing.T, addr string) uint16 {
	t.Helper()
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write %s: %v", addr, err)
	}
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// hasTuple reports whether the live conntrack table holds a v4 UDP entry
// matching (srcPort, dstPort).
func hasTuple(t *testing.T, srcPort, dstPort uint16) bool {
	t.Helper()
	conn, tuples, err := dumpConntrackTuples()
	if err != nil {
		t.Fatalf("dump conntrack: %v", err)
	}
	conn.Close()
	return slices.ContainsFunc(tuples, func(ct ctTuple) bool {
		return ct.proto == unix.IPPROTO_UDP && ct.srcPort == srcPort && ct.dstPort == dstPort
	})
}

// TestFlushDNSConntrack_Live exercises the full dump→filter→delete path
// against the running kernel: a UDP flow to :53 must be deleted, a UDP flow
// to another port must survive. Root-gated (ctnetlink deletes need
// CAP_NET_ADMIN) and skipped when conntrack isn't observing loopback (no
// tracking hooks registered — nothing to flush, nothing to test).
func TestFlushDNSConntrack_Live(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN for conntrack delete)")
	}

	// 127.0.0.2: loopback-net, no listener needed — the ICMP port
	// unreachable that answers doesn't remove the conntrack entry within
	// the test window.
	dnsPort := sendUDP(t, "127.0.0.2:53")
	otherPort := sendUDP(t, "127.0.0.2:5353")

	if !hasTuple(t, dnsPort, 53) {
		t.Skip("conntrack not tracking loopback flows on this kernel/config")
	}
	if !hasTuple(t, otherPort, 5353) {
		t.Fatal("control flow (:5353) not tracked despite :53 being tracked")
	}

	if err := FlushDNSConntrack(discardLogger()); err != nil {
		t.Fatalf("FlushDNSConntrack: %v", err)
	}

	// The delete is synchronous (ACKed per entry), but give the table a
	// beat on slow CI before declaring a leak.
	deadline := time.Now().Add(2 * time.Second)
	for hasTuple(t, dnsPort, 53) {
		if time.Now().After(deadline) {
			t.Fatal("dport-53 conntrack entry survived FlushDNSConntrack")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !hasTuple(t, otherPort, 5353) {
		t.Fatal("non-DNS conntrack entry (:5353) was deleted — flush overshot its scope")
	}
}
