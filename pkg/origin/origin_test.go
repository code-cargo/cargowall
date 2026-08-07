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

package origin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestObserver builds an Observer with only the join store live — nil
// pid/step maps exercise the guard insert uses when resolution is
// unavailable (records stay usable, identities zero).
func newTestObserver() *Observer {
	return &Observer{flows: make(map[flowKey][]Record)}
}

func v4Event(cookie uint64, srcIP, dstIP uint32, srcPort, dstPort uint16) *originEvent {
	return &originEvent{
		Cookie:    cookie,
		CgroupID:  100 + cookie,
		Timestamp: cookie, // monotonic enough for ordering assertions
		SrcIp:     srcIP,
		DstIp:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		IpVersion: 4,
		IpProto:   6,
		Flags:     flagTCPSyn,
	}
}

func TestLookupExactSourcePortIsAuthoritative(t *testing.T) {
	o := newTestObserver()
	o.insert(v4Event(1, 0xAC110002, 0x8C527203, 40001, 443))
	o.insert(v4Event(2, 0xAC110003, 0x8C527203, 40002, 443))

	got := o.LookupV4(0x8C527203, 443, 6, 40001)
	require.Len(t, got, 1)
	require.Equal(t, uint64(1), got[0].Cookie)
	require.Equal(t, "172.17.0.2", got[0].SrcIP.String())
	require.True(t, got[0].TCPSyn)
}

func TestLookupFallbackReturnsAllCandidatesNewestFirst(t *testing.T) {
	o := newTestObserver()
	o.insert(v4Event(1, 0xAC110002, 0x8C527203, 40001, 443))
	o.insert(v4Event(2, 0xAC110003, 0x8C527203, 40002, 443))

	// A rewritten source port misses the exact pass and returns everything,
	// newest first, so the caller can decide whether the candidates agree.
	got := o.LookupV4(0x8C527203, 443, 6, 55555)
	require.Len(t, got, 2)
	require.Equal(t, uint64(2), got[0].Cookie)
	require.Equal(t, uint64(1), got[1].Cookie)

	// srcPort 0 (protocol-block shape) skips the exact pass entirely.
	got = o.LookupV4(0x8C527203, 443, 6, 0)
	require.Len(t, got, 2)
}

func TestLookupMissesDisjointTuples(t *testing.T) {
	o := newTestObserver()
	o.insert(v4Event(1, 0xAC110002, 0x8C527203, 40001, 443))

	require.Nil(t, o.LookupV4(0x8C527203, 80, 6, 40001), "different port")
	require.Nil(t, o.LookupV4(0x8C527204, 443, 6, 40001), "different dst")
	require.Nil(t, o.LookupV4(0x8C527203, 443, 17, 40001), "different proto")

	var dst6 [16]byte
	dst6[15] = 1
	require.Nil(t, o.LookupV6(dst6, 443, 6, 40001), "different family")
}

func TestReEmitReplacesSameSocketEntry(t *testing.T) {
	o := newTestObserver()
	o.insert(v4Event(1, 0xAC110002, 0x8C527203, 40001, 443))
	old := o.LookupV4(0x8C527203, 443, 6, 40001)[0].Timestamp

	// The 10s re-emit for the same socket must refresh, not duplicate.
	refresh := v4Event(1, 0xAC110002, 0x8C527203, 40001, 443)
	refresh.Timestamp = 999
	o.insert(refresh)

	got := o.LookupV4(0x8C527203, 443, 6, 0)
	require.Len(t, got, 1)
	require.NotEqual(t, old, got[0].Timestamp)
	require.Equal(t, uint64(999), got[0].Timestamp)
}

func TestPerKeyCapDropsOldest(t *testing.T) {
	o := newTestObserver()
	for i := range perKeyMax + 3 {
		o.insert(v4Event(uint64(i+1), 0xAC110002, 0x8C527203, uint16(40000+i), 443))
	}
	got := o.LookupV4(0x8C527203, 443, 6, 0)
	require.Len(t, got, perKeyMax)
	require.Equal(t, uint64(perKeyMax+3), got[0].Cookie, "newest survives in front")
	for _, r := range got {
		require.NotEqual(t, uint16(40000), r.SrcPort, "oldest entry evicted")
	}
}

func TestStoreKeyCapEvictsOldestKey(t *testing.T) {
	o := newTestObserver()
	for i := range storeMaxKeys + 10 {
		o.insert(v4Event(uint64(i+1), 0xAC110002, uint32(0x0A000000+i), 40001, 443))
	}
	require.LessOrEqual(t, len(o.flows), storeMaxKeys)
	require.Nil(t, o.LookupV4(0x0A000000, 443, 6, 0), "oldest key evicted")
	require.NotNil(t, o.LookupV4(uint32(0x0A000000+storeMaxKeys+9), 443, 6, 0), "newest key present")
}

func TestInsertResolvesV6Source(t *testing.T) {
	o := newTestObserver()
	ev := &originEvent{
		Cookie:    7,
		IpVersion: 6,
		IpProto:   6,
		SrcPort:   40001,
		DstPort:   443,
	}
	copy(ev.SrcIp6[:], []byte{0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	ev.DstIp6[15] = 2
	o.insert(ev)

	var dst [16]byte
	dst[15] = 2
	got := o.LookupV6(dst, 443, 6, 40001)
	require.Len(t, got, 1)
	require.Equal(t, "2606:4700::1", got[0].SrcIP.String())
}

// Guards against silent key-shape drift: two inserts differing only in a
// field the key must include may never share a bucket.
func TestKeyIncludesEveryDiscriminator(t *testing.T) {
	fields := []struct {
		name string
		ev   *originEvent
	}{
		{"base", v4Event(1, 0xAC110002, 0x8C527203, 40001, 443)},
		{"port", v4Event(2, 0xAC110002, 0x8C527203, 40001, 8443)},
		{"proto", func() *originEvent { e := v4Event(3, 0xAC110002, 0x8C527203, 40001, 443); e.IpProto = 17; return e }()},
		{"dst", v4Event(4, 0xAC110002, 0x8C527204, 40001, 443)},
	}
	o := newTestObserver()
	for _, f := range fields {
		o.insert(f.ev)
	}
	require.Len(t, o.flows, len(fields), fmt.Sprintf("each variant must occupy its own key: %v", o.flows))
}
