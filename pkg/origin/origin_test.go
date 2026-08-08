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
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
)

// newTestObserver builds an Observer with the join store and the verdict
// queue live — nil pid/step maps exercise the guard insert uses when
// resolution is unavailable (records stay usable, identities zero). The
// reporting worker is NOT started; tests that need it run reportLoop
// themselves.
func newTestObserver() *Observer {
	return &Observer{
		flows:      make(map[flowKey][]Record),
		hot:        make(map[flowKey]struct{}),
		verdictCh:  make(chan Record, verdictQueueDepth),
		reportDone: make(chan struct{}),
		logger:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
}

func v4Event(cookie uint64, srcIP, dstIP uint32, srcPort, dstPort uint16) *bpf.OriginEvent {
	return &bpf.OriginEvent{
		Cookie:    cookie,
		CgroupID:  100 + cookie,
		Timestamp: cookie, // monotonic enough for ordering assertions
		SrcIp:     srcIP,
		DstIp:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		IpVersion: 4,
		IpProto:   6,
		Flags:     bpf.OriginFlagTCPSyn,
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
	ev := &bpf.OriginEvent{
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
		ev   *bpf.OriginEvent
	}{
		{"base", v4Event(1, 0xAC110002, 0x8C527203, 40001, 443)},
		{"port", v4Event(2, 0xAC110002, 0x8C527203, 40001, 8443)},
		{"proto", func() *bpf.OriginEvent { e := v4Event(3, 0xAC110002, 0x8C527203, 40001, 443); e.IpProto = 17; return e }()},
		{"dst", v4Event(4, 0xAC110002, 0x8C527204, 40001, 443)},
	}
	o := newTestObserver()
	for _, f := range fields {
		o.insert(f.ev)
	}
	require.Len(t, o.flows, len(fields), fmt.Sprintf("each variant must occupy its own key: %v", o.flows))
}

// The join store must be populated BEFORE the verdict sink can observe the
// record. In shadow mode (the default under --container-attribution) a
// would-block packet is passed and TC adjudicates it concurrently; if the
// sink ran first — it may spend 500ms in a PTR lookup — the TC event's
// Enrich would find no join candidate and file the flow as unattributed.
// The sink here performs the same lookup a TC event would.
func TestInsertStoresBeforeReporting(t *testing.T) {
	o := newTestObserver()
	go o.reportLoop()
	defer func() {
		close(o.verdictCh)
		<-o.reportDone
	}()

	seen := make(chan []Record, 1)
	o.SetVerdictSink(func(rec Record) {
		seen <- o.LookupV4(0x8C527203, rec.DstPort, rec.Proto, rec.SrcPort)
	})

	ev := v4Event(1, 0xAC110002, 0x8C527203, 40001, 443)
	ev.Verdict = uint8(VerdictWouldBlock)
	o.insert(ev)

	got := <-seen
	require.Len(t, got, 1, "the sink must observe the record already in the join store")
	require.Equal(t, uint64(1), got[0].Cookie)
	require.Equal(t, VerdictWouldBlock, got[0].Verdict)
	require.Equal(t, uint64(1), o.blocked.Load())
}

// A slow (or absent) reporting worker must never block insert: the send is
// non-blocking and overflow costs only the report.
func TestInsertNeverBlocksOnFullVerdictQueue(t *testing.T) {
	o := newTestObserver() // reportLoop deliberately not started
	for i := range verdictQueueDepth + 5 {
		ev := v4Event(uint64(i+1), 0xAC110002, 0x8C527203, uint16(40000+i), 443)
		ev.Verdict = uint8(VerdictBlock)
		o.insert(ev) // would deadlock here without the non-blocking send
	}
	require.Equal(t, uint64(5), o.verdictsDropped.Load())
	require.Equal(t, uint64(verdictQueueDepth+5), o.blocked.Load())
}

// Eviction is second-chance, not pure FIFO: a key re-emitted since eviction
// last considered it survives one rotation, so the hot destinations a build
// hammers are not the first casualties of a wide fan-out of one-shot keys.
func TestStoreEvictionGivesRefreshedKeysASecondChance(t *testing.T) {
	o := newTestObserver()
	for i := range storeMaxKeys {
		o.insert(v4Event(uint64(i+1), 0xAC110002, uint32(0x0A000000+i), 40001, 443))
	}
	// Refresh the OLDEST key (the 10s re-emit for a long-lived hot flow).
	o.insert(v4Event(1, 0xAC110002, 0x0A000000, 40001, 443))

	// The next new key must evict the idle second key, not the hot first.
	o.insert(v4Event(9999, 0xAC110002, 0x0B000000, 40001, 443))
	require.NotNil(t, o.LookupV4(0x0A000000, 443, 6, 0), "refreshed key must survive eviction")
	require.Nil(t, o.LookupV4(0x0A000001, 443, 6, 0), "idle key is the victim")
	require.LessOrEqual(t, len(o.flows), storeMaxKeys)
}

// TestOriginConstantsMatchBpfSource pins the Go constants to the C source
// the way TestDNSProxyFWMarkMatchesGoConstant pins the firewall mark: the
// ORIGIN_MODE_*, ORIGIN_VERDICT_* and ORIGIN_FLAG_* values are mirrored in
// three places (originbpf.c, this package, bpf/origin_event.go), and a
// drift would mislabel every verdict userspace reports.
func TestOriginConstantsMatchBpfSource(t *testing.T) {
	src, err := os.ReadFile("../../bpf/originbpf.c")
	require.NoError(t, err)

	defines := map[string]uint64{
		"ORIGIN_MODE_OBSERVE":        uint64(ModeObserve),
		"ORIGIN_MODE_SHADOW":         uint64(ModeShadow),
		"ORIGIN_MODE_ENFORCE":        uint64(ModeEnforce),
		"ORIGIN_VERDICT_NONE":        uint64(VerdictNone),
		"ORIGIN_VERDICT_ALLOW":       uint64(VerdictAllow),
		"ORIGIN_VERDICT_WOULD_BLOCK": uint64(VerdictWouldBlock),
		"ORIGIN_VERDICT_BLOCK":       uint64(VerdictBlock),
		"ORIGIN_FLAG_TCP_SYN":        uint64(bpf.OriginFlagTCPSyn),
		"ORIGIN_FLAG_TCP_MIDSTREAM":  uint64(bpf.OriginFlagTCPMidstream),
		"ORIGIN_CFG_KEY_MODE":        uint64(cfgKeyMode),
		"ORIGIN_CFG_KEY_LO_CARVEOUT": uint64(cfgKeyLoCarveout),
	}
	for name, want := range defines {
		re := regexp.MustCompile(`(?m)^#define ` + name + `\s+(0x[0-9A-Fa-f]+|\d+)\b`)
		m := re.FindStringSubmatch(string(src))
		require.NotNil(t, m, "originbpf.c must #define %s", name)
		got, err := strconv.ParseUint(m[1], 0, 64)
		require.NoError(t, err)
		require.Equal(t, want, got, "%s drifted between originbpf.c and the Go mirror", name)
	}
}
