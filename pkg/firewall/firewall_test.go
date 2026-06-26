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

package firewall

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// mockMap records Update/Delete calls and serves Lookup either from a
// configurable function (lookupFn) or from an in-memory store. When store is
// non-nil the mock behaves like a real map — Update/Delete mutate it and Lookup
// reflects prior writes — which the order-permutation tests rely on to assert
// the resulting allow/deny decision. When lookupFn is set it takes precedence,
// preserving the hand-configured lookups the single-call tests use.
type mockMap struct {
	updates  []mockUpdate
	deletes  []any
	store    map[any]any // dereferenced key value -> dereferenced value
	lookupFn func(key, valueOut any) error
}

type mockUpdate struct {
	key   any
	value any
	flags ebpf.MapUpdateFlags
}

func newMockMap() *mockMap {
	return &mockMap{
		lookupFn: func(_, _ any) error { return ebpf.ErrKeyNotExist },
	}
}

// newStatefulMockMap returns a mock backed by an in-memory store so Lookup
// reflects prior Update/Delete calls.
func newStatefulMockMap() *mockMap {
	return &mockMap{store: make(map[any]any)}
}

// deref returns the value a pointer points at, so the comparable struct value
// (not the pointer identity) is used as the store key/value.
func deref(p any) any {
	v := reflect.ValueOf(p)
	if v.Kind() == reflect.Pointer {
		return v.Elem().Interface()
	}
	return v.Interface()
}

func (m *mockMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	m.updates = append(m.updates, mockUpdate{key: key, value: value, flags: flags})
	if m.store != nil {
		m.store[deref(key)] = deref(value)
	}
	return nil
}

func (m *mockMap) Lookup(key, valueOut any) error {
	if m.lookupFn != nil {
		return m.lookupFn(key, valueOut)
	}
	stored, ok := m.store[deref(key)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(stored))
	return nil
}

func (m *mockMap) Delete(key any) error {
	m.deletes = append(m.deletes, key)
	if m.store != nil {
		delete(m.store, deref(key))
	}
	return nil
}

func newTestFirewall() (*FirewallImpl, map[string]*mockMap) {
	mocks := map[string]*mockMap{
		"cidrs":         newMockMap(),
		"ports":         newMockMap(),
		"cidrsV6":       newMockMap(),
		"portsV6":       newMockMap(),
		"defaultAction": newMockMap(),
		"auditMode":     newMockMap(),
	}
	fw := &FirewallImpl{
		cidrsMap:         mocks["cidrs"],
		portsMap:         mocks["ports"],
		cidrsV6Map:       mocks["cidrsV6"],
		portsV6Map:       mocks["portsV6"],
		defaultActionMap: mocks["defaultAction"],
		auditModeMap:     mocks["auditMode"],
		logger:           slog.Default(),
		ipPorts:          make(map[string]*ipPortState),
	}
	return fw, mocks
}

// newStatefulTestFirewall wires the firewall to stateful mocks so a sequence of
// AddIP calls can be replayed in any order and the resulting BPF map state
// queried — used by the add-order permutation tests.
func newStatefulTestFirewall() (*FirewallImpl, map[string]*mockMap) {
	mocks := map[string]*mockMap{
		"cidrs":         newStatefulMockMap(),
		"ports":         newStatefulMockMap(),
		"cidrsV6":       newStatefulMockMap(),
		"portsV6":       newStatefulMockMap(),
		"defaultAction": newStatefulMockMap(),
		"auditMode":     newStatefulMockMap(),
	}
	fw := &FirewallImpl{
		cidrsMap:         mocks["cidrs"],
		portsMap:         mocks["ports"],
		cidrsV6Map:       mocks["cidrsV6"],
		portsV6Map:       mocks["portsV6"],
		defaultActionMap: mocks["defaultAction"],
		auditModeMap:     mocks["auditMode"],
		logger:           slog.Default(),
		ipPorts:          make(map[string]*ipPortState),
	}
	return fw, mocks
}

// bpfDecideV4 mirrors the IPv4 decision in bpf/tcbpf.c against the final state
// of the stateful mocks: LPM lookup, then (when port-specific) the per-IP and
// wildcard port maps, falling back to the default action. It lets tests assert
// the real allow/deny outcome a packet would get rather than inspecting raw
// map writes.
func bpfDecideV4(cidrs, ports *mockMap, ip net.IP, port uint16, proto uint8, defaultAllow bool) bool {
	ipU := binary.NativeEndian.Uint32(ip.To4())
	if rv, ok := cidrs.store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: ipU}]; ok {
		rule := rv.(bpf.TcBpfLpmVal)
		if rule.PortSpecific == 0 {
			return rule.Action == 1
		}
		if pv, ok := ports.store[bpf.TcBpfPortKey{Ip: ipU, Port: port, Proto: proto}]; ok {
			return pv.(bpf.TcBpfPortVal).Action == 1
		}
		if pv, ok := ports.store[bpf.TcBpfPortKey{Ip: 0, Port: port, Proto: proto}]; ok {
			return pv.(bpf.TcBpfPortVal).Action == 1
		}
		return defaultAllow
	}
	if pv, ok := ports.store[bpf.TcBpfPortKey{Ip: 0, Port: port, Proto: proto}]; ok {
		return pv.(bpf.TcBpfPortVal).Action == 1
	}
	return defaultAllow
}

// bpfDecideV6 mirrors bpfDecideV4 for the IPv6 data path (TCP/UDP; ICMPv6 is
// unconditionally allowed by BPF before the maps are consulted).
func bpfDecideV6(cidrs, ports *mockMap, ip net.IP, port uint16, proto uint8, defaultAllow bool) bool {
	var ipArr [16]byte
	copy(ipArr[:], ip.To16())
	if rv, ok := cidrs.store[bpf.TcBpfLpmKeyV6{Prefixlen: 128, Ip: ipArr}]; ok {
		rule := rv.(bpf.TcBpfLpmVal)
		if rule.PortSpecific == 0 {
			return rule.Action == 1
		}
		if pv, ok := ports.store[bpf.TcBpfPortKeyV6{Ip: ipArr, Port: port, Proto: proto}]; ok {
			return pv.(bpf.TcBpfPortVal).Action == 1
		}
		if pv, ok := ports.store[bpf.TcBpfPortKeyV6{Port: port, Proto: proto}]; ok {
			return pv.(bpf.TcBpfPortVal).Action == 1
		}
		return defaultAllow
	}
	if pv, ok := ports.store[bpf.TcBpfPortKeyV6{Port: port, Proto: proto}]; ok {
		return pv.(bpf.TcBpfPortVal).Action == 1
	}
	return defaultAllow
}

// --- AddIP dedup detection ---

func TestAddIP_NewIP(t *testing.T) {
	fw, mocks := newTestFirewall()
	// Lookup returns ErrKeyNotExist (default) → new IP

	added, err := fw.AddIP(net.ParseIP("10.0.0.1"), config.ActionAllow, nil)
	require.NoError(t, err)
	assert.True(t, added)
	assert.Len(t, mocks["cidrs"].updates, 1, "cidrsMap.Update should be called once")
}

func TestAddIP_ExactDuplicate(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")
	ip4 := ip.To4()
	ipUint32 := binary.NativeEndian.Uint32(ip4)

	// Configure Lookup to return an existing entry that matches what AddIP would write
	mocks["cidrs"].lookupFn = func(key, valueOut any) error {
		k := key.(*bpf.TcBpfLpmKey)
		if k.Ip == ipUint32 {
			v := valueOut.(*bpf.TcBpfLpmVal)
			v.Action = 1 // ActionAllow
			v.PortSpecific = 0
			return nil
		}
		return ebpf.ErrKeyNotExist
	}

	added, err := fw.AddIP(ip, config.ActionAllow, nil)
	require.NoError(t, err)
	assert.False(t, added, "duplicate IP should not be added")
	assert.Empty(t, mocks["cidrs"].updates, "cidrsMap.Update should NOT be called for duplicate")
}

// Regression: when an IP is shared across hostname rules with disjoint port
// sets (e.g. foo.example.com→:443 and bar.example.com→:8080 both resolving
// to the same cloud IP), the second AddIP must still write the new (port,
// proto) entries even though the LPM (Action, PortSpecific) check matches.
// Pre-fix the per-port writes were skipped, leaving the second hostname's
// connections silently blackholed and audit-mislabelled as late-allowed.
//
// The `changed` return is true here because the per-port entry was new to
// map_ports — the caller's INFO log fires so operators can see that a new
// port was opened on a previously-allowed IP.
func TestAddIP_SharedIP_DifferentPorts_StillWritesPortEntries(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")
	ip4 := ip.To4()
	ipUint32 := binary.NativeEndian.Uint32(ip4)

	// Existing LPM entry from a prior AddIP for the same IP with a different
	// port set — Action and PortSpecific both match what we're about to write.
	mocks["cidrs"].lookupFn = func(key, valueOut any) error {
		k := key.(*bpf.TcBpfLpmKey)
		if k.Ip == ipUint32 {
			v := valueOut.(*bpf.TcBpfLpmVal)
			v.Action = 1       // ActionAllow
			v.PortSpecific = 1 // port-scoped (same as the call we're about to make)
			return nil
		}
		return ebpf.ErrKeyNotExist
	}
	// Default ports lookupFn returns ErrKeyNotExist → the (8080, tcp) entry
	// is "new" → portsChanged=true.

	changed, err := fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 8080, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	assert.True(t, changed, "per-port entry was newly written — caller can log it")

	// The (8080, tcp) port entry MUST have been written to portsMap so the
	// retry on the new port succeeds. Pre-fix this was skipped and the BPF
	// blocked the connection silently.
	require.Len(t, mocks["ports"].updates, 1, "per-port entry must be written even when LPM is a no-op")
	portKey := mocks["ports"].updates[0].key.(*bpf.TcBpfPortKey)
	assert.Equal(t, ipUint32, portKey.Ip)
	assert.Equal(t, uint16(8080), portKey.Port)
	assert.Equal(t, uint8(6), portKey.Proto, "TCP proto number")

	// ipPorts must accumulate (set semantics) so RemoveIP later cleans up
	// every (port, proto) ever written for this IP.
	assert.Equal(t, []portProto{{Port: 8080, Proto: 6}}, fw.ipPorts[ip.String()].ports)
}

// IPv6 sibling — same pattern, same bug, same fix.
func TestAddIPv6_SharedIP_DifferentPorts_StillWritesPortEntries(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("2001:db8::1")

	mocks["cidrsV6"].lookupFn = func(_, valueOut any) error {
		v := valueOut.(*bpf.TcBpfLpmVal)
		v.Action = 1
		v.PortSpecific = 1
		return nil
	}

	changed, err := fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 8080, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	assert.True(t, changed, "per-port v6 entry was newly written")

	require.Len(t, mocks["portsV6"].updates, 1, "per-port v6 entry must be written even when LPM is a no-op")
	portKey := mocks["portsV6"].updates[0].key.(*bpf.TcBpfPortKeyV6)
	assert.Equal(t, uint16(8080), portKey.Port)
	assert.Equal(t, uint8(6), portKey.Proto)
	assert.Equal(t, []portProto{{Port: 8080, Proto: 6}}, fw.ipPorts[ip.String()].ports)
}

// True duplicate — same (action, ports), all per-port entries already match.
// Both LPM no-op AND port lookups return existing matching values, so
// `changed` must be false. Guards against accidentally collapsing the
// "wrote port" detection back into "always returns true for non-empty ports".
func TestAddIP_TrueDuplicateWithPorts_ReportsUnchanged(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")

	mocks["cidrs"].lookupFn = func(_, valueOut any) error {
		v := valueOut.(*bpf.TcBpfLpmVal)
		v.Action = 1
		v.PortSpecific = 1
		return nil
	}
	mocks["ports"].lookupFn = func(_, valueOut any) error {
		v := valueOut.(*bpf.TcBpfPortVal)
		v.Action = 1 // already-present matching entry
		return nil
	}
	// Pre-populate ipPorts so the merge is a no-op too.
	fw.ipPorts[ip.String()] = &ipPortState{ports: []portProto{{Port: 443, Proto: 6}}}

	changed, err := fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	assert.False(t, changed, "true duplicate with matching state must report no change")
	assert.Equal(t, []portProto{{Port: 443, Proto: 6}}, fw.ipPorts[ip.String()].ports, "ipPorts unchanged")
}

// Two AddIP calls with disjoint port sets must accumulate both into ipPorts so
// RemoveIP cleans up every (port, proto) we've ever written. Pre-fix the second
// call overwrote ipPorts to its own ports only, leaving the first call's
// entries orphaned in map_ports after RemoveIP.
func TestAddIP_SharedIP_IpPortsAccumulatesAcrossCalls(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")

	// First AddIP: new IP with [443].
	changed, err := fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, []portProto{{Port: 443, Proto: 6}}, fw.ipPorts[ip.String()].ports)

	// Second AddIP: same IP, different port [8080]. Configure cidrs lookup
	// to return the LPM entry from the first call.
	ipUint32 := binary.NativeEndian.Uint32(ip.To4())
	mocks["cidrs"].lookupFn = func(key, valueOut any) error {
		k := key.(*bpf.TcBpfLpmKey)
		if k.Ip == ipUint32 {
			v := valueOut.(*bpf.TcBpfLpmVal)
			v.Action = 1
			v.PortSpecific = 1
			return nil
		}
		return ebpf.ErrKeyNotExist
	}

	changed, err = fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 8080, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	assert.True(t, changed, "new port entry was written")

	// BOTH ports tracked — RemoveIP will clean up both.
	assert.ElementsMatch(t,
		[]portProto{{Port: 443, Proto: 6}, {Port: 8080, Proto: 6}},
		fw.ipPorts[ip.String()].ports,
		"ipPorts must accumulate disjoint port sets across calls")
}

// Transitioning an IP from PortSpecific=1 to PortSpecific=0 (i.e. AddIP with
// nil ports after AddIP with some ports) must NOT delete the previously-written
// per-port entries: another hostname rule may still require them, and they are
// retained (inert under PortSpecific=0) so RemoveIP can clean up the full set.
// The all-ports grant becomes sticky — a later port-specific add must not flip
// PortSpecific back to 1 and narrow it (issue #71).
func TestAddIP_TransitionToAllPorts_KeepsPortEntriesAndIsSticky(t *testing.T) {
	fw, mocks := newStatefulTestFirewall()
	ip := net.ParseIP("10.0.0.1")

	// First call: add (ip, allow, [443, 8080]).
	_, err := fw.AddIP(ip, config.ActionAllow, []config.Port{
		{Port: 443, Protocol: config.ProtocolTCP},
		{Port: 8080, Protocol: config.ProtocolTCP},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []portProto{{Port: 443, Proto: 6}, {Port: 8080, Proto: 6}}, fw.ipPorts[ip.String()].ports)

	// Second call: transition to all-ports.
	changed, err := fw.AddIP(ip, config.ActionAllow, nil)
	require.NoError(t, err)
	assert.True(t, changed, "PortSpecific 1→0 LPM change must be reported")

	// No per-port entries are deleted — the previous fix blackholed other
	// contributors by deleting here.
	assert.Empty(t, mocks["ports"].deletes, "per-port entries must NOT be deleted on all-ports transition")

	// The IP is now all-ports allow and the union is retained for cleanup.
	st := fw.ipPorts[ip.String()]
	require.NotNil(t, st)
	assert.True(t, st.allPortsAllow, "all-ports allow grant recorded")
	assert.False(t, st.allPortsDeny)
	assert.ElementsMatch(t, []portProto{{Port: 443, Proto: 6}, {Port: 8080, Proto: 6}}, st.ports)

	// Every port is now allowed (PortSpecific=0), including one never added.
	assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 443, protoTCP, false))
	assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 9999, protoTCP, false))

	// Third call: a port-specific add must NOT narrow the sticky all-ports grant.
	changed, err = fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	assert.False(t, changed, "port-specific re-add over a sticky all-ports grant is a no-op")

	lpm := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: binary.NativeEndian.Uint32(ip.To4())}].(bpf.TcBpfLpmVal)
	assert.Equal(t, uint8(0), lpm.PortSpecific, "all-ports grant stays PortSpecific=0 after a port-specific add")
	assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 9999, protoTCP, false), "any port still allowed")
}

// An all-ports DENY over an existing all-ports ALLOW re-adds the IP as deny:
// deny wins on conflict. (The reverse — allow over an existing all-ports deny —
// is a no-op, covered by TestAddIP_AllPortsDeny_WinsOverAllPortsAllow.)
func TestAddIP_SameIPDifferentAction(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")
	ip4 := ip.To4()
	ipUint32 := binary.NativeEndian.Uint32(ip4)

	// Existing entry has Action=allow (1), all-ports; we'll add an all-ports deny.
	mocks["cidrs"].lookupFn = func(key, valueOut any) error {
		k := key.(*bpf.TcBpfLpmKey)
		if k.Ip == ipUint32 {
			v := valueOut.(*bpf.TcBpfLpmVal)
			v.Action = 1 // ActionAllow
			v.PortSpecific = 0
			return nil
		}
		return ebpf.ErrKeyNotExist
	}

	added, err := fw.AddIP(ip, config.ActionDeny, nil)
	require.NoError(t, err)
	assert.True(t, added, "all-ports deny over an existing all-ports allow must re-add (deny wins)")
	require.Len(t, mocks["cidrs"].updates, 1, "cidrsMap.Update should be called")
	lpm := mocks["cidrs"].updates[0].value.(*bpf.TcBpfLpmVal)
	assert.Equal(t, uint8(0), lpm.Action, "deny wins")
	assert.Equal(t, uint8(0), lpm.PortSpecific)
}

// --- AddIP + RemoveIP ipPorts tracking ---

func TestAddIP_WithPorts_TracksIPPorts(t *testing.T) {
	fw, _ := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")
	ports := []config.Port{
		{Port: 80, Protocol: config.ProtocolTCP},
		{Port: 443, Protocol: config.ProtocolTCP},
	}

	added, err := fw.AddIP(ip, config.ActionAllow, ports)
	require.NoError(t, err)
	assert.True(t, added)
	assert.Equal(t, []portProto{{Port: 80, Proto: 6}, {Port: 443, Proto: 6}}, fw.ipPorts[ip.String()].ports)
}

// An all-ports AddIP over an IP that previously had port-specific entries keeps
// those entries (retained but inert under PortSpecific=0) and records the sticky
// all-ports grant — it must NOT drop the per-IP state, or RemoveIP would later
// leak the retained map_ports entries.
func TestAddIP_WithoutPorts_KeepsRetainedPortsAndRecordsAllPorts(t *testing.T) {
	fw, _ := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")

	// Pre-populate ipPorts as if a previous call added ports.
	fw.ipPorts[ip.String()] = &ipPortState{ports: []portProto{{Port: 80, Proto: 6}}}

	added, err := fw.AddIP(ip, config.ActionAllow, nil)
	require.NoError(t, err)
	assert.True(t, added)

	st := fw.ipPorts[ip.String()]
	require.NotNil(t, st, "ipPorts entry must be retained so RemoveIP can clean up the union")
	assert.True(t, st.allPortsAllow, "all-ports allow grant recorded")
	assert.False(t, st.allPortsDeny)
	assert.Equal(t, []portProto{{Port: 80, Proto: 6}}, st.ports, "previously-written ports retained for cleanup")
}

func TestRemoveIP_WithTrackedPorts(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")

	// Pre-populate ipPorts
	fw.ipPorts[ip.String()] = &ipPortState{ports: []portProto{{Port: 80, Proto: 6}, {Port: 443, Proto: 6}}}

	err := fw.RemoveIP(ip)
	require.NoError(t, err)

	// cidrsMap.Delete called once for the IP
	assert.Len(t, mocks["cidrs"].deletes, 1)
	// portsMap.Delete called once per port
	assert.Len(t, mocks["ports"].deletes, 2)
	// ipPorts entry cleaned up
	_, exists := fw.ipPorts[ip.String()]
	assert.False(t, exists)
}

// --- UpdateAllowlistTC wildcard special cases ---

func TestUpdateAllowlistTC_IPv4Wildcard_OnlyPortsMap(t *testing.T) {
	fw, mocks := newTestFirewall()

	cm := config.NewConfigManager()
	err := cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []config.Port{{Port: 80, Protocol: config.ProtocolAll}, {Port: 443, Protocol: config.ProtocolAll}}, Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	// ProtocolAll expands to ICMP+TCP+UDP → 3 entries per port × 2 ports = 6.
	assert.Len(t, mocks["ports"].updates, 6, "should update portsMap for each port+protocol combo")
	assert.Empty(t, mocks["cidrs"].updates, "should NOT update cidrsMap for wildcard with ports")
}

func TestUpdateAllowlistTC_IPv6Wildcard_OnlyPortsV6Map(t *testing.T) {
	fw, mocks := newTestFirewall()

	cm := config.NewConfigManager()
	err := cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "::/0", Ports: []config.Port{{Port: 53, Protocol: config.ProtocolAll}}, Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	// ProtocolAll expands to ICMP+TCP+UDP → 3 entries for the single port.
	assert.Len(t, mocks["portsV6"].updates, 3, "should update portsV6Map for each port+protocol combo")
	assert.Empty(t, mocks["cidrsV6"].updates, "should NOT update cidrsV6Map for wildcard with ports")
}

func TestUpdateAllowlistTC_InvalidCIDR_Skipped(t *testing.T) {
	fw, mocks := newTestFirewall()

	// "not-a-cidr" fails net.ParseCIDR and net.ParseIP, so resolveRules skips it.
	// The rule won't appear in GetResolvedRules at all.
	cm := config.NewConfigManager()
	err := cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "not-a-cidr", Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	assert.Empty(t, mocks["cidrs"].updates, "no cidrsMap updates for invalid CIDR")
	assert.Empty(t, mocks["ports"].updates, "no portsMap updates for invalid CIDR")
}

// --- UpdateAllowlistTC hostname rules ---

func TestUpdateAllowlistTC_Hostname_CreatesPerIPEntries(t *testing.T) {
	fw, mocks := newTestFirewall()

	rules := []config.Rule{
		{Type: config.RuleTypeHostname, Value: "example.com", Ports: []config.Port{{Port: 443, Protocol: config.ProtocolAll}}, Action: config.ActionAllow},
	}

	cm := config.NewConfigManager()
	// First load initializes hostnameCache for "example.com"
	err := cm.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	// Simulate DNS resolution populating the cache
	cm.UpdateDNSMapping("example.com", "93.184.216.34")
	cm.UpdateDNSMapping("example.com", "93.184.216.35")

	// Second load picks up the cached IPs into resolved rules
	err = cm.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	// Each resolved IP gets a cidrsMap entry + a portsMap entry per protocol
	// (ProtocolAll expands to ICMP+TCP+UDP → 3 protocols × 1 port × 2 IPs = 6).
	assert.Len(t, mocks["cidrs"].updates, 2, "should add /32 LPM entry per resolved IP")
	assert.Len(t, mocks["ports"].updates, 6, "should add port+protocol entry per resolved IP")
}

// --- expandPorts protocol translation ---

func TestExpandPorts_ICMP(t *testing.T) {
	got := expandPorts([]config.Port{{Port: 0, Protocol: config.ProtocolICMP}})
	assert.Equal(t, []portProto{{Port: 0, Proto: protoICMP}}, got)
}

func TestExpandPorts_AllIncludesICMP(t *testing.T) {
	got := expandPorts([]config.Port{{Port: 443, Protocol: config.ProtocolAll}})
	assert.Equal(t, []portProto{
		{Port: 0, Proto: protoICMP},
		{Port: 443, Proto: protoTCP},
		{Port: 443, Proto: protoUDP},
	}, got)
}

func TestExpandPorts_MixedICMPAndTCP(t *testing.T) {
	got := expandPorts([]config.Port{
		{Port: 0, Protocol: config.ProtocolICMP},
		{Port: 443, Protocol: config.ProtocolTCP},
	})
	assert.Equal(t, []portProto{
		{Port: 0, Proto: protoICMP},
		{Port: 443, Proto: protoTCP},
	}, got)
}

func TestStripICMPForV6_NilInput(t *testing.T) {
	filtered, dropped := stripICMPForV6(nil)
	assert.Nil(t, filtered)
	assert.False(t, dropped)
}

func TestStripICMPForV6_EmptyInput(t *testing.T) {
	filtered, dropped := stripICMPForV6([]portProto{})
	assert.Empty(t, filtered)
	assert.False(t, dropped)
}

// --- UpdateAllowlistTC ICMP rules ---

func TestUpdateAllowlistTC_ICMPRule_WritesICMPPortEntry(t *testing.T) {
	fw, mocks := newTestFirewall()

	cm := config.NewConfigManager()
	err := cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "168.63.129.16/32", Ports: []config.Port{config.PortICMP}, Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	require.Len(t, mocks["cidrs"].updates, 1, "LPM entry for the /32 CIDR")
	lpmVal := mocks["cidrs"].updates[0].value.(*bpf.TcBpfLpmVal)
	assert.Equal(t, uint8(1), lpmVal.Action)
	assert.Equal(t, uint8(1), lpmVal.PortSpecific, "ICMP rule is port-specific (even though port=0)")

	require.Len(t, mocks["ports"].updates, 1, "port map entry for ICMP")
	pKey := mocks["ports"].updates[0].key.(*bpf.TcBpfPortKey)
	assert.Equal(t, uint16(0), pKey.Port)
	assert.Equal(t, protoICMP, pKey.Proto)
}

func TestUpdateAllowlistTC_IPv4Wildcard_ICMPOnly(t *testing.T) {
	fw, mocks := newTestFirewall()

	cm := config.NewConfigManager()
	err := cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []config.Port{config.PortICMP}, Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	assert.Empty(t, mocks["cidrs"].updates, "wildcard CIDR skips LPM entry")
	require.Len(t, mocks["ports"].updates, 1, "wildcard ICMP entry goes into port map with ip=0")
	pKey := mocks["ports"].updates[0].key.(*bpf.TcBpfPortKey)
	assert.Equal(t, uint32(0), pKey.Ip)
	assert.Equal(t, uint16(0), pKey.Port)
	assert.Equal(t, protoICMP, pKey.Proto)
}

// --- IPv6 ICMP filtering (hostname → v6 blackhole guard) ---

func TestAddIP_IPv6_ICMPOnly_SkipsWrites(t *testing.T) {
	fw, mocks := newTestFirewall()

	added, err := fw.AddIP(net.ParseIP("2001:db8::1"), config.ActionAllow, []config.Port{config.PortICMP})
	require.NoError(t, err)
	assert.False(t, added, "ICMP-only v6 rule should not produce a BPF write")
	assert.Empty(t, mocks["cidrsV6"].updates, "no v6 LPM entry for ICMP-only rule")
	assert.Empty(t, mocks["portsV6"].updates, "no v6 port-map entry for ICMP-only rule")
	_, tracked := fw.ipPorts["2001:db8::1"]
	assert.False(t, tracked, "ipPorts must not track an IP with no BPF state")
}

func TestAddIP_IPv6_MixedICMPAndTCP_DropsICMP(t *testing.T) {
	fw, mocks := newTestFirewall()

	added, err := fw.AddIP(net.ParseIP("2001:db8::1"), config.ActionAllow, []config.Port{
		config.PortICMP,
		{Port: 443, Protocol: config.ProtocolTCP},
	})
	require.NoError(t, err)
	assert.True(t, added)

	require.Len(t, mocks["cidrsV6"].updates, 1)
	lpmVal := mocks["cidrsV6"].updates[0].value.(*bpf.TcBpfLpmVal)
	assert.Equal(t, uint8(1), lpmVal.PortSpecific, "mixed rule stays port-specific after ICMP filter")

	require.Len(t, mocks["portsV6"].updates, 1, "only the TCP entry should be written")
	pKey := mocks["portsV6"].updates[0].key.(*bpf.TcBpfPortKeyV6)
	assert.Equal(t, uint16(443), pKey.Port)
	assert.Equal(t, protoTCP, pKey.Proto)
}

func TestUpdateAllowlistTC_HostnameResolvedToV6_ICMPOnly_NoV6Writes(t *testing.T) {
	fw, mocks := newTestFirewall()

	rules := []config.Rule{
		{Type: config.RuleTypeHostname, Value: "v6only.example", Ports: []config.Port{config.PortICMP}, Action: config.ActionAllow},
	}

	cm := config.NewConfigManager()
	err := cm.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	cm.UpdateDNSMapping("v6only.example", "2001:db8::1")

	err = cm.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	assert.Empty(t, mocks["cidrsV6"].updates, "ICMP-only hostname with v6 resolution must not write v6 LPM")
	assert.Empty(t, mocks["portsV6"].updates, "ICMP-only hostname with v6 resolution must not write v6 port map")
}

func TestUpdateAllowlistTC_HostnameResolvedToV6_MixedPorts_FiltersICMP(t *testing.T) {
	fw, mocks := newTestFirewall()

	rules := []config.Rule{
		{Type: config.RuleTypeHostname, Value: "mixed.example", Ports: []config.Port{
			config.PortICMP,
			{Port: 443, Protocol: config.ProtocolTCP},
		}, Action: config.ActionAllow},
	}

	cm := config.NewConfigManager()
	err := cm.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	cm.UpdateDNSMapping("mixed.example", "2001:db8::1")

	err = cm.LoadConfigFromRules(rules, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	require.Len(t, mocks["cidrsV6"].updates, 1)
	lpmVal := mocks["cidrsV6"].updates[0].value.(*bpf.TcBpfLpmVal)
	assert.Equal(t, uint8(1), lpmVal.PortSpecific)

	require.Len(t, mocks["portsV6"].updates, 1, "only the TCP entry should be written for v6")
	pKey := mocks["portsV6"].updates[0].key.(*bpf.TcBpfPortKeyV6)
	assert.Equal(t, uint16(443), pKey.Port)
	assert.Equal(t, protoTCP, pKey.Proto)
}

// --- issue #71: shared-IP all-ports + port-specific accounting ---

// contributor is one hostname rule resolving to a shared IP: a set of ports
// (nil = all-ports) added with config.ActionAllow.
type contributor struct {
	name  string
	ports []config.Port
}

// permutations returns every ordering of the indices [0, n).
func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var res [][]int
	for _, sub := range permutations(n - 1) {
		for i := 0; i <= len(sub); i++ {
			cp := make([]int, 0, len(sub)+1)
			cp = append(cp, sub[:i]...)
			cp = append(cp, n-1)
			cp = append(cp, sub[i:]...)
			res = append(res, cp)
		}
	}
	return res
}

func orderName(contribs []contributor, order []int) string {
	name := ""
	for i, idx := range order {
		if i > 0 {
			name += "→"
		}
		name += contribs[idx].name
	}
	return name
}

// Acceptance criterion 1: a shared IP allowed by {80/tcp, 443} (host A), []
// all-ports (host B) and [443] (host C), added in ANY order, allows TCP/80,
// TCP/443 and any other port afterward. The all-ports grant must win and be
// sticky regardless of when the narrowing port-specific rules arrive.
func TestAddIP_SharedIP_AllPortsWinsAnyOrder_V4(t *testing.T) {
	contribs := []contributor{
		{"A{80/tcp,443/all}", []config.Port{{Port: 80, Protocol: config.ProtocolTCP}, {Port: 443, Protocol: config.ProtocolAll}}},
		{"B{all-ports}", nil},
		{"C{443/tcp}", []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}},
	}
	ip := net.ParseIP("23.37.18.39")
	ipU := binary.NativeEndian.Uint32(ip.To4())

	for _, order := range permutations(len(contribs)) {
		t.Run(orderName(contribs, order), func(t *testing.T) {
			fw, mocks := newStatefulTestFirewall()
			for _, idx := range order {
				_, err := fw.AddIP(ip, config.ActionAllow, contribs[idx].ports)
				require.NoError(t, err)
			}

			lpm := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: ipU}].(bpf.TcBpfLpmVal)
			assert.Equal(t, uint8(0), lpm.PortSpecific, "all-ports grant must leave PortSpecific=0")
			assert.Equal(t, uint8(1), lpm.Action)

			// TCP/80, TCP/443 and an arbitrary other port are all allowed.
			for _, port := range []uint16{80, 443, 9999} {
				assert.Truef(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, port, protoTCP, false),
					"TCP/%d must be allowed", port)
			}
		})
	}
}

// IPv6 sibling of the all-ports-wins acceptance test.
func TestAddIP_SharedIP_AllPortsWinsAnyOrder_V6(t *testing.T) {
	contribs := []contributor{
		{"A{80/tcp,443/all}", []config.Port{{Port: 80, Protocol: config.ProtocolTCP}, {Port: 443, Protocol: config.ProtocolAll}}},
		{"B{all-ports}", nil},
		{"C{443/tcp}", []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}},
	}
	ip := net.ParseIP("2606:4700::1")
	var ipArr [16]byte
	copy(ipArr[:], ip.To16())

	for _, order := range permutations(len(contribs)) {
		t.Run(orderName(contribs, order), func(t *testing.T) {
			fw, mocks := newStatefulTestFirewall()
			for _, idx := range order {
				_, err := fw.AddIP(ip, config.ActionAllow, contribs[idx].ports)
				require.NoError(t, err)
			}

			lpm := mocks["cidrsV6"].store[bpf.TcBpfLpmKeyV6{Prefixlen: 128, Ip: ipArr}].(bpf.TcBpfLpmVal)
			assert.Equal(t, uint8(0), lpm.PortSpecific, "all-ports grant must leave PortSpecific=0")
			assert.Equal(t, uint8(1), lpm.Action)

			for _, port := range []uint16{80, 443, 9999} {
				assert.Truef(t, bpfDecideV6(mocks["cidrsV6"], mocks["portsV6"], ip, port, protoTCP, false),
					"TCP/%d must be allowed", port)
			}
		})
	}
}

// Acceptance criterion 2: a shared IP allowed only by [443] (host A) and
// [80/tcp] (host B), added in any order, allows TCP/80 AND TCP/443 — and stays
// port-specific, so an unrelated port is still denied (no accidental all-ports).
func TestAddIP_SharedIP_TwoPortSpecificUnionAnyOrder_V4(t *testing.T) {
	contribs := []contributor{
		{"A{443/tcp}", []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}},
		{"B{80/tcp}", []config.Port{{Port: 80, Protocol: config.ProtocolTCP}}},
	}
	ip := net.ParseIP("23.45.137.206")
	ipU := binary.NativeEndian.Uint32(ip.To4())

	for _, order := range permutations(len(contribs)) {
		t.Run(orderName(contribs, order), func(t *testing.T) {
			fw, mocks := newStatefulTestFirewall()
			for _, idx := range order {
				_, err := fw.AddIP(ip, config.ActionAllow, contribs[idx].ports)
				require.NoError(t, err)
			}

			lpm := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: ipU}].(bpf.TcBpfLpmVal)
			assert.Equal(t, uint8(1), lpm.PortSpecific, "no all-ports rule → stays port-specific")

			assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 80, protoTCP, false), "TCP/80 allowed")
			assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 443, protoTCP, false), "TCP/443 allowed")
			assert.False(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 9999, protoTCP, false), "other port denied")
		})
	}
}

// IPv6 sibling of the two-port-specific union acceptance test.
func TestAddIP_SharedIP_TwoPortSpecificUnionAnyOrder_V6(t *testing.T) {
	contribs := []contributor{
		{"A{443/tcp}", []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}},
		{"B{80/tcp}", []config.Port{{Port: 80, Protocol: config.ProtocolTCP}}},
	}
	ip := net.ParseIP("2001:db8:cafe::1")
	var ipArr [16]byte
	copy(ipArr[:], ip.To16())

	for _, order := range permutations(len(contribs)) {
		t.Run(orderName(contribs, order), func(t *testing.T) {
			fw, mocks := newStatefulTestFirewall()
			for _, idx := range order {
				_, err := fw.AddIP(ip, config.ActionAllow, contribs[idx].ports)
				require.NoError(t, err)
			}

			lpm := mocks["cidrsV6"].store[bpf.TcBpfLpmKeyV6{Prefixlen: 128, Ip: ipArr}].(bpf.TcBpfLpmVal)
			assert.Equal(t, uint8(1), lpm.PortSpecific, "no all-ports rule → stays port-specific")

			assert.True(t, bpfDecideV6(mocks["cidrsV6"], mocks["portsV6"], ip, 80, protoTCP, false), "TCP/80 allowed")
			assert.True(t, bpfDecideV6(mocks["cidrsV6"], mocks["portsV6"], ip, 443, protoTCP, false), "TCP/443 allowed")
			assert.False(t, bpfDecideV6(mocks["cidrsV6"], mocks["portsV6"], ip, 9999, protoTCP, false), "other port denied")
		})
	}
}

// A port-specific AddIP must not downgrade a PortSpecific=0 grant that already
// exists in BPF but was not written through this firewall instance (e.g. by
// UpdateAllowlistTC, which does not populate ipPorts). The fresh accumulator
// seeds its sticky flag from the existing LPM entry.
func TestAddIP_PortSpecific_DoesNotDowngradeSeededAllPortsLPM_V4(t *testing.T) {
	fw, mocks := newStatefulTestFirewall()
	ip := net.ParseIP("198.51.100.5")
	ipU := binary.NativeEndian.Uint32(ip.To4())

	// Pre-existing all-ports allow entry with no ipPorts tracking.
	mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: ipU}] = bpf.TcBpfLpmVal{Action: 1, PortSpecific: 0}

	_, err := fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)

	lpm := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: ipU}].(bpf.TcBpfLpmVal)
	assert.Equal(t, uint8(0), lpm.PortSpecific, "existing all-ports grant must not be downgraded")
	assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 9999, protoTCP, false), "any port still allowed")
}

// An all-ports deny is preserved as a deny-all LPM entry (PortSpecific=0,
// action=deny), even under a default-allow policy — guards against the
// recompute accidentally turning an empty-ports deny into "consult map_ports".
func TestAddIP_AllPortsDeny_BlocksAll_V4(t *testing.T) {
	fw, mocks := newStatefulTestFirewall()
	ip := net.ParseIP("203.0.113.66")
	ipU := binary.NativeEndian.Uint32(ip.To4())

	_, err := fw.AddIP(ip, config.ActionDeny, nil)
	require.NoError(t, err)

	lpm := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: ipU}].(bpf.TcBpfLpmVal)
	assert.Equal(t, uint8(0), lpm.PortSpecific)
	assert.Equal(t, uint8(0), lpm.Action)
	// Even with a default-allow policy the IP is blocked on every port.
	assert.False(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 443, protoTCP, true))
}

// On a shared IP, an all-ports DENY wins over an all-ports ALLOW regardless of
// add order: a host the policy denies outright is not re-opened by an unrelated
// hostname sharing the address.
func TestAddIP_AllPortsDeny_WinsOverAllPortsAllow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order []config.Action
	}{
		{"allow_then_deny", []config.Action{config.ActionAllow, config.ActionDeny}},
		{"deny_then_allow", []config.Action{config.ActionDeny, config.ActionAllow}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw, mocks := newStatefulTestFirewall()
			ip := net.ParseIP("203.0.113.77")
			ipU := binary.NativeEndian.Uint32(ip.To4())
			for _, action := range tc.order {
				_, err := fw.AddIP(ip, action, nil)
				require.NoError(t, err)
			}
			lpm := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: ipU}].(bpf.TcBpfLpmVal)
			assert.Equal(t, uint8(0), lpm.Action, "deny must win")
			assert.Equal(t, uint8(0), lpm.PortSpecific)
			assert.False(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 443, protoTCP, true))
		})
	}
}

// Documents the issue #71 allow-priority tradeoff: a port-specific DENY on an IP
// that already carries a sticky all-ports ALLOW is inert (the BPF model can't
// express "allow all except port N"). The deny is write-skipped, not tracked,
// and the port stays allowed; the inert intent is surfaced via a Warn log.
func TestAddIP_PortSpecificDeny_InertUnderAllPortsAllow_V4(t *testing.T) {
	fw, mocks := newStatefulTestFirewall()
	ip := net.ParseIP("23.37.18.39")

	_, err := fw.AddIP(ip, config.ActionAllow, nil) // all-ports allow (e.g. OCSP host)
	require.NoError(t, err)

	changed, err := fw.AddIP(ip, config.ActionDeny, []config.Port{{Port: 8080, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	assert.False(t, changed, "inert port-specific deny must report no observable change")

	// The deny is neither written to map_ports nor tracked in the union.
	_, denyWritten := mocks["ports"].store[bpf.TcBpfPortKey{Ip: binary.NativeEndian.Uint32(ip.To4()), Port: 8080, Proto: protoTCP}]
	assert.False(t, denyWritten, "inert per-port entry must not be written")
	assert.Empty(t, fw.ipPorts[ip.String()].ports, "inert ports must not be tracked")

	// 8080 stays allowed (all-ports allow wins) — issue #71 priority preserved.
	assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], ip, 8080, protoTCP, false))
}

// The fix must cover the config-load write path too: UpdateAllowlistTC and AddIP
// share the per-IP accumulator, so an all-ports rule loaded from config and a
// port-specific rule resolved at runtime (in either order) for the same IP leave
// the IP all-ports — not narrowed to the port-specific set (issue #71, altitude).
func TestSharedIP_UpdateAllowlistTC_AndAddIP_Unified_V4(t *testing.T) {
	ip := "23.37.18.39"

	t.Run("config_all_ports_then_runtime_port_specific", func(t *testing.T) {
		fw, mocks := newStatefulTestFirewall()
		cm := config.NewConfigManager()
		rules := []config.Rule{{Type: config.RuleTypeHostname, Value: "ocsp.example", Action: config.ActionAllow}} // all-ports
		require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionDeny))
		cm.UpdateDNSMapping("ocsp.example", ip)
		require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionDeny))
		require.NoError(t, fw.UpdateAllowlistTC(cm)) // config-load writes all-ports /32

		// Runtime DNS resolution of a different, port-specific hostname → same IP.
		_, err := fw.AddIP(net.ParseIP(ip), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
		require.NoError(t, err)

		lpm := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: binary.NativeEndian.Uint32(net.ParseIP(ip).To4())}].(bpf.TcBpfLpmVal)
		assert.Equal(t, uint8(0), lpm.PortSpecific, "config all-ports grant must not be narrowed by a runtime port-specific add")
		assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], net.ParseIP(ip), 9999, protoTCP, false), "any port still allowed")
	})

	t.Run("runtime_port_specific_then_config_all_ports", func(t *testing.T) {
		fw, mocks := newStatefulTestFirewall()
		_, err := fw.AddIP(net.ParseIP(ip), config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
		require.NoError(t, err)

		cm := config.NewConfigManager()
		rules := []config.Rule{{Type: config.RuleTypeHostname, Value: "ocsp.example", Action: config.ActionAllow}} // all-ports
		require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionDeny))
		cm.UpdateDNSMapping("ocsp.example", ip)
		require.NoError(t, cm.LoadConfigFromRules(rules, config.ActionDeny))
		require.NoError(t, fw.UpdateAllowlistTC(cm)) // config all-ports over a runtime port-specific IP

		lpm := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: binary.NativeEndian.Uint32(net.ParseIP(ip).To4())}].(bpf.TcBpfLpmVal)
		assert.Equal(t, uint8(0), lpm.PortSpecific, "config all-ports grant must broaden the runtime port-specific entry")
		assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], net.ParseIP(ip), 9999, protoTCP, false), "any port allowed")
	})
}

// Acceptance criterion 3: RemoveIP removes the whole IP and the full union of
// its port entries (no leak), and leaves an unrelated IP's contributors intact.
func TestRemoveIP_CleansFullUnion_LeavesOtherIPsIntact_V4(t *testing.T) {
	fw, mocks := newStatefulTestFirewall()
	x := net.ParseIP("203.0.113.10")
	y := net.ParseIP("203.0.113.20")
	xU := binary.NativeEndian.Uint32(x.To4())

	// X accumulates several contributors' ports.
	_, err := fw.AddIP(x, config.ActionAllow, []config.Port{{Port: 80, Protocol: config.ProtocolTCP}, {Port: 443, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	_, err = fw.AddIP(x, config.ActionAllow, []config.Port{{Port: 8080, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)

	// Y is an independent shared IP.
	_, err = fw.AddIP(y, config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)

	require.NoError(t, fw.RemoveIP(x))

	// X is gone from tracking, the LPM trie and the port map (full union).
	_, exists := fw.ipPorts[x.String()]
	assert.False(t, exists, "removed IP must be dropped from tracking")
	_, lpmExists := mocks["cidrs"].store[bpf.TcBpfLpmKey{Prefixlen: 32, Ip: xU}]
	assert.False(t, lpmExists, "removed IP must be gone from the LPM trie")
	for k := range mocks["ports"].store {
		assert.NotEqual(t, xU, k.(bpf.TcBpfPortKey).Ip, "no port entry for the removed IP may remain")
	}
	assert.False(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], x, 80, protoTCP, false))

	// Y is untouched.
	require.NotNil(t, fw.ipPorts[y.String()])
	assert.Equal(t, []portProto{{Port: 443, Proto: protoTCP}}, fw.ipPorts[y.String()].ports)
	assert.True(t, bpfDecideV4(mocks["cidrs"], mocks["ports"], y, 443, protoTCP, false), "unrelated IP stays allowed")
}

// Guards the package-local permutations helper used by the order-independence
// tests: n! orderings, each a permutation of [0, n).
func TestPermutationsHelper(t *testing.T) {
	got := permutations(3)
	require.Len(t, got, 6)
	seen := make(map[string]bool, len(got))
	for _, p := range got {
		require.Len(t, p, 3)
		sum := 0
		for _, v := range p {
			sum += v
		}
		assert.Equal(t, 3, sum, "each permutation contains 0,1,2 exactly once")
		seen[fmt.Sprint(p)] = true
	}
	assert.Len(t, seen, 6, "all permutations distinct")
}
