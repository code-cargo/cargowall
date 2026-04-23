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
	"log/slog"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// mockMap records Update/Delete calls and delegates Lookup to a configurable function.
type mockMap struct {
	updates  []mockUpdate
	deletes  []any
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

func (m *mockMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	m.updates = append(m.updates, mockUpdate{key: key, value: value, flags: flags})
	return nil
}

func (m *mockMap) Lookup(key, valueOut any) error {
	return m.lookupFn(key, valueOut)
}

func (m *mockMap) Delete(key any) error {
	m.deletes = append(m.deletes, key)
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
		ipPorts:          make(map[string][]portProto),
	}
	return fw, mocks
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
	assert.Equal(t, []portProto{{Port: 8080, Proto: 6}}, fw.ipPorts[ip.String()])
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
	assert.Equal(t, []portProto{{Port: 8080, Proto: 6}}, fw.ipPorts[ip.String()])
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
	fw.ipPorts[ip.String()] = []portProto{{Port: 443, Proto: 6}}

	changed, err := fw.AddIP(ip, config.ActionAllow, []config.Port{{Port: 443, Protocol: config.ProtocolTCP}})
	require.NoError(t, err)
	assert.False(t, changed, "true duplicate with matching state must report no change")
	assert.Equal(t, []portProto{{Port: 443, Proto: 6}}, fw.ipPorts[ip.String()], "ipPorts unchanged")
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
	assert.Equal(t, []portProto{{Port: 443, Proto: 6}}, fw.ipPorts[ip.String()])

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
		fw.ipPorts[ip.String()],
		"ipPorts must accumulate disjoint port sets across calls")
}

// Transitioning an IP from PortSpecific=1 to PortSpecific=0 (i.e. AddIP with
// nil ports after AddIP with some ports) must delete the previously-written
// per-port entries from map_ports. Pre-fix they were silently orphaned: the
// LPM's new PortSpecific=0 made them inert, but the entries themselves stayed
// in the map and ipPorts was dropped — so RemoveIP could never find them.
func TestAddIP_TransitionToAllPorts_DeletesStalePortEntries(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")
	ipUint32 := binary.NativeEndian.Uint32(ip.To4())

	// First call: add (ip, allow, [443, 8080]) with no existing LPM entry.
	_, err := fw.AddIP(ip, config.ActionAllow, []config.Port{
		{Port: 443, Protocol: config.ProtocolTCP},
		{Port: 8080, Protocol: config.ProtocolTCP},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []portProto{{Port: 443, Proto: 6}, {Port: 8080, Proto: 6}}, fw.ipPorts[ip.String()])

	// Second call: transition to all-ports. Configure the LPM lookup to return
	// the previous (Action=allow, PortSpecific=1) entry.
	mocks["cidrs"].lookupFn = func(_, valueOut any) error {
		v := valueOut.(*bpf.TcBpfLpmVal)
		v.Action = 1
		v.PortSpecific = 1
		return nil
	}

	changed, err := fw.AddIP(ip, config.ActionAllow, nil)
	require.NoError(t, err)
	assert.True(t, changed, "PortSpecific 1→0 LPM change must be reported")

	// portsMap.Delete must have been called for each previously-tracked entry.
	require.Len(t, mocks["ports"].deletes, 2, "stale per-port entries must be deleted from map_ports")
	deletedKeys := make(map[uint16]uint8, 2)
	for _, k := range mocks["ports"].deletes {
		pk := k.(*bpf.TcBpfPortKey)
		assert.Equal(t, ipUint32, pk.Ip)
		deletedKeys[pk.Port] = pk.Proto
	}
	assert.Equal(t, uint8(6), deletedKeys[443])
	assert.Equal(t, uint8(6), deletedKeys[8080])

	// ipPorts dropped — the IP is now PortSpecific=0 and has no per-port state.
	_, exists := fw.ipPorts[ip.String()]
	assert.False(t, exists, "ipPorts entry must be removed after PortSpecific=0 transition")
}

func TestAddIP_SameIPDifferentAction(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")
	ip4 := ip.To4()
	ipUint32 := binary.NativeEndian.Uint32(ip4)

	// Existing entry has Action=deny (0), we'll add with ActionAllow
	mocks["cidrs"].lookupFn = func(key, valueOut any) error {
		k := key.(*bpf.TcBpfLpmKey)
		if k.Ip == ipUint32 {
			v := valueOut.(*bpf.TcBpfLpmVal)
			v.Action = 0 // ActionDeny
			v.PortSpecific = 0
			return nil
		}
		return ebpf.ErrKeyNotExist
	}

	added, err := fw.AddIP(ip, config.ActionAllow, nil)
	require.NoError(t, err)
	assert.True(t, added, "same IP with different action should be re-added")
	assert.Len(t, mocks["cidrs"].updates, 1, "cidrsMap.Update should be called")
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
	assert.Equal(t, []portProto{{Port: 80, Proto: 6}, {Port: 443, Proto: 6}}, fw.ipPorts[ip.String()])
}

func TestAddIP_WithoutPorts_CleansUpIPPorts(t *testing.T) {
	fw, _ := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")

	// Pre-populate ipPorts as if a previous call added ports
	fw.ipPorts[ip.String()] = []portProto{{Port: 80, Proto: 6}}

	added, err := fw.AddIP(ip, config.ActionAllow, nil)
	require.NoError(t, err)
	assert.True(t, added)
	_, exists := fw.ipPorts[ip.String()]
	assert.False(t, exists, "ipPorts entry should be removed when no ports specified")
}

func TestRemoveIP_WithTrackedPorts(t *testing.T) {
	fw, mocks := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")

	// Pre-populate ipPorts
	fw.ipPorts[ip.String()] = []portProto{{Port: 80, Proto: 6}, {Port: 443, Proto: 6}}

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
