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
		ipPorts:          make(map[string][]uint16),
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
	ports := []uint16{80, 443}

	added, err := fw.AddIP(ip, config.ActionAllow, ports)
	require.NoError(t, err)
	assert.True(t, added)
	assert.Equal(t, ports, fw.ipPorts[ip.String()])
}

func TestAddIP_WithoutPorts_CleansUpIPPorts(t *testing.T) {
	fw, _ := newTestFirewall()
	ip := net.ParseIP("10.0.0.1")

	// Pre-populate ipPorts as if a previous call added ports
	fw.ipPorts[ip.String()] = []uint16{80}

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
	fw.ipPorts[ip.String()] = []uint16{80, 443}

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
		{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []uint16{80, 443}, Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	assert.Len(t, mocks["ports"].updates, 2, "should update portsMap for each port")
	assert.Empty(t, mocks["cidrs"].updates, "should NOT update cidrsMap for wildcard with ports")
}

func TestUpdateAllowlistTC_IPv6Wildcard_OnlyPortsV6Map(t *testing.T) {
	fw, mocks := newTestFirewall()

	cm := config.NewConfigManager()
	err := cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeCIDR, Value: "::/0", Ports: []uint16{53}, Action: config.ActionAllow},
	}, config.ActionDeny)
	require.NoError(t, err)

	err = fw.UpdateAllowlistTC(cm)
	require.NoError(t, err)

	assert.Len(t, mocks["portsV6"].updates, 1, "should update portsV6Map for each port")
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
		{Type: config.RuleTypeHostname, Value: "example.com", Ports: []uint16{443}, Action: config.ActionAllow},
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

	// Each resolved IP gets a cidrsMap entry + a portsMap entry (one port per IP)
	assert.Len(t, mocks["cidrs"].updates, 2, "should add /32 LPM entry per resolved IP")
	assert.Len(t, mocks["ports"].updates, 2, "should add port entry per resolved IP")
}
