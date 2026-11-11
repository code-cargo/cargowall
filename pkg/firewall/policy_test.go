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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	rand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// cappedMap is a stateful mock map with a kernel map's capacity: an update
// that would add a key past it fails, as the kernel's does.
type cappedMap struct {
	*mockMap
	capacity int
}

func (m *cappedMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	if _, held := m.store[deref(key)]; !held && len(m.store) >= m.capacity {
		return fmt.Errorf("update: %w", unix.E2BIG)
	}
	return m.mockMap.Update(key, value, flags)
}

// stepTestMaps are a firewall's four rule maps, in ruleMap order.
type stepTestMaps [numRuleMaps]*cappedMap

func newStepTestFirewall(capacity int, logger *slog.Logger) (*FirewallImpl, stepTestMaps) {
	var maps stepTestMaps
	for i := range maps {
		maps[i] = &cappedMap{mockMap: newStatefulMockMap(), capacity: capacity}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	fw := &FirewallImpl{
		cidrsMap:         maps[ruleMapCIDRs],
		portsMap:         maps[ruleMapPorts],
		cidrsV6Map:       maps[ruleMapCIDRsV6],
		portsV6Map:       maps[ruleMapPortsV6],
		defaultActionMap: newStatefulMockMap(),
		auditModeMap:     newStatefulMockMap(),
		logger:           logger,
		ipPorts:          make(map[string]*ipPortState),
	}
	fw.steps.setBudget(capacity - jobReservedEntries)
	return fw, maps
}

// keyPolicy returns the policy a rule-map key belongs to.
func keyPolicy(t *testing.T, key any) uint32 {
	t.Helper()
	switch k := key.(type) {
	case bpf.TcBpfRuleKey:
		return k.Policy
	case bpf.TcBpfRuleKeyV6:
		return k.Policy
	case bpf.TcBpfRulePortKey:
		return k.Policy
	case bpf.TcBpfRulePortKeyV6:
		return k.Policy
	}
	t.Fatalf("not a rule-map key: %T", key)
	return 0
}

// entriesOf returns a map's entries under policy.
func entriesOf(t *testing.T, m *cappedMap, policy uint32) map[any]any {
	t.Helper()
	out := map[any]any{}
	for k, v := range m.store {
		if keyPolicy(t, k) == policy {
			out[k] = v
		}
	}
	return out
}

// stepEntries counts the entries step policies hold in a map.
func stepEntries(t *testing.T, m *cappedMap) int {
	t.Helper()
	n := 0
	for k := range m.store {
		if keyPolicy(t, k) != bpf.PolicyJob {
			n++
		}
	}
	return n
}

func storeSizes(maps stepTestMaps) (out [numRuleMaps]int) {
	for i, m := range maps {
		out[i] = len(m.store)
	}
	return out
}

// testIPv4 and testIPv6 return the i-th address of disjoint test pools.
func testIPv4(base byte, i int) net.IP {
	return net.IPv4(base, byte(i>>16), byte(i>>8), byte(i)).To4()
}

func testIPv6(base byte, i int) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, net.ParseIP("2001:db8::"))
	ip[6] = base
	binary.BigEndian.PutUint32(ip[12:], uint32(i))
	return ip
}

var tcp443 = []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}

// ruleMapEntries is the rule maps' size for a policy with steps.
const ruleMapEntries = int(bpf.RuleMapEntries)

// The split is sized against the maps the BPF objects declare, SizeRuleMaps
// sizes them for a policy without steps or with, and every step policy fits
// a bridge stamp.
func TestRuleMapSizes(t *testing.T) {
	spec, err := bpf.LoadTcBpf()
	require.NoError(t, err)
	for m := range numRuleMaps {
		ms := spec.Maps[m.String()]
		require.NotNil(t, ms, m.String())
		assert.Equal(t, uint32(ruleMapEntries), ms.MaxEntries, "%s: verdict.h declares the size with steps", m)
	}
	assert.Equal(t, ruleMapEntries, jobReservedEntries+stepEntryBudget)
	assert.Equal(t, int(bpf.RuleMapEntriesJobOnly), jobReservedEntries)
	assert.Equal(t, bpf.StepStampPolicyMax, uint32(config.MaxStepPolicies))

	for _, c := range []struct {
		steps bool
		want  uint32
	}{{false, bpf.RuleMapEntriesJobOnly}, {true, bpf.RuleMapEntries}, {false, bpf.RuleMapEntriesJobOnly}} {
		require.NoError(t, bpf.SizeRuleMaps(spec, c.steps))
		for m := range numRuleMaps {
			assert.Equal(t, c.want, spec.Maps[m.String()].MaxEntries, "%s, steps %v", m, c.steps)
		}
	}
	delete(spec.Maps, "map_ports_v6")
	require.Error(t, bpf.SizeRuleMaps(spec, true), "a stale spec is an error, not a skip")
}

func TestAddPolicyIP_RefusesTheJobsPolicy(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	_, err := fw.AddPolicyIP(bpf.PolicyJob, net.ParseIP("93.184.216.34"), nil, nil)
	require.Error(t, err)
	_, err = fw.AddPolicyIP(bpf.PolicyJob, net.ParseIP("2606:2800:220:1::1"), tcp443, nil)
	require.Error(t, err)
	assert.Equal(t, [numRuleMaps]int{}, storeSizes(maps))
}

// A step write lands under its policy alone, as an allow.
func TestAddPolicyIP_WritesItsPolicyAlone(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)

	v4 := net.ParseIP("93.184.216.34")
	changed, err := fw.AddPolicyIP(3, v4, tcp443, nil)
	require.NoError(t, err)
	assert.True(t, changed)
	ip := binary.NativeEndian.Uint32(v4.To4())
	assert.Equal(t, map[any]any{bpf.RuleKey(3, 32, ip): bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1}}, entriesOf(t, maps[ruleMapCIDRs], 3))
	assert.Equal(t, map[any]any{bpf.RulePortKey(3, ip, 443, protoTCP, 0): bpf.TcBpfPortVal{Action: 1}}, entriesOf(t, maps[ruleMapPorts], 3))

	changed, err = fw.AddPolicyIP(3, v4, tcp443, nil)
	require.NoError(t, err)
	assert.False(t, changed, "a repeat changes nothing")

	v6 := net.ParseIP("2606:2800:220:1::1")
	_, err = fw.AddPolicyIP(7, v6, nil, nil)
	require.NoError(t, err)
	var ip16 [16]byte
	copy(ip16[:], v6.To16())
	assert.Equal(t, map[any]any{bpf.RuleKeyV6(7, 128, ip16): bpf.TcBpfLpmVal{Action: 1}}, entriesOf(t, maps[ruleMapCIDRsV6], 7))

	for m := range numRuleMaps {
		assert.Empty(t, entriesOf(t, maps[m], bpf.PolicyJob), "%s: a step write reached the job's policy", m)
	}

	// ICMP-only on IPv6 writes nothing (ICMPv6 is always allowed), and
	// charges nothing.
	_, err = fw.AddPolicyIP(7, net.ParseIP("2606:2800:220:1::2"), []config.Port{config.PortICMP}, nil)
	require.NoError(t, err)
	assert.Len(t, maps[ruleMapCIDRsV6].store, 1)
	assert.Equal(t, 1, fw.steps.used(ruleMapCIDRsV6))
}

// Each (policy, IP) accumulates on its own: one policy's all-ports grant
// neither widens nor narrows another's entry for the same IP.
func TestAddPolicyIP_AccumulatorsArePerPolicy(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	v4 := net.ParseIP("93.184.216.34")
	ip := binary.NativeEndian.Uint32(v4.To4())
	lpm := func(policy uint32) any { return maps[ruleMapCIDRs].store[bpf.RuleKey(policy, 32, ip)] }

	_, err := fw.AddIP(v4, config.ActionDeny, nil)
	require.NoError(t, err)
	_, err = fw.AddPolicyIP(3, v4, tcp443, nil)
	require.NoError(t, err)
	_, err = fw.AddPolicyIP(4, v4, nil, nil)
	require.NoError(t, err)
	_, err = fw.AddPolicyIP(3, v4, []config.Port{{Port: 80, Protocol: config.ProtocolTCP}}, nil)
	require.NoError(t, err)
	_, err = fw.AddIP(v4, config.ActionAllow, tcp443)
	require.NoError(t, err)

	assert.Equal(t, bpf.TcBpfLpmVal{Action: 0}, lpm(bpf.PolicyJob), "the job's all-ports deny stays")
	assert.Equal(t, bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1}, lpm(3), "the job's deny doesn't make policy 3 all-ports")
	assert.Equal(t, bpf.TcBpfLpmVal{Action: 1}, lpm(4))
	assert.Len(t, entriesOf(t, maps[ruleMapPorts], 3), 2, "policy 3 unions its ports")
	assert.Len(t, entriesOf(t, maps[ruleMapPorts], 4), 0)

	// And the other way: a step's all-ports grant doesn't stick to the job.
	w := net.ParseIP("93.184.216.35")
	wip := binary.NativeEndian.Uint32(w.To4())
	_, err = fw.AddPolicyIP(3, w, nil, nil)
	require.NoError(t, err)
	_, err = fw.AddIP(w, config.ActionAllow, tcp443)
	require.NoError(t, err)
	assert.Equal(t, bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1}, maps[ruleMapCIDRs].store[bpf.RuleKey(bpf.PolicyJob, 32, wip)])
}

// UpdateAllowlistTC writes each step's CIDR rules under its policy, gated
// on the job's CIDR denies and with those inside them carved out, and the
// job's entries come out exactly as they do with no steps.
func TestUpdateAllowlistTC_StepRules(t *testing.T) {
	jobRules := []config.Rule{
		{Type: config.RuleTypeCIDR, Value: "10.0.0.0/8", Ports: []config.Port{{Port: 22, Protocol: config.ProtocolTCP}}, Action: config.ActionDeny},
		{Type: config.RuleTypeCIDR, Value: "172.16.5.0/24", Action: config.ActionDeny},
		{Type: config.RuleTypeCIDR, Value: "8.8.8.8/32", Ports: []config.Port{config.PortDNS}, Action: config.ActionAllow},
		{Type: config.RuleTypeCIDR, Value: "2001:db8:1::/48", Action: config.ActionAllow},
		{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []config.Port{{Port: 123, Protocol: config.ProtocolUDP}}, Action: config.ActionAllow},
	}
	steps := []config.StepConfig{
		{ID: "a", Rules: []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "192.168.10.0/24", Ports: tcp443},
			{Type: config.RuleTypeCIDR, Value: "10.1.2.3"}, // inside the job's 10/8 deny on 22, on all ports: withheld
			{Type: config.RuleTypeCIDR, Value: "10.1.2.4", Ports: []config.Port{{Port: 22, Protocol: config.ProtocolTCP}, {Port: 443, Protocol: config.ProtocolTCP}}},
			{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0", Ports: []config.Port{{Port: 9000, Protocol: config.ProtocolTCP}}},
			{Type: config.RuleTypeCIDR, Value: "172.16.0.0/12"},
			{Type: config.RuleTypeCIDR, Value: "10.0.0.0/7", Ports: []config.Port{{Port: 22, Protocol: config.ProtocolTCP}, {Port: 443, Protocol: config.ProtocolTCP}}},
			{Type: config.RuleTypeHostname, Value: "step.example.com"},
		}},
		{ID: "b", Rules: []config.Rule{
			{Type: config.RuleTypeCIDR, Value: "2001:db8:5::/48", Ports: tcp443},
			{Type: config.RuleTypeCIDR, Value: "::/0", Ports: []config.Port{{Port: 9001, Protocol: config.ProtocolTCP}}},
			{Type: config.RuleTypeCIDR, Value: "0.0.0.0/0"},
		}},
	}
	sync := func(steps []config.StepConfig) stepTestMaps {
		cm := config.NewConfigManager()
		require.NoError(t, cm.LoadConfig(writeStepConfig(t, jobRules, steps)))
		fw, maps := newStepTestFirewall(ruleMapEntries, nil)
		require.NoError(t, fw.UpdateAllowlistTC(cm))
		return maps
	}
	without, with := sync(nil), sync(steps)
	for m := range numRuleMaps {
		assert.Equal(t, entriesOf(t, without[m], bpf.PolicyJob), entriesOf(t, with[m], bpf.PolicyJob), "%s: the job's entries changed", m)
	}

	net4 := func(s string) uint32 { return binary.NativeEndian.Uint32(net.ParseIP(s).To4()) }
	net6 := func(s string) (out [16]byte) { copy(out[:], net.ParseIP(s).To16()); return out }
	portAllow := bpf.TcBpfPortVal{Action: 1}

	carved := func(bits uint8) bpf.TcBpfLpmVal { return bpf.TcBpfLpmVal{Action: 0, HostBits: bits} }
	portDeny := bpf.TcBpfPortVal{Action: 0}
	assert.Equal(t, map[any]any{
		bpf.RuleKey(1, 24, net4("192.168.10.0")): bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1, HostBits: 8},
		bpf.RuleKey(1, 32, net4("10.1.2.4")):     bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1},
		bpf.RuleKey(1, 12, net4("172.16.0.0")):   bpf.TcBpfLpmVal{Action: 1, HostBits: 20},
		bpf.RuleKey(1, 7, net4("10.0.0.0")):      bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1, HostBits: 25},
		// The job's 10/8 deny on 22, inside the wildcard and the /7: carved,
		// denying 22 and allowing the /7's 443, while the wildcard's 9000
		// reaches through a miss.
		bpf.RuleKey(1, 8, net4("10.0.0.0")): bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1, HostBits: 24},
		// The job's 172.16.5.0/24 deny on all ports: carved whole.
		bpf.RuleKey(1, 24, net4("172.16.5.0")): carved(8),
	}, entriesOf(t, with[ruleMapCIDRs], 1))
	assert.Equal(t, map[any]any{
		bpf.RulePortKey(1, net4("192.168.10.0"), 443, protoTCP, 8): portAllow,
		bpf.RulePortKey(1, net4("10.1.2.4"), 443, protoTCP, 0):     portAllow,
		bpf.RulePortKey(1, net4("10.1.2.4"), 22, protoTCP, 0):      portDeny, // trimmed: the job denies 22 there
		bpf.RulePortKey(1, 0, 9000, protoTCP, 0):                   portAllow,
		bpf.RulePortKey(1, net4("10.0.0.0"), 22, protoTCP, 25):     portAllow, // the /7's own
		bpf.RulePortKey(1, net4("10.0.0.0"), 443, protoTCP, 25):    portAllow,
		bpf.RulePortKey(1, net4("10.0.0.0"), 22, protoTCP, 24):     portDeny,
		bpf.RulePortKey(1, net4("10.0.0.0"), 443, protoTCP, 24):    portAllow,
	}, entriesOf(t, with[ruleMapPorts], 1))
	assert.Equal(t, map[any]any{
		bpf.RuleKey(2, 0, 0): bpf.TcBpfLpmVal{Action: 1, HostBits: 32},
		// Inside step b's 0.0.0.0/0 on all ports: the 10/8 deny on 22 carved
		// on 22 (the /0 keeps nothing inside it: no entry can say all ports
		// but 22), the 172.16.5.0/24 deny on all ports carved whole.
		bpf.RuleKey(2, 8, net4("10.0.0.0")):    bpf.TcBpfLpmVal{Action: 0, PortSpecific: 1, HostBits: 24},
		bpf.RuleKey(2, 24, net4("172.16.5.0")): carved(8),
	}, entriesOf(t, with[ruleMapCIDRs], 2))
	assert.Equal(t, map[any]any{
		bpf.RulePortKey(2, net4("10.0.0.0"), 22, protoTCP, 24): portDeny,
	}, entriesOf(t, with[ruleMapPorts], 2))
	assert.Equal(t, map[any]any{
		bpf.RuleKeyV6(2, 48, net6("2001:db8:5::")): bpf.TcBpfLpmVal{Action: 1, PortSpecific: 1, HostBits: 80},
	}, entriesOf(t, with[ruleMapCIDRsV6], 2))
	assert.Equal(t, map[any]any{
		bpf.RulePortKeyV6(2, net6("2001:db8:5::"), 443, protoTCP, 80): portAllow,
		bpf.RulePortKeyV6(2, [16]byte{}, 9001, protoTCP, 0):           portAllow,
	}, entriesOf(t, with[ruleMapPortsV6], 2))
}

// writeStepConfig writes a JSON policy with job rules and steps, for
// LoadConfig, the loader that takes steps.
func writeStepConfig(t *testing.T, rules []config.Rule, steps []config.StepConfig) string {
	t.Helper()
	cfg := config.FirewallConfig{DefaultAction: config.ActionDeny, Rules: rules, Steps: steps}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// fillCase fills one map's step budget and then the job's reservation.
type fillCase struct {
	m ruleMap
	// add installs the i-th destination of a pool, under policy (0 for the job).
	add func(fw *FirewallImpl, policy uint32, pool byte, i int) error
	// per is how many entries of m one add takes.
	per int
}

func fillCases() []fillCase {
	ports4 := []config.Port{
		{Port: 1, Protocol: config.ProtocolTCP},
		{Port: 2, Protocol: config.ProtocolTCP},
		{Port: 3, Protocol: config.ProtocolTCP},
		{Port: 4, Protocol: config.ProtocolTCP},
	}
	add := func(ip func(byte, int) net.IP, ports []config.Port) func(*FirewallImpl, uint32, byte, int) error {
		return func(fw *FirewallImpl, policy uint32, pool byte, i int) error {
			if policy == bpf.PolicyJob {
				_, err := fw.AddIP(ip(pool, i), config.ActionAllow, ports)
				return err
			}
			_, err := fw.AddPolicyIP(policy, ip(pool, i), ports, nil)
			return err
		}
	}
	return []fillCase{
		{ruleMapCIDRs, add(testIPv4, nil), 1},
		{ruleMapPorts, add(testIPv4, ports4), 4},
		{ruleMapCIDRsV6, add(testIPv6, nil), 1},
		{ruleMapPortsV6, add(testIPv6, ports4), 4},
	}
}

// Step installs can never reduce what the job can install: fill the steps'
// share of each map, across several policies, then show a step write past it
// is refused and installs nothing, and the job's whole reservation still
// lands. The mock maps hold exactly ruleMapEntries, as the kernel's do.
func TestStepBudget_FillThenJobInstallLands(t *testing.T) {
	for _, c := range fillCases() {
		t.Run(c.m.String(), func(t *testing.T) {
			fw, maps := newStepTestFirewall(ruleMapEntries, nil)
			adds := stepEntryBudget / c.per
			for i := range adds {
				require.NoError(t, c.add(fw, uint32(1+i%3), 10, i), "step add %d", i)
			}
			require.Equal(t, stepEntryBudget, stepEntries(t, maps[c.m]))
			require.Equal(t, stepEntryBudget, fw.steps.used(c.m))

			before := storeSizes(maps)
			err := c.add(fw, 2, 10, adds)
			require.ErrorIs(t, err, ErrStepBudget)
			assert.Equal(t, before, storeSizes(maps), "a refused step write installs nothing, in any map")

			// Rewriting what a step already holds costs nothing.
			require.NoError(t, c.add(fw, uint32(1+(adds-1)%3), 10, adds-1))

			for i := range jobReservedEntries / c.per {
				require.NoError(t, c.add(fw, bpf.PolicyJob, 20, i), "job add %d", i)
			}
			assert.Len(t, maps[c.m].store, ruleMapEntries)
			assert.Len(t, entriesOf(t, maps[c.m], bpf.PolicyJob), jobReservedEntries)
		})
	}
}

// Without the reservation the same fill would leave the job no room: the
// steps alone can't fill a map, so this pins that the capacity, not the
// test, is what the job's installs would hit.
func TestStepBudget_JobBeyondItsReservationHitsTheMap(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	for i := range stepEntryBudget {
		_, err := fw.AddPolicyIP(1, testIPv4(10, i), nil, nil)
		require.NoError(t, err)
	}
	for i := range jobReservedEntries {
		_, err := fw.AddIP(testIPv4(20, i), config.ActionAllow, nil)
		require.NoError(t, err)
	}
	_, err := fw.AddIP(testIPv4(20, jobReservedEntries), config.ActionAllow, nil)
	require.ErrorIs(t, err, unix.E2BIG)
	assert.Len(t, maps[ruleMapCIDRs].store, ruleMapEntries)
}

// A step write is admitted whole or not at all: an add whose LPM entry
// fits but whose port entries don't installs neither, and a new port on an
// installed IP is refused without touching its other entries.
func TestStepBudget_AllOrNothing(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	fw.steps.setBudget(3)
	two := []config.Port{{Port: 80, Protocol: config.ProtocolTCP}, {Port: 443, Protocol: config.ProtocolTCP}}

	_, err := fw.AddPolicyIP(1, testIPv4(10, 1), two, nil)
	require.NoError(t, err)
	_, err = fw.AddPolicyIP(1, testIPv4(10, 2), two, nil)
	require.ErrorIs(t, err, ErrStepBudget, "two more port entries don't fit beside two")
	assert.Len(t, maps[ruleMapCIDRs].store, 1)
	assert.Len(t, maps[ruleMapPorts].store, 2)
	assert.Equal(t, 1, fw.steps.used(ruleMapCIDRs))
	assert.Nil(t, fw.stepIPs[policyIP{1, testIPv4(10, 2).String()}], "a refused add leaves no accumulator")

	_, err = fw.AddPolicyIP(1, testIPv4(10, 1), []config.Port{{Port: 8080, Protocol: config.ProtocolTCP}}, nil)
	require.NoError(t, err, "the third port entry fits")
	_, err = fw.AddPolicyIP(1, testIPv4(10, 1), []config.Port{{Port: 8081, Protocol: config.ProtocolTCP}}, nil)
	require.ErrorIs(t, err, ErrStepBudget)
	assert.Len(t, maps[ruleMapPorts].store, 3)

	// An all-ports grant on the installed IP needs no new entry.
	_, err = fw.AddPolicyIP(1, testIPv4(10, 1), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, bpf.TcBpfLpmVal{Action: 1}, maps[ruleMapCIDRs].store[bpf.RuleKey(1, 32, binary.NativeEndian.Uint32(testIPv4(10, 1)))])
	// And under it, port entries are inert, so they're neither written nor charged.
	_, err = fw.AddPolicyIP(1, testIPv4(10, 1), []config.Port{{Port: 9999, Protocol: config.ProtocolTCP}}, nil)
	require.NoError(t, err)
	assert.Equal(t, 3, fw.steps.used(ruleMapPorts))
}

// A key a write lists twice is charged once: a rule's ports can expand to
// the same entry twice (443/tcp and 443/all both give 443/tcp).
func TestStepBudget_DuplicatePortsChargedOnce(t *testing.T) {
	fw, maps := newStepTestFirewall(ruleMapEntries, nil)
	fw.steps.setBudget(3)
	_, err := fw.AddPolicyIP(1, testIPv4(10, 1), []config.Port{
		{Port: 443, Protocol: config.ProtocolTCP}, {Port: 443, Protocol: config.ProtocolAll},
	}, nil)
	require.NoError(t, err, "three distinct entries fit a budget of three")
	assert.Len(t, maps[ruleMapPorts].store, 3)
	assert.Equal(t, 3, fw.steps.used(ruleMapPorts))
}

// A step's subnet and wildcard entries are charged too, in both families,
// and a refusal in the sync is a Warn that leaves the rest of the sync, the
// job's rules included, in place.
func TestStepBudget_SyncChargesSubnetsAndWildcards(t *testing.T) {
	two := []config.Port{{Port: 80, Protocol: config.ProtocolTCP}, {Port: 443, Protocol: config.ProtocolTCP}}
	for _, c := range []struct {
		family           string
		job              string
		subnet, wildcard string
		other            string
		lpm, ports       ruleMap
	}{
		{"IPv4", "8.8.8.8/32", "192.168.0.0/24", "0.0.0.0/0", "172.16.0.0/12", ruleMapCIDRs, ruleMapPorts},
		{"IPv6", "2001:db8:8::8/128", "2001:db8:1::/48", "::/0", "2001:db8:2::/48", ruleMapCIDRsV6, ruleMapPortsV6},
	} {
		t.Run(c.family, func(t *testing.T) {
			var logs bytes.Buffer
			fw, maps := newStepTestFirewall(ruleMapEntries, slog.New(slog.NewTextHandler(&logs, nil)))
			fw.steps.setBudget(3)
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfig(writeStepConfig(t,
				[]config.Rule{{Type: config.RuleTypeCIDR, Value: c.job, Action: config.ActionAllow}},
				[]config.StepConfig{{ID: "a", Rules: []config.Rule{
					{Type: config.RuleTypeCIDR, Value: c.subnet, Ports: two},
					{Type: config.RuleTypeCIDR, Value: c.wildcard, Ports: two},
					{Type: config.RuleTypeCIDR, Value: c.other},
				}}})))
			require.NoError(t, fw.UpdateAllowlistTC(cm))

			assert.Len(t, entriesOf(t, maps[c.lpm], 1), 2, "the subnet and the other prefix")
			assert.Len(t, entriesOf(t, maps[c.ports], 1), 2, "the subnet's; the wildcard's didn't fit")
			assert.Equal(t, 2, fw.steps.used(c.ports))
			assert.Len(t, entriesOf(t, maps[c.lpm], bpf.PolicyJob), 1)
			assert.Contains(t, logs.String(), noRoomStepShare)
			assert.Contains(t, logs.String(), "destination="+c.wildcard)
		})
	}
}

// The job comes first for room: past its reservation its entries take room
// the steps' share counts on. A step write the ledger admits but the map has
// no room for is refused the same way, with the same rate-limited Warn,
// naming the job's entries as the cause.
func TestStepBudget_JobPastItsReservation(t *testing.T) {
	var logs bytes.Buffer
	fw, maps := newStepTestFirewall(10, slog.New(slog.NewTextHandler(&logs, nil)))
	fw.steps.setBudget(6) // a reservation of 4
	for i := range 6 {
		_, err := fw.AddIP(testIPv4(20, i), config.ActionAllow, nil)
		require.NoError(t, err, "the job's own policy may hold more than its reservation")
	}
	for i := range 4 {
		_, err := fw.AddPolicyIP(1, testIPv4(10, i), nil, nil)
		require.NoError(t, err)
	}
	require.Equal(t, 4, fw.steps.used(ruleMapCIDRs), "within the steps' share")

	_, err := fw.AddPolicyIP(1, testIPv4(10, 4), nil, nil)
	require.ErrorIs(t, err, ErrStepBudget)
	require.ErrorIs(t, err, unix.E2BIG, "the map's own refusal underneath")
	assert.Len(t, maps[ruleMapCIDRs].store, 10)
	assert.Contains(t, logs.String(), noRoomJob)

	// The sync's step CIDRs are refused the same way, under the same limit.
	_, err = fw.AddPolicyIP(1, testIPv4(10, 5), nil, nil)
	require.ErrorIs(t, err, ErrStepBudget)
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("Step rule entry not installed")), "one Warn per interval, whatever the cause")
	fw.steps.warned = time.Now().Add(-2 * stepBudgetWarnInterval)
	fw.writeStepCIDRsLocked(config.StepRules{StepID: "a", Policy: 1, Rules: []config.ResolvedRule{{
		Type: config.RuleTypeCIDR, Value: "10.200.0.0/16", IPNet: &net.IPNet{IP: net.IPv4(10, 200, 0, 0).To4(), Mask: net.CIDRMask(16, 32)},
	}}})
	assert.Equal(t, 2, bytes.Count(logs.Bytes(), []byte(noRoomJob)))
	assert.Contains(t, logs.String(), "refused=2", "the refusal held back, and the sync's")
	assert.NotContains(t, logs.String(), "Step rule not installed;", "a refusal for room is the rate-limited Warn alone")
}

// The ledger stays what the maps hold when the maps fill too: with the job
// past its reservation, step writes the ledger admits are refused by the
// map itself, some part-way, and each is refunded what it didn't write.
func TestStepLedger_MatchesTheMapsWhenFull(t *testing.T) {
	for seed := range uint64(20) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 202))
			fw, maps := newStepTestFirewall(24, nil)
			fw.steps.setBudget(16)
			ports := [][]config.Port{nil, tcp443, {{Port: 80, Protocol: config.ProtocolTCP}, {Port: 8080, Protocol: config.ProtocolUDP}}}
			for range 200 {
				var ip net.IP
				if rng.IntN(2) == 0 {
					ip = testIPv4(10, rng.IntN(20))
				} else {
					ip = testIPv6(10, rng.IntN(20))
				}
				ps := ports[rng.IntN(len(ports))]
				if rng.IntN(3) == 0 {
					_, _ = fw.AddIP(ip, config.ActionAllow, ps) // the job may meet a full map too
				} else if _, err := fw.AddPolicyIP(uint32(1+rng.IntN(3)), ip, ps, nil); err != nil {
					require.ErrorIs(t, err, ErrStepBudget)
				}
				for m := range numRuleMaps {
					require.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
					require.LessOrEqual(t, fw.steps.used(m), 16, "%s over budget", m)
				}
			}
		})
	}
}

// The refusal Warn is rate-limited, and reports what it held back.
func TestStepBudget_WarnIsRateLimited(t *testing.T) {
	var logs bytes.Buffer
	fw, _ := newStepTestFirewall(ruleMapEntries, slog.New(slog.NewTextHandler(&logs, nil)))
	fw.steps.setBudget(1)
	_, err := fw.AddPolicyIP(1, testIPv4(10, 0), nil, nil)
	require.NoError(t, err)
	for i := 1; i <= 5; i++ {
		_, err := fw.AddPolicyIP(1, testIPv4(10, i), nil, nil)
		require.ErrorIs(t, err, ErrStepBudget)
	}
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte(noRoomStepShare)))
	assert.Contains(t, logs.String(), "refused=1")

	fw.steps.warned = time.Now().Add(-2 * stepBudgetWarnInterval)
	_, err = fw.AddPolicyIP(1, testIPv4(10, 6), nil, nil)
	require.ErrorIs(t, err, ErrStepBudget)
	assert.Equal(t, 2, bytes.Count(logs.Bytes(), []byte(noRoomStepShare)))
	assert.Contains(t, logs.String(), "refused=5", "four held back, and this one")
}

// The ledger agrees with the maps, whatever mix of step and job writes runs:
// random adds across policies, families, repeated IPs, port sets and
// all-ports transitions, under a budget small enough to refuse often. And
// step writes never touch the job's entries: those come out exactly as the
// job's writes alone make them.
func TestStepLedger_MatchesTheMaps(t *testing.T) {
	for seed := range uint64(20) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 105))
			fw, maps := newStepTestFirewall(ruleMapEntries, nil)
			fw.steps.setBudget(40)
			jobOnly, jobMaps := newStepTestFirewall(ruleMapEntries, nil)

			portPool := []config.Port{
				{Port: 80, Protocol: config.ProtocolTCP},
				{Port: 443, Protocol: config.ProtocolTCP},
				{Port: 53, Protocol: config.ProtocolUDP},
				{Port: 8080, Protocol: config.ProtocolAll},
				config.PortICMP,
			}
			randomPorts := func() []config.Port {
				if rng.IntN(3) == 0 {
					return nil
				}
				var ps []config.Port
				for _, p := range portPool {
					if rng.IntN(2) == 0 {
						ps = append(ps, p)
					}
				}
				return ps
			}
			randomIP := func() net.IP {
				if rng.IntN(2) == 0 {
					return testIPv4(10, rng.IntN(12))
				}
				return testIPv6(10, rng.IntN(12))
			}
			for range 300 {
				ip, ports := randomIP(), randomPorts()
				if rng.IntN(4) == 0 {
					action := config.ActionAllow
					if rng.IntN(3) == 0 {
						action = config.ActionDeny
					}
					_, err := fw.AddIP(ip, action, ports)
					require.NoError(t, err)
					_, err = jobOnly.AddIP(ip, action, ports)
					require.NoError(t, err)
					continue
				}
				before := storeSizes(maps)
				_, err := fw.AddPolicyIP(uint32(1+rng.IntN(4)), ip, ports, nil)
				if err != nil {
					require.ErrorIs(t, err, ErrStepBudget)
					require.Equal(t, before, storeSizes(maps), "a refused write installed something")
				}
				for m := range numRuleMaps {
					require.Equal(t, stepEntries(t, maps[m]), fw.steps.used(m), "%s ledger", m)
					require.LessOrEqual(t, fw.steps.used(m), 40, "%s over budget", m)
				}
			}
			for m := range numRuleMaps {
				assert.Equal(t, entriesOf(t, jobMaps[m], bpf.PolicyJob), entriesOf(t, maps[m], bpf.PolicyJob), "%s: step writes changed the job's entries", m)
			}
		})
	}
}
