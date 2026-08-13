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

package containers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/code-cargo/cargowall/pkg/origin"
)

// The join-agreement policy in isolation. Tracker-level Enrich tests cover
// the same matrix end to end; this pins the pure decision function so the
// "disagreement degrades stricter" rule is checkable at a glance.
func TestResolveJoin(t *testing.T) {
	ctrA := &containerInfo{id: strings.Repeat("a", 64)}
	ctrB := &containerInfo{id: strings.Repeat("b", 64)}
	byCgroup := map[uint64]*containerInfo{1: ctrA, 2: ctrB}
	classify := func(r origin.Record) *containerInfo { return byCgroup[r.CgroupID] }
	rec := func(cgroup uint64, ordinal uint32) origin.Record {
		return origin.Record{CgroupID: cgroup, StepOrdinal: ordinal}
	}

	tests := []struct {
		name     string
		recs     []origin.Record
		wantKind joinKind
		wantInfo *containerInfo
	}{
		{"no candidates", nil, joinNone, nil},
		{"single container", []origin.Record{rec(1, 5)}, joinResolved, ctrA},
		{"single host flow", []origin.Record{rec(0, 5)}, joinResolved, nil},
		{"agreement", []origin.Record{rec(1, 5), rec(1, 5)}, joinResolved, ctrA},
		{"same container, different ordinals", []origin.Record{rec(1, 5), rec(1, 6)}, joinAmbiguousContainers, nil},
		{"different containers", []origin.Record{rec(1, 5), rec(2, 5)}, joinAmbiguousContainers, nil},
		{"container vs host", []origin.Record{rec(1, 5), rec(0, 5)}, joinAmbiguousMixed, nil},
		{"hosts disagreeing on ordinal", []origin.Record{rec(0, 5), rec(0, 6)}, joinAmbiguousMixed, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveJoin(tt.recs, classify)
			assert.Equal(t, tt.wantKind, got.kind)
			if tt.wantKind == joinResolved {
				assert.Equal(t, tt.wantInfo, got.info)
				assert.Equal(t, tt.recs[0], got.rec, "newest candidate wins")
			}
		})
	}
}

// Two processes in one container to the same destination agree on
// everything but the PID (MASQUERADE hid the source ports, so the exact
// match missed). The container and step claims stand; the process claim
// must not — stamping either PID and its comm would be a coin flip
// reported as fact in the audit stream, the live log, and the OTLP export.
func TestResolveJoinPIDDisagreementDropsProcessClaim(t *testing.T) {
	ctrA := &containerInfo{id: strings.Repeat("a", 64)}
	byCgroup := map[uint64]*containerInfo{1: ctrA}
	classify := func(r origin.Record) *containerInfo { return byCgroup[r.CgroupID] }

	got := resolveJoin([]origin.Record{
		{CgroupID: 1, StepOrdinal: 5, PID: 101},
		{CgroupID: 1, StepOrdinal: 5, PID: 202},
	}, classify)
	assert.Equal(t, joinResolved, got.kind)
	assert.Equal(t, ctrA, got.info)
	assert.Equal(t, uint32(5), got.rec.StepOrdinal, "step claim survives")
	assert.Zero(t, got.rec.PID, "a disagreed PID must never be claimed")

	got = resolveJoin([]origin.Record{
		{CgroupID: 1, StepOrdinal: 5, PID: 101},
		{CgroupID: 1, StepOrdinal: 5, PID: 101},
	}, classify)
	assert.Equal(t, joinResolved, got.kind)
	assert.Equal(t, uint32(101), got.rec.PID, "an agreed PID is claimed")
}

// IPv6 addresses must reach the DNS client index: TC enrichment can match
// v6 containers via cgroup id, and DNS attribution must not be the one path
// that silently misses them.
func TestCollectIPsIncludesIPv6(t *testing.T) {
	insp := containerInspect{}
	insp.NetworkSettings.IPAddress = "172.17.0.2"
	insp.NetworkSettings.GlobalIPv6Address = "fd00::2"
	insp.NetworkSettings.Networks = map[string]struct {
		IPAddress           string `json:"IPAddress"`
		IPPrefixLen         int    `json:"IPPrefixLen"`
		GlobalIPv6Address   string `json:"GlobalIPv6Address"`
		GlobalIPv6PrefixLen int    `json:"GlobalIPv6PrefixLen"`
	}{
		"bridge": {IPAddress: "172.17.0.2", GlobalIPv6Address: "fd00::2"},
		"custom": {IPAddress: "172.18.0.9", GlobalIPv6Address: "fd01::9"},
	}
	got := collectIPs(insp)
	assert.ElementsMatch(t, []string{"172.17.0.2", "fd00::2", "172.18.0.9", "fd01::9"}, got,
		"v4 and v6, deduplicated across the default and named networks")
}

// Bridge subnets feed the enforce-mode carve-out (AllowLocalSubnet):
// container→container traffic on a user-defined bridge never leaves the
// host and TC never adjudicated it, so a missed subnet is a broken network
// under --cgroup-enforce — and each subnet must carry its network name so
// carvePrefix can gate on the driver.
func TestCollectSubnetsDerivesBridgeNetworks(t *testing.T) {
	insp := containerInspect{}
	insp.NetworkSettings.IPAddress = "172.17.0.2"
	insp.NetworkSettings.IPPrefixLen = 16
	insp.NetworkSettings.Networks = map[string]struct {
		IPAddress           string `json:"IPAddress"`
		IPPrefixLen         int    `json:"IPPrefixLen"`
		GlobalIPv6Address   string `json:"GlobalIPv6Address"`
		GlobalIPv6PrefixLen int    `json:"GlobalIPv6PrefixLen"`
	}{
		"custom": {IPAddress: "172.18.0.9", IPPrefixLen: 24, GlobalIPv6Address: "fd01::9", GlobalIPv6PrefixLen: 64},
		// Zero prefix (host networking, or a daemon that omits it) must not
		// produce a 0.0.0.0/0-shaped carve-out.
		"weird": {IPAddress: "10.0.0.5", IPPrefixLen: 0},
	}
	got := collectSubnets(insp)
	var rendered []string
	for _, s := range got {
		rendered = append(rendered, s.network+"="+s.prefix.String())
	}
	assert.ElementsMatch(t, []string{"=172.17.0.0/16", "custom=172.18.0.0/24", "custom=fd01::/64"}, rendered,
		"masked network prefixes with their network names, zero-prefix entries dropped")
}
