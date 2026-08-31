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

package config

import (
	"fmt"
	"testing"
	"time"
)

// TestNameResolvedToIP covers the evidence behind the L7 per-IP binding, and
// in particular that the two very different sources both count: the forward
// cache (rule hostnames, which accumulates across round-robin answers) and the
// recorded CNAME chain (derived targets, which never enter the forward cache
// because it is only seeded for tracked rule hostnames).
func TestNameResolvedToIP(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "good.example", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatal(err)
	}

	// Forward-cache binding for a tracked rule hostname, including a second
	// round-robin address.
	cm.RecordForwardResolution("good.example", "104.16.1.1")
	cm.RecordForwardResolution("good.example", "104.16.2.2")
	if !cm.NameResolvedToIP("good.example", "104.16.1.1") {
		t.Error("first resolved address must bind")
	}
	if !cm.NameResolvedToIP("good.example", "104.16.2.2") {
		t.Error("round-robin second address must bind (the cache accumulates)")
	}
	if cm.NameResolvedToIP("good.example", "203.0.113.7") {
		t.Error("an address the name never resolved to must NOT bind")
	}

	// Chain binding: BOTH the origin and every edge label it chains through
	// are names a client can legitimately present, so both must bind.
	cm.RecordCNAMEChain("23.56.109.139",
		[]string{"builds.example", "trafficmanager.example", "a441.edge.example"}, time.Minute)
	for _, name := range []string{"builds.example", "trafficmanager.example", "a441.edge.example"} {
		if !cm.NameResolvedToIP(name, "23.56.109.139") {
			t.Errorf("chain hop %q must bind to the chain's IP", name)
		}
	}
	if cm.NameResolvedToIP("unrelated.example", "23.56.109.139") {
		t.Error("a name outside the chain must not bind")
	}

	// Case-insensitive, matching how names are stored.
	if !cm.NameResolvedToIP("A441.EDGE.EXAMPLE", "23.56.109.139") {
		t.Error("binding must be case-insensitive")
	}

	// Degenerate inputs.
	if cm.NameResolvedToIP("", "104.16.1.1") || cm.NameResolvedToIP("good.example", "") {
		t.Error("empty name or ip must not bind")
	}
}

// TestNameResolvedToIP_WildcardSharedEdge is the case --tls-sni=enforce-pinned exists
// for: two concrete names under wildcard allows resolve (chainless A) to ONE
// shared edge IP. The old implementation leaned on ipToHostname (last-write-
// wins), so the first name's binding vanished when the second resolved. The
// dedicated evidence store must keep BOTH.
func TestNameResolvedToIP_WildcardSharedEdge(t *testing.T) {
	cm := NewConfigManager()
	const edge = "104.16.1.1"
	cm.RecordForwardResolution("a.wildcard.example", edge)
	cm.RecordForwardResolution("b.wildcard.example", edge) // same IP, later

	if !cm.NameResolvedToIP("a.wildcard.example", edge) {
		t.Error("first name must still bind after a second resolved to the same edge")
	}
	if !cm.NameResolvedToIP("b.wildcard.example", edge) {
		t.Error("second name must bind")
	}
}

// TestNameResolvedToIP_PTRIsNotEvidence is the security property behind
// --tls-sni=enforce-pinned: reverse-DNS names must never mint a binding. PTR records
// are controlled by whoever holds the destination IP, so if UpdateDNSMapping
// (which the blocked-event pipeline calls with PTR-derived names) seeded the
// evidence store, an attacker could set PTR(theirIP)=allowed.example and have
// their own SNI-ignoring server admitted under that name.
func TestNameResolvedToIP_PTRIsNotEvidence(t *testing.T) {
	cm := NewConfigManager()
	const attackerIP = "203.0.113.50"

	// Exactly what resolveDestination does after a lazy PTR lookup.
	cm.UpdateDNSMapping("allowed.example", attackerIP)

	if cm.NameResolvedToIP("allowed.example", attackerIP) {
		t.Fatal("a reverse-DNS mapping must NOT create L7 binding evidence - " +
			"PTR is attacker-controlled at the destination IP")
	}
	// The display/attribution side still works, unchanged.
	if got := cm.LookupHostnameByIP(attackerIP); got != "allowed.example" {
		t.Errorf("reverse attribution = %q, want allowed.example (unchanged)", got)
	}
	// A genuine forward resolution does bind.
	cm.RecordForwardResolution("allowed.example", attackerIP)
	if !cm.NameResolvedToIP("allowed.example", attackerIP) {
		t.Error("a forward resolution must bind")
	}
}

// TestNameResolvedToIP_ChainHopsBindRegardlessOfTTL: chain hops are recorded
// as binding evidence on the same count-bounded, refresh-on-use lifecycle as a
// direct forward resolution - deliberately NOT the chain's response TTL. A
// ttl==0 CDN answer previously expired the target-hop binding instantly, so a
// client dialing the edge label directly was denied name_not_at_ip.
func TestNameResolvedToIP_ChainHopsBindRegardlessOfTTL(t *testing.T) {
	cm := NewConfigManager()
	const edge = "203.0.113.9"
	cm.RecordCNAMEChain(edge, []string{"origin.example", "edge.example"}, 0) // ttl 0

	for _, name := range []string{"origin.example", "edge.example"} {
		if !cm.NameResolvedToIP(name, edge) {
			t.Errorf("chain hop %q must bind even with a zero-TTL response", name)
		}
	}
}

// TestBindingEvidenceIsBounded: the store is capped by count (not swept by
// TTL), so the many-names-to-one-IP shape pin-ip targets cannot grow it
// without limit - an attacker issuing DNS queries under a wildcard allow must
// not be able to grow daemon memory at zero cost.
func TestBindingEvidenceIsBounded(t *testing.T) {
	cm := NewConfigManager()
	const edge = "104.16.1.1"
	for i := 0; i < maxBindingNames+500; i++ {
		cm.RecordForwardResolution(fmt.Sprintf("host%d.wildcard.example", i), edge)
	}
	cm.bindMu.Lock()
	n := len(cm.nameToIPs)
	cm.bindMu.Unlock()
	if n > maxBindingNames {
		t.Errorf("nameToIPs grew to %d, want <= %d", n, maxBindingNames)
	}

	cm2 := NewConfigManager()
	for i := 0; i < maxBindingIPsPerName+50; i++ {
		cm2.RecordForwardResolution("rr.example", fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	cm2.bindMu.Lock()
	m := len(cm2.nameToIPs["rr.example"].ips)
	cm2.bindMu.Unlock()
	if m > maxBindingIPsPerName {
		t.Errorf("per-name IPs grew to %d, want <= %d", m, maxBindingIPsPerName)
	}
}

// TestBindingEvidenceRefreshOnUse: an actively-used binding must survive
// eviction pressure, so a long-lived cached-IP client is never deadlocked into
// a name_not_at_ip deny it cannot self-heal.
func TestBindingEvidenceRefreshOnUse(t *testing.T) {
	cm := NewConfigManager()
	const edge = "104.16.1.1"
	cm.RecordForwardResolution("hot.example", edge)

	for i := 0; i < maxBindingNames+100; i++ {
		cm.RecordForwardResolution(fmt.Sprintf("cold%d.example", i), edge)
		if i%50 == 0 && !cm.NameResolvedToIP("hot.example", edge) {
			t.Fatalf("hot binding evicted at i=%d despite being in use", i)
		}
	}
	if !cm.NameResolvedToIP("hot.example", edge) {
		t.Error("a continuously-used binding must not be evicted")
	}
}
