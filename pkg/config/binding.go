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
	"strings"
	"time"
)

// The L7 per-IP binding evidence store (Manager.nameToIPs): every (name, IP)
// pair this daemon observed FORWARD-resolving, with a last-seen/last-used
// time. It is its own store because the neighboring maps drop or forge
// evidence a security check needs — hostnameCache is keyed by rule.Value, so a
// wildcard rule's concrete names never enter it, and ipToHostname is
// last-write-wins display attribution seeded from reverse-DNS PTR names.
//
// It also has its own mutex (Manager.bindMu), NOT cm.mu. Both of its hot paths
// sit under someone else's lock — one lookup per L7 punt, taken while the
// oracle holds l.mu, and one per resolved IP of every allowed DNS answer — so
// running them on the config manager's exclusive lock serialized the proxy's
// resolutions and the oracle's verdicts against each other and against every
// MatchHostnameRule. Lock order where both are held is cm.mu then bindMu
// (RecordCNAMEChain); nothing takes them the other way.
//
// The store is capped by COUNT rather than swept by TTL: its lifetime must
// track the L4 and L7-scope map entries it gates, which never expire, or a
// long-lived cached-IP client would deadlock into a name_not_at_ip deny it
// cannot self-heal. Eviction is least-recently-used and NameResolvedToIP
// refreshes on every hit, so an actively-used binding never drops while stale
// ones age out under pressure.
const (
	// maxBindingIPsPerName caps addresses remembered per name; round-robin and
	// geo-steering rarely exceed a handful. Oldest-seen address evicted first.
	maxBindingIPsPerName = 32
	// maxBindingNames caps distinct names, bounding the wildcard shape pin-ip
	// targets (many subdomains, few edge IPs) so DNS queries cannot grow the
	// store without limit. Least-recently-touched name evicted first.
	maxBindingNames = 8192
)

// nameBinding is one name's addresses with the time each was last seen or
// used. newest is maintained on every write as the max over ips, so eviction
// scans names alone: recomputing it per name made the overflow scan
// O(names x ips) — ~260k map iterations for every new name once the cap is
// reached, which is precisely the wildcard flood the cap exists to bound.
type nameBinding struct {
	ips    map[string]time.Time
	newest time.Time
}

// recordBindingLocked records that name forward-resolved to ip at now. Callers
// hold cm.bindMu. ONLY forward-resolution paths (RecordForwardResolution and
// RecordCNAMEChain) may reach this; a reverse-DNS name must never seed it.
func (cm *Manager) recordBindingLocked(name, ip string, now time.Time) {
	if name == "" || ip == "" {
		return
	}
	b := cm.nameToIPs[name]
	if b == nil {
		if len(cm.nameToIPs) >= maxBindingNames {
			cm.evictOldestBindingNameLocked()
		}
		b = &nameBinding{ips: make(map[string]time.Time)}
		cm.nameToIPs[name] = b
	}
	if _, exists := b.ips[ip]; !exists && len(b.ips) >= maxBindingIPsPerName {
		var oldestIP string
		var oldestT time.Time
		for k, t := range b.ips {
			if oldestIP == "" || t.Before(oldestT) {
				oldestIP, oldestT = k, t
			}
		}
		delete(b.ips, oldestIP)
	}
	b.ips[ip] = now
	if now.After(b.newest) {
		b.newest = now
	}
}

// evictOldestBindingNameLocked drops the name whose newest binding is oldest —
// the least-recently-active name. O(names) but only on overflow of the cap.
func (cm *Manager) evictOldestBindingNameLocked() {
	var oldestName string
	var oldestNewest time.Time
	for name, b := range cm.nameToIPs {
		if oldestName == "" || b.newest.Before(oldestNewest) {
			oldestName, oldestNewest = name, b.newest
		}
	}
	if oldestName != "" {
		delete(cm.nameToIPs, oldestName)
	}
}

// RecordForwardResolution records that hostname forward-resolved to ip through
// the proxy — L7 per-IP binding evidence for --tls-sni=enforce-pinned. MUST be called
// only from the DNS proxy's forward-response path; never with a name derived
// from a reverse-DNS PTR, which an attacker at the destination IP controls.
func (cm *Manager) RecordForwardResolution(hostname, ip string) {
	hostname = strings.ToLower(hostname)
	cm.bindMu.Lock()
	defer cm.bindMu.Unlock()
	cm.recordBindingLocked(hostname, ip, time.Now())
}

// NameResolvedToIP reports whether hostname was observed FORWARD-resolving to
// ip through this daemon's proxy — as a queried name (RecordForwardResolution)
// or as a hop of a recorded CNAME chain (RecordCNAMEChain feeds the same
// store). It is the evidence behind the L7 per-IP binding: without it an
// allowed name is a passphrase that opens ANY L7-scoped IP, including one
// where an attacker runs a server that ignores SNI.
//
// Reverse-DNS names never enter the store. A PTR is controlled by whoever
// holds the destination IP, so accepting one would let a self-set
// PTR(theirIP)=allowed.example forge the binding and defeat --tls-sni=enforce-pinned.
func (cm *Manager) NameResolvedToIP(hostname, ip string) bool {
	if hostname == "" || ip == "" {
		return false
	}
	hostname = strings.ToLower(hostname)

	cm.bindMu.Lock()
	defer cm.bindMu.Unlock()

	b := cm.nameToIPs[hostname]
	if b == nil {
		return false
	}
	if _, ok := b.ips[ip]; !ok {
		return false
	}
	// Refresh on use so an actively-exercised binding is never the LRU victim.
	now := time.Now()
	b.ips[ip] = now
	if now.After(b.newest) {
		b.newest = now
	}
	return true
}
