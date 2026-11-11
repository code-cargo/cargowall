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

// RecordReverseName records hostname, a reverse-lookup (PTR) answer, as ip's
// name, unless ip already has one, and reports whether it did. A PTR name is
// the destination's own claim, and it decides attribution and which rule a
// denial is late-allowed under, so it must never replace a forward name: one
// the proxy recorded from a DNS answer, or a tracked name's cached address.
// A lookup takes long enough for a forward answer to land while it runs.
func (cm *Manager) RecordReverseName(hostname, ip string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if _, named := cm.ipToHostname[ip]; named {
		return false
	}
	for _, ips := range cm.hostnameCache {
		for _, cached := range ips {
			if cached.String() == ip {
				return false
			}
		}
	}
	cm.updateDNSMappingLocked(hostname, ip)
	return true
}
