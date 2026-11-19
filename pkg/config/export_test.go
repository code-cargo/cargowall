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

import "net/netip"

// TCModelAllows exposes the modelled TC verdict to the external kernel test,
// which checks it against the real program.
func TCModelAllows(cm *Manager, ip netip.Addr, port uint16, proto uint8) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return newTCModel(cm.resolvedRules, cm.config.DefaultAction).allows(ip, tcProbe{port, proto})
}
