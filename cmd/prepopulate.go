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

package cmd

import (
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/dns"
)

// recordSystemCacheAnswer applies one Phase-1 pre-population answer: the IPs
// a rule hostname currently resolves to through the system resolver — the
// IPs live processes are already using. The mapping feeds attribution for
// every name. Forward-resolution evidence — a FORWARD lookup of a rule name,
// the same evidence class as the proxy's own answers, and what lets an IP be
// L7-scoped at all (RegisterL7Identity scopes iff bound) — is minted only for
// a name the wire answered. A name the proxy itself answers from resolved's
// local state (dns.Server.LocalAlias: _gateway, the machine's own name) is
// an address alias no peer presents; scoping its address against it would
// make every flow there an L7 miss.
func recordSystemCacheAnswer(configMgr *config.Manager, dnsServer *dns.Server, hostname string, ips []string) {
	alias := dnsServer.LocalAlias(hostname)
	for _, ip := range ips {
		configMgr.UpdateDNSMapping(hostname, ip)
		if !alias {
			configMgr.RecordForwardResolution(hostname, ip)
		}
	}
}
