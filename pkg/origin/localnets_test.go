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

package origin

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The subnet-validation policy, pure over synthetic interfaces: this is the
// machinery that keeps a workload-created `docker network create --subnet`
// from carving real network space out of the enforcing cgroup hook.
func TestValidateLocalSubnet(t *testing.T) {
	ipnet := func(cidr string) *net.IPNet {
		ip, n, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		n.IP = ip
		return n
	}
	eth0 := hostIface{name: "eth0", addrs: []*net.IPNet{ipnet("10.1.0.194/16")}}
	docker0 := hostIface{name: "docker0", isBridge: true, addrs: []*net.IPNet{ipnet("172.17.0.1/16")}}
	tun0 := hostIface{name: "tun0", addrs: []*net.IPNet{ipnet("10.8.0.5/16")}}
	ifaces := []hostIface{eth0, docker0, tun0}

	tests := []struct {
		name    string
		prefix  string
		refused bool
	}{
		{"legit default bridge (own gateway exempt)", "172.17.0.0/16", false},
		{"legit user-defined bridge, disjoint space", "172.20.0.0/16", false},
		{"wider than any bridge needs", "10.0.0.0/8", true},
		{"claims the host's own VPC subnet", "10.1.0.0/16", true},
		{"claims the VPN's exact range (tun0 own==prefix but not a bridge)", "10.8.0.0/16", true},
		{"v6 width cap", "fd00::/48", true},
		{"legit v6 bridge subnet", "fd01::/64", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tt.prefix)
			reason := validateLocalSubnet(prefix.Masked(), ifaces)
			if tt.refused {
				assert.NotEmpty(t, reason, "must be refused")
			} else {
				assert.Empty(t, reason, "must be carved: %s", reason)
			}
		})
	}
}
