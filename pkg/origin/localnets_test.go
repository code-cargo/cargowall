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
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
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

// AllowLocalNetwork writes the entry the hook reads: cg_origin_egress looks
// up map_local_nets with {prefixlen 32 (128), destination}, so an address
// inside a carved subnet must hit and one outside must not — which also
// pins the key's byte order. A refused prefix must write nothing.
func TestAllowLocalNetwork_WritesWhatTheHookLooksUp(t *testing.T) {
	o := newTestObserver()
	o.objs = *loadL7Objects(t)

	hit4 := func(addr string) bool {
		a4 := netip.MustParseAddr(addr).As4()
		var v uint8
		err := o.objs.MapLocalNets.Lookup(bpf.OriginBpfLpmKey{Prefixlen: 32, Ip: binary.NativeEndian.Uint32(a4[:])}, &v)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false
		}
		require.NoError(t, err)
		return true
	}
	hit6 := func(addr string) bool {
		key := bpf.OriginBpfLpmKeyV6{Prefixlen: 128, Ip: netip.MustParseAddr(addr).As16()}
		var v uint8
		err := o.objs.MapLocalNetsV6.Lookup(key, &v)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false
		}
		require.NoError(t, err)
		return true
	}

	// Address space no test host has an interface in, so validation passes.
	require.NoError(t, o.AllowLocalNetwork(netip.MustParsePrefix("10.254.3.9/16")))
	assert.True(t, hit4("10.254.0.1"))
	assert.True(t, hit4("10.254.255.254"))
	assert.False(t, hit4("10.253.0.1"))
	assert.False(t, hit4("0.0.254.10"), "a byte-swapped key would carve 0.0.0.0/16 instead")

	require.NoError(t, o.AllowLocalNetwork(netip.MustParsePrefix("fd00:cafe:1::/64")))
	assert.True(t, hit6("fd00:cafe:1::7"))
	assert.False(t, hit6("fd00:cafe:2::7"))

	err := o.AllowLocalNetwork(netip.MustParsePrefix("172.0.0.0/8"))
	require.ErrorIs(t, err, ErrLocalNetworkRefused, "wider than /16 is refused")
	assert.False(t, hit4("172.1.2.3"), "a refused prefix writes nothing")
}
