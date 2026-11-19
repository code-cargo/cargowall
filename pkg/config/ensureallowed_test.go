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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const upstreamIP = "10.0.0.2"

var (
	udp53  = []Port{{Port: 53, Protocol: ProtocolUDP}}
	tcp53  = []Port{{Port: 53, Protocol: ProtocolTCP}}
	tcp443 = []Port{{Port: 443, Protocol: ProtocolTCP}}
)

func cidrRule(value string, action Action, ports ...Port) Rule {
	return Rule{Type: RuleTypeCIDR, Value: value, Ports: ports, Action: action}
}

// tcAllows is the modelled TC verdict for a packet to ip under cm's rules.
func tcAllows(cm *Manager, ip string, p tcProbe) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return newTCModel(cm.resolvedRules, cm.config.DefaultAction).allows(netip.MustParseAddr(ip), p)
}

var (
	probeUDP53  = tcProbe{53, tcProtoUDP}
	probeTCP53  = tcProbe{53, tcProtoTCP}
	probeTCP443 = tcProbe{443, tcProtoTCP}
	probeTCP22  = tcProbe{22, tcProtoTCP}
	probeICMP   = tcProbe{0, tcProtoICMP}
	otherProbes = []tcProbe{probeTCP53, probeTCP443, probeTCP22, probeICMP}
)

func autoAdded(cm *Manager) []string {
	var out []string
	for _, r := range cm.config.Rules {
		if r.AutoAddedType != AutoAddedTypeNone {
			out = append(out, r.Value)
		}
	}
	return out
}

// EnsureDNSAllowed adds the upstream's /32 exactly when the TC program would
// otherwise drop {upstream, 53, UDP}, and only when the add changes nothing
// else about that address.
func TestEnsureDNSAllowed_ByTCVerdict(t *testing.T) {
	for _, tt := range []struct {
		name          string
		rules         []Rule
		defaultAction Action
		wantAdded     bool
		// wantUDP53 is the verdict after the call. Every other probe keeps
		// the verdict it had before.
		wantUDP53 bool
	}{
		{
			name:  "no rule for the upstream",
			rules: []Rule{cidrRule("192.0.2.0/24", ActionAllow)}, defaultAction: ActionDeny,
			wantAdded: true, wantUDP53: true,
		},
		{
			// Port entries for a subnet are keyed by its network address,
			// so they never answer for 10.0.0.2.
			name:  "port-specific subnet rule does not cover it",
			rules: []Rule{cidrRule("10.0.0.0/16", ActionAllow, udp53...)}, defaultAction: ActionDeny,
			wantAdded: true, wantUDP53: true,
		},
		{
			name:  "all-ports subnet allow covers it",
			rules: []Rule{cidrRule("10.0.0.0/8", ActionAllow)}, defaultAction: ActionDeny,
			wantAdded: false, wantUDP53: true,
		},
		{
			// Written after the /8, the host folds its all-ports allow in.
			name: "port rule for a host inside a broad allow",
			rules: []Rule{
				cidrRule("10.0.0.0/8", ActionAllow),
				cidrRule("10.0.0.2/32", ActionAllow, tcp53...),
			},
			defaultAction: ActionDeny,
			wantAdded:     false, wantUDP53: true,
		},
		{
			// Written before the /8, the host's /32 is the longest match
			// and names only TCP 53.
			name: "broad allow shadowed by a narrower port rule",
			rules: []Rule{
				cidrRule("10.0.0.2/32", ActionAllow, tcp53...),
				cidrRule("10.0.0.0/8", ActionAllow),
			},
			defaultAction: ActionDeny,
			wantAdded:     true, wantUDP53: true,
		},
		{
			name:  "host rule already allows it",
			rules: []Rule{cidrRule("10.0.0.2/32", ActionAllow, udp53...)}, defaultAction: ActionDeny,
			wantAdded: false, wantUDP53: true,
		},
		{
			name:  "port-scoped 0.0.0.0/0 allows it everywhere",
			rules: []Rule{cidrRule("0.0.0.0/0", ActionAllow, udp53...)}, defaultAction: ActionDeny,
			wantAdded: false, wantUDP53: true,
		},
		{
			// The subnet's port entry answers only for 10.0.0.0.
			name:  "port-scoped broad deny does not suppress it",
			rules: []Rule{cidrRule("10.0.0.0/8", ActionDeny, udp53...)}, defaultAction: ActionDeny,
			wantAdded: true, wantUDP53: true,
		},
		{
			// A host inside an all-ports deny stays denied, so the /32
			// would change nothing.
			name:  "broad all-ports deny under default deny is kept",
			rules: []Rule{cidrRule("10.0.0.0/8", ActionDeny)}, defaultAction: ActionDeny,
			wantAdded: false, wantUDP53: false,
		},
		{
			name:  "broad all-ports deny under default allow is kept",
			rules: []Rule{cidrRule("10.0.0.0/8", ActionDeny)}, defaultAction: ActionAllow,
			wantAdded: false, wantUDP53: false,
		},
		{
			name: "broad all-ports deny with a wildcard port allow is kept",
			rules: []Rule{
				cidrRule("10.0.0.0/8", ActionDeny),
				cidrRule("0.0.0.0/0", ActionAllow, tcp443...),
			},
			defaultAction: ActionDeny,
			wantAdded:     false, wantUDP53: false,
		},
		{
			name:  "host deny on the port is kept",
			rules: []Rule{cidrRule("10.0.0.2/32", ActionDeny, udp53...)}, defaultAction: ActionAllow,
			wantAdded: false, wantUDP53: false,
		},
		{
			name:  "host deny on all ports is kept",
			rules: []Rule{cidrRule("10.0.0.2/32", ActionDeny)}, defaultAction: ActionDeny,
			wantAdded: false, wantUDP53: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewConfigManager()
			require.NoError(t, cm.LoadConfigFromRules(tt.rules, tt.defaultAction))
			before := make(map[tcProbe]bool)
			for _, p := range otherProbes {
				before[p] = tcAllows(cm, upstreamIP, p)
			}

			cm.EnsureDNSAllowed([]string{upstreamIP})

			if tt.wantAdded {
				assert.Equal(t, []string{"10.0.0.2/32"}, autoAdded(cm))
			} else {
				assert.Empty(t, autoAdded(cm))
			}
			assert.Equal(t, tt.wantUDP53, tcAllows(cm, upstreamIP, probeUDP53), "10.0.0.2:53/udp")
			for _, p := range otherProbes {
				assert.Equal(t, before[p], tcAllows(cm, upstreamIP, p), "10.0.0.2 %+v must keep its verdict", p)
			}
		})
	}
}

// An all-ports auto-allow under a port-specific host entry is still added:
// the firewall's all-ports allow wins on that host.
func TestEnsureInfraAllowed_AllPortsOverPortSpecificHost(t *testing.T) {
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]Rule{cidrRule("169.254.169.254/32", ActionAllow, tcp443...)}, ActionDeny))
	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, nil, AutoAddedTypeCloudMetadata)
	assert.Equal(t, []string{"169.254.169.254/32"}, autoAdded(cm))
	for _, p := range []tcProbe{probeTCP22, probeUDP53, probeICMP} {
		assert.True(t, tcAllows(cm, "169.254.169.254", p), "%+v", p)
	}
}

// A v4-mapped spelling is stored as the plain IPv4 /32.
func TestEnsureDNSAllowed_V4MappedSpelling(t *testing.T) {
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, ActionDeny))
	cm.EnsureDNSAllowed([]string{"::ffff:10.0.0.2"})
	assert.Equal(t, []string{"10.0.0.2/32"}, autoAdded(cm))
	assert.True(t, tcAllows(cm, upstreamIP, probeUDP53))
}
