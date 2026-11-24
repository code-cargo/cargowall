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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
)

// infos returns the INFO lines among logs.
func infos(logs []string) []string {
	var out []string
	for _, line := range logs {
		if strings.Contains(line, "level=INFO") {
			out = append(out, line)
		}
	}
	return out
}

func enforcingPolicy(searchDomains ...string) *cargowallv1pb.CargoWallPolicy {
	return &cargowallv1pb.CargoWallPolicy{
		Mode:          datapb.CargoWallMode_CARGO_WALL_MODE_ENFORCE,
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		Rules: []*cargowallv1pb.CargoWallPolicy_Rule{{
			Type:   datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME,
			Value:  "github.com",
			Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW,
		}},
		SearchDomains: searchDomains,
	}
}

// One search domain cargowall refuses, merged in from anywhere up the
// policy chain, must not refuse the policy: the run would fall to the
// policy-fetch failure posture and nothing in the policy would apply.
func TestLoadConfigFromCargoWall_InvalidSearchDomainDropped(t *testing.T) {
	logs := captureLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromCargoWall(enforcingPolicy(".compute.internal", "corp", ".corp.example.com")))

	assert.False(t, cm.IsAuditMode(), "the policy loads and enforces")
	assert.Equal(t, []string{".compute.internal", ".corp.example.com"}, cm.GetSearchDomains())
	assert.True(t, cm.HasSearchDomainSuffix("build.corp.example.com"), "the valid entries apply")
	assert.Equal(t, ActionDeny, cm.GetDefaultAction())
	assert.Len(t, cm.config.Rules, 1, "the rules apply")

	ws := warns(*logs)
	require.Len(t, ws, 1)
	assert.Contains(t, ws[0], `\".corp\": a single label`, "the Warn names the entry and its reason")
	assert.Contains(t, ws[0], "the rest of the policy loaded")
}

func TestLoadConfigFromCargoWall_OnlySearchDomainInvalid(t *testing.T) {
	logs := captureLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromCargoWall(enforcingPolicy("co.uk")))

	assert.False(t, cm.IsAuditMode())
	assert.Empty(t, cm.GetSearchDomains())
	assert.Len(t, cm.config.Rules, 1)
	assert.Len(t, warns(*logs), 1)
}

// Several refused entries share one Warn line: each Warn becomes a job
// annotation, and an always-active Kubernetes suffix is no misconfiguration
// at all, so it is reported at Info.
func TestLoadConfigFromCargoWall_SearchDomainDropClasses(t *testing.T) {
	refused := []struct{ domain, reason string }{
		{"corp", "a single label"},
		{"home.arpa", "a public suffix"},
		{"co.uk", "a public suffix"},
		{"", "empty"},
		{"bad_label.example.com", "an invalid label"},
		{"10.in-addr.arpa", "under a reverse-lookup zone"},
	}

	for _, tc := range refused {
		t.Run(tc.domain, func(t *testing.T) {
			logs := captureLogs(t)
			cm := NewConfigManager()
			require.NoError(t, cm.LoadConfigFromCargoWall(enforcingPolicy(tc.domain, ".compute.internal")))
			assert.Equal(t, []string{".compute.internal"}, cm.GetSearchDomains())
			ws := warns(*logs)
			require.Len(t, ws, 1)
			assert.Contains(t, ws[0], tc.reason)
		})
	}

	t.Run("svc.cluster.local", func(t *testing.T) {
		logs := captureLogs(t)
		cm := NewConfigManager()
		require.NoError(t, cm.LoadConfigFromCargoWall(enforcingPolicy("svc.cluster.local", ".compute.internal")))
		assert.Equal(t, []string{".compute.internal"}, cm.GetSearchDomains())
		assert.Empty(t, warns(*logs), "an always-active suffix changes nothing, so it is not a Warn")
		var dropped []string
		for _, line := range infos(*logs) {
			if strings.Contains(line, "always active for stripping") {
				dropped = append(dropped, line)
			}
		}
		require.Len(t, dropped, 1)
		assert.Contains(t, dropped[0], ".svc.cluster.local")
	})

	t.Run("all together", func(t *testing.T) {
		logs := captureLogs(t)
		cm := NewConfigManager()
		require.NoError(t, cm.LoadConfigFromCargoWall(enforcingPolicy(
			"corp", "home.arpa", "co.uk", "svc.cluster.local", ".compute.internal")))
		assert.Equal(t, []string{".compute.internal"}, cm.GetSearchDomains())
		ws := warns(*logs)
		require.Len(t, ws, 1, "one Warn covers every refused entry")
		for _, d := range []string{`\".corp\"`, `\".home.arpa\"`, `\".co.uk\"`} {
			assert.Contains(t, ws[0], d)
		}
		assert.Contains(t, ws[0], "count=3")
		assert.NotContains(t, ws[0], "svc.cluster.local")
	})
}

// The operator of one run writes the local file and the environment, so a
// bad entry there still stops the load, on the first invalid entry.
func TestLocalAndEnvSearchDomainsStillFailOnInvalid(t *testing.T) {
	for _, d := range []string{"corp", "home.arpa", "co.uk", "svc.cluster.local"} {
		t.Run(d, func(t *testing.T) {
			cm := NewConfigManager()
			err := cm.LoadConfig(writeJSONConfig(t,
				`{"defaultAction": "deny", "searchDomains": [".compute.internal", "`+d+`"]}`))
			require.Error(t, err, "local file")
			assert.Contains(t, err.Error(), "."+d)

			clearOtherCargowallEnv(t)
			t.Setenv("CARGOWALL_SEARCH_DOMAINS", ".compute.internal,"+d)
			err = NewConfigManager().LoadFromEnv()
			require.Error(t, err, "environment")
			assert.Contains(t, err.Error(), "CARGOWALL_SEARCH_DOMAINS")
			assert.Contains(t, err.Error(), `".`+d+`"`, "the error names the offending entry")
		})
	}
}

// Reverse-zone entries are dropped with the others, on the one Warn line,
// not each on a line of its own.
func TestLoadConfigFromCargoWall_ReverseZoneAndRefusedShareOneWarn(t *testing.T) {
	logs := captureLogs(t)
	cm := NewConfigManager()
	require.NoError(t, cm.LoadConfigFromCargoWall(enforcingPolicy(
		"10.in-addr.arpa", "168.192.in-addr.arpa", "ip6.arpa", "corp", ".compute.internal")))
	assert.Equal(t, []string{".compute.internal"}, cm.GetSearchDomains())
	ws := warns(*logs)
	require.Len(t, ws, 1, "one Warn for every drop: %v", ws)
	assert.Contains(t, ws[0], "count=4")
	for _, d := range []string{`\".10.in-addr.arpa\"`, `\".168.192.in-addr.arpa\"`, `\".ip6.arpa\"`, `\".corp\"`} {
		assert.Contains(t, ws[0], d)
	}
}

// The line names at most maxReportedSearchDomains entries and counts the
// rest, so a long merged list still makes a readable annotation.
func TestLoadConfigFromCargoWall_SearchDomainWarnIsCapped(t *testing.T) {
	logs := captureLogs(t)
	var domains []string
	for i := 0; i < maxReportedSearchDomains+5; i++ {
		domains = append(domains, fmt.Sprintf("corp%d", i))
	}
	require.NoError(t, NewConfigManager().LoadConfigFromCargoWall(enforcingPolicy(domains...)))
	ws := warns(*logs)
	require.Len(t, ws, 1)
	assert.Contains(t, ws[0], fmt.Sprintf("count=%d", maxReportedSearchDomains+5))
	assert.Contains(t, ws[0], "and 5 more")
	assert.Contains(t, ws[0], `\".corp9\"`)
	assert.NotContains(t, ws[0], `\".corp10\"`)
}

// A policy that fails to load for another reason says nothing about its
// search domains: the line would claim the rest of the policy loaded.
func TestLoadConfigFromCargoWall_NoSearchDomainReportWhenLoadFails(t *testing.T) {
	logs := captureLogs(t)
	policy := enforcingPolicy("corp", "svc.cluster.local")
	policy.Rules = append(policy.Rules, &cargowallv1pb.CargoWallPolicy_Rule{Value: "1.2.3.4/32"}) // no rule type
	require.Error(t, NewConfigManager().LoadConfigFromCargoWall(policy))
	for _, line := range *logs {
		assert.NotContains(t, line, "Search domains in the CodeCargo policy")
	}
}
