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
	"log/slog"
	"slices"
	"testing"
)

// countRules returns how many resolved rules carry the given auto-added
// type, so a replay that duplicated entries is visible rather than hidden
// behind a "does it match" check.
func countRules(cm *Manager, autoType AutoAddedType) int {
	n := 0
	for _, r := range cm.GetResolvedRules() {
		if r.AutoAddedType == autoType {
			n++
		}
	}
	return n
}

// A config load replaces cm.config wholesale. Every auto-added
// infrastructure allow must survive it — the auto-allow pass now runs
// before the policy fetch, so a wipe would leave the DNS proxy refusing
// infrastructure hostnames for the length of that fetch (issue #119).
func TestAutoAllowReplay_SurvivesConfigLoad(t *testing.T) {
	cm := NewConfigManager()
	cm.EnsureBaseConfig()

	cm.EnsureHostnameAllowed("blob.core.windows.net", []Port{PortHTTPS}, AutoAddedTypeAzureInfrastructure)
	cm.EnsureInfraAllowed([]string{"168.63.129.16"}, []Port{PortHTTP}, AutoAddedTypeAzureInfrastructure)
	cm.AddSearchDomains([]string{".internal.cloudapp.net"}, slog.Default())

	// The policy that lands afterwards names none of them.
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	v := cm.MatchHostnameRule("productionresultssa16.blob.core.windows.net")
	if !v.HasAllow() {
		t.Errorf("after load, MatchHostnameRule(subdomain) = %+v, want allow", v)
	}
	if v.AllowRule != "blob.core.windows.net" {
		t.Errorf("after load, AllowRule = %q, want blob.core.windows.net", v.AllowRule)
	}
	if !slices.Contains(cm.GetSearchDomains(), ".internal.cloudapp.net") {
		t.Errorf("after load, GetSearchDomains() = %v, want the auto-added suffix", cm.GetSearchDomains())
	}
	if got := countRules(cm, AutoAddedTypeAzureInfrastructure); got != 2 {
		t.Errorf("after load, azure_infrastructure rules = %d, want 2 (hostname + CIDR, no duplicates)", got)
	}
	if !cm.MatchHostnameRule("github.com").HasAllow() {
		t.Errorf("the loaded policy's own rules must still apply")
	}
}

// Replay runs the same suppression checks as the original call against the
// NEWLY loaded ruleset, so an operator deny arriving with the policy still
// vetoes an infra auto-allow — the precedence the old "auto-allow always
// runs last" ordering gave for free.
func TestAutoAllowReplay_LoadedDenyVetoesInfraAllow(t *testing.T) {
	cm := NewConfigManager()
	cm.EnsureBaseConfig()
	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []Port{PortHTTP}, AutoAddedTypeCloudMetadata)

	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeCIDR, Value: "169.254.0.0/16", Action: ActionDeny},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	if got := countRules(cm, AutoAddedTypeCloudMetadata); got != 0 {
		t.Errorf("cloud_metadata rules after a covering deny = %d, want 0 (vetoed)", got)
	}
}

// Helpers called before any loader has run record their input even though
// the application no-ops on a nil config, so the first load installs them.
// This is what lets the auto-allow pass precede the policy fetch.
func TestAutoAllowReplay_RecordedBeforeAnyConfigExists(t *testing.T) {
	cm := NewConfigManager()

	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)
	if len(cm.GetResolvedRules()) != 0 {
		t.Fatalf("nil config must stay ruleless, got %d rules", len(cm.GetResolvedRules()))
	}

	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if !cm.MatchHostnameRule("github.com").HasAllow() {
		t.Errorf("the recorded allow must land on the first loaded config")
	}
}

// Repeated identical calls (call sites that predate the replay layer still
// name the same hostname twice) must not stack up entries that re-log and
// re-apply on every load.
func TestAutoAllowReplay_DedupsIdenticalCalls(t *testing.T) {
	cm := NewConfigManager()
	cm.EnsureBaseConfig()

	for range 3 {
		cm.EnsureHostnameAllowed("app.codecargo.com", []Port{PortHTTPS}, AutoAddedTypeCodeCargoService)
	}
	if got := len(cm.autoAllows); got != 1 {
		t.Errorf("recorded auto-allows = %d, want 1", got)
	}

	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if got := countRules(cm, AutoAddedTypeCodeCargoService); got != 1 {
		t.Errorf("codecargo_service rules after load = %d, want 1", got)
	}
}

// EnsureBaseConfig only fills a vacuum: an already-loaded policy must not be
// replaced by the deny-default stub.
func TestEnsureBaseConfig_LeavesLoadedConfigAlone(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionAllow); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cm.EnsureBaseConfig()

	if got := cm.GetDefaultAction(); got != ActionAllow {
		t.Errorf("GetDefaultAction() = %q, want %q (loaded config untouched)", got, ActionAllow)
	}
	if !cm.MatchHostnameRule("github.com").HasAllow() {
		t.Errorf("the loaded rule must survive EnsureBaseConfig")
	}
}

// A fresh manager has no config at all, so the base config must both exist
// and be deny-default — the same posture GetDefaultAction reports for nil.
func TestEnsureBaseConfig_SeedsDenyDefault(t *testing.T) {
	cm := NewConfigManager()
	cm.EnsureBaseConfig()

	if got := cm.GetDefaultAction(); got != ActionDeny {
		t.Errorf("GetDefaultAction() = %q, want %q", got, ActionDeny)
	}
	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)
	if !cm.MatchHostnameRule("github.com").HasAllow() {
		t.Errorf("the seeded config must accept auto-allow rules")
	}
}
