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
	"strings"
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

// Hostname auto-allows have no deny-veto: an allow for a name the policy
// denies is appended anyway and wins on exact-match-last. That asymmetry
// with the CIDR path predates the replay layer, and this pins the property
// that matters here — the reorder must not CHANGE the verdict. Both
// orderings (helpers after the load, as before #119; helpers before it,
// replayed) must agree, whatever that verdict is.
func TestAutoAllowReplay_HostnamePrecedenceUnchangedByOrdering(t *testing.T) {
	const host = "blob.core.windows.net"
	policy := []Rule{{Type: RuleTypeHostname, Value: host, Action: ActionDeny}}

	// Pre-#119 ordering: policy first, auto-allow after.
	afterLoad := NewConfigManager()
	if err := afterLoad.LoadConfigFromRules(policy, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	afterLoad.EnsureHostnameAllowed(host, []Port{PortHTTPS}, AutoAddedTypeAzureInfrastructure)

	// Post-#119 ordering: auto-allow first, replayed by the load.
	beforeLoad := NewConfigManager()
	beforeLoad.EnsureHostnameAllowed(host, []Port{PortHTTPS}, AutoAddedTypeAzureInfrastructure)
	if err := beforeLoad.LoadConfigFromRules(policy, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	got, want := beforeLoad.MatchHostnameRule(host), afterLoad.MatchHostnameRule(host)
	if got.HasAllow() != want.HasAllow() || got.HasDeny() != want.HasDeny() ||
		got.AllowRule != want.AllowRule || got.DenyRule != want.DenyRule {
		t.Errorf("verdict differs by ordering:\n  replayed    = %+v\n  after-load  = %+v", got, want)
	}
	// Documenting the shared verdict rather than asserting it is right: the
	// auto-allow wins. Whether it should is issue #121.
	if !got.HasAllow() {
		t.Errorf("expected the documented (allow-wins) verdict, got %+v", got)
	}
}

// A helper called before any loader has run is matchable immediately — the
// property the whole reorder rests on, since the DNS proxy arms query
// filtering before the first policy source is read.
func TestAutoAllowReplay_MatchableOnAFreshManager(t *testing.T) {
	cm := NewConfigManager()

	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)
	if !cm.MatchHostnameRule("api.github.com").HasAllow() {
		t.Fatalf("auto-allow must be matchable with no config loaded, got %d rules", len(cm.GetResolvedRules()))
	}

	// And it survives the load that arrives later.
	if err := cm.LoadConfigFromRules(nil, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if !cm.MatchHostnameRule("api.github.com").HasAllow() {
		t.Errorf("the journalled allow must survive the first loaded config")
	}
}

// Repeated identical calls (call sites that predate the replay layer still
// name the same hostname twice) must not stack up entries that re-log and
// re-apply on every load.
func TestAutoAllowReplay_DedupsIdenticalCalls(t *testing.T) {
	cm := NewConfigManager()

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

// The ops log announces an auto-allow once, where it is installed. A replay
// must stay silent: re-announcing the same rules on every load misdates the
// install, and the #119 CI gate — which asserts the last announcement
// precedes the DNS proxy arming — cannot tell a replay from a late install.
func TestAutoAllowReplay_DoesNotReAnnounce(t *testing.T) {
	var captured []string
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&captureWriter{out: &captured},
		&slog.HandlerOptions{Level: slog.LevelDebug})))

	cm := NewConfigManager()
	cm.EnsureHostnameAllowed("gitlab.com", []Port{PortHTTPS}, AutoAddedTypeGitLabService)
	cm.EnsureInfraAllowed([]string{"169.254.169.254"}, []Port{PortHTTP}, AutoAddedTypeCloudMetadata)

	if got := countLines(captured, "Auto-added infrastructure hostname allow rule"); got != 1 {
		t.Fatalf("hostname install announcements = %d, want 1", got)
	}
	if got := countLines(captured, "Auto-added allow rule"); got != 1 {
		t.Fatalf("CIDR install announcements = %d, want 1", got)
	}

	captured = nil
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	if got := countLines(captured, "Auto-added"); got != 0 {
		t.Errorf("replay re-announced %d install lines, want 0: %v", got, captured)
	}
	// Silent, but not absent from the log entirely — and the rules landed.
	if got := countLines(captured, "Re-applied journalled auto-allows"); got != 1 {
		t.Errorf("replay summary lines = %d, want 1", got)
	}
	if !cm.MatchHostnameRule("gitlab.com").HasAllow() {
		t.Errorf("a silent replay must still install the rules")
	}
}

func countLines(lines []string, substr string) int {
	n := 0
	for _, line := range lines {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// Seeding only fills a vacuum: an auto-allow arriving after a policy load
// must not replace that policy with the deny-default stub.
func TestAutoAllowSeed_LeavesLoadedConfigAlone(t *testing.T) {
	cm := NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{
		{Type: RuleTypeHostname, Value: "github.com", Action: ActionAllow},
	}, ActionAllow); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}

	cm.EnsureHostnameAllowed("app.codecargo.com", []Port{PortHTTPS}, AutoAddedTypeCodeCargoService)

	if got := cm.GetDefaultAction(); got != ActionAllow {
		t.Errorf("GetDefaultAction() = %q, want %q (loaded config untouched)", got, ActionAllow)
	}
	if !cm.MatchHostnameRule("github.com").HasAllow() {
		t.Errorf("the loaded rule must survive an auto-allow")
	}
}

// The seeded config is deny-default — the same posture GetDefaultAction
// already reports for a nil config, so seeding widens what is allowed before
// a policy lands, never what is denied.
func TestAutoAllowSeed_IsDenyDefault(t *testing.T) {
	cm := NewConfigManager()
	cm.EnsureHostnameAllowed("github.com", []Port{PortHTTPS}, AutoAddedTypeGitHubService)

	if got := cm.GetDefaultAction(); got != ActionDeny {
		t.Errorf("GetDefaultAction() = %q, want %q", got, ActionDeny)
	}
	if cm.MatchHostnameRule("evil.example.com").Matched() {
		t.Errorf("seeding must not allow anything but the auto-allows themselves")
	}
}
