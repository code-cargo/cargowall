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

func TestSetHostSearchDomains_StripOnly(t *testing.T) {
	cm := newCMWithSearchDomains(t, []Rule{
		{Type: RuleTypeHostname, Value: "myservice", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "blocked", Action: ActionDeny},
	})
	cm.SetHostSearchDomains([]string{"corp.lan", "lan"}, slog.Default())

	v := cm.MatchHostnameRule("myservice.corp.lan")
	if !v.HasAllow() || v.AllowRule != "myservice" {
		t.Errorf("myservice.corp.lan: verdict %+v, want allow via rule myservice", v)
	}
	if v := cm.MatchHostnameRule("blocked.lan"); !v.HasDeny() {
		t.Errorf("blocked.lan: verdict %+v, want deny via stripped form", v)
	}
	if v := cm.MatchHostnameRule("other.corp.lan"); v.Matched() {
		t.Errorf("other.corp.lan: verdict %+v, want no match — stripping is not a bypass", v)
	}
	if cm.HasSearchDomainSuffix("other.corp.lan") {
		t.Error("host search domains must never grant the search-domain bypass")
	}
	if got := cm.StripSearchDomains("myservice.corp.lan"); got != "myservice.corp.lan" {
		t.Errorf("StripSearchDomains = %q, want the name unchanged: the host list is a matching candidate, not the canonical strip", got)
	}
	if got := cm.FindTrackedHostname("myservice.corp.lan"); got != "myservice" {
		t.Errorf("FindTrackedHostname = %q, want myservice (attribution names the rule that fired)", got)
	}
}

// A host suffix longer than a policy suffix must not displace the stripped
// form existing rules were written against (#130 review). Runner pod in
// namespace "runners": the Kubernetes strip yields db.runners, the host strip
// yields db; rules against either must keep matching.
func TestHostSearch_DoesNotDisplacePolicyStrip(t *testing.T) {
	const fqdn = "db.runners.svc.cluster.local"
	hostList := []string{"runners.svc.cluster.local", "svc.cluster.local", "cluster.local"}

	cm := newCMWithSearchDomains(t, []Rule{{Type: RuleTypeHostname, Value: "db.runners", Action: ActionAllow}})
	cm.SetHostSearchDomains(hostList, slog.Default())
	if v := cm.MatchHostnameRule(fqdn); !v.HasAllow() || v.AllowRule != "db.runners" {
		t.Errorf("allow db.runners: verdict %+v, want allow via db.runners", v)
	}
	if got := cm.FindTrackedHostname(fqdn); got != "db.runners" {
		t.Errorf("FindTrackedHostname = %q, want db.runners", got)
	}

	// Deny variant under default allow: the deny must keep applying.
	cm = NewConfigManager()
	if err := cm.LoadConfigFromRules([]Rule{{Type: RuleTypeHostname, Value: "db.runners", Action: ActionDeny}}, ActionAllow); err != nil {
		t.Fatal(err)
	}
	cm.SetHostSearchDomains(hostList, slog.Default())
	if v := cm.MatchHostnameRule(fqdn); !v.HasDeny() || v.DenyRule != "db.runners" {
		t.Errorf("deny db.runners: verdict %+v, want deny via db.runners", v)
	}

	// The host strip is an additional form: a rule against it matches too.
	cm = newCMWithSearchDomains(t, []Rule{{Type: RuleTypeHostname, Value: "db", Action: ActionAllow}})
	cm.SetHostSearchDomains(hostList, slog.Default())
	if v := cm.MatchHostnameRule(fqdn); !v.HasAllow() || v.AllowRule != "db" {
		t.Errorf("allow db: verdict %+v, want allow via db (host strip)", v)
	}

	// Operator suffix plus a longer DHCP suffix, no Kubernetes involved.
	cm = newCMWithSearchDomains(t, []Rule{{Type: RuleTypeHostname, Value: "db.team", Action: ActionAllow}}, ".corp.example")
	cm.SetHostSearchDomains([]string{"team.corp.example"}, slog.Default())
	if v := cm.MatchHostnameRule("db.team.corp.example"); !v.HasAllow() || v.AllowRule != "db.team" {
		t.Errorf("operator strip: verdict %+v, want allow via db.team", v)
	}
}

// Policy strip and host strip matching opposite rules is a mixed verdict,
// and attribution follows the deny — the same precedence the two-form
// verdict always had.
func TestHostSearch_PolicyAndHostFormsDisagree(t *testing.T) {
	cm := newCMWithSearchDomains(t, []Rule{
		{Type: RuleTypeHostname, Value: "db.runners", Action: ActionAllow},
		{Type: RuleTypeHostname, Value: "db", Action: ActionDeny},
	})
	cm.SetHostSearchDomains([]string{"runners.svc.cluster.local"}, slog.Default())
	v := cm.MatchHostnameRule("db.runners.svc.cluster.local")
	if !v.HasAllow() || v.AllowRule != "db.runners" || !v.HasDeny() || v.DenyRule != "db" {
		t.Errorf("verdict %+v, want mixed: allow db.runners, deny db", v)
	}
	if got := cm.FindTrackedHostname("db.runners.svc.cluster.local"); got != "db" {
		t.Errorf("FindTrackedHostname = %q, want db (deny outranks allow)", got)
	}
}

// Within the host list the longest suffix wins, as within the policy list:
// with "search corp.lan lan" a resolver expands "a" to "a.corp.lan", whose
// host form is "a" — not "a.corp".
func TestSetHostSearchDomains_LongestSuffixWins(t *testing.T) {
	cm := newCMWithSearchDomains(t, []Rule{{Type: RuleTypeHostname, Value: "a", Action: ActionAllow}})
	cm.SetHostSearchDomains([]string{"lan", "corp.lan"}, slog.Default())
	if v := cm.MatchHostnameRule("a.corp.lan"); !v.HasAllow() || v.AllowRule != "a" {
		t.Errorf("verdict %+v, want allow via rule a", v)
	}

	cm = newCMWithSearchDomains(t, []Rule{{Type: RuleTypeHostname, Value: "a.corp", Action: ActionAllow}})
	cm.SetHostSearchDomains([]string{"lan", "corp.lan"}, slog.Default())
	if v := cm.MatchHostnameRule("a.corp.lan"); v.Matched() {
		t.Errorf("verdict %+v, want no match: only the longest host suffix is a candidate", v)
	}
}

func TestSetHostSearchDomains_NormalizesAndSkipsPublicSuffixes(t *testing.T) {
	cm := NewConfigManager()
	cm.SetHostSearchDomains([]string{" Corp.LAN. ", "lan", "internal", "home.arpa", "com", "co.uk", "github.io", "", "lan"}, slog.Default())
	got := cm.HostSearchDomains()
	slices.Sort(got)
	want := []string{".corp.lan", ".home.arpa", ".internal", ".lan"}
	if !slices.Equal(got, want) {
		t.Errorf("HostSearchDomains = %v, want %v (public suffixes skipped, single private labels kept, deduped)", got, want)
	}
}

func TestSetHostSearchDomains_SurvivesPolicyLoadAndClears(t *testing.T) {
	cm := NewConfigManager()
	cm.SetHostSearchDomains([]string{"lan"}, slog.Default())
	if err := cm.LoadConfigFromRules([]Rule{{Type: RuleTypeHostname, Value: "svc", Action: ActionAllow}}, ActionDeny); err != nil {
		t.Fatalf("LoadConfigFromRules() error = %v", err)
	}
	if !cm.MatchHostnameRule("svc.lan").HasAllow() {
		t.Error("host search list must survive a policy load")
	}
	cm.SetHostSearchDomains(nil, slog.Default())
	if cm.MatchHostnameRule("svc.lan").HasAllow() {
		t.Error("a cleared host search list must stop stripping")
	}
}

func TestIsHostSearchSuffix(t *testing.T) {
	cm := NewConfigManager()
	cm.SetHostSearchDomains([]string{"corp.lan", "lan"}, slog.Default())
	for suffix, want := range map[string]bool{
		"corp.lan": true, "CORP.LAN": true, ".corp.lan": true, "corp.lan.": true, "lan": true,
		"blacksmith.sh": false, "orp.lan": false, "": false,
	} {
		if got := cm.IsHostSearchSuffix(suffix); got != want {
			t.Errorf("IsHostSearchSuffix(%q) = %v, want %v", suffix, got, want)
		}
	}
}

func TestIsPublicSuffix(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"lan", false},       // unknown single label: the PSL default rule, not a real suffix
		{"internal", false},  // private-use entry, single label
		{"home.arpa", false}, // ICANN PSL entry, but RFC 8375 special-use: unregistrable, safe to strip
		{"corp.lan", false},
		{"compute.internal", false},
		{"com", true},
		{"co.uk", true},
		{"github.io", true}, // private PSL entry, multi-label
	} {
		if got := isPublicSuffix(tc.in); got != tc.want {
			t.Errorf("isPublicSuffix(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
