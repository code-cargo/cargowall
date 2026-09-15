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
	if got := cm.StripSearchDomains("myservice.corp.lan"); got != "myservice" {
		t.Errorf("StripSearchDomains = %q, want myservice", got)
	}
}

func TestSetHostSearchDomains_LongestSuffixWins(t *testing.T) {
	cm := newCMWithSearchDomains(t, []Rule{{Type: RuleTypeHostname, Value: "a", Action: ActionAllow}})
	cm.SetHostSearchDomains([]string{"lan", "corp.lan"}, slog.Default())
	if got := cm.StripSearchDomains("a.corp.lan"); got != "a" {
		t.Errorf("StripSearchDomains = %q, want a (longest suffix)", got)
	}
}

func TestSetHostSearchDomains_NormalizesAndSkipsPublicSuffixes(t *testing.T) {
	cm := NewConfigManager()
	cm.SetHostSearchDomains([]string{" Corp.LAN. ", "lan", "internal", "com", "co.uk", "github.io", "", "lan"}, slog.Default())
	got := cm.HostSearchDomains()
	slices.Sort(got)
	want := []string{".corp.lan", ".internal", ".lan"}
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

func TestIsPublicSuffix(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"lan", false},      // unknown single label: the PSL default rule, not a real suffix
		{"internal", false}, // private-use entry, single label
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
