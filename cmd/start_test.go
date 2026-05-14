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
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Regression test for the nil-ports security bug: when an existing IP's
// hostname maps to a port-scoped allow rule, the firewall add must use the
// rule's ports, not nil (BPF treats nil as allow-on-all-ports).
func TestGateExistingConnections_InheritsRulePorts(t *testing.T) {
	wantPorts := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "*.compute-1.amazonaws.com", Ports: wantPorts, Action: config.ActionAllow},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("ec2-1-2-3-4.compute-1.amazonaws.com", "1.2.3.4")

	fw := firewall.NewMockFirewall(t)
	fw.EXPECT().AddIP(net.ParseIP("1.2.3.4"), config.ActionAllow, wantPorts).Return(true, nil).Once()

	gateExistingConnections([]string{"1.2.3.4"}, cm, fw, nil, quietLogger())
}

// Pre-existing connections to IPs we can't identify keep the all-ports allow
// policy so we don't break running processes at startup.
func TestGateExistingConnections_UnresolvableStillAllAllowed(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	fw := firewall.NewMockFirewall(t)
	// The matcher needs the typed nil ([]config.Port(nil)) — testify's mock
	// uses ObjectsAreEqual, which treats untyped nil and a typed nil slice
	// as different. The production code passes the result of MatchHostnameRule,
	// whose third return is a typed nil for the unresolvable case.
	fw.EXPECT().AddIP(net.ParseIP("203.0.113.5"), config.ActionAllow, []config.Port(nil)).Return(true, nil).Once()

	gateExistingConnections([]string{"203.0.113.5"}, cm, fw, nil, quietLogger())
}

// Denied pre-existing connections must not be added to the allowlist —
// NewMockFirewall(t) fails the test on any unexpected AddIP call.
func TestGateExistingConnections_DeniedHostnameNotAdded(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "blocked.example.com", Action: config.ActionDeny},
	}, config.ActionAllow))
	cm.UpdateDNSMapping("blocked.example.com", "10.20.30.40")

	fw := firewall.NewMockFirewall(t)

	gateExistingConnections([]string{"10.20.30.40"}, cm, fw, nil, quietLogger())
}

// hostnameRulesFor returns the allow-rule hostname strings tagged with the
// given AutoAddedType, in declaration order.
func hostnameRulesFor(t *testing.T, cm *config.Manager, want config.AutoAddedType) []string {
	t.Helper()
	var out []string
	for _, r := range cm.GetResolvedRules() {
		if r.Type == config.RuleTypeHostname && r.AutoAddedType == want && r.Action == config.ActionAllow {
			out = append(out, r.Value)
		}
	}
	return out
}

func TestAutoAllowGitlabHosts_DefaultsAndEnvDiscovery(t *testing.T) {
	t.Setenv("CI_SERVER_URL", "https://gitlab.example.com")
	t.Setenv("CI_REGISTRY", "https://registry.example.com")
	t.Setenv("CI_API_V4_URL", "https://gitlab.example.com/api/v4")
	t.Setenv("CI_PAGES_URL", "")
	t.Setenv("CI_REPOSITORY_URL", "")
	t.Setenv("CI_DEPENDENCY_PROXY_SERVER", "")
	t.Setenv("CI_PROJECT_URL", "")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	autoAllowGitlabHosts(cm, quietLogger())

	got := hostnameRulesFor(t, cm, config.AutoAddedTypeGitLabService)

	// Defaults must be present.
	require.Contains(t, got, "gitlab.com")
	require.Contains(t, got, "registry.gitlab.com")
	// Env-discovered hostnames must be present (deduplicated by EnsureHostnameAllowed).
	require.Contains(t, got, "gitlab.example.com")
	require.Contains(t, got, "registry.example.com")
}

func TestAutoAllowGitlabHosts_ServiceHostsEnvOverridesDefaults(t *testing.T) {
	t.Setenv("CARGOWALL_GITLAB_SERVICE_HOSTS", "gitlab.internal,gitlab-runner.internal")
	t.Setenv("CI_SERVER_URL", "")
	t.Setenv("CI_REGISTRY", "")
	t.Setenv("CI_API_V4_URL", "")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	autoAllowGitlabHosts(cm, quietLogger())

	got := hostnameRulesFor(t, cm, config.AutoAddedTypeGitLabService)
	require.Contains(t, got, "gitlab.internal")
	require.Contains(t, got, "gitlab-runner.internal")
	require.NotContains(t, got, "gitlab.com", "default hosts should be replaced when env override is set")
}

func TestAutoAllowGitHubHosts_RuntimeURLDiscovery(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_URL", "https://pipelines.actions.githubusercontent.com/abc/")
	t.Setenv("ACTIONS_RESULTS_URL", "https://results-receiver.actions.githubusercontent.com")
	t.Setenv("ACTIONS_CACHE_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	autoAllowGitHubHosts(cm, quietLogger())

	got := hostnameRulesFor(t, cm, config.AutoAddedTypeGitHubService)
	require.Contains(t, got, "github.com")
	require.Contains(t, got, "pipelines.actions.githubusercontent.com")
	require.Contains(t, got, "results-receiver.actions.githubusercontent.com")
}
