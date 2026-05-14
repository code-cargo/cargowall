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

	"github.com/stretchr/testify/mock"
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

// applyAutoAllowHelpers must NOT touch the firewall when no helper would
// run — otherwise it'd push an unchanged allowlist on every call and waste
// BPF map work for standalone users with no auto-allow flags set.
func TestApplyAutoAllowHelpers_NoFlagsNoUpdate(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	// NewMockFirewall(t) fails the test on any unexpected call, so the
	// absence of an EXPECT() asserts UpdateAllowlistTC is never invoked.
	fw := firewall.NewMockFirewall(t)

	cmd := &StartCmd{} // every flag false, no ApiUrl
	applyAutoAllowHelpers(cmd, cm, fw, quietLogger())
}

// When at least one helper runs, the dispatcher must call UpdateAllowlistTC
// exactly once at the end (not once per helper).
func TestApplyAutoAllowHelpers_AnyFlagTriggersSingleUpdate(t *testing.T) {
	t.Setenv("CI_SERVER_URL", "")
	t.Setenv("CI_REGISTRY", "")
	t.Setenv("CI_API_V4_URL", "")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	fw := firewall.NewMockFirewall(t)
	fw.EXPECT().UpdateAllowlistTC(mock.Anything).Return(nil).Once()

	cmd := &StartCmd{AutoAllowGitlabHosts: true}
	applyAutoAllowHelpers(cmd, cm, fw, quietLogger())
}

// ApiUrl alone (no CI flags) is enough to trigger the dispatcher because the
// CodeCargo API allow runs whenever an api-url is set.
func TestApplyAutoAllowHelpers_ApiUrlAloneTriggersUpdate(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	fw := firewall.NewMockFirewall(t)
	fw.EXPECT().UpdateAllowlistTC(mock.Anything).Return(nil).Once()

	cmd := &StartCmd{ApiUrl: "https://api.codecargo.com"}
	applyAutoAllowHelpers(cmd, cm, fw, quietLogger())

	// And the API hostname should be in the resolved rules.
	got := hostnameRulesFor(t, cm, config.AutoAddedTypeCodeCargoService)
	require.Contains(t, got, "api.codecargo.com")
}

func TestApplyCloudMetadataAllows_NoUpstreamsGCPOnly(t *testing.T) {
	t.Setenv("CARGOWALL_AZURE_INFRA_HOSTS", "")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	applyCloudMetadataAllows(cm, nil, quietLogger())

	// Link-local metadata IP allowed on 80 — covers Azure IMDS and GCP both.
	require.Equal(t, config.AutoAddedTypeGCPInfrastructure,
		cm.GetAutoAllowedType("169.254.169.254", 80, ""))

	// No Azure-specific rules added when no Azure wireserver in upstreams.
	require.Equal(t, config.AutoAddedTypeNone,
		cm.GetAutoAllowedType("168.63.129.16", 80, ""))
	require.Empty(t, hostnameRulesFor(t, cm, config.AutoAddedTypeAzureInfrastructure))
}

func TestApplyCloudMetadataAllows_AzureDetectedAddsWireserver(t *testing.T) {
	t.Setenv("CARGOWALL_AZURE_INFRA_HOSTS", "")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	applyCloudMetadataAllows(cm, []string{"168.63.129.16"}, quietLogger())

	// Wireserver HTTP and health ports get the Azure tag. Port 53 is added
	// by EnsureDNSAllowed first and tagged "dns"; GetAutoAllowedType is
	// first-match-wins, so the later AzureInfrastructure rule is shadowed
	// for port 53 only. Asserting both pins down the actual semantics.
	for _, port := range []uint16{80, 32526} {
		require.Equal(t, config.AutoAddedTypeAzureInfrastructure,
			cm.GetAutoAllowedType("168.63.129.16", port, ""),
			"168.63.129.16:%d should be auto-allowed as Azure infra", port)
	}
	require.Equal(t, config.AutoAddedTypeDNS,
		cm.GetAutoAllowedType("168.63.129.16", 53, ""),
		"168.63.129.16:53 is tagged DNS by EnsureDNSAllowed (first-match wins)")

	// Azure infrastructure hostnames added.
	azureHosts := hostnameRulesFor(t, cm, config.AutoAddedTypeAzureInfrastructure)
	require.Contains(t, azureHosts, "trafficmanager.net")
	require.Contains(t, azureHosts, "blob.core.windows.net")

	// GCP-tagged metadata IP still allowed (the always-on baseline).
	require.Equal(t, config.AutoAddedTypeGCPInfrastructure,
		cm.GetAutoAllowedType("169.254.169.254", 80, ""))
}

func TestApplyCloudMetadataAllows_AzureHostsEnvOverride(t *testing.T) {
	t.Setenv("CARGOWALL_AZURE_INFRA_HOSTS", "internal.example,corp.example")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	applyCloudMetadataAllows(cm, []string{"168.63.129.16"}, quietLogger())

	azureHosts := hostnameRulesFor(t, cm, config.AutoAddedTypeAzureInfrastructure)
	require.Contains(t, azureHosts, "internal.example")
	require.Contains(t, azureHosts, "corp.example")
	require.NotContains(t, azureHosts, "trafficmanager.net",
		"default hosts should be replaced when env override is set")
}

// autoAllowFromEnvURLs must skip env values that parse as URLs without an
// authority component (e.g. a bare hostname with no scheme), otherwise we'd
// add a malformed empty-hostname rule and silently widen the policy.
func TestAutoAllowFromEnvURLs_SkipsMalformedURLs(t *testing.T) {
	t.Setenv("TEST_URL_BARE", "gitlab.example") // no scheme → u.Hostname() == ""
	t.Setenv("TEST_URL_EMPTY", "")
	t.Setenv("TEST_URL_VALID", "https://valid.example/path")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	autoAllowFromEnvURLs(cm, quietLogger(), config.AutoAddedTypeGitLabService, "test",
		[]string{"TEST_URL_BARE", "TEST_URL_EMPTY", "TEST_URL_VALID"})

	got := hostnameRulesFor(t, cm, config.AutoAddedTypeGitLabService)
	require.Equal(t, []string{"valid.example"}, got,
		"only the well-formed URL's hostname should be added")
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
