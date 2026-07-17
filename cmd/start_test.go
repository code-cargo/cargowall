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
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

	gateExistingConnections(existingConns{"1.2.3.4": {{Port: 443, Protocol: config.ProtocolTCP}}}, cm, fw, nil, quietLogger())
}

// Pre-existing connections to IPs we can't identify are kept alive, but only
// on their observed remote ports — an unidentifiable peer must not be opened
// on every port.
func TestGateExistingConnections_UnresolvableAllowsObservedPortsOnly(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	observed := []config.Port{
		{Port: 8443, Protocol: config.ProtocolTCP},
		{Port: 4433, Protocol: config.ProtocolUDP},
	}
	fw := firewall.NewMockFirewall(t)
	fw.EXPECT().AddIP(net.ParseIP("203.0.113.5"), config.ActionAllow, observed).Return(true, nil).Once()

	gateExistingConnections(existingConns{"203.0.113.5": observed}, cm, fw, nil, quietLogger())
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

	gateExistingConnections(existingConns{"10.20.30.40": {{Port: 443, Protocol: config.ProtocolTCP}}}, cm, fw, nil, quietLogger())
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

// emptyDMI / dmiWithVendor / dmiWithChassisTag isolate cloud-detection tests
// from the CI host's real DMI so the test suite is portable across runners.
func emptyDMI(t *testing.T) string {
	t.Helper()
	t.Setenv("CARGOWALL_CLOUD_PROVIDER", "")
	return t.TempDir()
}

func dmiWithVendor(t *testing.T, vendor string) string {
	t.Helper()
	t.Setenv("CARGOWALL_CLOUD_PROVIDER", "")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sys_vendor"), []byte(vendor), 0o644))
	return dir
}

func dmiWithChassisTag(t *testing.T, tag string) string {
	t.Helper()
	t.Setenv("CARGOWALL_CLOUD_PROVIDER", "")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "chassis_asset_tag"), []byte(tag), 0o644))
	return dir
}

func TestApplyCloudMetadataAllows_NoUpstreamsNoProviderDetected(t *testing.T) {
	t.Setenv("CARGOWALL_AZURE_INFRA_HOSTS", "")
	dmi := emptyDMI(t)

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	applyCloudMetadataAllows(cm, nil, dmi, quietLogger())

	// Shared link-local metadata IP allowed on 80 — the always-on baseline.
	require.Equal(t, config.AutoAddedTypeCloudMetadata,
		cm.GetAutoAllowedType("169.254.169.254", 80, config.ProtocolAll, ""))

	// No provider-specific rules added.
	require.Equal(t, config.AutoAddedTypeNone,
		cm.GetAutoAllowedType("168.63.129.16", 80, config.ProtocolAll, ""))
	require.Empty(t, hostnameRulesFor(t, cm, config.AutoAddedTypeAzureInfrastructure))
	require.Empty(t, cm.GetSearchDomains())
}

func TestApplyCloudMetadataAllows_AzureDetectedViaWireserver(t *testing.T) {
	t.Setenv("CARGOWALL_AZURE_INFRA_HOSTS", "")
	dmi := emptyDMI(t)

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	applyCloudMetadataAllows(cm, []string{"168.63.129.16"}, dmi, quietLogger())

	// Wireserver HTTP and health ports get the Azure tag. Port 53 is added
	// by EnsureDNSAllowed first and tagged "dns"; GetAutoAllowedType is
	// first-match-wins, so the later AzureInfrastructure rule is shadowed
	// for port 53 only. Asserting both pins down the actual semantics.
	for _, port := range []uint16{80, 32526} {
		require.Equal(t, config.AutoAddedTypeAzureInfrastructure,
			cm.GetAutoAllowedType("168.63.129.16", port, config.ProtocolAll, ""),
			"168.63.129.16:%d should be auto-allowed as Azure infra", port)
	}
	require.Equal(t, config.AutoAddedTypeDNS,
		cm.GetAutoAllowedType("168.63.129.16", 53, config.ProtocolAll, ""),
		"168.63.129.16:53 is tagged DNS by EnsureDNSAllowed (first-match wins)")

	// Azure infrastructure hostnames added.
	azureHosts := hostnameRulesFor(t, cm, config.AutoAddedTypeAzureInfrastructure)
	require.Contains(t, azureHosts, "trafficmanager.net")
	require.Contains(t, azureHosts, "blob.core.windows.net")

	// Shared metadata IP still allowed (the always-on baseline).
	require.Equal(t, config.AutoAddedTypeCloudMetadata,
		cm.GetAutoAllowedType("169.254.169.254", 80, config.ProtocolAll, ""))

	// Azure VM default internal DNS suffix auto-added.
	require.Contains(t, cm.GetSearchDomains(), ".internal.cloudapp.net")
}

func TestApplyCloudMetadataAllows_AzureHostsEnvOverride(t *testing.T) {
	t.Setenv("CARGOWALL_AZURE_INFRA_HOSTS", "internal.example,corp.example")
	dmi := emptyDMI(t)

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	applyCloudMetadataAllows(cm, []string{"168.63.129.16"}, dmi, quietLogger())

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

func TestDetectCloudProvider(t *testing.T) {
	tests := []struct {
		name       string
		envValue   string
		vendor     string // "" means no sys_vendor file
		chassisTag string // "" means no chassis_asset_tag file
		upstreams  []string
		want       cloudProvider
	}{
		{"env override aws", "aws", "", "", nil, cloudProviderAWS},
		{"env override azure", "azure", "", "", nil, cloudProviderAzure},
		{"env override gcp", "gcp", "", "", nil, cloudProviderGCP},
		{"env override case-insensitive", "AWS", "", "", nil, cloudProviderAWS},
		{"env override unknown value ignored", "linode", "Amazon EC2", "", nil, cloudProviderAWS},
		{"dmi aws", "", "Amazon EC2", "", nil, cloudProviderAWS},
		{"dmi azure via chassis tag", "", "Microsoft Corporation", azureChassisAssetTag, nil, cloudProviderAzure},
		{"dmi azure chassis tag only (no vendor)", "", "", azureChassisAssetTag, nil, cloudProviderAzure},
		{"plain Hyper-V VM is NOT Azure (vendor matches, chassis tag does not)", "", "Microsoft Corporation", "", nil, cloudProviderUnknown},
		{"dmi gcp", "", "Google", "", nil, cloudProviderGCP},
		{"dmi gcp with full name", "", "Google Compute Engine", "", nil, cloudProviderGCP},
		{"dmi ignored when env set", "azure", "Amazon EC2", "", nil, cloudProviderAzure},
		{"wireserver fallback when no DMI", "", "", "", []string{azureWireserverIP}, cloudProviderAzure},
		{"wireserver fallback ignored when DMI says AWS", "", "Amazon EC2", "", []string{azureWireserverIP}, cloudProviderAWS},
		{"plain Hyper-V VM with wireserver upstream IS Azure (via fallback)", "", "Microsoft Corporation", "", []string{azureWireserverIP}, cloudProviderAzure},
		{"unknown vendor and no wireserver", "", "Bochs", "", []string{"8.8.8.8"}, cloudProviderUnknown},
		{"no signals at all", "", "", "", nil, cloudProviderUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CARGOWALL_CLOUD_PROVIDER", tc.envValue)
			dir := t.TempDir()
			if tc.vendor != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "sys_vendor"), []byte(tc.vendor), 0o644))
			}
			if tc.chassisTag != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "chassis_asset_tag"), []byte(tc.chassisTag), 0o644))
			}
			got := detectCloudProvider(dir, tc.upstreams)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestApplyCloudMetadataAllows_AWSDetected(t *testing.T) {
	t.Setenv("CARGOWALL_AZURE_INFRA_HOSTS", "")
	dmi := dmiWithVendor(t, "Amazon EC2")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	applyCloudMetadataAllows(cm, nil, dmi, quietLogger())

	// Shared metadata IP still allowed (covers AWS IMDS at 169.254.169.254).
	require.Equal(t, config.AutoAddedTypeCloudMetadata,
		cm.GetAutoAllowedType("169.254.169.254", 80, config.ProtocolAll, ""))

	// AWS internal DNS suffixes auto-added.
	domains := cm.GetSearchDomains()
	require.Contains(t, domains, ".compute.internal")
	require.Contains(t, domains, ".ec2.internal")

	// No Azure-specific allows.
	require.Empty(t, hostnameRulesFor(t, cm, config.AutoAddedTypeAzureInfrastructure))
}

func TestApplyCloudMetadataAllows_AzureDetectedViaDMI(t *testing.T) {
	t.Setenv("CARGOWALL_AZURE_INFRA_HOSTS", "")
	// chassis_asset_tag is the Azure-specific signal — plain Hyper-V VMs
	// share the "Microsoft Corporation" sys_vendor but not this tag.
	dmi := dmiWithChassisTag(t, azureChassisAssetTag)

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	// Empty upstreams: DMI is the only signal. Confirms the DMI path is wired
	// even when systemd-resolved isn't readable.
	applyCloudMetadataAllows(cm, nil, dmi, quietLogger())

	// Azure wireserver allowed on its specific ports.
	require.Equal(t, config.AutoAddedTypeAzureInfrastructure,
		cm.GetAutoAllowedType("168.63.129.16", 80, config.ProtocolAll, ""))

	// Azure infrastructure hostnames added.
	azureHosts := hostnameRulesFor(t, cm, config.AutoAddedTypeAzureInfrastructure)
	require.Contains(t, azureHosts, "trafficmanager.net")

	// Default Azure internal DNS suffix added.
	require.Contains(t, cm.GetSearchDomains(), ".internal.cloudapp.net")
}

func TestApplyCloudMetadataAllows_GCPDetected(t *testing.T) {
	dmi := dmiWithVendor(t, "Google Compute Engine")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	applyCloudMetadataAllows(cm, nil, dmi, quietLogger())

	require.Equal(t, config.AutoAddedTypeCloudMetadata,
		cm.GetAutoAllowedType("169.254.169.254", 80, config.ProtocolAll, ""))

	// GCP internal DNS suffix auto-added (covers metadata.google.internal).
	require.Contains(t, cm.GetSearchDomains(), ".google.internal")

	// No Azure-specific allows.
	require.Empty(t, hostnameRulesFor(t, cm, config.AutoAddedTypeAzureInfrastructure))
}

// writeProcNetFixture writes a /proc/net/{tcp,udp}{,6}-format file. Lines
// share the sl/local_address/rem_address/st column layout; trailing columns
// are irrelevant to the parser.
func writeProcNetFixture(t *testing.T, name string, lines []string) string {
	t.Helper()
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for _, l := range lines {
		content += l + "\n"
	}
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestScanProcNet(t *testing.T) {
	// Remote addresses are hex little-endian per 4-byte group:
	// "22D8B85D" = 93.184.216.34, "0100007F" = 127.0.0.1. Ports are
	// big-endian hex: 01BB = 443, 0050 = 80, 0035 = 53.
	tests := []struct {
		name       string
		lines      []string
		isIPv6     bool
		wantStates map[string]bool
		proto      config.ProtocolType
		want       map[string][]config.Port
	}{
		{
			name: "tcp keeps established and in-flight handshakes with observed ports",
			lines: []string{
				"   0: 0100000A:D431 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1", // ESTABLISHED
				"   1: 0100000A:D432 0101A8C0:0050 02 00000000:00000000 00:00000000 00000000  1000        0 2", // SYN_SENT
				"   2: 0100000A:D433 0201A8C0:0050 03 00000000:00000000 00:00000000 00000000  1000        0 3", // SYN_RECV
			},
			wantStates: tcpScanStates,
			proto:      config.ProtocolTCP,
			want: map[string][]config.Port{
				"93.184.216.34": {{Port: 443, Protocol: config.ProtocolTCP}},
				"192.168.1.1":   {{Port: 80, Protocol: config.ProtocolTCP}},
				"192.168.1.2":   {{Port: 80, Protocol: config.ProtocolTCP}},
			},
		},
		{
			name: "tcp skips closing and listening states",
			lines: []string{
				"   0: 0100000A:D431 22D8B85D:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 1", // TIME_WAIT
				"   1: 0100000A:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2", // LISTEN
			},
			wantStates: tcpScanStates,
			proto:      config.ProtocolTCP,
			want:       map[string][]config.Port{},
		},
		{
			name: "skips loopback and zero remotes even in wanted states",
			lines: []string{
				"   0: 0100000A:D431 0100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1", // loopback
				"   1: 0100000A:D432 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 2", // unspecified
			},
			wantStates: tcpScanStates,
			proto:      config.ProtocolTCP,
			want:       map[string][]config.Port{},
		},
		{
			name: "udp keeps connected sockets only",
			lines: []string{
				"   0: 0100000A:8235 22D8B85D:0035 01 00000000:00000000 00:00000000 00000000  1000        0 1", // connected
				"   1: 0100000A:8236 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 2", // unconnected
			},
			wantStates: udpScanStates,
			proto:      config.ProtocolUDP,
			want: map[string][]config.Port{
				"93.184.216.34": {{Port: 53, Protocol: config.ProtocolUDP}},
			},
		},
		{
			name: "malformed lines are skipped",
			lines: []string{
				"garbage",
				"   0: 0100000A:D431",
				"   1: 0100000A:D431 ZZZZZZZZ:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1",
				"   2: 0100000A:D431 22D8B85D:ZZZZ 01 00000000:00000000 00:00000000 00000000  1000        0 2",
				"   3: 0100000A:D431 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 3",
			},
			wantStates: tcpScanStates,
			proto:      config.ProtocolTCP,
			want: map[string][]config.Port{
				"93.184.216.34": {{Port: 443, Protocol: config.ProtocolTCP}},
			},
		},
		{
			name: "ipv6 decodes groups and skips link-local",
			lines: []string{
				"   0: 00000000000000000000000001000000:D431 B80D01200000000067452301EFCDAB89:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1",
				"   1: 00000000000000000000000001000000:D432 000080FE000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2", // fe80::1 link-local
				"   2: 00000000000000000000000001000000:D433 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 3", // unspecified
			},
			isIPv6:     true,
			wantStates: tcpScanStates,
			proto:      config.ProtocolTCP,
			want: map[string][]config.Port{
				"2001:db8::123:4567:89ab:cdef": {{Port: 443, Protocol: config.ProtocolTCP}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeProcNetFixture(t, "procnet", tt.lines)
			seen := make(map[string]map[config.Port]bool)
			require.NoError(t, scanProcNet(path, tt.isIPv6, tt.wantStates, tt.proto, seen))

			got := make(map[string][]config.Port, len(seen))
			for ip, ports := range seen {
				for p := range ports {
					got[ip] = append(got[ip], p)
				}
			}
			require.Len(t, got, len(tt.want))
			for ip, wantPorts := range tt.want {
				require.ElementsMatch(t, wantPorts, got[ip], "ports for %s", ip)
			}
		})
	}
}

// hexIPv4LE encodes an IPv4 address in the little-endian hex format used by
// /proc/net/tcp remote-address columns.
func hexIPv4LE(t *testing.T, ip string) string {
	t.Helper()
	b := net.ParseIP(ip).To4()
	require.NotNil(t, b, "not an IPv4 address: %s", ip)
	return fmt.Sprintf("%02X%02X%02X%02X", b[3], b[2], b[1], b[0])
}

// tcpTuple is shorthand for an observed TCP remote port in tests.
func tcpTuple(port uint16) config.Port {
	return config.Port{Port: port, Protocol: config.ProtocolTCP}
}

// withProcNetFixture points procNetSources at a single fixture file listing
// the given remote "ip:port" TCP tuples as ESTABLISHED connections,
// restoring the real /proc sources when the test ends.
func withProcNetFixture(t *testing.T, tuples ...string) {
	t.Helper()
	lines := make([]string, 0, len(tuples))
	for i, tuple := range tuples {
		host, portStr, err := net.SplitHostPort(tuple)
		require.NoError(t, err, "fixture tuple must be ip:port: %s", tuple)
		port, err := strconv.ParseUint(portStr, 10, 16)
		require.NoError(t, err)
		lines = append(lines, fmt.Sprintf("   %d: 0100000A:D431 %s:%04X 01 00000000:00000000 00:00000000 00000000  1000        0 1", i, hexIPv4LE(t, host), port))
	}
	path := writeProcNetFixture(t, "tcp", lines)
	saved := procNetSources
	procNetSources = []procNetSource{{path: path, states: tcpScanStates, proto: config.ProtocolTCP}}
	t.Cleanup(func() { procNetSources = saved })
}

// The exclude set lets the pre-attach re-scan return only tuples that
// appeared after the initial scan — including a new port on an already-seen
// peer.
func TestScanExistingConnections_Exclude(t *testing.T) {
	withProcNetFixture(t, "198.51.100.7:443", "198.51.100.7:8443", "203.0.113.9:443")

	all, err := scanExistingConnections(nil)
	require.NoError(t, err)
	require.Equal(t, existingConns{
		"198.51.100.7": {tcpTuple(443), tcpTuple(8443)},
		"203.0.113.9":  {tcpTuple(443)},
	}, all)

	delta, err := scanExistingConnections(map[string]bool{
		tupleKey("198.51.100.7", tcpTuple(443)): true,
		tupleKey("203.0.113.9", tcpTuple(443)):  true,
	})
	require.NoError(t, err)
	require.Equal(t, existingConns{
		"198.51.100.7": {tcpTuple(8443)},
	}, delta, "a new port on an already-gated peer must still surface in the delta")
}

// A missing optional source (e.g. IPv6 disabled) must not fail the scan; a
// missing required source must.
func TestScanExistingConnections_OptionalSourceMayBeAbsent(t *testing.T) {
	path := writeProcNetFixture(t, "tcp", []string{
		"   0: 0100000A:D431 " + hexIPv4LE(t, "198.51.100.7") + ":01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1",
	})
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	saved := procNetSources
	t.Cleanup(func() { procNetSources = saved })

	procNetSources = []procNetSource{
		{path: path, states: tcpScanStates, proto: config.ProtocolTCP},
		{path: missing, states: udpScanStates, proto: config.ProtocolUDP, optional: true},
	}
	conns, err := scanExistingConnections(nil)
	require.NoError(t, err)
	require.Equal(t, existingConns{"198.51.100.7": {tcpTuple(443)}}, conns)

	procNetSources = []procNetSource{{path: missing, states: tcpScanStates, proto: config.ProtocolTCP}}
	_, err = scanExistingConnections(nil)
	require.Error(t, err)
}

// Regression: --allow-existing-connections used to be a silent no-op unless
// --prepopulate-dns-cache was also set (the scan only ran inside the
// prepopulate block, so the gate never received IPs). The scan must run for
// either flag alone, and not at all when both are off.
func TestScanExistingForStartup_EitherFlagScans(t *testing.T) {
	withProcNetFixture(t, "198.51.100.7:443")
	want := existingConns{"198.51.100.7": {tcpTuple(443)}}

	allowOnly := &StartCmd{AllowExistingConnections: true}
	require.Equal(t, want, scanExistingForStartup(allowOnly, quietLogger()))

	prepopOnly := &StartCmd{PrepopulateDNSCache: true}
	require.Equal(t, want, scanExistingForStartup(prepopOnly, quietLogger()))

	require.Nil(t, scanExistingForStartup(&StartCmd{}, quietLogger()))
}

func TestGateExistingStartupConnections_GatesAndRecords(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	// Unmatched IP: the allow must be scoped to the observed tuple.
	fw := firewall.NewMockFirewall(t)
	fw.EXPECT().AddIP(net.ParseIP("198.51.100.7"), config.ActionAllow, []config.Port{tcpTuple(443)}).Return(true, nil).Once()

	cmd := &StartCmd{AllowExistingConnections: true}
	gated := gateExistingStartupConnections(cmd, existingConns{"198.51.100.7": {tcpTuple(443)}}, cm, fw, nil, quietLogger())
	require.True(t, gated[tupleKey("198.51.100.7", tcpTuple(443))],
		"gated tuples must be recorded for the delta re-scan")
}

// With the flag off nothing is gated — NewMockFirewall(t) fails the test on
// any unexpected AddIP call.
func TestGateExistingStartupConnections_FlagOffDoesNotGate(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	fw := firewall.NewMockFirewall(t)
	require.Nil(t, gateExistingStartupConnections(&StartCmd{}, existingConns{"198.51.100.7": {tcpTuple(443)}}, cm, fw, nil, quietLogger()))
}

// The pre-attach re-scan must gate only tuples that appeared after the
// initial scan — already-gated tuples must not be re-processed, but a new
// port on an already-gated peer must be.
func TestRescanAndGateDelta_GatesOnlyNewConnections(t *testing.T) {
	withProcNetFixture(t, "198.51.100.7:443", "198.51.100.7:8443", "203.0.113.9:443")

	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules(nil, config.ActionDeny))

	fw := firewall.NewMockFirewall(t)
	fw.EXPECT().AddIP(net.ParseIP("198.51.100.7"), config.ActionAllow, []config.Port{tcpTuple(8443)}).Return(true, nil).Once()
	fw.EXPECT().AddIP(net.ParseIP("203.0.113.9"), config.ActionAllow, []config.Port{tcpTuple(443)}).Return(true, nil).Once()

	cmd := &StartCmd{AllowExistingConnections: true}
	rescanAndGateDelta(cmd, map[string]bool{tupleKey("198.51.100.7", tcpTuple(443)): true}, cm, fw, nil, quietLogger())
}

func TestRescanAndGateDelta_FlagOffDoesNotScan(t *testing.T) {
	withProcNetFixture(t, "198.51.100.7:443")

	fw := firewall.NewMockFirewall(t)
	rescanAndGateDelta(&StartCmd{}, nil, config.NewConfigManager(), fw, nil, quietLogger())
}
