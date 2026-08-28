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
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// redirectStateFiles points the effective-mode and downgrade state files at
// tempdir paths for the duration of the test, restoring the real paths on
// cleanup.
func redirectStateFiles(t *testing.T) (modePath, downgradePath string) {
	t.Helper()
	oldMode, oldDowngrade := modeFile, downgradeFile
	dir := t.TempDir()
	modeFile = filepath.Join(dir, "cargowall-mode")
	downgradeFile = filepath.Join(dir, "cargowall-downgrade")
	t.Cleanup(func() { modeFile, downgradeFile = oldMode, oldDowngrade })
	return modeFile, downgradeFile
}

// readDowngradeFile parses the protojson downgrade record a test run wrote.
func readDowngradeFile(t *testing.T, path string) *cargowallv1pb.CargoWallDowngrade {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "downgrade record must be written")
	var d cargowallv1pb.CargoWallDowngrade
	require.NoError(t, protojson.Unmarshal(data, &d))
	return &d
}

// TestLoadCIConfig_ApiFailureModes is the (error class × --api-failure-mode)
// posture table: only genuine retrieval failures (transport / server /
// malformed) may downgrade to audit or abort. Authoritative answers — 404
// not-onboarded (the everyday case for users without a CodeCargo account,
// since api-url defaults to the SaaS), 401/403 bad token, 400 inactive repo —
// must keep today's env/file fallback no matter what the flag says.
func TestLoadCIConfig_ApiFailureModes(t *testing.T) {
	setFastPolicyRetries(t)

	const (
		respTransport  = -1 // server closed before the request: no HTTP response
		respUnloadable = -2 // 200 whose policy LoadConfigFromCargoWall rejects
		respOK         = 200
	)

	// Short aliases to keep the table readable.
	const (
		dtNone      = datapb.CargoWallDowngradeType_CARGO_WALL_DOWNGRADE_TYPE_UNSPECIFIED
		dtAudit     = datapb.CargoWallDowngradeType_CARGO_WALL_DOWNGRADE_TYPE_AUDIT_FALLBACK
		dtLockdown  = datapb.CargoWallDowngradeType_CARGO_WALL_DOWNGRADE_TYPE_LOCKDOWN
		fcNone      = datapb.CargoWallFetchFailureClass_CARGO_WALL_FETCH_FAILURE_CLASS_UNSPECIFIED
		fcTransport = datapb.CargoWallFetchFailureClass_CARGO_WALL_FETCH_FAILURE_CLASS_TRANSPORT
		fcServer    = datapb.CargoWallFetchFailureClass_CARGO_WALL_FETCH_FAILURE_CLASS_SERVER
		fcMalformed = datapb.CargoWallFetchFailureClass_CARGO_WALL_FETCH_FAILURE_CLASS_MALFORMED
	)

	tests := []struct {
		name          string
		resp          int
		failureMode   string
		wantLoaded    bool
		wantAuditMode bool
		wantLockdown  bool
		wantSentinel  bool
		wantModeFile  string // "" = file must not exist
		// wantDowngrade is the expected downgrade record type;
		// UNSPECIFIED = the downgrade file must not exist.
		wantDowngrade datapb.CargoWallDowngradeType
		// wantClass is the expected failure class on the downgrade record.
		wantClass datapb.CargoWallFetchFailureClass
	}{
		// Local fallback writes NO mode file: absence means "no SaaS-derived
		// posture", and local runs at exactly the posture the flags request —
		// matching the identical env/file outcome after a 404.
		{"server error, local keeps enforce", 500, "local", false, false, false, false, "", dtNone, fcNone},
		{"server error, empty mode defaults to local", 500, "", false, false, false, false, "", dtNone, fcNone},
		{"server error, audit downgrades", 500, "audit", false, true, false, false, "audit", dtAudit, fcServer},
		{"server error, fail locks down", 500, "fail", false, false, true, true, "", dtLockdown, fcServer},
		{"transport error, audit downgrades", respTransport, "audit", false, true, false, false, "audit", dtAudit, fcTransport},
		{"transport error, fail locks down", respTransport, "fail", false, false, true, true, "", dtLockdown, fcTransport},
		{"unloadable policy, audit downgrades", respUnloadable, "audit", false, true, false, false, "audit", dtAudit, fcMalformed},
		{"404 not onboarded, audit must not downgrade", 404, "audit", false, false, false, false, "", dtNone, fcNone},
		{"404 not onboarded, fail must not lock down", 404, "fail", false, false, false, false, "", dtNone, fcNone},
		{"401 unauthorized, fail must not lock down", 401, "fail", false, false, false, false, "", dtNone, fcNone},
		{"400 precondition, audit must not downgrade", 400, "audit", false, false, false, false, "", dtNone, fcNone},
		{"success ignores failure mode", respOK, "fail", true, true, false, false, "audit", dtNone, fcNone},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			modePath, downgradePath := redirectStateFiles(t)
			failurePath := filepath.Join(t.TempDir(), "cargowall-failed")

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch tc.resp {
				case respUnloadable:
					// Rule type left unspecified → LoadConfigFromCargoWall
					// rejects the policy after a successful fetch.
					_, _ = w.Write([]byte(`{"mode": "CARGO_WALL_MODE_ENFORCE", "rules": [{"value": "1.2.3.4/32"}]}`))
				case respOK:
					_, _ = w.Write([]byte(`{"mode": "CARGO_WALL_MODE_AUDIT", "default_action": "CARGO_WALL_ACTION_TYPE_DENY"}`))
				default:
					w.WriteHeader(tc.resp)
				}
			}))
			t.Cleanup(srv.Close)
			apiURL := srv.URL
			if tc.resp == respTransport {
				srv.Close()
			}

			cmd := &StartCmd{
				GithubAction:   true,
				ApiUrl:         apiURL,
				Token:          "test-token",
				ApiFailureMode: tc.failureMode,
				FailureFile:    failurePath,
				Config:         filepath.Join(t.TempDir(), "no-config.json"),
			}

			cm := config.NewConfigManager()
			loaded := loadCIConfig(context.Background(), cmd, cm, nil, quietLogger())

			assert.Equal(t, tc.wantLoaded, loaded)
			assert.Equal(t, tc.wantAuditMode, cm.IsAuditMode(), "posture lives on the config manager")
			assert.Equal(t, tc.wantLockdown, cmd.policyLockdown)

			if tc.wantSentinel {
				data, rerr := os.ReadFile(failurePath)
				require.NoError(t, rerr, "fail mode must write the failure sentinel")
				assert.Contains(t, string(data), "policy fetch")
			} else {
				_, serr := os.Stat(failurePath)
				assert.True(t, os.IsNotExist(serr), "failure sentinel must not be written")
			}

			if tc.wantModeFile == "" {
				// Absent in lockdown AND on non-retrieval fallbacks: file
				// absence has always meant "no SaaS policy in play" to the
				// summary step, and the everyday not-onboarded case must
				// keep that contract.
				_, serr := os.Stat(modePath)
				assert.True(t, os.IsNotExist(serr), "mode file must not be written")
			} else {
				data, rerr := os.ReadFile(modePath)
				require.NoError(t, rerr, "mode file must be written")
				assert.Equal(t, tc.wantModeFile, string(data))
			}

			if tc.wantDowngrade != dtNone {
				d := readDowngradeFile(t, downgradePath)
				assert.Equal(t, tc.wantDowngrade, d.Type)
				assert.Equal(t, tc.wantClass, d.FailureClass)
				assert.NotEmpty(t, d.Detail, "human-readable detail must ride along")
				if tc.resp > 0 {
					require.NotNil(t, d.HttpStatus, "status must be recorded when a response was received")
					assert.Equal(t, uint32(tc.resp), *d.HttpStatus)
				} else if tc.resp == respTransport {
					assert.Nil(t, d.HttpStatus, "no status on transport failures")
				}
			} else {
				_, serr := os.Stat(downgradePath)
				assert.True(t, os.IsNotExist(serr), "downgrade record must only be written on a posture change")
			}
		})
	}
}

// TestLoadCIConfig_LockdownSkipsLocalConfig: --api-failure-mode=fail means
// "do not trust local config" — in lockdown the env/file fallback must be
// skipped so the deny-all bootstrap stays in force, while "local" mode picks
// the same env config up.
func TestLoadCIConfig_LockdownSkipsLocalConfig(t *testing.T) {
	setFastPolicyRetries(t)
	t.Setenv("CARGOWALL_DEFAULT_ACTION", "allow")

	for _, tc := range []struct {
		failureMode string
		wantAction  config.Action
	}{
		{"fail", config.ActionDeny},
		{"local", config.ActionAllow},
	} {
		t.Run(tc.failureMode, func(t *testing.T) {
			redirectStateFiles(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(srv.Close)

			cmd := &StartCmd{
				GithubAction:   true,
				ApiUrl:         srv.URL,
				Token:          "test-token",
				ApiFailureMode: tc.failureMode,
				FailureFile:    filepath.Join(t.TempDir(), "cargowall-failed"),
			}
			cm := config.NewConfigManager()
			loadCIConfig(context.Background(), cmd, cm, nil, quietLogger())

			assert.Equal(t, tc.wantAction, cm.GetDefaultAction())
		})
	}
}

// TestLoadCIConfig_CancelledContextSkipsPostureHandling guards the SIGTERM
// unwind path: a fetch killed by shutdown-signal cancellation must not be
// misreported as an outage — no lockdown, no audit downgrade, and no
// sentinel/state files while the process is unwinding.
func TestLoadCIConfig_CancelledContextSkipsPostureHandling(t *testing.T) {
	setFastPolicyRetries(t)
	modePath, downgradePath := redirectStateFiles(t)
	failurePath := filepath.Join(t.TempDir(), "cargowall-failed")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := &StartCmd{
		GithubAction:   true,
		ApiUrl:         "http://127.0.0.1:1",
		Token:          "test-token",
		ApiFailureMode: "fail",
		FailureFile:    failurePath,
	}
	cm := config.NewConfigManager()
	loaded := loadCIConfig(ctx, cmd, cm, nil, quietLogger())

	assert.False(t, loaded)
	assert.False(t, cmd.policyLockdown, "cancellation must not enter lockdown")
	assert.False(t, cm.IsAuditMode())
	for _, p := range []string{failurePath, downgradePath, modePath} {
		_, err := os.Stat(p)
		assert.True(t, os.IsNotExist(err), "no state file may be written while unwinding: %s", p)
	}
}

// TestLoadCIConfig_FailureModesSyncAuditLogger: the DNS proxy consults the
// audit logger (not cmd.AuditMode) at query time, so BOTH posture-changing
// branches must re-sync it — audit (enforce→audit: DNS filtering must go
// permissive) and fail (audit→lockdown: DNS filtering must go strict, or a
// run started with --audit-mode keeps a DNS-tunnel escape hatch inside the
// fail-closed posture).
func TestLoadCIConfig_FailureModesSyncAuditLogger(t *testing.T) {
	setFastPolicyRetries(t)

	tests := []struct {
		name          string
		failureMode   string
		initialAudit  bool
		wantAuditMode bool
	}{
		{"audit downgrade flips logger on", "audit", false, true},
		{"fail lockdown flips logger off", "fail", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redirectStateFiles(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(srv.Close)

			auditLogger, err := events.NewAuditLogger(filepath.Join(t.TempDir(), "audit.ndjson"), tc.initialAudit)
			require.NoError(t, err)
			t.Cleanup(func() { auditLogger.Close() })

			cmd := &StartCmd{
				GithubAction:   true,
				ApiUrl:         srv.URL,
				Token:          "test-token",
				ApiFailureMode: tc.failureMode,
				FailureFile:    filepath.Join(t.TempDir(), "cargowall-failed"),
			}
			// Mirror StartCargoWall: the CLI flag seeds the manager.
			cm := config.NewConfigManager()
			cm.SetAuditMode(tc.initialAudit)
			loadCIConfig(context.Background(), cmd, cm, auditLogger, quietLogger())

			assert.Equal(t, tc.wantAuditMode, cm.IsAuditMode())
			assert.Equal(t, tc.wantAuditMode, auditLogger.IsAuditMode(), "audit logger must be re-synced with the effective posture")
		})
	}
}

// TestWriteSentinel_AtomicReplaceIsSymlinkSafe: sentinels are written as
// root to fixed paths in world-writable /tmp. The temp-file+rename publish
// must replace a pre-planted symlink (or plain file) at the path itself
// without ever following it — the planted target's content stays untouched —
// and must leave no temp litter behind.
func TestWriteSentinel_AtomicReplaceIsSymlinkSafe(t *testing.T) {
	dir := t.TempDir()

	// Pre-planted plain file: replaced, not followed or refused.
	existing := filepath.Join(dir, "existing")
	require.NoError(t, os.WriteFile(existing, []byte("planted"), 0o644))
	require.NoError(t, writeSentinel(existing, []byte("new")))
	data, err := os.ReadFile(existing)
	require.NoError(t, err)
	assert.Equal(t, "new", string(data))

	// Pre-planted symlink: the LINK is replaced by a regular file; the
	// target an attacker chose is never written through.
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("victim"), 0o644))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	require.NoError(t, writeSentinel(link, []byte("ok")))
	data, err = os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "victim", string(data), "symlink target must not be written through")
	fi, err := os.Lstat(link)
	require.NoError(t, err)
	assert.True(t, fi.Mode().IsRegular(), "path must now be a regular file, not the symlink")
	data, err = os.ReadFile(link)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(data))

	// No temp files left behind.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.ElementsMatch(t, []string{"existing", "target", "link"}, names)
}

// TestRemoveStaleStateFiles: a persistent runner's leftovers (a stale ready
// sentinel is a fail-open, a stale failure sentinel a false abort) must all
// be cleared at process entry, and absence must be a no-op.
func TestRemoveStaleStateFiles(t *testing.T) {
	modePath, downgradePath := redirectStateFiles(t)
	dir := t.TempDir()
	cmd := &StartCmd{
		ReadyFile:   filepath.Join(dir, "ready"),
		FailureFile: filepath.Join(dir, "failed"),
	}

	stale := []string{cmd.ReadyFile, cmd.FailureFile, modePath, downgradePath}
	for _, p := range stale {
		require.NoError(t, os.WriteFile(p, []byte("stale"), 0o644))
	}

	removeStaleStateFiles(cmd, quietLogger())
	for _, p := range stale {
		_, err := os.Stat(p)
		assert.True(t, os.IsNotExist(err), "stale state file must be removed: %s", p)
	}

	// Idempotent when nothing is stale.
	removeStaleStateFiles(cmd, quietLogger())
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

// No flags means no helpers, and therefore no rules and no config — a
// standalone run must not acquire a policy it never asked for.
func TestPopulateAutoAllowRules_NoFlagsInstallsNothing(t *testing.T) {
	cm := config.NewConfigManager()

	cmd := &StartCmd{} // every flag false, no ApiUrl
	populateAutoAllowRules(cmd, cm, quietLogger())

	require.Equal(t, config.ActionDeny, cm.GetDefaultAction())
	require.Empty(t, cm.GetResolvedRules(), "no helper enabled means no rules")
}

// The infrastructure allows must be queryable on a manager that has never
// loaded a policy — that is the whole point of running this pass before the
// DNS proxy arms filtering (#119).
func TestPopulateAutoAllowRules_MatchableBeforeAnyPolicyLoad(t *testing.T) {
	cm := config.NewConfigManager()

	cmd := &StartCmd{ApiUrl: "https://app.codecargo.com"}
	populateAutoAllowRules(cmd, cm, quietLogger())

	require.True(t, cm.MatchHostnameRule("app.codecargo.com").HasAllow(),
		"the SaaS API hostname must be allowed before the policy fetch it carries")
}

// ApiUrl alone (no CI flags) is enough, because the CodeCargo API allow runs
// whenever an api-url is set.
func TestPopulateAutoAllowRules_ApiUrlAloneAddsHostname(t *testing.T) {
	cm := config.NewConfigManager()

	cmd := &StartCmd{ApiUrl: "https://api.codecargo.com"}
	populateAutoAllowRules(cmd, cm, quietLogger())

	got := hostnameRulesFor(t, cm, config.AutoAddedTypeCodeCargoService)
	require.Contains(t, got, "api.codecargo.com")
}

// The pass runs before the policy fetch, so the policy that lands afterwards
// must not wipe what it installed — the failure this whole reordering exists
// to prevent (#119).
func TestPopulateAutoAllowRules_SurvivesLaterPolicyLoad(t *testing.T) {
	t.Setenv("CI_SERVER_URL", "")
	t.Setenv("CI_REGISTRY", "")
	t.Setenv("CI_API_V4_URL", "")

	cm := config.NewConfigManager()
	cmd := &StartCmd{AutoAllowGitlabHosts: true, ApiUrl: "https://app.codecargo.com"}
	populateAutoAllowRules(cmd, cm, quietLogger())

	// A policy naming none of the auto-allowed hostnames.
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "github.com", Action: config.ActionAllow},
	}, config.ActionDeny))

	require.True(t, cm.MatchHostnameRule("app.codecargo.com").HasAllow(),
		"the SaaS API hostname must survive the policy load")
	require.Contains(t, hostnameRulesFor(t, cm, config.AutoAddedTypeGitLabService), "gitlab.com")
	require.True(t, cm.MatchHostnameRule("github.com").HasAllow(), "policy rules still load")
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

// TestTeardownList_OnceAcrossPaths: each registered undo runs at most once
// whether the graceful defer or the second-signal force path executes first —
// the property that makes forceAll safe to race against defers.
func TestTeardownList_OnceAcrossPaths(t *testing.T) {
	td := &teardownList{}
	var order []string
	a := td.add(func() { order = append(order, "a") })
	b := td.add(func() { order = append(order, "b") })

	b()           // graceful defer ran b first
	td.forceAll() // force path must run a but not re-run b
	a()           // late defer for a is now a no-op

	assert.Equal(t, []string{"b", "a"}, order, "each undo runs exactly once across both paths")
}

// forceAll must run undos in reverse registration order (defer LIFO), with
// nothing pre-run — the previous test cannot show this, since its only
// remaining undo is a single function.
func TestTeardownList_ForceAllRunsInReverseOrder(t *testing.T) {
	td := &teardownList{}
	var order []string
	for _, name := range []string{"first", "second", "third"} {
		td.add(func() { order = append(order, name) })
	}

	td.forceAll()

	assert.Equal(t, []string{"third", "second", "first"}, order)
}

// An undo registered WHILE forceAll is running (main is still mid-startup,
// e.g. attaching TC or enabling sudo lockdown) must still execute — a
// one-shot snapshot would skip it and strand that mutation.
func TestTeardownList_ForceAllPicksUpLateRegistrations(t *testing.T) {
	td := &teardownList{}
	var order []string
	td.add(func() {
		order = append(order, "early")
		// Simulates startup registering another undo after forceAll began.
		td.add(func() { order = append(order, "late") })
	})

	td.forceAll()

	assert.Equal(t, []string{"early", "late"}, order, "late registrations must not be skipped")
}

// TestStartCargoWall_FatalErrorWritesFailureSentinel: ANY fatal startup error
// must publish the failure sentinel so wait-ready fails fast with the reason
// instead of burning its timeout. Driven through the earliest fatal path
// (eBPF unsupported in the unprivileged test environment).
func TestStartCargoWall_FatalErrorWritesFailureSentinel(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged environment so the eBPF capability check fails")
	}
	redirectStateFiles(t)
	failurePath := filepath.Join(t.TempDir(), "cargowall-failed")

	cmd := &StartCmd{
		Logger:      quietLogger(),
		FailureFile: failurePath,
	}
	err := StartCargoWall(cmd, nil)
	require.Error(t, err)

	data, rerr := os.ReadFile(failurePath)
	require.NoError(t, rerr, "fatal startup error must write the failure sentinel")
	assert.Contains(t, string(data), "cargowall startup failed")
}

// Lockdown skips the env/file fallback, so a hostname-less --api-url leaves
// the manager with no config at all — and the CI infrastructure auto-allows
// that run afterwards must still stick, or lockdown is a blackhole with no
// DNS or infra allows rather than the documented deny-all posture.
func TestLoadCIConfig_LockdownKeepsInfraAllowsWithHostnamelessApiUrl(t *testing.T) {
	setFastPolicyRetries(t)
	redirectStateFiles(t)

	cmd := &StartCmd{
		GithubAction:   true,
		ApiUrl:         "api.codecargo.io", // no scheme → url.Hostname() == ""
		Token:          "test-token",
		ApiFailureMode: ApiFailureModeFail,
		FailureFile:    filepath.Join(t.TempDir(), "cargowall-failed"),
		DNSUpstream:    "8.8.8.8:53",
	}
	cm := config.NewConfigManager()
	loadCIConfig(context.Background(), cmd, cm, nil, quietLogger())

	require.True(t, cmd.policyLockdown, "an unsupported scheme is a transport failure")
	assert.Equal(t, config.ActionDeny, cm.GetDefaultAction())
	// The DNS/infra auto-allows are wired to the listeners, not to CI mode,
	// so probe the property directly: a rule landing proves lockdown left the
	// manager writable for them (the helpers seed a deny-default config when
	// the fetch never produced one — issue #119).
	cm.EnsureDNSAllowed([]string{"127.0.0.1"})
	assert.NotEmpty(t, cm.GetResolvedRules(), "lockdown must still accept the DNS/infra allows")
	assert.Equal(t, config.ActionDeny, cm.GetDefaultAction(), "seeding must not soften the lockdown posture")
}

// The pid stamped into a sentinel identifies its run exactly — a leftover
// pidfile from a SIGKILLed run cannot legitimize that run's sentinel, which
// mtime-only anchoring could not prevent.
func TestWriteFailureSentinel_StampsPidAndSanitizes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failed")
	require.NoError(t, writeFailureSentinel(path, "boom\n::error::injected"))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	first, rest, _ := strings.Cut(string(data), "\n")
	assert.Equal(t, fmt.Sprintf("pid=%d", os.Getpid()), first)
	assert.NotContains(t, rest, "\n::error::", "control characters must be stripped from the reason")
	assert.Contains(t, rest, "::error::injected", "the text itself is kept, just never at a line start")
}
