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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
)

// No test reads the host's own default config file.
func init() { defaultConfigPath = "/nonexistent/cargowall-test/config.json" }

// badConfig writes a config file cargowall refuses: a port entry with no
// protocol, which a loose read would leave on every port.
func badConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(
		`{"rules": [{"type": "hostname", "value": "example.com", "action": "allow", "ports": [{"port": 443}]}]}`), 0o600))
	return path
}

// The local configuration applies offline: an explicit --config that
// doesn't load, for whatever reason, fails startup.
func TestLoadCIConfig_ExplicitConfigThatDoesNotLoadFails(t *testing.T) {
	redirectStateFiles(t)
	for name, path := range map[string]string{
		"refused by the strict read": badConfig(t),
		"missing":                    filepath.Join(t.TempDir(), "missing.json"),
	} {
		t.Run(name, func(t *testing.T) {
			cmd := &StartCmd{GithubAction: true, Config: path}
			loaded, err := loadCIConfig(context.Background(), cmd, config.NewConfigManager(), nil, quietLogger())
			require.Error(t, err)
			assert.False(t, loaded)
			assert.Contains(t, err.Error(), "config file "+path+" did not load")
		})
	}
}

// A file at the default path is the configuration meant to apply as much as
// one --config names: when it's there and doesn't load, startup fails, and
// the failure sentinel names it. Only a default path with no file at it
// leaves deny-all.
func TestLoadCIConfig_BrokenDefaultFileFails(t *testing.T) {
	redirectStateFiles(t)
	old := defaultConfigPath
	defaultConfigPath = badConfig(t)
	t.Cleanup(func() { defaultConfigPath = old })

	cmd := &StartCmd{GithubAction: true}
	loaded, err := loadCIConfig(context.Background(), cmd, config.NewConfigManager(), nil, quietLogger())
	require.Error(t, err)
	assert.False(t, loaded)
	sentinel := filepath.Join(t.TempDir(), "cargowall-failed")
	publishStartupFailure(sentinel, err, cmd.refusedPosture, quietLogger())
	data, rerr := os.ReadFile(sentinel)
	require.NoError(t, rerr)
	assert.Contains(t, string(data), "config file "+defaultConfigPath+" did not load")

	require.Error(t, loadPlainConfig(&StartCmd{}, config.NewConfigManager(), quietLogger()), "plain mode too")
}

// Without --config, the default path with no file at it leaves deny-all,
// as before, and an environment configuration is read ahead of any file.
func TestLoadCIConfig_DefaultPathAndEnvUnchanged(t *testing.T) {
	redirectStateFiles(t)
	cm := config.NewConfigManager()
	loaded, err := loadCIConfig(context.Background(), &StartCmd{GithubAction: true}, cm, nil, quietLogger())
	require.NoError(t, err)
	assert.False(t, loaded)
	assert.Empty(t, cm.GetResolvedRules())

	t.Setenv("CARGOWALL_ALLOWED_HOSTS", "github.com")
	cm = config.NewConfigManager()
	_, err = loadCIConfig(context.Background(), &StartCmd{GithubAction: true, Config: badConfig(t)}, cm, nil, quietLogger())
	require.NoError(t, err, "the environment's configuration applies, so the file is never read")
	assert.Len(t, cm.GetResolvedRules(), 1)
}

// When a CodeCargo policy loads, or the run is in policy lockdown, the
// file is never read, so a broken one is no error.
func TestLoadCIConfig_BrokenConfigIgnoredWhenPolicyOrLockdown(t *testing.T) {
	redirectStateFiles(t)
	srv := policyServer(t, "", "", `{"default_action": "CARGO_WALL_ACTION_TYPE_DENY"}`)
	cmd := &StartCmd{GithubAction: true, ApiUrl: srv.URL, Token: "test-token", Config: badConfig(t)}
	loaded, err := loadCIConfig(context.Background(), cmd, config.NewConfigManager(), nil, quietLogger())
	require.NoError(t, err)
	assert.True(t, loaded)

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(down.Close)
	cmd = &StartCmd{
		GithubAction: true, ApiUrl: down.URL, Token: "test-token",
		ApiFailureMode: ApiFailureModeFail, FailureFile: filepath.Join(t.TempDir(), "failed"), Config: badConfig(t),
	}
	_, err = loadCIConfig(context.Background(), cmd, config.NewConfigManager(), nil, quietLogger())
	require.NoError(t, err)
	assert.True(t, cmd.policyLockdown)
}

// Outside CI mode the config file is all there is: an explicit --config
// that doesn't load fails startup, and the default path not loading leaves
// deny-all.
func TestLoadPlainConfig(t *testing.T) {
	err := loadPlainConfig(&StartCmd{Config: badConfig(t)}, config.NewConfigManager(), quietLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not load")
	require.NoError(t, loadPlainConfig(&StartCmd{}, config.NewConfigManager(), quietLogger()))
}

// The error a bad explicit --config returns takes the path every startup
// failure does: the failure sentinel names it, and the process exits
// non-zero, as no posture was refused.
func TestBadConfigStartupFailure(t *testing.T) {
	cmd := &StartCmd{GithubAction: true, Config: badConfig(t)}
	_, err := loadCIConfig(context.Background(), cmd, config.NewConfigManager(), nil, quietLogger())
	require.Error(t, err)

	sentinel := filepath.Join(t.TempDir(), "cargowall-failed")
	publishStartupFailure(sentinel, err, cmd.refusedPosture, quietLogger())
	data, rerr := os.ReadFile(sentinel)
	require.NoError(t, rerr)
	assert.Contains(t, string(data), "cargowall startup failed: config file "+cmd.Config+" did not load")
	assert.NotContains(t, string(data), "refused=")

	exit := refusalExit(err, cmd)
	require.Error(t, exit)
	var refusal refusalError
	assert.False(t, errors.As(exit, &refusal), "a config failure exits 1, not with the refusal status")
}
