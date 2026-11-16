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
	"strings"
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
			assert.Equal(t, refusedConfig, cmd.refusedPosture)
		})
	}
}

// A file at the default path is the configuration meant to apply as much as
// one --config names: when it's there and doesn't load, whether it doesn't
// parse or can't be read, startup fails, and the failure sentinel names it.
// Only a default path with no file at it leaves deny-all.
func TestLoadCIConfig_BrokenDefaultFileFails(t *testing.T) {
	redirectStateFiles(t)
	for name, path := range map[string]string{
		"refused by the strict read": badConfig(t),
		"a directory":                t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			old := defaultConfigPath
			defaultConfigPath = path
			t.Cleanup(func() { defaultConfigPath = old })

			cmd := &StartCmd{GithubAction: true}
			loaded, err := loadCIConfig(context.Background(), cmd, config.NewConfigManager(), nil, quietLogger())
			require.Error(t, err)
			assert.False(t, loaded)
			assert.Equal(t, refusedConfig, cmd.refusedPosture)
			sentinel := filepath.Join(t.TempDir(), "cargowall-failed")
			publishStartupFailure(sentinel, err, cmd.refusedPosture, quietLogger())
			data, rerr := os.ReadFile(sentinel)
			require.NoError(t, rerr)
			assert.Contains(t, string(data), "\nrefused=config\n")
			assert.Contains(t, string(data), "config file "+path+" did not load")

			plain := &StartCmd{}
			require.Error(t, loadPlainConfig(plain, config.NewConfigManager(), quietLogger()), "plain mode too")
			assert.Equal(t, refusedConfig, plain.refusedPosture)
		})
	}
}

// Without --config, the default path with no file at it leaves deny-all,
// as before, and refuses nothing; an environment configuration is read
// ahead of any file.
func TestLoadCIConfig_DefaultPathAndEnvUnchanged(t *testing.T) {
	redirectStateFiles(t)
	cm := config.NewConfigManager()
	cmd := &StartCmd{GithubAction: true}
	loaded, err := loadCIConfig(context.Background(), cmd, cm, nil, quietLogger())
	require.NoError(t, err)
	assert.False(t, loaded)
	assert.Empty(t, cm.GetResolvedRules())
	assert.Empty(t, cmd.refusedPosture)

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
	assert.Empty(t, cmd.refusedPosture)

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
	assert.Empty(t, cmd.refusedPosture)
}

// Outside CI mode the config file is all there is: an explicit --config
// that doesn't load fails startup, and the default path not loading leaves
// deny-all.
func TestLoadPlainConfig(t *testing.T) {
	cmd := &StartCmd{Config: badConfig(t)}
	err := loadPlainConfig(cmd, config.NewConfigManager(), quietLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not load")
	assert.Equal(t, refusedConfig, cmd.refusedPosture)

	cmd = &StartCmd{}
	require.NoError(t, loadPlainConfig(cmd, config.NewConfigManager(), quietLogger()))
	assert.Empty(t, cmd.refusedPosture)
}

// A config file that doesn't load is a refusal, as a fail-closed posture's
// loss is: the failure sentinel names it on a refused= line and the file in
// the reason, and the process exits with the refusal status, so the action
// fails the step whatever fail-on-unsupported says.
func TestBadConfigStartupFailure(t *testing.T) {
	cmd := &StartCmd{GithubAction: true, Config: badConfig(t)}
	_, err := loadCIConfig(context.Background(), cmd, config.NewConfigManager(), nil, quietLogger())
	require.Error(t, err)

	sentinel := filepath.Join(t.TempDir(), "cargowall-failed")
	publishStartupFailure(sentinel, err, cmd.refusedPosture, quietLogger())
	data, rerr := os.ReadFile(sentinel)
	require.NoError(t, rerr)
	pid, rest, _ := strings.Cut(string(data), "\n")
	assert.True(t, strings.HasPrefix(pid, "pid="))
	assert.True(t, strings.HasPrefix(rest, "refused=config\ncargowall startup failed: config file "+cmd.Config+" did not load"), rest)

	exit := refusalExit(err, cmd)
	var refusal refusalError
	require.True(t, errors.As(exit, &refusal), "a config failure exits with the refusal status")
	assert.Equal(t, exitRefused, refusal.ExitCode())
	assert.ErrorIs(t, exit, err)
}
