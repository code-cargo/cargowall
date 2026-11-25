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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
)

// A fetched policy carrying a search domain cargowall refuses loads, the
// refused entry dropped: it is no longer classified malformed, so no
// --api-failure-mode posture applies. Under fail that posture was the
// lockdown, and under audit the downgrade.
func TestLoadCIConfig_RefusedSearchDomainStillLoadsPolicy(t *testing.T) {
	setFastPolicyRetries(t)
	for _, mode := range []string{"fail", "audit"} {
		t.Run(mode, func(t *testing.T) {
			modePath, downgradePath := redirectStateFiles(t)
			failurePath := filepath.Join(t.TempDir(), "cargowall-failed")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"mode": "CARGO_WALL_MODE_ENFORCE", "default_action": "CARGO_WALL_ACTION_TYPE_DENY",
					"search_domains": ["corp", "svc.cluster.local", ".compute.internal"]}`))
			}))
			t.Cleanup(srv.Close)

			cmd := &StartCmd{
				GithubAction:   true,
				ApiUrl:         srv.URL,
				Token:          "test-token",
				ApiFailureMode: mode,
				FailureFile:    failurePath,
			}
			cm := config.NewConfigManager()
			loaded, err := loadCIConfig(context.Background(), cmd, cm, nil, quietLogger())
			require.NoError(t, err)

			assert.True(t, loaded, "the policy loads")
			assert.False(t, cmd.policyLockdown, "no lockdown")
			assert.False(t, cm.IsAuditMode(), "no downgrade: the policy enforces")
			assert.Equal(t, []string{".compute.internal"}, cm.GetSearchDomains())
			_, serr := os.Stat(downgradePath)
			assert.True(t, os.IsNotExist(serr), "no downgrade record")
			_, serr = os.Stat(failurePath)
			assert.True(t, os.IsNotExist(serr), "no failure sentinel")
			data, rerr := os.ReadFile(modePath)
			require.NoError(t, rerr)
			assert.Equal(t, "enforce", string(data))
		})
	}
}

// The SaaS sidecar loads its policy through the extension hook, not the
// policy fetch: there a search domain cargowall refuses used to fail
// startup outright. It is dropped there too, and the policy loads.
func TestLoadHookPolicy_RefusedSearchDomainStillLoadsPolicy(t *testing.T) {
	cleaned := 0
	hooks := &StartHooks{
		LoadPolicy: func(context.Context, *StartCmd) (*cargowallv1pb.CargoWallPolicy, events.StateMachineClient, func(), error) {
			return &cargowallv1pb.CargoWallPolicy{
				Mode:          datapb.CargoWallMode_CARGO_WALL_MODE_ENFORCE,
				DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
				SearchDomains: []string{"corp", ".compute.internal"},
			}, nil, func() { cleaned++ }, nil
		},
	}
	cm := config.NewConfigManager()
	_, cleanup, err := loadHookPolicy(context.Background(), &StartCmd{}, hooks, cm, nil)
	require.NoError(t, err, "a refused search domain no longer fails the hook path")
	require.NotNil(t, cleanup)
	assert.Equal(t, []string{".compute.internal"}, cm.GetSearchDomains())
	assert.False(t, cm.IsAuditMode())
	assert.Zero(t, cleaned, "the caller owns the cleanup on success")

	// A policy that fails to load still fails the hook path, and the hook's
	// cleanup has run.
	hooks.LoadPolicy = func(context.Context, *StartCmd) (*cargowallv1pb.CargoWallPolicy, events.StateMachineClient, func(), error) {
		return &cargowallv1pb.CargoWallPolicy{Rules: []*cargowallv1pb.CargoWallPolicy_Rule{{Value: "1.2.3.4/32"}}},
			nil, func() { cleaned++ }, nil
	}
	_, _, err = loadHookPolicy(context.Background(), &StartCmd{}, hooks, config.NewConfigManager(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load CargoWall config")
	assert.Equal(t, 1, cleaned)
}
