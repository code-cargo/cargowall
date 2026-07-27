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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
)

// policyEndpoint is the path fetchPolicyFromAPI is expected to call.
const policyEndpoint = "/api/cargowall/v1/action/policy"

// policyServer returns an httptest server that serves the given JSON body for
// the policy endpoint. It asserts the request method, path, job_key/version
// query and bearer token match what fetchPolicyFromAPI is expected to send, so
// the tests also catch endpoint regressions.
func policyServer(t *testing.T, wantJobKey, wantVersion, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, policyEndpoint, r.URL.Path)
		// Assert presence/absence explicitly: fetchPolicyFromAPI must omit an
		// unset param entirely, not send it empty.
		assertQueryParam(t, r, "job_key", wantJobKey)
		assertQueryParam(t, r, "version", wantVersion)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// assertQueryParam asserts that name is absent when want is empty, and carries
// exactly want otherwise.
func assertQueryParam(t *testing.T, r *http.Request, name, want string) {
	t.Helper()
	got, present := r.URL.Query()[name]
	if want == "" {
		assert.False(t, present, "%s must be absent when unset", name)
		return
	}
	assert.Equal(t, []string{want}, got)
}

// TestFetchPolicyFromAPI_IgnoresUnknownField guards against the forward-compat
// bug where a newer controller adding an additive field made the agent reject
// the entire policy (loadCIConfig then warns and falls back to env/file config).
func TestFetchPolicyFromAPI_IgnoresUnknownField(t *testing.T) {
	body := `{
		"mode": "CARGO_WALL_MODE_AUDIT",
		"default_action": "CARGO_WALL_ACTION_TYPE_DENY",
		"future_feature": {"enabled": true, "level": 3},
		"another_unknown": "ignore me"
	}`
	srv := policyServer(t, "job-123", "v1.2.3", body)

	policy, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "job-123", "v1.2.3")
	require.NoError(t, err, "unknown fields must not cause the policy to be dropped")
	require.NotNil(t, policy)
	assert.Equal(t, datapb.CargoWallMode_CARGO_WALL_MODE_AUDIT, policy.Mode)
	assert.Equal(t, datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY, policy.DefaultAction)
}

// TestFetchPolicyFromAPI_IgnoresUnknownEnumValue confirms an enum value name the
// agent doesn't know yet is ignored (field left at its zero value) rather than
// failing the whole parse. Known fields on the same message still parse.
func TestFetchPolicyFromAPI_IgnoresUnknownEnumValue(t *testing.T) {
	body := `{
		"mode": "CARGO_WALL_MODE_FUTURE_VALUE",
		"default_action": "CARGO_WALL_ACTION_TYPE_ALLOW"
	}`
	srv := policyServer(t, "", "", body)

	policy, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	require.NoError(t, err, "unknown enum names must not cause the policy to be dropped")
	require.NotNil(t, policy)
	assert.Equal(t, datapb.CargoWallMode_CARGO_WALL_MODE_UNSPECIFIED, policy.Mode)
	assert.Equal(t, datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW, policy.DefaultAction)
}

// TestFetchPolicyFromAPI_ReportsVersionWithoutJobKey covers the mixed case: the
// agent reports its version (#92) on a run with no job key, so version must
// still be sent and job_key must stay absent.
func TestFetchPolicyFromAPI_ReportsVersionWithoutJobKey(t *testing.T) {
	srv := policyServer(t, "", "v1.2.3", `{"mode": "CARGO_WALL_MODE_AUDIT"}`)

	policy, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "v1.2.3")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, datapb.CargoWallMode_CARGO_WALL_MODE_AUDIT, policy.Mode)
}
