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
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
)

// fetchPolicyFromAPI fetches the resolved CargoWall policy from the CodeCargo
// SaaS API. The endpoint returns the merged policy (org defaults + repo
// overrides + job-level overrides) as a CargoWallPolicy protobuf message
// serialised as JSON.
func fetchPolicyFromAPI(ctx context.Context, apiUrl, token, jobKey string) (*cargowallv1pb.CargoWallPolicy, error) {
	endpoint := strings.TrimRight(apiUrl, "/") + "/api/cargowall/v1/action/policy"
	if jobKey != "" {
		endpoint += "?job_key=" + url.QueryEscape(jobKey)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch policy from API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned non-OK status %d: %s", resp.StatusCode, string(body))
	}

	var policy cargowallv1pb.CargoWallPolicy
	if err := protojson.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy response: %w", err)
	}

	return &policy, nil
}
