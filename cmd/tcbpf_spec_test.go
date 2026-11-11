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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

// The tcbpf spec as startCargoWall loads it: the rule maps at the job's
// size for a policy without step rules (and for one whose steps a default
// allow drops), at the size with steps for one with them; the
// step-attribution maps shrunk when the feature is off.
func TestLoadTcSpec(t *testing.T) {
	ruleMaps := []string{bpf.TcBpfMapMapCidrs, bpf.TcBpfMapMapPorts, bpf.TcBpfMapMapCidrsV6, bpf.TcBpfMapMapPortsV6}
	tagMaps := []string{"map_task_step", "map_sock_step", "map_task_nspid"}
	full, err := bpf.LoadTcBpf()
	require.NoError(t, err)

	steps := `"steps": [{"id": "fetch", "rules": [{"type": "hostname", "value": "step.example.com"}]}]`
	for _, c := range []struct {
		name            string
		policy          string
		stepAttribution bool
		ruleSize        uint32
	}{
		{"no steps", `{"defaultAction": "deny", "rules": []}`, true, bpf.RuleMapEntriesJobOnly},
		{"steps", `{"defaultAction": "deny", "rules": [], ` + steps + `}`, true, bpf.RuleMapEntries},
		{"steps a default allow drops", `{"defaultAction": "allow", "rules": [], ` + steps + `}`, true, bpf.RuleMapEntriesJobOnly},
		{"steps, step attribution off", `{"defaultAction": "deny", "rules": [], ` + steps + `}`, false, bpf.RuleMapEntries},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			require.NoError(t, os.WriteFile(path, []byte(c.policy), 0o600))
			cm := config.NewConfigManager()
			require.NoError(t, cm.LoadConfig(path))

			spec, err := loadTcSpec(c.stepAttribution, cm)
			require.NoError(t, err)
			for _, name := range ruleMaps {
				assert.Equal(t, c.ruleSize, spec.Maps[name].MaxEntries, name)
			}
			for _, name := range tagMaps {
				want := full.Maps[name].MaxEntries
				if !c.stepAttribution {
					want = 64
				}
				assert.Equal(t, want, spec.Maps[name].MaxEntries, name)
			}
		})
	}
}
