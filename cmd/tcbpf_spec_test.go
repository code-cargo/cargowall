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
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

const specSteps = `"steps": [{"id": "fetch", "rules": [{"type": "hostname", "value": "step.example.com"}]}]`

// loadPolicyFile loads policy, a JSON config, into cm.
func loadPolicyFile(t *testing.T, cm *config.Manager, policy string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(path, []byte(policy), 0o600))
	require.NoError(t, cm.LoadConfig(path))
}

// The tcbpf spec as startCargoWall loads it: the rule maps at the job's
// size for a policy without step rules (and for one whose steps a default
// allow drops, and for a run that loaded none), at the size with steps for
// one with them; the step-attribution maps shrunk when the feature is off.
// The step rules are settled after it, loaded or not.
func TestLoadTcSpec(t *testing.T) {
	ruleMaps := []string{bpf.TcBpfMapMapCidrs, bpf.TcBpfMapMapPorts, bpf.TcBpfMapMapCidrsV6, bpf.TcBpfMapMapPortsV6}
	tagMaps := []string{"map_task_step", "map_sock_step", "map_task_nspid"}
	full, err := bpf.LoadTcBpf()
	require.NoError(t, err)

	steps := specSteps
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
		{"no policy loaded", "", false, bpf.RuleMapEntriesJobOnly},
	} {
		t.Run(c.name, func(t *testing.T) {
			cm := config.NewConfigManager()
			if c.policy != "" {
				loadPolicyFile(t, cm, c.policy)
			}

			spec, hasSteps, err := loadTcSpec(&StartCmd{StepAttribution: c.stepAttribution}, cm)
			require.NoError(t, err)
			assert.Equal(t, c.ruleSize == bpf.RuleMapEntries, hasSteps, "steps, for the gate")
			known, _ := cm.StepRulesKnown()
			assert.True(t, known, "the step rules are settled")
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

// The step-rules gate as startCargoWall loads tcbpf: on exactly when the
// startup policy has steps, read once, before the load, so a policy the
// load sees arrive changes nothing; and a verifier rejection of the gate-on
// load loads again with it off, with a Warn, where any other failure is the
// load's failure.
func TestLoadTcObjects_StepRulesGate(t *testing.T) {
	gateOf := func(spec *ebpf.CollectionSpec) uint8 {
		var b uint8
		require.NoError(t, spec.Variables[bpf.TcBpfVarStepRulesEnabled].Get(&b))
		return b
	}
	withSteps := `{"defaultAction": "deny", "rules": [], ` + specSteps + `}`
	for _, c := range []struct {
		name     string
		policy   string
		load     func(attempt int, cm *config.Manager) error
		gates    []uint8 // the gate each load attempt saw
		warned   bool
		failWith string
	}{
		{name: "steps", policy: withSteps, gates: []uint8{1}},
		{name: "no steps", policy: `{"defaultAction": "deny", "rules": []}`, gates: []uint8{0}},
		{name: "no policy", gates: []uint8{0}},
		{
			name: "a policy that arrives during the load", policy: `{"defaultAction": "deny", "rules": []}`,
			load: func(_ int, cm *config.Manager) error {
				loadPolicyFile(t, cm, withSteps)
				return nil
			},
			gates: []uint8{0},
		},
		{
			name: "the verifier rejects the step lookup", policy: withSteps,
			load: func(attempt int, _ *config.Manager) error {
				if attempt == 0 {
					return &ebpf.VerifierError{Cause: errors.New("too complex")}
				}
				return nil
			},
			gates: []uint8{1, 0}, warned: true,
		},
		{
			name: "the verifier rejects a load without steps", policy: `{"defaultAction": "deny", "rules": []}`,
			load:  func(int, *config.Manager) error { return &ebpf.VerifierError{Cause: errors.New("too complex")} },
			gates: []uint8{0}, failWith: "too complex",
		},
		{
			name: "another failure", policy: withSteps,
			load:  func(int, *config.Manager) error { return errors.New("no memory") },
			gates: []uint8{1}, failWith: "no memory",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			cm := config.NewConfigManager()
			if c.policy != "" {
				loadPolicyFile(t, cm, c.policy)
			}
			var gates []uint8
			loadCollection = func(_ *slog.Logger, collection string, spec *ebpf.CollectionSpec, _ ebpf.CollectionOptions, _ any) error {
				require.Equal(t, "tcbpf", collection)
				gates = append(gates, gateOf(spec))
				if c.load != nil {
					return c.load(len(gates)-1, cm)
				}
				return nil
			}
			t.Cleanup(func() { loadCollection = defaultLoadCollection })

			var logs bytes.Buffer
			var objs bpf.TcBpfObjects
			err := loadTcObjects(&StartCmd{}, cm, slog.New(slog.NewTextHandler(&logs, nil)), &objs)
			if c.failWith != "" {
				require.ErrorContains(t, err, c.failWith)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, c.gates, gates)
			assert.Equal(t, c.warned, bytes.Contains(logs.Bytes(), []byte("Step rules are off")))
		})
	}
}
