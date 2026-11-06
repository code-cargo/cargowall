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

package steps

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/code-cargo/cargowall/pkg/events"
)

// envArea lays entries out as execve leaves them: each NUL-terminated.
func envArea(entries ...string) []byte {
	return []byte(strings.Join(entries, "\x00") + "\x00")
}

func TestIdentify(t *testing.T) {
	step := func(id string) Identity { return Identity{StepID: id, Class: events.StepClassStep} }
	runner := Identity{Class: events.StepClassRunner}
	unknown := Identity{Class: events.StepClassUnknown}

	// The shape of a hosted runner's step environment: the name sits among
	// GITHUB_ACTION_* neighbours that share its prefix.
	hosted := envArea("HOME=/home/runner", "GITHUB_ACTION_PATH=/home/runner/work/_actions/x",
		"GITHUB_ACTION_REPOSITORY=actions/cache", "GITHUB_ACTION=cache", "GITHUB_ACTION_REF=v4", "CI=true")

	for _, tc := range []struct {
		name   string
		env    []byte
		envLen int // 0 = len(env)
		want   Identity
	}{
		{name: "step", env: hosted, want: step("cache")},
		{name: "generated name", env: envArea("A=1", "GITHUB_ACTION=__run_2"), want: step("__run_2")},
		{name: "first entry", env: envArea("GITHUB_ACTION=build"), want: step("build")},
		{name: "last entry, no trailing NUL", env: []byte("A=1\x00GITHUB_ACTION=build"), want: step("build")},
		// hashFiles(): all of it read, and no step named.
		{name: "runner helper", env: envArea("HOME=/home/runner", "GITHUB_ACTION_PATH=/x", "PATH=/usr/bin"), want: runner},
		{name: "unreadable", env: nil, envLen: -1, want: unknown},
		{name: "empty value", env: envArea("GITHUB_ACTION="), want: unknown},
		{name: "control character", env: envArea("GITHUB_ACTION=a\tb"), want: unknown},
		{name: "space", env: envArea("GITHUB_ACTION=a b"), want: unknown},
		{name: "non-ASCII", env: envArea("GITHUB_ACTION=é"), want: unknown},
		{name: "too long", env: envArea("GITHUB_ACTION=" + strings.Repeat("a", maxStepIDLen+1)), want: unknown},
		{name: "longest", env: envArea("GITHUB_ACTION=" + strings.Repeat("a", maxStepIDLen)), want: step(strings.Repeat("a", maxStepIDLen))},
		{name: "two entries", env: envArea("GITHUB_ACTION=a", "GITHUB_ACTION=b"), want: unknown},
		{name: "prefix only", env: envArea("XGITHUB_ACTION=a", "GITHUB_ACTIONS=true"), want: runner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := tc.envLen
			switch n {
			case 0:
				n = len(tc.env)
			case -1:
				n = 0
			}
			assert.Equal(t, tc.want, identify(tc.env, n))
		})
	}
}

// The kernel copies at most STEP_ENV_MAX bytes and reports the area's whole
// length. A cut before the name, or through it, identifies nothing: a cut
// name could pass for a shorter one.
func TestIdentify_CutEnvironment(t *testing.T) {
	env := envArea("A=1", "GITHUB_ACTION=build-and-test", "B=2")
	whole := len(env)
	at := strings.Index(string(env), "GITHUB_ACTION=")
	end := at + len("GITHUB_ACTION=build-and-test")

	assert.Equal(t, Identity{StepID: "build-and-test", Class: events.StepClassStep},
		identify(env[:end+1], whole), "cut after the name's NUL")
	assert.Equal(t, Identity{Class: events.StepClassUnknown},
		identify(env[:end], whole), "cut right before the name's NUL")
	assert.Equal(t, Identity{Class: events.StepClassUnknown},
		identify(env[:end-4], whole), "cut through the name")
	assert.Equal(t, Identity{Class: events.StepClassUnknown},
		identify(env[:at], whole), "cut before the name")
	assert.Equal(t, Identity{Class: events.StepClassUnknown},
		identify(envArea("A=1", "B=2"), whole+100), "a cut area naming no step is no runner helper")
}
