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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/code-cargo/cargowall/pkg/origin"
)

// The mode ladder is the safety gate for phase 3b: enforcement must be
// opt-in, and merely turning container attribution on must never start
// dropping traffic.
func TestResolveMode(t *testing.T) {
	tests := []struct {
		name        string
		attribution bool
		enforce     bool
		want        origin.Mode
	}{
		{"attribution off", false, false, origin.ModeObserve},
		{"attribution on defaults to shadow", true, false, origin.ModeShadow},
		{"enforce opt-in", true, true, origin.ModeEnforce},
		{
			// --cgroup-enforce without container attribution leaves the hook
			// unloaded entirely, so it cannot enforce. Fail-safe direction:
			// TC keeps enforcing, nothing silently half-enables.
			"enforce without attribution stays observe", false, true, origin.ModeObserve,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveMode(tt.attribution, tt.enforce))
		})
	}
}

// A nil *containerAttribution is the disabled feature; every method must be
// safe on it so startCargoWall can wire the subsystem unconditionally.
func TestContainerAttributionNilSafe(t *testing.T) {
	var a *containerAttribution
	assert.NotPanics(t, func() {
		a.enableMode()
		a.Close()
		assert.Nil(t, a.enricherArg())
		assert.Nil(t, a.observerProgram())
		a.startUserspace(t.Context(), nil, "", nil, nil)
	})
}
