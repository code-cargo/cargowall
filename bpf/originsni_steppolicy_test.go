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

package bpf

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/sni/snitest"
)

// A punt carries the step policy its socket is judged by, as the kernel
// read it with the punt (step_policy_judged): the policy the socket's step
// tag is bound to with step rules on, and the job's, 0, with them off or
// with the tag unbound. The oracle judges the flow's name by it.
func TestOriginL7PuntCarriesStepPolicy(t *testing.T) {
	for _, c := range []struct {
		name       string
		stepRules  bool
		bound      uint32 // the tag's binding, 0 for none
		wantPolicy uint16
	}{
		{"step rules on, the tag bound", true, 3, 3},
		{"step rules on, the tag unbound", true, 0, 0},
		{"step rules off", false, 3, 0},
		{"a binding past 16 bits reads as the job's", true, 0x10003, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			requireBPF(t)
			spec, err := LoadOriginBpf()
			require.NoError(t, err)
			require.NoError(t, SetStepRules(spec, c.stepRules))
			var objs OriginBpfObjects
			require.NoError(t, spec.LoadAndAssign(&objs, nil))
			t.Cleanup(func() { objs.Close() })
			h := l7HarnessFor(t, &objs, l7ModeObserve, 443, L7ScopeTLS)

			conn, cookie, _ := h.dial(t)
			require.NoError(t, objs.MapSockStep.Put(cookie, uint32(9)))
			if c.bound != 0 {
				require.NoError(t, objs.MapStepPolicy.Put(uint32(9), c.bound))
			}
			_, err = conn.Write(snitest.BuildClientHello("step.example.com"))
			require.NoError(t, err)
			require.Equal(t, c.wantPolicy, readL7SampleFor(t, h.rd, cookie).StepPolicy)
		})
	}
}
