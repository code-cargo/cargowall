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
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
)

// verifierBudgetPct is the share of the verifier's instruction limit any one
// program may use on the kernel running this suite. It is deliberately well
// under 100%: the count is kernel-specific (cg_origin_egress is ~660k on the
// 6.17 kernel CI runs on and over the limit on Blacksmith's 6.6, issue
// #138), so creep that is still comfortable here is what an older verifier
// turns into a load failure. Raising this needs a measurement on the oldest
// kernel we support, not just a green CI.
const verifierBudgetPct = 80.0

// TestVerifierBudget loads every program of every collection with verifier
// statistics and logs the processed-instruction count per program, so the
// number is in the test output on whatever kernel runs the suite (grep
// "verifier:"). Each program is loaded on its own, from a copy of the spec
// with the other programs removed: a whole-collection load stops at the
// first rejection, which would hide the numbers of the programs behind it.
// Fails when a program does not load or crosses verifierBudgetPct.
func TestVerifierBudget(t *testing.T) {
	requireBPF(t)

	collections := []struct {
		name    string
		load    func() (*ebpf.CollectionSpec, error)
		prepare func(*ebpf.CollectionSpec) error
	}{
		{"tcbpf", LoadTcBpf, nil},
		// pidns_ino gates the namespace walk; at its zero default the
		// verifier prunes that code as dead and step_fork would be
		// under-counted. Set it the way steps.Start does.
		{"stepbpf", LoadStepBpf, func(spec *ebpf.CollectionSpec) error {
			return spec.Variables[StepBpfVarPidnsIno].Set(pidnsInode(t))
		}},
		{"originbpf", LoadOriginBpf, nil},
	}

	for _, c := range collections {
		spec, err := c.load()
		require.NoError(t, err, "load %s spec", c.name)
		if c.prepare != nil {
			require.NoError(t, c.prepare(spec), "prepare %s spec", c.name)
		}
		names := make([]string, 0, len(spec.Programs))
		for n := range spec.Programs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			one := spec.Copy()
			for n := range one.Programs {
				if n != name {
					delete(one.Programs, n)
				}
			}
			coll, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
			})
			if err != nil {
				var verr *ebpf.VerifierError
				if errors.As(err, &verr) {
					// The rejection is the finding, not a skip: log it in the
					// same shape as a passing line, count included.
					insns, _ := cargowallEbpf.ParseVerifierInsns(strings.Join(verr.Log, "\n"))
					t.Errorf("verifier: collection=%s program=%s processed=%d pct=%.1f FAILED: %v",
						c.name, name, insns, 100*float64(insns)/cargowallEbpf.InsnLimit, verr.Cause)
					continue
				}
				// Anything else is an environment limit (no kernel BTF for
				// the step collection, say), which other tests already report.
				t.Logf("verifier: collection=%s program=%s not loadable here: %v", c.name, name, err)
				continue
			}
			insns, ok := cargowallEbpf.VerifierInsns(coll.Programs[name])
			coll.Close()
			require.True(t, ok, "%s/%s has no stats line in its verifier log", c.name, name)
			pct := 100 * float64(insns) / cargowallEbpf.InsnLimit
			t.Logf("verifier: collection=%s program=%s processed=%d pct=%.1f", c.name, name, insns, pct)
			if pct > verifierBudgetPct {
				t.Errorf("%s/%s uses %.1f%% of the verifier budget (tripwire %.0f%%)", c.name, name, pct, verifierBudgetPct)
			}
		}
	}
}
