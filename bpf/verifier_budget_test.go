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
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
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

// TestVerifierBudget loads every collection with verifier statistics and
// logs the processed-instruction count per program, so the number is in the
// test output on whatever kernel runs the suite (grep "verifier:"), and
// fails when a program does not load or crosses verifierBudgetPct.
func TestVerifierBudget(t *testing.T) {
	requireBPF(t)

	collections := []struct {
		name    string
		load    func() (*ebpf.CollectionSpec, error)
		prepare func(*ebpf.CollectionSpec) error
		objs    func() any
	}{
		{"tcbpf", LoadTcBpf, nil, func() any { return &TcBpfObjects{} }},
		// pidns_ino gates the namespace walk; at its zero default the
		// verifier prunes that code as dead and step_fork would be
		// under-counted. Set it the way steps.Start does.
		{"stepbpf", LoadStepBpf, setPidnsIno, func() any { return &StepBpfObjects{} }},
		{"originbpf", LoadOriginBpf, nil, func() any { return &OriginBpfObjects{} }},
	}

	for _, c := range collections {
		spec, err := c.load()
		require.NoError(t, err, "load %s spec", c.name)
		if c.prepare != nil {
			require.NoError(t, c.prepare(spec), "prepare %s spec", c.name)
		}
		objs := c.objs()
		err = spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
		})
		if err != nil {
			var verr *ebpf.VerifierError
			if errors.As(err, &verr) {
				// The rejection is the finding, not a skip. The wrapped error
				// names the program and ends with the verifier's own "BPF
				// program is too large. Processed 1000001 insn"; the count is
				// also parsed out so the line reads like the passing ones.
				insns, _ := cargowallEbpf.ParseVerifierInsns(strings.Join(verr.Log, "\n"))
				t.Errorf("verifier: collection=%s processed=%d pct=%.1f FAILED: %v",
					c.name, insns, 100*float64(insns)/cargowallEbpf.InsnLimit, err)
				continue
			}
			// Anything else is an environment limit (no kernel BTF for the
			// step collection, say), which the other tests already report.
			t.Logf("verifier: collection=%s not loadable here: %v", c.name, err)
			continue
		}
		progs := cargowallEbpf.Programs(objs)
		names := make([]string, 0, len(progs))
		for n := range progs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			insns, ok := cargowallEbpf.VerifierInsns(progs[n])
			require.True(t, ok, "%s/%s has no stats line in its verifier log", c.name, n)
			pct := 100 * float64(insns) / cargowallEbpf.InsnLimit
			t.Logf("verifier: collection=%s program=%s processed=%d pct=%.1f", c.name, n, insns, pct)
			if pct > verifierBudgetPct {
				t.Errorf("%s/%s uses %.1f%% of the verifier budget (tripwire %.0f%%)", c.name, n, pct, verifierBudgetPct)
			}
		}
		closeObjects(objs)
	}
}

func setPidnsIno(spec *ebpf.CollectionSpec) error {
	fi, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return err
	}
	v := spec.Variables[StepBpfVarPidnsIno]
	if v == nil {
		return fmt.Errorf("no %s variable in the step spec", StepBpfVarPidnsIno)
	}
	return v.Set(uint32(fi.Sys().(*syscall.Stat_t).Ino))
}

func closeObjects(objs any) {
	if c, ok := objs.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}
