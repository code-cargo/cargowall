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
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
)

// loadCollection loads a collection spec into a bpf2go objects struct
// (pkg/ebpf.LoadObjects); a seam for the step-rules gate's tests.
var loadCollection = defaultLoadCollection

var defaultLoadCollection = cargowallEbpf.LoadObjects

// loadTcObjects loads the tcbpf collection into objs, from loadTcSpec's
// spec, with step rules on exactly when the startup policy has steps and
// step attribution is on: without it no socket carries a step's tag, so no
// step could be judged by its rules. The gate is decided once, from the
// policy in hand before the load: it is a load-time constant, and nothing
// delivers a policy after the load, so a path that ever did would have to
// reload the collection to change it. On a kernel whose verifier rejects
// the step lookup, the collection loads without it (bpf.LoadWithStepRules):
// the steps lose their own rules, with a Warn, and the loss reads as
// HasStepRules with objs.StepRules false.
func loadTcObjects(cmd *StartCmd, configMgr *config.Manager, logger *slog.Logger, objs *bpf.TcBpfObjects) error {
	spec, steps, err := loadTcSpec(cmd, configMgr)
	if err != nil {
		return err
	}
	gate := steps && cmd.StepAttribution
	if steps && !gate {
		logger.Info("Step rules stay off: without step attribution no socket carries a step, so every step gets the job's rules")
	}
	opts := ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats}}
	on, err := bpf.LoadWithStepRules(spec, gate, func(spec *ebpf.CollectionSpec) error {
		return loadCollection(logger, "tcbpf", spec, opts, objs)
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			logger.Error("eBPF verifier error - Full log follows:")
			// Print the full log to stderr since it might be very long
			_, _ = fmt.Fprintf(os.Stderr, "\n=== VERIFIER LOG START ===\n%s\n=== VERIFIER LOG END ===\n", verr.Log)
		}
		return fmt.Errorf("failed to load TC eBPF objects: %w", err)
	}
	if gate && !on {
		logger.Warn("Step rules are off: this kernel's verifier rejected the step lookup, so every step gets the job's rules alone")
	}
	return nil
}

// loadTcSpec loads the tcbpf collection spec, sized for the run.
//
// The step-attribution maps preallocate ~8MB of kernel memory at their full
// size (hash maps preallocate by default). They are shrunk when the feature
// is off — every non-GitHub run — but never when it is on: stepbpf.c
// declares the full sizes and MapReplacements rejects mismatched specs.
//
// The rule maps are sized for the policy in hand (bpf.SizeRuleMaps): at the
// job's size alone without step rules, as before step policies, and with
// room for the steps' with them. The policy is read once, here, before the
// load; nothing loads one after it. So this settles the step rules: a run
// that loaded no policy has none (config.Manager.SettleStepRules). It
// reports whether the policy has steps, for the step-rules gate.
func loadTcSpec(cmd *StartCmd, configMgr *config.Manager) (*ebpf.CollectionSpec, bool, error) {
	spec, err := bpf.LoadTcBpf()
	if err != nil {
		return nil, false, fmt.Errorf("failed to load TC eBPF spec: %w", err)
	}
	if !cmd.StepAttribution {
		// Present unless the generated spec is stale (go generate not run);
		// verify-bpf-generated-code guards that, but don't panic if it slips.
		for _, name := range []string{"map_task_step", "map_sock_step", "map_task_nspid"} {
			if m := spec.Maps[name]; m != nil {
				m.MaxEntries = 64
			}
		}
	}
	configMgr.SettleStepRules()
	steps := configMgr.HasStepRules()
	if err := bpf.SizeRuleMaps(spec, steps); err != nil {
		return nil, false, fmt.Errorf("failed to size the rule maps: %w", err)
	}
	return spec, steps, nil
}
