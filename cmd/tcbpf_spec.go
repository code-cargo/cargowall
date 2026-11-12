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
	"github.com/code-cargo/cargowall/pkg/steps"
)

// loadCollection loads a collection spec into a bpf2go objects struct, an
// attempt a rejection of which is retried tentatively; a seam for the
// step-rules gate's tests.
var loadCollection = cargowallEbpf.LoadObjectsAttempt

// loadTcObjects loads the tcbpf collection into objs, from loadTcSpec's
// spec, with step rules on exactly when the startup policy has steps and
// step attribution is on (loadTcSpec drops them without it). The gate is
// decided once, from the policy in hand before the load: it is a load-time
// constant, and nothing delivers a policy after the load, so a path that
// ever did would have to reload the collection to change it. On a kernel
// whose verifier rejects the gate-on load, the collection loads without the
// step lookup (bpf.LoadWithStepRules), and the policy's step rules are
// dropped with the rejection as the reason (config.Manager.StepRulesLost):
// every step gets the job's rules, which fails closed.
func loadTcObjects(cmd *StartCmd, configMgr *config.Manager, logger *slog.Logger, objs *bpf.TcBpfObjects) error {
	spec, steps, err := loadTcSpec(cmd, configMgr)
	if err != nil {
		return err
	}
	if why := configMgr.StepRulesLost(); why != "" {
		logger.Info("Step rules stay off: "+why, "result", "every step gets the job's rules")
	}
	opts := ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats}}
	on, rejected, err := bpf.LoadWithStepRules(spec, steps, func(spec *ebpf.CollectionSpec, tentative bool) error {
		return loadCollection(logger, "tcbpf", spec, opts, objs, tentative)
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
	if steps && !on {
		dropStepRules(configMgr, "tcbpf "+cargowallEbpf.RejectionReason(rejected), logger)
	}
	return nil
}

// stepRulesHook is the cgroup hook's step-rules gate (origin.Observer).
type stepRulesHook interface {
	StepRules() bool
	StepRulesLost() string
}

// settleStepTier drops the policy's step rules when, the hooks loaded,
// nothing can judge a step by them: the step tracker did not start, so no
// socket carries a step, or the cgroup hook's verifier rejected the step
// lookup there alone (obs.StepRulesLost). Then the DNS path installs and
// scopes nothing for a step, which would narrow the job's flows for no
// step's benefit. obs is nil without the hook.
func settleStepTier(configMgr *config.Manager, stepTracker *steps.Tracker, stepErr error, obs stepRulesHook, logger *slog.Logger) {
	if !configMgr.HasStepRules() {
		return
	}
	switch {
	case stepTracker == nil && stepErr != nil:
		dropStepRules(configMgr, "step attribution did not start: "+cargowallEbpf.RejectionReason(stepErr), logger)
	case stepTracker == nil:
		dropStepRules(configMgr, "step attribution did not start", logger)
	case obs != nil && !obs.StepRules():
		dropStepRules(configMgr, "originbpf "+obs.StepRulesLost(), logger)
	}
}

// dropStepRules drops the policy's step rules for why, with a Warn.
func dropStepRules(configMgr *config.Manager, why string, logger *slog.Logger) {
	if configMgr.DropStepRules(why) {
		logger.Warn("Step rules are off: "+why, "result", "every step gets the job's rules")
	}
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
// that loaded no policy has none (config.Manager.SettleStepRules), and,
// with step attribution off, drops them: no socket would carry a step. It
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
	if !cmd.StepAttribution {
		configMgr.DropStepRules("step attribution is off, so no socket carries a step")
	}
	steps := configMgr.HasStepRules()
	if err := bpf.SizeRuleMaps(spec, steps); err != nil {
		return nil, false, fmt.Errorf("failed to size the rule maps: %w", err)
	}
	return spec, steps, nil
}
