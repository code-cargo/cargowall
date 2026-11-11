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
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/code-cargo/cargowall/bpf"
	"github.com/code-cargo/cargowall/pkg/config"
)

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
// load; nothing loads one after it.
func loadTcSpec(stepAttribution bool, configMgr *config.Manager) (*ebpf.CollectionSpec, error) {
	spec, err := bpf.LoadTcBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load TC eBPF spec: %w", err)
	}
	if !stepAttribution {
		// Present unless the generated spec is stale (go generate not run);
		// verify-bpf-generated-code guards that, but don't panic if it slips.
		for _, name := range []string{"map_task_step", "map_sock_step", "map_task_nspid"} {
			if m := spec.Maps[name]; m != nil {
				m.MaxEntries = 64
			}
		}
	}
	if err := bpf.SizeRuleMaps(spec, configMgr.HasStepRules()); err != nil {
		return nil, fmt.Errorf("failed to size the rule maps: %w", err)
	}
	return spec, nil
}
