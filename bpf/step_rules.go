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

	"github.com/cilium/ebpf"
)

// SetStepRules sets the step-rules gate, step_rules_enabled in verdict.h, of
// a collection spec that includes verdict.h (tcbpf or originbpf), before it
// is loaded. Off, the verifier prunes the step-rule lookup from the verdict
// altogether. On, a packet the job's rules decide nothing about may be
// allowed by the own rules of the step whose process made its socket.
func SetStepRules(spec *ebpf.CollectionSpec, on bool) error {
	// The variable has the same name in both collections.
	v := spec.Variables[TcBpfVarStepRulesEnabled]
	if v == nil {
		return errors.New("spec has no " + TcBpfVarStepRulesEnabled + " variable (stale generated code)")
	}
	var b uint8
	if on {
		b = 1
	}
	return v.Set(b)
}

// StepRules reports the step-rules gate a loaded tcbpf collection was built
// with, so a collection sharing its maps can be built the same way. A gate
// it cannot read reads as on: the lookup then runs, and where no step is
// bound to a policy it finds none, so it changes no verdict.
func (o *TcBpfObjects) StepRules() bool {
	var b uint8
	if o.StepRulesEnabled == nil || o.StepRulesEnabled.Get(&b) != nil {
		return true
	}
	return b != 0
}
