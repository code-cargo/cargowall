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
	return gateOn(o.StepRulesEnabled)
}

// StepRules reports the step-rules gate a loaded originbpf collection was
// built with, as TcBpfObjects.StepRules does tcbpf's.
func (o *OriginBpfObjects) StepRules() bool {
	return gateOn(o.StepRulesEnabled)
}

func gateOn(v *ebpf.Variable) bool {
	var b uint8
	if v == nil || v.Get(&b) != nil {
		return true
	}
	return b != 0
}

// LoadWithStepRules loads spec by load with the step-rules gate set to on
// and, should the verifier reject that load, once more with the gate off: a
// kernel that cannot verify the step lookup costs the steps their own rules,
// never the hook. The steps' traffic then gets the job's rules, which is
// fail-closed. load is told whether a rejection of its attempt would be
// retried (tentative), so it can leave the reporting to the caller. It
// reports whether what loaded has the gate on and, when a gate-on load was
// rejected, why.
func LoadWithStepRules(spec *ebpf.CollectionSpec, on bool, load func(spec *ebpf.CollectionSpec, tentative bool) error) (stepRules bool, rejected, err error) {
	if err := SetStepRules(spec, on); err != nil {
		return false, nil, err
	}
	err = load(spec, on)
	var verr *ebpf.VerifierError
	if err == nil || !on || !errors.As(err, &verr) {
		return on && err == nil, nil, err
	}
	if serr := SetStepRules(spec, false); serr != nil {
		return false, err, serr
	}
	return false, err, load(spec, false)
}

// The rule maps' sizes. verdict.h declares the larger, for a policy with
// steps, whose rules share each map with the job's. A policy without steps
// loads them at RuleMapEntriesJobOnly, all they held before step policies,
// so a job with no step rules pays nothing for them.
const (
	RuleMapEntries        uint32 = 16384
	RuleMapEntriesJobOnly uint32 = 4096
)

// ruleMaps are the four rule maps, of the same names in every collection
// that includes verdict.h.
var ruleMaps = []string{TcBpfMapMapCidrs, TcBpfMapMapPorts, TcBpfMapMapCidrsV6, TcBpfMapMapPortsV6}

// SizeRuleMaps sizes a tcbpf spec's rule maps, before it is loaded, for a
// policy with steps or without. The size is read once, from the policy in
// hand at the load: nothing loads a policy after it, and a path that did
// would have to reload the maps to take steps a small load has no room
// for. A collection sharing the maps takes the loaded maps' sizes.
func SizeRuleMaps(spec *ebpf.CollectionSpec, steps bool) error {
	n := RuleMapEntriesJobOnly
	if steps {
		n = RuleMapEntries
	}
	for _, name := range ruleMaps {
		m := spec.Maps[name]
		if m == nil {
			return errors.New("spec has no " + name + " map (stale generated code)")
		}
		m.MaxEntries = n
	}
	return nil
}

// The bridge stamp, STEP_STAMP_* in verdict.h: a packet's mark carries a
// step policy as StepStampMagic | policy, from a Docker bridge port's ingress
// to the uplink's TC egress. A policy past StepStampPolicyMax fits no
// stamp, and its containers' traffic gets the job's rules.
const (
	StepStampMagic     uint32 = 0xCA1B0000
	StepStampMask      uint32 = 0xFFFF0000
	StepStampPolicyMax uint32 = 0xFFFF
)

// BridgeSocketless is how many IP packets have reached a Docker bridge
// port's ingress with no socket, map_br_sockless summed over the CPUs: 0
// while the kernel keeps a container's socket on its packets there, as the
// bridge stamp needs. Packets with no socket by nature (IGMP reports, a nested
// namespace's forwarded traffic) count too.
func (o *TcBpfObjects) BridgeSocketless() (uint64, error) {
	var perCPU []uint64
	if err := o.MapBrSockless.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var n uint64
	for _, v := range perCPU {
		n += v
	}
	return n, nil
}
