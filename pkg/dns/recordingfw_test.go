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

package dns

import (
	"errors"
	"net"
	"sync"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// recordingFirewall is a firewall.Firewall that keeps what was written under
// which policy: the job's allows (AddIP) and each step policy's (AddPolicyIP).
type recordingFirewall struct {
	mu        sync.Mutex
	jobAllow  map[string][]config.Port
	jobDeny   map[string]bool
	step      map[uint32]map[string][]config.Port
	stepErr   error
	withhold  bool // admits nothing and writes nothing, as the step gate may
	removeErr error
	// failAfterScope fails a write after its scope ran, as a map refusing
	// an admitted write does.
	failAfterScope error
	removed        []string      // addresses RemovePolicyIP took out
	stepAdd        chan struct{} // signalled on each step write, if set
	policy0        int           // AddPolicyIP calls naming the job's policy
}

func newRecordingFirewall() *recordingFirewall {
	return &recordingFirewall{
		jobAllow: map[string][]config.Port{},
		jobDeny:  map[string]bool{},
		step:     map[uint32]map[string][]config.Port{},
	}
}

func (f *recordingFirewall) SetDefaultAction(config.Action) error { return nil }

func (f *recordingFirewall) SetAuditMode(bool) error { return nil }

func (f *recordingFirewall) UpdateAllowlistTC(cm *config.Manager) error { return nil }

func (f *recordingFirewall) RemoveIP(net.IP) error { return nil }

func (f *recordingFirewall) stepIPs(policy uint32) map[string][]config.Port {
	return f.snapshot(policy)
}

func (f *recordingFirewall) AddIP(ip net.IP, action config.Action, ports []config.Port) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if action == config.ActionAllow {
		f.jobAllow[ip.String()] = config.UnionPorts(f.jobAllow[ip.String()], ports)
	} else {
		f.jobDeny[ip.String()] = true
	}
	return true, nil
}

// AddPolicyIP admits a write unless stepErr refuses it, as the step budget
// would, before scope runs; scope's error withholds it, as the firewall's.
func (f *recordingFirewall) AddPolicyIP(policy uint32, ip net.IP, ports []config.Port, scope func() error) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if policy == 0 {
		f.policy0++
		return false, errors.New("AddPolicyIP under the job's policy")
	}
	if f.stepErr != nil {
		return false, f.stepErr
	}
	if f.withhold {
		return false, nil
	}
	if scope != nil {
		if err := scope(); err != nil {
			return false, err
		}
	}
	if f.failAfterScope != nil {
		return false, f.failAfterScope
	}
	if f.step[policy] == nil {
		f.step[policy] = map[string][]config.Port{}
	}
	prev, seen := f.step[policy][ip.String()]
	if seen {
		ports = config.UnionPorts(prev, ports)
	}
	f.step[policy][ip.String()] = ports
	if f.stepAdd != nil {
		f.stepAdd <- struct{}{}
	}
	return true, nil
}

// RemovePolicyIP takes ip out of step policy's writes, failing while
// removeErr is set.
func (f *recordingFirewall) RemovePolicyIP(policy uint32, ip net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.step[policy], ip.String())
	f.removed = append(f.removed, ip.String())
	return nil
}

// Allows models the verdict over what was written: a job deny decides, then
// the job's allows, then policy's own. Ports nil are all ports.
func (f *recordingFirewall) Allows(policy uint32, ip net.IP, port uint16, proto uint8) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.jobDeny[ip.String()] {
		return false
	}
	if ports, ok := f.jobAllow[ip.String()]; ok && config.DstPortAllowedByRule(port, proto, ports) {
		return true
	}
	ports, ok := f.step[policy][ip.String()]
	return policy != 0 && ok && config.DstPortAllowedByRule(port, proto, ports)
}

func (f *recordingFirewall) snapshot(policy uint32) map[string][]config.Port {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]config.Port{}
	for ip, ps := range f.step[policy] {
		out[ip] = ps
	}
	return out
}

func (f *recordingFirewall) jobAllows(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.jobAllow[ip]
	return ok
}

var _ firewall.Firewall = (*recordingFirewall)(nil)
