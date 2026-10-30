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

// Slots of map_scope_stats, mirroring SCOPE_STAT_* in scopebpf.c: the one
// Go copy, which pkg/origin reports from and TestScopeStatSlotsMatchSource
// pins to the C source.
const (
	ScopeStatFull       = iota // map_scope_cgroups was full
	ScopeStatRoot              // a task of ours entered the root cgroup
	ScopeStatFailed            // any other update or delete failure as tasks enter
	ScopeStatShared            // a task outside our pid namespace entered a recorded cgroup
	ScopeStatUnreleased        // a released cgroup's entry could not be deleted
	ScopeStatsMax
)
