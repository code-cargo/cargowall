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
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
)

// stepEndsLost sums map_step_ends_lost over the CPUs.
func stepEndsLost(t *testing.T, objs *StepBpfObjects) uint64 {
	t.Helper()
	var perCPU []uint64
	require.NoError(t, objs.MapStepEndsLost.Lookup(uint32(0), &perCPU))
	var n uint64
	for _, v := range perCPU {
		n += v
	}
	return n
}

// TestStepEnd_LostIsCounted: a step end the ring has no room for, its
// reader gone quiet and full with exec events, is counted.
func TestStepEnd_LostIsCounted(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	// With no reader, about sixty exec events (each over STEP_ENV_MAX) fill
	// the ring's 2MB but for less than one more, and the fork and end
	// events after take what is left, a few hundred roots on.
	for i := 0; i < 5000 && stepEndsLost(t, objs) == 0; i++ {
		require.NoError(t, exec.Command("true").Run())
	}
	require.NotZero(t, stepEndsLost(t, objs), "the ends that found the ring full are counted")
}

// TestStepEnd_AfterExec: a step root that exits after its exec reports
// its step's end, once, dated when it exited, and leaves nothing behind.
func TestStepEnd_AfterExec(t *testing.T) {
	tcObjs, objs, iter := loadStepObjects(t)
	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	child := exec.Command("true")
	require.NoError(t, child.Start())
	childPID := uint32(child.Process.Pid)
	fork, _ := awaitStepEvent(t, rd, stepEvFork, 0, func(f StepBpfStepChildEvent, _ StepBpfStepExecEvent) bool {
		return f.Tgid == childPID
	})
	require.NoError(t, child.Wait())
	end, _ := awaitStepEvent(t, rd, stepEvEnd, fork.Ordinal, func(StepBpfStepChildEvent, StepBpfStepExecEvent) bool {
		return true
	})
	require.Zero(t, end.Pad)
	require.True(t, end.Ktime > fork.Ktime && end.Ktime <= monoNow(t),
		"the end is dated when the root exited: %d not in (%d, now]", end.Ktime, fork.Ktime)
	var k, v uint32
	require.False(t, objs.MapStepLive.Iterate().Next(&k, &v), "the ended root is out of map_step_live")
}

// TestStepEnd_LiveFullIsCounted: a root map_step_live has no room for
// at its exec will never report its end, and that end is counted lost.
func TestStepEnd_LiveFullIsCounted(t *testing.T) {
	tcObjs, objs, iter := loadStepObjectsWith(t, func(spec *ebpf.CollectionSpec) {
		spec.Maps["map_step_live"].MaxEntries = 2
	})
	selfTgid, ok := globalTgid(t, iter, os.Getpid())
	require.True(t, ok)
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{WorkerTgid: selfTgid, Enabled: 1, NextOrdinal: 5}))

	// Three roots running at once, past their exec: the third finds the
	// map full.
	var roots []*exec.Cmd
	for range 3 {
		c := exec.Command("sleep", "2")
		require.NoError(t, c.Start())
		roots = append(roots, c)
	}
	t.Cleanup(func() {
		for _, c := range roots {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})
	require.Eventually(t, func() bool { return stepEndsLost(t, objs) == 1 }, 2*time.Second, 10*time.Millisecond,
		"the root that found map_step_live full")
}
