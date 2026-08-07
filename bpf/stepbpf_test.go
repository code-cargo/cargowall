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
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
)

// stepChildEventT mirrors struct step_child_event in stepbpf.c.
type stepChildEventT struct {
	Tgid    uint32
	Ordinal uint32
}

// TestStepFork verifies the step-attribution collection end to end on a real
// kernel: it loads StepBpf against TcBpf's shared maps, attaches the tp_btf
// tracepoints, declares the test process itself as Runner.Worker, forks a
// child, and asserts the kernel assigned it the configured ordinal and
// emitted the new-step ringbuf notification — the exact contract
// pkg/steps.Start builds on. Requires root and kernel BTF.
func TestStepFork(t *testing.T) {
	tcObjs := loadBPFObjects(t)

	spec, err := LoadStepBpf()
	require.NoError(t, err)

	var objs StepBpfObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"map_task_step":  tcObjs.MapTaskStep,
			"map_sock_step":  tcObjs.MapSockStep,
			"map_step_state": tcObjs.MapStepState,
		},
	}); err != nil {
		t.Skipf("step BPF objects not loadable (kernel BTF required): %v", err)
	}
	t.Cleanup(func() { objs.Close() })

	forkLink, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.StepFork,
		AttachType: ebpf.AttachTraceRawTp,
	})
	require.NoError(t, err, "attach sched_process_fork")
	t.Cleanup(func() { forkLink.Close() })

	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.StepExit,
		AttachType: ebpf.AttachTraceRawTp,
	})
	require.NoError(t, err, "attach sched_process_exit")
	t.Cleanup(func() { exitLink.Close() })

	rd, err := ringbuf.NewReader(objs.MapStepEvents)
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() })

	// Declare this test process as the worker: its next direct child gets
	// ordinal 5. Uses the bpf2go-generated state struct so kernel and Go
	// layouts cannot drift.
	const wantOrdinal = 5
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{
		WorkerTgid:  uint32(os.Getpid()),
		Enabled:     1,
		NextOrdinal: wantOrdinal,
	}))

	child := exec.Command("sleep", "1")
	require.NoError(t, child.Start())
	childPID := uint32(child.Process.Pid)
	defer func() { _ = child.Wait() }()

	// The fork hook runs synchronously inside fork(), so the tag must be
	// visible as soon as Start returns.
	var got uint32
	require.NoError(t, tcObjs.MapTaskStep.Lookup(childPID, &got),
		"child tid must be tagged immediately after fork")

	// The new-step notification must arrive for the reconciler. Other test
	// machinery may fork too, so scan until the child's event or deadline,
	// logging every boundary seen for diagnosis.
	rd.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		record, err := rd.Read()
		require.NoError(t, err, "step ringbuf event for the child must arrive")
		require.GreaterOrEqual(t, len(record.RawSample), int(unsafe.Sizeof(stepChildEventT{})))
		ev := (*stepChildEventT)(unsafe.Pointer(&record.RawSample[0]))
		comm, _ := os.ReadFile("/proc/" + strconv.Itoa(int(ev.Tgid)) + "/comm")
		t.Logf("boundary event: tgid=%d ordinal=%d comm=%q", ev.Tgid, ev.Ordinal, string(comm))
		if ev.Tgid != childPID {
			continue
		}
		require.Equal(t, got, ev.Ordinal, "map tag and boundary event must agree")
		require.GreaterOrEqual(t, ev.Ordinal, uint32(wantOrdinal))
		break
	}

	// Exit hygiene: once the child is reaped, its tag must be gone.
	require.NoError(t, child.Wait())
	require.Eventually(t, func() bool {
		var v uint32
		return tcObjs.MapTaskStep.Lookup(childPID, &v) != nil
	}, 2*time.Second, 50*time.Millisecond, "exit tracepoint must delete the child's tag")

	// Disable so later tests in this package see inert step hooks.
	require.NoError(t, tcObjs.MapStepState.Put(uint32(0), TcBpfStepState{}))
}

// TestBlockedEventLayoutMatchesBTF pins the kernel↔userspace event layout:
// every member of the C struct blocked_event (as compiled, via BTF) must sit
// at the same offset as its field in the Go mirror, and the sizes must
// match. This is the guard the step_ordinal repurposing needs — a swapped
// or shifted field (e.g. pid↔step_ordinal) changes a BTF offset and fails
// here, where the ringbuf-decoding tests would silently mis-attribute.
// (A cookie-seeded end-to-end test is not possible: PROG_TEST_RUN allocates
// a real socket for the skb, so its cookie is fresh and unknowable.)
func TestBlockedEventLayoutMatchesBTF(t *testing.T) {
	spec, err := LoadTcBpf()
	require.NoError(t, err)

	typ, err := spec.Types.AnyTypeByName("blocked_event")
	require.NoError(t, err)
	st, ok := typ.(*btf.Struct)
	require.True(t, ok, "blocked_event must be a struct, got %T", typ)

	var evt bpfBlockedEvent
	require.Equal(t, uint32(unsafe.Sizeof(evt)), st.Size, "struct size")

	goOffsets := map[string]uintptr{
		"ip_version":   unsafe.Offsetof(evt.IpVersion),
		"allowed":      unsafe.Offsetof(evt.Allowed),
		"ip_proto":     unsafe.Offsetof(evt.IpProto),
		"flags":        unsafe.Offsetof(evt.Flags),
		"src_ip":       unsafe.Offsetof(evt.SrcIp),
		"dst_ip":       unsafe.Offsetof(evt.DstIp),
		"src_port":     unsafe.Offsetof(evt.SrcPort),
		"dst_port":     unsafe.Offsetof(evt.DstPort),
		"src_ip6":      unsafe.Offsetof(evt.SrcIp6),
		"dst_ip6":      unsafe.Offsetof(evt.DstIp6),
		"timestamp":    unsafe.Offsetof(evt.Timestamp),
		"pid":          unsafe.Offsetof(evt.Pid),
		"step_ordinal": unsafe.Offsetof(evt.StepOrdinal),
	}

	seen := make(map[string]bool)
	for _, m := range st.Members {
		want, known := goOffsets[m.Name]
		require.True(t, known, "C member %q has no Go mirror field", m.Name)
		require.Equal(t, want, uintptr(m.Offset.Bytes()), "offset of %q", m.Name)
		seen[m.Name] = true
	}
	require.Len(t, seen, len(goOffsets), "Go mirror has fields the C struct lacks")
}

// TestStepChildEventLayoutMatchesBTF pins the reconciler notification layout
// the same way.
func TestStepChildEventLayoutMatchesBTF(t *testing.T) {
	spec, err := LoadStepBpf()
	require.NoError(t, err)

	typ, err := spec.Types.AnyTypeByName("step_child_event")
	require.NoError(t, err)
	st, ok := typ.(*btf.Struct)
	require.True(t, ok, "step_child_event must be a struct, got %T", typ)

	var ev stepChildEventT
	require.Equal(t, uint32(unsafe.Sizeof(ev)), st.Size, "struct size")
	require.Len(t, st.Members, 2)
	require.Equal(t, "tgid", st.Members[0].Name)
	require.Equal(t, uintptr(st.Members[0].Offset.Bytes()), unsafe.Offsetof(ev.Tgid))
	require.Equal(t, "ordinal", st.Members[1].Name)
	require.Equal(t, uintptr(st.Members[1].Offset.Bytes()), unsafe.Offsetof(ev.Ordinal))
}

// TestStepMapsShrunkLoad pins the memory optimization in cmd/start.go:
// with step attribution off, the step maps are resized down before load,
// and the collection must still pass the verifier at the small sizes.
func TestStepMapsShrunkLoad(t *testing.T) {
	requireBPF(t)
	spec, err := LoadTcBpf()
	require.NoError(t, err)
	spec.Maps["map_task_step"].MaxEntries = 64
	spec.Maps["map_sock_step"].MaxEntries = 64

	var objs TcBpfObjects
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	objs.Close()
}
