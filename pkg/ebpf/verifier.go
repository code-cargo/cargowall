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

package ebpf

import (
	"log/slog"
	"reflect"
	"regexp"
	"sort"
	"strconv"

	"github.com/cilium/ebpf"
)

// InsnLimit is the kernel's BPF_COMPLEXITY_LIMIT_INSNS — the ceiling on how
// many instructions the verifier will process for one program — unchanged
// since 5.2.
const InsnLimit = 1_000_000

// processedRe matches the statistics line the verifier appends to its log
// when a program is loaded with LogLevelStats:
// "processed 657658 insns (limit 1000000) max_states_per_insn ...".
var processedRe = regexp.MustCompile(`processed (\d+) insns`)

// VerifierInsns reports how many instructions the verifier processed for
// prog. ok is false when prog was loaded without ebpf.LogLevelStats (there
// is no stats line to read) or the log is otherwise unparseable.
//
// The number is a property of the kernel as much as of the program — the
// same cg_origin_egress verifies in ~660k instructions on 6.17 and is
// rejected at the limit on 6.6 (issue #138) — so it is worth surfacing on
// every kernel the daemon runs on, not only the one CI measures.
func VerifierInsns(prog *ebpf.Program) (insns int, ok bool) {
	if prog == nil {
		return 0, false
	}
	m := processedRe.FindAllStringSubmatch(prog.VerifierLog, -1)
	if len(m) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(m[len(m)-1][1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// Programs collects the loaded programs of a bpf2go objects struct (or a
// pointer to one), keyed by their kernel-visible section name from the
// `ebpf:"..."` tag. It walks embedded structs, so passing the whole
// *XxxObjects works. Nil programs are skipped.
func Programs(objs any) map[string]*ebpf.Program {
	out := make(map[string]*ebpf.Program)
	collectPrograms(reflect.ValueOf(objs), out)
	return out
}

var programType = reflect.TypeOf((*ebpf.Program)(nil))

func collectPrograms(v reflect.Value, out map[string]*ebpf.Program) {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f, fv := t.Field(i), v.Field(i)
		if f.Type == programType {
			if name := f.Tag.Get("ebpf"); name != "" && !fv.IsNil() {
				out[name] = fv.Interface().(*ebpf.Program)
			}
			continue
		}
		if f.Anonymous || f.Type.Kind() == reflect.Struct {
			collectPrograms(fv, out)
		}
	}
}

// LogVerifierStats logs the processed-instruction count of every program in
// objs that was loaded with LogLevelStats. Programs using at least one
// percent of the budget log at Info — in practice the one or two that could
// ever hit the limit — the rest at Debug, so the startup log carries the
// number an operator on an unfamiliar kernel needs without eleven lines of
// noise.
func LogVerifierStats(logger *slog.Logger, collection string, objs any) {
	progs := Programs(objs)
	names := make([]string, 0, len(progs))
	for n := range progs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		insns, ok := VerifierInsns(progs[n])
		if !ok {
			continue
		}
		pct := 100 * float64(insns) / InsnLimit
		attrs := []any{"collection", collection, "program", n, "processed_insns", insns, "limit", InsnLimit, "pct", pct}
		if pct >= 1 {
			logger.Info("BPF program verified", attrs...)
		} else {
			logger.Debug("BPF program verified", attrs...)
		}
	}
}
