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
	"errors"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// InsnLimit is the kernel's BPF_COMPLEXITY_LIMIT_INSNS — the ceiling on how
// many instructions the verifier will process for one program — unchanged
// since 5.2.
const InsnLimit = 1_000_000

// processedRe matches the statistics line the verifier appends to its log
// when a program is loaded with LogLevelStats — "processed 657658 insns
// (limit 1000000) max_states_per_insn ..." — and the rejection it writes
// when the limit is hit: "BPF program is too large. Processed 1000001 insn".
var processedRe = regexp.MustCompile(`(?i)processed (\d+) insns?`)

// programRe finds the program name in cilium/ebpf's wrapping of a collection
// load failure ("... program cg_origin_egress: load program: ..."). The
// verifier log itself never names the program.
var programRe = regexp.MustCompile(`program ([A-Za-z0-9_]+): load program`)

// VerifierInsns reports how many instructions the verifier processed for
// prog. ok is false when prog was loaded without ebpf.LogLevelStats (there
// is no stats line to read) or the log is otherwise unparseable.
//
// The number is a property of the kernel as much as of the program — the
// same cg_origin_egress verifies in ~660k instructions on 6.17 and is
// rejected at the limit on 6.6 — so it is worth surfacing on every kernel
// the daemon runs on, not only the one CI measures.
func VerifierInsns(prog *ebpf.Program) (insns int, ok bool) {
	if prog == nil {
		return 0, false
	}
	return ParseVerifierInsns(prog.VerifierLog)
}

// ParseVerifierInsns extracts the processed-instruction count from verifier
// log text: the last "processed N insns" stats line of a successful load, or
// the "Processed N insn" of a rejection (then N is the limit plus one). ok is
// false when neither is present.
func ParseVerifierInsns(log string) (insns int, ok bool) {
	m := processedRe.FindAllStringSubmatch(log, -1)
	if len(m) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(m[len(m)-1][1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// LogVerifierStats logs the processed-instruction count of every program in
// progs (a loaded ebpf.Collection's Programs) that carries a stats line.
// Programs using at least one percent of the budget log at Info — in
// practice the one or two that could ever hit the limit — the rest at Debug,
// so the startup log carries the number an operator on an unfamiliar kernel
// needs without eleven lines of noise.
func LogVerifierStats(logger *slog.Logger, collection string, progs map[string]*ebpf.Program) {
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

// LogVerifierRejection logs the same attributes for a program the verifier
// refused, from the error a collection load returned. This is the line that
// matters on the kernel a program is too big for: nothing loads, so
// LogVerifierStats never runs, and the count in the error text is only there
// by accident of how cilium/ebpf trims the log. Returns false (and logs
// nothing) when err is not a verifier rejection.
func LogVerifierRejection(logger *slog.Logger, collection string, err error) bool {
	var verr *ebpf.VerifierError
	if !errors.As(err, &verr) {
		return false
	}
	program := "unknown"
	if m := programRe.FindStringSubmatch(err.Error()); m != nil {
		program = m[1]
	}
	insns, _ := ParseVerifierInsns(strings.Join(verr.Log, "\n"))
	logger.Error("BPF program rejected by the verifier",
		"collection", collection, "program", program,
		"processed_insns", insns, "limit", InsnLimit, "pct", 100*float64(insns)/InsnLimit,
		"error", verr.Cause)
	return true
}
