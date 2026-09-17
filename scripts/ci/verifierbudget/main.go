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

// verifierbudget loads every cargowall BPF program on the running kernel with
// verifier statistics enabled and reports how many instructions the verifier
// processed for each, against the 1,000,000 limit. Nothing is attached and
// nothing is enforced; it needs root (or CAP_BPF + CAP_PERFMON) to load.
//
// The count is a property of the kernel as much as of the program: the same
// cg_origin_egress verifies in ~700k instructions on the 6.17 Azure kernel CI
// runs on and is rejected at the limit on Blacksmith's 6.6 (issue #138). Run
// it on every kernel we claim to support, not only CI's. The exit status is
// non-zero when any program fails to load, so it can gate a pipeline, and a
// markdown table is appended to $GITHUB_STEP_SUMMARY when that is set.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/bpf"
)

// insnLimit is the kernel's BPF_COMPLEXITY_LIMIT_INSNS, unchanged since 5.2.
const insnLimit = 1_000_000

type collection struct {
	name    string
	load    func() (*ebpf.CollectionSpec, error)
	prepare func(*ebpf.CollectionSpec) error
}

type result struct {
	collection string
	program    string
	insns      int
	err        error
}

// processedRe matches both the stats line of a successful load
// ("processed 705123 insns (limit 1000000) ...") and the rejection message
// ("BPF program is too large. Processed 1000001 insn").
var processedRe = regexp.MustCompile(`(?i)processed (\d+) insns?`)

func main() {
	cols := []collection{
		{name: "tcbpf", load: bpf.LoadTcBpf},
		// pidns_ino gates the namespace walk: at its zero default the
		// verifier prunes that code as dead and step_fork / step_task_iter
		// would be under-counted. Set it the way steps.Start does.
		{name: "stepbpf", load: bpf.LoadStepBpf, prepare: setPidns},
		{name: "originbpf", load: bpf.LoadOriginBpf},
	}

	var results []result
	failed := false
	for _, c := range cols {
		spec, err := c.load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %s spec: %v\n", c.name, err)
			os.Exit(2)
		}
		if c.prepare != nil {
			if err := c.prepare(spec); err != nil {
				fmt.Fprintf(os.Stderr, "prepare %s spec: %v\n", c.name, err)
				os.Exit(2)
			}
		}
		names := make([]string, 0, len(spec.Programs))
		for n := range spec.Programs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			r := measure(c.name, spec, n)
			if r.err != nil {
				failed = true
			}
			results = append(results, r)
		}
	}

	kernel := kernelRelease()
	report(os.Stdout, kernel, results)
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if err := appendSummary(p, kernel, results); err != nil {
			fmt.Fprintf(os.Stderr, "write step summary: %v\n", err)
		}
	}
	if failed {
		os.Exit(1)
	}
}

// measure loads one program of spec in isolation — every other program is
// dropped from a copy of the spec — so a program that blows the budget cannot
// hide the numbers of the ones that do not.
func measure(col string, spec *ebpf.CollectionSpec, name string) result {
	one := spec.Copy()
	for n := range one.Programs {
		if n != name {
			delete(one.Programs, n)
		}
	}
	r := result{collection: col, program: name}
	coll, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		r.err = err
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			r.insns = parseProcessed(strings.Join(verr.Log, "\n"))
			if verr.Cause != nil {
				r.err = verr.Cause
			}
		}
		return r
	}
	defer coll.Close()
	r.insns = parseProcessed(coll.Programs[name].VerifierLog)
	return r
}

// parseProcessed returns the instruction count from the last "processed N"
// occurrence in a verifier log, or 0 when there is none.
func parseProcessed(log string) int {
	matches := processedRe.FindAllStringSubmatch(log, -1)
	if len(matches) == 0 {
		return 0
	}
	n, err := strconv.Atoi(matches[len(matches)-1][1])
	if err != nil {
		return 0
	}
	return n
}

// setPidns mirrors steps.Start: the daemon's pid-namespace inode is what the
// namespace walk compares against, so the walk is only live when it is set.
func setPidns(spec *ebpf.CollectionSpec) error {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return fmt.Errorf("stat pid namespace: %w", err)
	}
	v := spec.Variables[bpf.StepBpfVarPidnsIno]
	if v == nil {
		return errors.New("stepbpf spec has no pidns_ino variable")
	}
	return v.Set(uint32(st.Ino))
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Release[:])
}

func status(r result) string {
	if r.err == nil {
		return "ok"
	}
	msg := r.err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 100 {
		msg = msg[:100] + "…"
	}
	return "FAILED: " + msg
}

func pct(insns int) float64 { return 100 * float64(insns) / insnLimit }

func report(w io.Writer, kernel string, results []result) {
	fmt.Fprintf(w, "BPF verifier budget on kernel %s (limit %d insns)\n\n", kernel, insnLimit)
	fmt.Fprintf(w, "%-10s %-20s %10s %7s  %s\n", "COLLECTION", "PROGRAM", "PROCESSED", "%LIMIT", "RESULT")
	for _, r := range results {
		fmt.Fprintf(w, "%-10s %-20s %10d %6.1f%%  %s\n", r.collection, r.program, r.insns, pct(r.insns), status(r))
	}
}

func appendSummary(path, kernel string, results []result) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "### CargoWall BPF verifier budget\n\nKernel `%s`, limit %d instructions per program.\n\n", kernel, insnLimit)
	b.WriteString("| Collection | Program | Processed | % of limit | Result |\n|---|---|---:|---:|---|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | `%s` | %d | %.1f%% | %s |\n", r.collection, r.program, r.insns, pct(r.insns), status(r))
	}
	b.WriteString("\n")
	_, err = f.WriteString(b.String())
	return err
}
