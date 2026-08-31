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

// Command bpfspec prints a canonical, order-independent summary of a compiled
// BPF object's map and program definitions.
//
// verify-bpf-generated-code compares a committed object against a freshly
// generated one. It cannot compare bytes: clang emits the .BTF string table in
// an order that is not stable across hosts. But excluding .BTF wholesale makes
// the check blind to everything that LIVES there — map definitions are BTF
// types, so `max_entries` can change with no effect on disassembly, section
// sizes, symbols or relocations. A stale object then compares equal while
// silently rejecting writes to a key the new one accepts, which is how an L7
// mode gate ends up permanently off.
//
// So: read the definitions with the same loader the daemon uses, and print
// them sorted. Semantic, and immune to the string ordering that forced the
// byte comparison out in the first place.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/cilium/ebpf"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: bpfspec <object.o>")
		os.Exit(2)
	}
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "bpfspec: %v\n", err)
		os.Exit(1)
	}

	names := make([]string, 0, len(spec.Maps))
	for n := range spec.Maps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		m := spec.Maps[n]
		fmt.Printf("map %s type=%s key=%d value=%d max_entries=%d flags=%#x\n",
			n, m.Type, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
	}

	names = names[:0]
	for n := range spec.Programs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := spec.Programs[n]
		fmt.Printf("prog %s type=%s attach=%s section=%q insns=%d\n",
			n, p.Type, p.AttachType, p.SectionName, len(p.Instructions))
	}
}
