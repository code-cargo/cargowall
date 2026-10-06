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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVerifierInsns(t *testing.T) {
	// Stats line of a successful load (LogLevelStats), as 6.17 writes it.
	n, ok := ParseVerifierInsns("processed 657658 insns (limit 1000000) max_states_per_insn 42 total_states 9000 peak_states 800 mark_read 120\n")
	assert.True(t, ok)
	assert.Equal(t, 657658, n)

	// Rejection text, as 6.6 wrote it on Blacksmith (issue #138).
	n, ok = ParseVerifierInsns("BPF program is too large. Processed 1000001 insn")
	assert.True(t, ok)
	assert.Equal(t, 1000001, n)

	// LogLevelBranch logs carry the stats line last; take the last match.
	n, ok = ParseVerifierInsns("0: (b7) r0 = 0\nprocessed 5 insns (limit 1000000)\n...\nprocessed 5546 insns (limit 1000000)\n")
	assert.True(t, ok)
	assert.Equal(t, 5546, n)

	_, ok = ParseVerifierInsns("")
	assert.False(t, ok)
	_, ok = ParseVerifierInsns("no stats here")
	assert.False(t, ok)
}
