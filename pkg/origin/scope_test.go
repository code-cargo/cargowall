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

package origin

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestScopeStatSlotsMatchKernel pins podScope's stat slots to
// SCOPE_STAT_* in scopebpf.c: a drift would report one shortfall as the
// other, or read past the map.
func TestScopeStatSlotsMatchKernel(t *testing.T) {
	src, err := os.ReadFile("../../bpf/scopebpf.c")
	require.NoError(t, err)
	for name, want := range map[string]uint64{
		"SCOPE_STAT_FULL": scopeStatFull,
		"SCOPE_STAT_ROOT": scopeStatRoot,
		"SCOPE_STATS_MAX": scopeStatsMax,
	} {
		m := regexp.MustCompile(`(?m)^#define ` + name + `\s+(\d+)\b`).FindSubmatch(src)
		require.NotNil(t, m, "scopebpf.c must #define %s", name)
		got, err := strconv.ParseUint(string(m[1]), 10, 64)
		require.NoError(t, err)
		require.Equal(t, want, got, "%s drifted between scopebpf.c and pkg/origin", name)
	}
}
