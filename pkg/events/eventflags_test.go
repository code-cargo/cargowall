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

package events

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBpfEventFlagsMatchTcSource pins the blocked_event flag bits decoded
// here to the EVENT_FLAG_* defines cw_tc_egress sets them from.
func TestBpfEventFlagsMatchTcSource(t *testing.T) {
	src, err := os.ReadFile("../../bpf/tcbpf.c")
	require.NoError(t, err)
	for name, want := range map[string]uint64{
		"EVENT_FLAG_MIDSTREAM": BpfEventFlagMidstream,
		"EVENT_FLAG_STEP_TIER": BpfEventFlagStepTier,
	} {
		m := regexp.MustCompile(`(?m)^#define ` + name + `\s+(0x[0-9A-Fa-f]+|\d+)\b`).FindStringSubmatch(string(src))
		require.NotNil(t, m, "tcbpf.c must #define %s", name)
		got, err := strconv.ParseUint(m[1], 0, 64)
		require.NoError(t, err)
		require.Equal(t, want, got, "%s drifted between tcbpf.c and the Go mirror", name)
	}
}
