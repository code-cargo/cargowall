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

package containers

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Full 64-char id: docker names cgroup paths with the full form, never the
// 12-char prefix, and verifyContainerTask matches on what docker writes.
var testContainerID = strings.Repeat("c", 64)

// cgroupV2Line is the systemd-driver v2 entry for a docker container, the
// shape production hosts show in /proc/<pid>/cgroup.
func cgroupV2Line(id string) string {
	return "0::/system.slice/docker-" + id + ".scope"
}

// writeProcEntry fabricates the /proc/<pid>/{cgroup,comm} pair the package
// reads, under an injectable proc root.
func writeProcEntry(t *testing.T, procRoot string, pid int, cgroupContent, comm string) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroupContent), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644))
}

// mkScopeDir creates the container's cgroup v2 scope directory and returns
// its inode — the value bpf_skb_cgroup_id reports for the container's
// sockets, and therefore what verifyContainerTask must hand back.
func mkScopeDir(t *testing.T, cgroupRoot, id string) uint64 {
	t.Helper()
	dir := filepath.Join(cgroupRoot, "system.slice", "docker-"+id+".scope")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	var st unix.Stat_t
	require.NoError(t, unix.Stat(dir, &st))
	return st.Ino
}

func TestVerifyContainerTask(t *testing.T) {
	otherID := strings.Repeat("d", 64)
	tests := []struct {
		name    string
		cgroup  string // "" = no /proc/<pid>/cgroup at all (process gone)
		mkScope bool
		wantErr bool
		wantIno bool // expect the scope dir inode rather than 0
	}{
		{
			name:    "v2 line matching container",
			cgroup:  cgroupV2Line(testContainerID) + "\n",
			mkScope: true,
			wantIno: true,
		},
		{
			// A recycled PID lands in some other container's cgroup: identity
			// must fail so the tag never reaches an unrelated process.
			name:    "cgroup names different container",
			cgroup:  cgroupV2Line(otherID) + "\n",
			wantErr: true,
		},
		{
			name:    "pid gone",
			cgroup:  "",
			wantErr: true,
		},
		{
			// v1/hybrid host: identity is still provable from a v1 hierarchy;
			// only the cgroup-id classification is unavailable.
			name:   "v1 lines only",
			cgroup: "12:memory:/docker/" + testContainerID + "\n1:name=systemd:/docker/" + testContainerID + "\n",
		},
		{
			// v2 path in /proc but no directory under cgroupRoot (unmounted
			// or vanished cgroup): degrade to IP classification, not error.
			name:   "v2 path matching but directory missing",
			cgroup: cgroupV2Line(testContainerID) + "\n",
		},
		{
			// Identity via v1 while the v2 line names a foreign path: no
			// usable cgroup id, but the tag is still safe to apply.
			name:   "foreign v2 path with v1 identity",
			cgroup: "0::/user.slice/session-1.scope\n12:memory:/docker/" + testContainerID + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procRoot, cgroupRoot := t.TempDir(), t.TempDir()
			const pid = 1234
			if tt.cgroup != "" {
				writeProcEntry(t, procRoot, pid, tt.cgroup, "app")
			}
			var wantIno uint64
			if tt.mkScope {
				wantIno = mkScopeDir(t, cgroupRoot, testContainerID)
			}

			ino, err := verifyContainerTask(procRoot, cgroupRoot, pid, testContainerID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantIno {
				assert.Equal(t, wantIno, ino)
				assert.NotZero(t, ino)
			} else {
				assert.Zero(t, ino)
			}
		})
	}
}
