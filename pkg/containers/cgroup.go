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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// verifyContainerTask confirms that pid currently belongs to containerID by
// reading /proc/<pid>/cgroup and requiring a cgroup path that names the full
// container id (docker uses the full 64-char id in both the systemd scope
// name and the cgroupfs directory). This is the identity check between
// inspect and tag: a recycled pid belongs to some other cgroup and fails
// here, so PID reuse can never tag an unrelated process. Returns the cgroup
// v2 id (the cgroup directory inode — what bpf_skb_cgroup_id reports for the
// container's sockets), or 0 when only a v1 hierarchy names the container
// (identity still confirmed; cgroup-based classification just unavailable).
func verifyContainerTask(procRoot, cgroupRoot string, pid int, containerID string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return 0, fmt.Errorf("read cgroup of pid %d: %w", pid, err)
	}

	identityConfirmed := false
	var v2Path string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		// Format: hierarchy-ID:controller-list:cgroup-path; v2 is "0::<path>".
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if strings.Contains(parts[2], containerID) {
			identityConfirmed = true
		}
		if parts[0] == "0" && parts[1] == "" {
			v2Path = parts[2]
		}
	}
	if !identityConfirmed {
		return 0, fmt.Errorf("pid %d is not in a cgroup of container %s", pid, containerID[:min(12, len(containerID))])
	}
	if v2Path == "" || !strings.Contains(v2Path, containerID) {
		return 0, nil // v1/hybrid or foreign v2 path: identity ok, no usable cgroup id
	}

	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(cgroupRoot, v2Path), &st); err != nil {
		return 0, nil // cgroup vanished or unmounted at this root: degrade to IP classification
	}
	return st.Ino, nil
}
