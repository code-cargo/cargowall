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

package podenv

// A process's name and parents from /proc, as podenv and pkg/steps read
// them.

import (
	"bytes"
	"os"
	"strconv"
	"strings"
)

// Comm is the trimmed /proc/<pid>/comm, or "" when unreadable.
func Comm(pid int) string {
	comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}

// ParentPid is pid's parent, from /proc/<pid>/stat.
func ParentPid(pid int) (int, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	return parseStatPPid(data)
}

// parseStatPPid reads the parent from a /proc/<pid>/stat. The comm field
// (2) can contain spaces and parentheses, so it parses from the last ')':
// state is the field after it, ppid the one after that.
func parseStatPPid(stat []byte) (int, bool) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(string(stat[i+1:]))
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, false
	}
	return ppid, true
}

// AncestorByComm walks the parent chain from fromPid, itself included,
// for a process whose comm matches, stopping short of init. Bounded to
// defend against a cyclic or corrupt /proc snapshot; real chains reach pid
// 1 in far fewer hops.
func AncestorByComm(fromPid int, comm string) (int, bool) {
	pid := fromPid
	for range 64 {
		if pid <= 1 {
			return 0, false
		}
		if Comm(pid) == comm {
			return pid, true
		}
		ppid, ok := ParentPid(pid)
		if !ok {
			return 0, false
		}
		pid = ppid
	}
	return 0, false
}
