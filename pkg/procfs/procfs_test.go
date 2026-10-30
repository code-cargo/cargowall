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

package procfs

import (
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// Note: none of these assume a process name is absent from the test's
// ancestry beyond the one they look for: in CI the suite runs on a runner,
// whose ancestry holds Runner.Worker, and in Lima under sudo.

func TestParentPid(t *testing.T) {
	if ppid, ok := ParentPid(os.Getpid()); !ok || ppid != os.Getppid() {
		t.Errorf("ParentPid(self) = %d, %v; want %d", ppid, ok, os.Getppid())
	}
	// PID 0 has no /proc entry.
	if _, ok := ParentPid(0); ok {
		t.Errorf("ParentPid(0): want false")
	}
}

// /proc/<pid>/stat names the process in parentheses, a name that may hold
// spaces and parentheses of its own, then its state and parent.
func TestParseStatPPid(t *testing.T) {
	for in, want := range map[string]int{
		"4242 (sudo) S 4100 4242 4100 0 -1":        4100,
		"4243 (a b) (c)) R 1 4243 4243 0 -1":       1,
		"1 (systemd) S 0 1 1 0 -1 4194560 75 7 0 ": 0,
	} {
		if got, ok := parseStatPPid([]byte(in)); !ok || got != want {
			t.Errorf("parseStatPPid(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "4242 sudo S 1", "4242 (sudo)", "4242 (sudo) S x"} {
		if _, ok := parseStatPPid([]byte(in)); ok {
			t.Errorf("parseStatPPid(%q): want false", in)
		}
	}
}

func TestComm(t *testing.T) {
	// comm is the executable's basename, cut to 15 bytes.
	if comm := Comm(os.Getpid()); comm == "" || len(comm) > 15 {
		t.Errorf("Comm(self) = %q", comm)
	}
	if comm := Comm(0); comm != "" {
		t.Errorf("Comm(0) = %q, want none", comm)
	}
}

func TestAncestorByComm(t *testing.T) {
	parent := Comm(os.Getppid())
	if parent == "" {
		t.Fatal("no name for our parent")
	}
	if pid, comm, ok := AncestorByComm(os.Getpid(), "no-such-comm-xx", parent); !ok || pid != os.Getppid() || comm != parent {
		t.Errorf("AncestorByComm(self, ..., %q) = %d, %q, %v; want %d", parent, pid, comm, ok, os.Getppid())
	}
	if _, _, ok := AncestorByComm(os.Getpid(), "no-such-comm-xx"); ok {
		t.Errorf("AncestorByComm(self, no-such-comm-xx): want false")
	}
}

// A socket is found by its inode among its holder's descriptors, and
// among every process's, where both ends of a pair are ours.
func TestSocketHolders(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	var st unix.Stat_t
	if err := unix.Fstat(fds[0], &st); err != nil {
		t.Fatal(err)
	}
	ours, err := Sockets(os.Getpid())
	if err != nil || !slices.Contains(ours, st.Ino) {
		t.Errorf("Sockets(self) = %v, %v; want it to hold %d", ours, err, st.Ino)
	}
	holders, err := SocketHolders(map[uint64]bool{st.Ino: true, 1<<40 + 7: true})
	if err != nil || !slices.Equal(holders[st.Ino], []int{os.Getpid()}) || len(holders) != 1 {
		t.Errorf("SocketHolders = %v, %v; want only %d holding %d", holders, err, os.Getpid(), st.Ino)
	}
}
