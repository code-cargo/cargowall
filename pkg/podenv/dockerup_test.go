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

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// withInterfaces stands names in for the host's interfaces for the test.
func withInterfaces(t *testing.T, names ...string) {
	t.Helper()
	saved := interfaces
	t.Cleanup(func() { interfaces = saved })
	interfaces = func() ([]net.Interface, error) {
		var out []net.Interface
		for _, name := range names {
			out = append(out, net.Interface{Name: name})
		}
		return out, nil
	}
}

// pingCounter serves /_ping on a unix socket of its own, answering once
// ready closes (nil for at once), and counts the requests that reached it.
func pingCounter(t *testing.T, ready <-chan struct{}) (string, *atomic.Int32) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		fmt.Fprint(w, "OK")
	})}
	go func() {
		if ready != nil {
			<-ready
		}
		_ = srv.Serve(l)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = l.Close()
	})
	return sock, &n
}

// Docker's bridges are found by its naming alone, and the daemon is asked
// whether it answers only with a socket and a bridge to show for it: a
// socket with no bridge is not asked, nor is no socket. One that accepts
// and does not answer costs the 2s, and says why.
func TestProbeUp(t *testing.T) {
	withInterfaces(t, "lo", "eth0", "docker0", "br-1a2b3c4d5e6f", "br-ex", "vmbr0")
	sock, pings := pingCounter(t, nil)
	d := Dockerd{Kind: DockerdLocal}
	d.probeUp(sock)
	if want := []string{"docker0", "br-1a2b3c4d5e6f"}; !slices.Equal(d.Bridges, want) || !d.Answers || pings.Load() != 1 {
		t.Fatalf("bridges %v, answers %v, %d pings; want %v, true, 1", d.Bridges, d.Answers, pings.Load(), want)
	}

	withInterfaces(t, "lo", "eth0", "br-ex")
	sock, pings = pingCounter(t, nil)
	d = Dockerd{Kind: DockerdLocal}
	d.probeUp(sock)
	if len(d.Bridges) != 0 || d.Answers || pings.Load() != 0 || !d.Pending() {
		t.Fatalf("no bridge: bridges %v, answers %v, %d pings, pending %v; want none asked, pending",
			d.Bridges, d.Answers, pings.Load(), d.Pending())
	}

	withInterfaces(t, "docker0")
	d = Dockerd{Kind: DockerdAbsent}
	d.probeUp(filepath.Join(t.TempDir(), "none.sock"))
	if !d.Unreachable() || d.Answers {
		t.Fatalf("bridges with no socket: unreachable %v, answers %v", d.Unreachable(), d.Answers)
	}

	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	sock, _ = pingCounter(t, never)
	d = Dockerd{Kind: DockerdLocal}
	began := time.Now()
	d.probeUp(sock)
	if took := time.Since(began); took > 3*time.Second || d.Answers || !d.Pending() || !strings.Contains(d.Reason, "its answer") {
		t.Fatalf("a socket that does not answer: took %s, answers %v, pending %v, reason %q", took, d.Answers,
			d.Pending(), d.Reason)
	}
}

// A daemon that has already answered, its /info or servingPid's request, is
// not asked again.
func TestProbeUpAnsweredAlready(t *testing.T) {
	withInterfaces(t, "docker0")
	sock, pings := pingCounter(t, nil)
	d := Dockerd{Kind: DockerdForeign, info: &daemonInfo{}}
	d.probeUp(sock)
	if !d.Answers || pings.Load() != 0 {
		t.Fatalf("answers %v after %d pings; want true after none", d.Answers, pings.Load())
	}
}

// What startup makes of the daemon's state.
func TestDockerdUpClasses(t *testing.T) {
	for _, c := range []struct {
		name                       string
		d                          Dockerd
		none, pending, unreachable bool
	}{
		{name: "no socket, no bridge", d: Dockerd{Kind: DockerdAbsent}, none: true},
		{name: "bridges, no socket", d: Dockerd{Kind: DockerdAbsent, Bridges: []string{"docker0"}}, unreachable: true},
		{name: "socket, no bridge yet", d: Dockerd{Kind: DockerdLocal}, pending: true},
		{name: "a stale socket", d: Dockerd{Kind: DockerdUnknown}, pending: true},
		{name: "bridges, not answering", d: Dockerd{Kind: DockerdLocal, Bridges: []string{"docker0"}}, pending: true},
		{name: "up", d: Dockerd{Kind: DockerdLocal, Bridges: []string{"docker0"}, Answers: true}},
	} {
		if c.d.None() != c.none || c.d.Pending() != c.pending || c.d.Unreachable() != c.unreachable {
			t.Errorf("%s: none %v pending %v unreachable %v, want %v %v %v", c.name, c.d.None(), c.d.Pending(),
				c.d.Unreachable(), c.none, c.pending, c.unreachable)
		}
	}
}
