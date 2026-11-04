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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
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

// withInterfacesErr makes listing the host's interfaces fail for the test.
func withInterfacesErr(t *testing.T, err error) {
	t.Helper()
	saved := interfaces
	t.Cleanup(func() { interfaces = saved })
	interfaces = func() ([]net.Interface, error) { return nil, err }
}

// Docker's bridges are found by its naming alone, and a daemon behind a
// socket is asked whether it answers whether or not it has made one: one
// with none may be up, its default bridge renamed. Its answer decides,
// within 2s where there are bridges to show for it, or bridges that could
// not be listed, and 300ms where there are none, so a socket that accepts
// and does not answer costs only that. Bridges that could not be listed are
// unknown, not none. With no socket nothing is asked.
func TestProbeUp(t *testing.T) {
	listErr := errors.New("netlink: operation not permitted")
	for _, c := range []struct {
		name       string
		interfaces []string // nil with listErr: the listing fails
		failList   bool
		kind       DockerdKind
		answer     bool // the socket answers; false: it accepts and never does
		bridges    []string
		answers    bool
		within     [2]time.Duration // how long the probe may take
		pending    bool
		none       bool
		unreach    bool
	}{
		{
			name: "bridges, answering", interfaces: []string{"lo", "eth0", "docker0", "br-1a2b3c4d5e6f", "br-ex", "vmbr0"},
			kind: DockerdLocal, answer: true, bridges: []string{"docker0", "br-1a2b3c4d5e6f"}, answers: true,
			within: [2]time.Duration{0, time.Second},
		},
		{
			name: "no Docker bridge, answering (a renamed default bridge)", interfaces: []string{"lo", "eth0", "laneb0"},
			kind: DockerdLocal, answer: true, answers: true, within: [2]time.Duration{0, time.Second},
		},
		{
			name: "no bridge, silent", interfaces: []string{"lo", "eth0"}, kind: DockerdLocal, pending: true,
			within: [2]time.Duration{250 * time.Millisecond, time.Second},
		},
		{
			name: "bridges, silent", interfaces: []string{"docker0"}, kind: DockerdLocal, bridges: []string{"docker0"},
			pending: true, within: [2]time.Duration{1900 * time.Millisecond, 3 * time.Second},
		},
		{
			name: "bridges not listed, silent", failList: true, kind: DockerdLocal, pending: true,
			within: [2]time.Duration{1900 * time.Millisecond, 3 * time.Second},
		},
		{name: "bridges not listed, no socket", failList: true, kind: DockerdAbsent, unreach: true},
		{name: "bridges, no socket", interfaces: []string{"docker0"}, kind: DockerdAbsent, bridges: []string{"docker0"}, unreach: true},
		{name: "no bridge, no socket", interfaces: []string{"lo"}, kind: DockerdAbsent, none: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.failList {
				withInterfacesErr(t, listErr)
			} else {
				withInterfaces(t, c.interfaces...)
			}
			ready := make(chan struct{})
			if c.answer {
				close(ready)
			} else {
				t.Cleanup(func() { close(ready) })
			}
			sock, pings := pingCounter(t, ready)
			if c.kind == DockerdAbsent {
				sock = filepath.Join(t.TempDir(), "none.sock")
			}
			d := Dockerd{Kind: c.kind}
			began := time.Now()
			d.probeUp(sock)
			took := time.Since(began)
			if !slices.Equal(d.Bridges, c.bridges) || d.Answers != c.answers || d.Pending() != c.pending ||
				d.None() != c.none || d.Unreachable() != c.unreach {
				t.Fatalf("bridges %v answers %v pending %v none %v unreachable %v; want %v %v %v %v %v", d.Bridges,
					d.Answers, d.Pending(), d.None(), d.Unreachable(), c.bridges, c.answers, c.pending, c.none, c.unreach)
			}
			if c.kind != DockerdAbsent && (took < c.within[0] || took > c.within[1]) {
				t.Errorf("took %s, want within %v", took, c.within)
			}
			if c.answers && pings.Load() != 1 {
				t.Errorf("%d pings, want 1", pings.Load())
			}
			if c.failList && (!errors.Is(d.BridgesErr, listErr) || !strings.Contains(d.Reason, "its bridges")) {
				t.Errorf("bridges error %v, reason %q", d.BridgesErr, d.Reason)
			}
			if c.pending && !strings.Contains(d.Reason, "its answer") {
				t.Errorf("reason %q does not say why it did not answer", d.Reason)
			}
		})
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
		{name: "socket, no answer", d: Dockerd{Kind: DockerdLocal}, pending: true},
		{name: "socket, no Docker bridge, answering", d: Dockerd{Kind: DockerdLocal, Answers: true}},
		{name: "bridges not listed, no socket", d: Dockerd{Kind: DockerdAbsent, BridgesErr: errors.New("x")}, unreachable: true},
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

// readsDaemon is a shape whose hook scope reads the daemon's runtime: a
// privileged container's, outside Kubernetes, in a pid namespace of its own.
func readsDaemon(d Dockerd) Shape {
	const own = "/system.slice/docker-a.scope"
	return Shape{
		CgroupNS: CgroupNSHost, PidNS: PidNSPrivate, CgroupPath: own, CgroupMount: CgroupMountOurs,
		SocketCgroups: SocketCgroupsKept, InitCgroup: own, OwnTree: CgroupTreeOurs, Dockerd: d,
	}
}

// Before a daemon has answered, it is asked only the one ping: a socket
// that accepts and never answers costs a probe that reads the runtime only
// the ping's 300ms, not a wait for its server, and its server, runtime and
// tree go unread. The daemon is pending, which HookScopeOrPending defers
// and HookScope refuses. One that answers is found serving; where nothing
// reads the runtime, nothing is looked for past the ping.
func TestProbeDaemon(t *testing.T) {
	withInterfaces(t)
	silent, _ := pingCounter(t, make(chan struct{}))
	s := readsDaemon(Dockerd{})
	if !s.readsRuntime(true) {
		t.Fatal("the shape must read the daemon's runtime")
	}
	began := time.Now()
	s.probeDaemon(silent, true)
	if took := time.Since(began); took > time.Second {
		t.Errorf("a silent socket took %v, want only the one ping", took)
	}
	d := s.Dockerd
	if d.Kind != DockerdLocal || d.Answers || d.pid != 0 || d.Runtime != 0 ||
		!strings.Contains(d.Reason, "its runtime: not looked for until it answers") {
		t.Errorf("silent socket: %+v, want local by its listener, no answer, nothing more read", d)
	}
	if _, pending, err := s.HookScopeOrPending(); !pending || err != nil {
		t.Errorf("silent socket: pending %v, %v; want the daemon's rules deferred", pending, err)
	}
	if _, err := s.HookScope(); err == nil || !strings.Contains(err.Error(), "not looked for until it answers") {
		t.Errorf("silent socket: HookScope() = %v, want the refusal, saying why", err)
	}

	served := fakeDaemon(t, http.StatusOK, `{}`)
	s = readsDaemon(Dockerd{})
	s.probeDaemon(served, true)
	if !s.Dockerd.Answers || s.Dockerd.pid != int32(os.Getpid()) {
		t.Errorf("answering daemon: %+v, want it answering, this process serving", s.Dockerd)
	}
	s = readsDaemon(Dockerd{})
	s.probeDaemon(served, false)
	if !s.Dockerd.Answers || s.Dockerd.pid != 0 || s.Dockerd.Reason != "" {
		t.Errorf("answering daemon, the hook off: %+v, want only its answer read", s.Dockerd)
	}
}

// Recheck probes the daemon again, as Detect does for a hook that may load,
// and keeps every other fact: a daemon still to come up when found, now
// answering, is the daemon's rules' to decide, no longer pending, with no
// trace of the first probe's failure. The shape it was given is unchanged.
func TestRecheck(t *testing.T) {
	withInterfaces(t, "docker0")
	served := fakeDaemon(t, http.StatusOK, `{}`)
	s := readsDaemon(Dockerd{Kind: DockerdUnknown, Reason: "dial: connection refused"})
	if _, pending, err := s.HookScopeOrPending(); !pending || err != nil {
		t.Fatalf("before: pending %v, %v; want the daemon's rules deferred", pending, err)
	}
	r := s.Recheck(served)
	d := r.Dockerd
	if d.Kind != DockerdLocal || !d.Answers || strings.Contains(d.Reason, "refused") || !slices.Equal(d.Bridges, []string{"docker0"}) {
		t.Errorf("rechecked: %+v, want local, answering, docker0, no stale reason", d)
	}
	if _, pending, _ := r.HookScopeOrPending(); pending {
		t.Error("rechecked: still pending, want the daemon's rules decided")
	}
	if s.Dockerd.Kind != DockerdUnknown {
		t.Errorf("Recheck changed the shape it was given: %+v", s.Dockerd)
	}
	r.Dockerd = s.Dockerd
	if !reflect.DeepEqual(r, s) {
		t.Errorf("Recheck changed facts that are not the daemon's: %+v, want %+v", r, s)
	}
}
