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
