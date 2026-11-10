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

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/containers"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/origin"
	"github.com/code-cargo/cargowall/pkg/podenv"
	"github.com/code-cargo/cargowall/pkg/tc"
)

// fakeLink is an attachment the fake attacher made: attached until its
// interface goes, or it is closed.
type fakeLink struct {
	f        *fakePorts
	index    int
	attached bool
	closed   int
}

func (l *fakeLink) Attached() bool { return l.attached && l.closed == 0 }

func (l *fakeLink) Close() error {
	l.closed++
	l.f.order = append(l.f.order, fmt.Sprintf("close %d", l.index))
	return nil
}

// fakePorts stands in for the kernel's interfaces, network.WatchLinks and
// tc.AttachIngress.
type fakePorts struct {
	initial []network.Link // what the watch lists when it starts
	fail    map[int]error  // attach failures, by index
	links   []*fakeLink
	order   []string // attaches and closes, as they came
	onLink  func(network.Link)
	onGone  func(int)
	watches int
	stopped int
}

func (f *fakePorts) attach(index int, _ string, _ *ebpf.Program, _ *slog.Logger) (tc.Attachment, error) {
	if err := f.fail[index]; err != nil {
		return nil, err
	}
	l := &fakeLink{f: f, index: index, attached: true}
	f.links = append(f.links, l)
	f.order = append(f.order, fmt.Sprintf("attach %d", index))
	return l, nil
}

func (f *fakePorts) watch(onLink func(network.Link), onGone func(int), _ *slog.Logger) (io.Closer, error) {
	f.watches++
	f.onLink, f.onGone = onLink, onGone
	for _, l := range f.initial {
		onLink(l)
	}
	return closerFunc(func() error { f.stopped++; return nil }), nil
}

type closerFunc func() error

func (c closerFunc) Close() error { return c() }

// live is the indexes of the attachments not closed, sorted.
func (f *fakePorts) live() []int {
	var out []int
	for _, l := range f.links {
		if l.closed == 0 {
			out = append(out, l.index)
		}
	}
	slices.Sort(out)
	return out
}

func newFakeStamp(f *fakePorts, log *bytes.Buffer) *bridgeStamp {
	return &bridgeStamp{
		attach: f.attach,
		watch:  f.watch,
		logger: slog.New(slog.NewTextHandler(log, nil)),
		links:  make(map[int]network.Link),
		named:  make(map[string]bool),
		ports:  make(map[int]tc.Attachment),
		failed: make(map[int]bool),
	}
}

func bridge(index int, name string) network.Link {
	return network.Link{Index: index, Name: name, Kind: "bridge"}
}

func port(index int, name, kind string, master int) network.Link {
	return network.Link{Index: index, Name: name, Kind: kind, Master: master}
}

// With step rules off there is no stamp: the tracker is handed no bridge
// callbacks and no watch starts.
func TestBridgeStamp_OffIsNil(t *testing.T) {
	b := newBridgeStamp(nil, slog.New(slog.DiscardHandler))
	require.Nil(t, b)
	assert.Nil(t, b.onBridge())
	assert.Nil(t, b.onBridgeGone())
	assert.NotPanics(t, b.start)
	assert.NotPanics(t, b.Close)
}

// The program goes on a Docker bridge's veth ports, those there are when
// the watch starts and those that come, and on nothing else: not a port of
// another bridge, nor one that is no veth, nor a veth on no bridge. A port
// listed before its bridge is attached once the bridge is.
func TestBridgeStamp_AttachesDockerBridgeVethPorts(t *testing.T) {
	f := &fakePorts{initial: []network.Link{
		port(10, "veth1", "veth", 3), // before its bridge
		bridge(3, "docker0"),
		bridge(4, "br-0123456789ab"),
		bridge(5, "virbr0"),
		bridge(6, "br-lan"),
		port(11, "veth2", "veth", 4),
		port(12, "veth3", "veth", 5),
		port(13, "veth4", "veth", 6),
		port(14, "tap0", "tun", 3),
		port(15, "veth5", "veth", 0),
	}}
	b := newFakeStamp(f, &bytes.Buffer{})
	b.start()
	assert.Equal(t, []int{10, 11}, f.live())

	f.onLink(port(16, "veth6", "veth", 0))
	f.onLink(port(16, "veth6", "veth", 4)) // enslaved
	assert.Equal(t, []int{10, 11, 16}, f.live())
	f.onLink(port(16, "veth6", "veth", 4)) // up, still attached
	assert.Len(t, f.links, 3, "a report of an attached port attaches nothing more")
}

// A bridge the tracker names (com.docker.network.bridge.name) is Docker's
// from then on: its ports are attached then, and the ones that come.
func TestBridgeStamp_TrackerNamedBridge(t *testing.T) {
	f := &fakePorts{initial: []network.Link{bridge(7, "ci-br"), port(20, "veth1", "veth", 7)}}
	b := newFakeStamp(f, &bytes.Buffer{})
	b.start()
	assert.Empty(t, f.live())
	b.up("ci-br")
	assert.Equal(t, []int{20}, f.live())
	f.onLink(port(21, "veth2", "veth", 7))
	assert.Equal(t, []int{20, 21}, f.live())
}

// A port is detached when it leaves the bridge, when it goes, and when its
// bridge goes; an attachment found dead is replaced.
func TestBridgeStamp_DetachesAndReattaches(t *testing.T) {
	f := &fakePorts{initial: []network.Link{
		bridge(3, "docker0"), port(10, "veth1", "veth", 3), port(11, "veth2", "veth", 3), port(12, "veth3", "veth", 3),
	}}
	b := newFakeStamp(f, &bytes.Buffer{})
	b.start()
	require.Equal(t, []int{10, 11, 12}, f.live())

	f.onLink(port(10, "veth1", "veth", 0)) // nomaster
	f.onGone(11)
	assert.Equal(t, []int{12}, f.live())

	f.links[2].attached = false // the interface at 12 was recreated in a gap
	f.order = nil
	f.onLink(port(12, "veth3", "veth", 3))
	assert.Equal(t, []int{12}, f.live())
	// The dead one first: under clsact, its filter is known by the index
	// alone, and closing it after would remove the new one.
	assert.Equal(t, []string{"close 12", "attach 12"}, f.order, "attached afresh, the dead attachment closed first")

	f.onLink(port(10, "veth1", "veth", 3))
	f.onGone(3) // the bridge
	assert.Empty(t, f.live())
}

// The tracker's report that a bridge's network is gone keeps the name
// Docker's while a device by that name is there (a recreated bridge,
// reported before the destroy), and drops it once there is none.
func TestBridgeStamp_TrackerGoneAfterRecreate(t *testing.T) {
	f := &fakePorts{initial: []network.Link{bridge(7, "ci-br"), port(20, "veth1", "veth", 7)}}
	b := newFakeStamp(f, &bytes.Buffer{})
	b.start()
	b.up("ci-br")
	b.gone("ci-br")
	f.onLink(port(21, "veth2", "veth", 7))
	assert.Equal(t, []int{20, 21}, f.live(), "a destroy that comes after its recreate leaves the new bridge Docker's")

	f.onGone(20)
	f.onGone(21)
	f.onGone(7)
	b.gone("ci-br")
	f.onLink(bridge(8, "ci-br")) // another bridge by the name, none of Docker's
	f.onLink(port(22, "veth2", "veth", 8))
	assert.Empty(t, f.live())
}

// A port the program can't be attached to is warned of, once, while the
// rest go on, and tried again on each report: warned of again only after
// an attach there worked or it went. So is a watch that can't start.
func TestBridgeStamp_FailuresWarn(t *testing.T) {
	f := &fakePorts{
		initial: []network.Link{bridge(3, "docker0"), port(10, "veth1", "veth", 3), port(11, "veth2", "veth", 3)},
		fail:    map[int]error{10: errors.New("attach TCX ingress: permission denied")},
	}
	var log bytes.Buffer
	b := newFakeStamp(f, &log)
	b.start()
	assert.Equal(t, []int{11}, f.live())
	assert.Contains(t, log.String(), `level=WARN msg="Docker bridge port left unstamped`)
	assert.Contains(t, log.String(), "port=veth1 bridge=docker0")
	warned := func() int { return strings.Count(log.String(), "Docker bridge port left unstamped") }
	f.onLink(port(10, "veth1", "veth", 3))
	f.onLink(port(10, "veth1", "veth", 3))
	assert.Equal(t, 1, warned(), "warned of once")
	f.onGone(10)
	f.onLink(port(10, "veth1", "veth", 3))
	assert.Equal(t, 2, warned(), "a port that went and came is warned of afresh")
	delete(f.fail, 10)
	f.onLink(port(10, "veth1", "veth", 3))
	assert.Equal(t, []int{10, 11}, f.live(), "tried again on its next report")
	f.fail[10] = errors.New("attach TCX ingress: permission denied")
	f.links[len(f.links)-1].attached = false
	f.onLink(port(10, "veth1", "veth", 3))
	assert.Equal(t, 3, warned(), "warned of afresh after an attach there worked")

	log.Reset()
	b = newFakeStamp(f, &log)
	b.watch = func(func(network.Link), func(int), *slog.Logger) (io.Closer, error) {
		return nil, errors.New("subscribe to interface events: permission denied")
	}
	b.start()
	assert.Contains(t, log.String(), `level=WARN msg="Cannot watch interfaces for Docker bridge ports`)
}

// Close stops the watch and detaches every port, and nothing is attached
// after.
func TestBridgeStamp_CloseDetachesEverything(t *testing.T) {
	f := &fakePorts{initial: []network.Link{bridge(3, "docker0"), port(10, "veth1", "veth", 3)}}
	b := newFakeStamp(f, &bytes.Buffer{})
	b.start()
	b.Close()
	assert.Equal(t, 1, f.stopped)
	assert.Empty(t, f.live())
	f.onLink(port(11, "veth2", "veth", 3))
	b.up("ci-br")
	assert.Len(t, f.links, 1)
}

// startUserspace starts the stamp's watch and hands the tracker the
// stamp's callbacks, none with the stamp off, and the attribution's Close
// detaches the ports.
func TestBridgeStamp_TrackerWiring(t *testing.T) {
	saved := startTracker
	t.Cleanup(func() { startTracker = saved })
	var handed containers.Options
	startTracker = func(_ context.Context, opts containers.Options, _ containers.StepTagger, _ *origin.Observer,
		_ *events.AuditLogger, _ *slog.Logger,
	) (*containers.Tracker, error) {
		handed = opts
		return nil, errors.New("a stand-in for the tracker")
	}
	u, _ := dockerUpFor(t, podenv.Dockerd{Kind: podenv.DockerdLocal}, &StartCmd{})

	a := &containerAttribution{logger: slog.New(slog.DiscardHandler)}
	a.startUserspace(t.Context(), nil, false, nil, u)
	assert.Nil(t, handed.OnBridge)
	assert.Nil(t, handed.OnBridgeGone)

	f := &fakePorts{initial: []network.Link{bridge(7, "ci-br"), port(20, "veth1", "veth", 7)}}
	a.stamp = newFakeStamp(f, &bytes.Buffer{})
	a.startUserspace(t.Context(), nil, false, nil, u)
	assert.Equal(t, 1, f.watches)
	require.NotNil(t, handed.OnBridge)
	require.NotNil(t, handed.OnBridgeGone)
	handed.OnBridge("ci-br")
	assert.Equal(t, []int{20}, f.live())
	a.Close()
	assert.Empty(t, f.live())
	assert.Equal(t, 1, f.stopped)
}
