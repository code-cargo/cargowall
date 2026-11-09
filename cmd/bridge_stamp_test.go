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
	"log/slog"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/containers"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/origin"
	"github.com/code-cargo/cargowall/pkg/podenv"
	"github.com/code-cargo/cargowall/pkg/tc"
)

// fakeLink is an attachment the fake attacher made: attached until its
// device goes, or it is closed.
type fakeLink struct {
	dev      string
	attached bool
	closed   int
}

func (l *fakeLink) Attached() bool { return l.attached && l.closed == 0 }

func (l *fakeLink) Close() error {
	l.closed++
	return nil
}

// fakeBridges stands in for the host's devices and tc.AttachIngress.
type fakeBridges struct {
	index map[string]int // the devices there are, by name
	fail  map[string]error
	links []*fakeLink
}

func (f *fakeBridges) attach(dev string, _ *ebpf.Program, _ *slog.Logger) (tc.Attachment, error) {
	if err := f.fail[dev]; err != nil {
		return nil, err
	}
	l := &fakeLink{dev: dev, attached: true}
	f.links = append(f.links, l)
	return l, nil
}

func (f *fakeBridges) ifindex(dev string) (int, error) {
	if idx, ok := f.index[dev]; ok {
		return idx, nil
	}
	return 0, fmt.Errorf("route ip+net: no such network interface %s", dev)
}

// remove takes dev away, and with it every attachment on it.
func (f *fakeBridges) remove(dev string) {
	delete(f.index, dev)
	for _, l := range f.links {
		if l.dev == dev {
			l.attached = false
		}
	}
}

// live is the attachments not closed.
func (f *fakeBridges) live() []string {
	var out []string
	for _, l := range f.links {
		if l.closed == 0 {
			out = append(out, l.dev)
		}
	}
	return out
}

func newFakeStamp(f *fakeBridges, log *bytes.Buffer) *bridgeStamp {
	return &bridgeStamp{
		attach:  f.attach,
		ifindex: f.ifindex,
		logger:  slog.New(slog.NewTextHandler(log, nil)),
		bridges: make(map[string]stampedBridge),
	}
}

// With step rules off there is no stamp, and the tracker is handed no
// bridge callbacks, so it does no bridge work.
func TestBridgeStamp_OffIsNil(t *testing.T) {
	b := newBridgeStamp(nil, slog.New(slog.DiscardHandler))
	require.Nil(t, b)
	assert.Nil(t, b.onBridge())
	assert.Nil(t, b.onBridgeGone())
	assert.NotPanics(t, b.Close)
}

// A bridge reported again, still attached, is left as it is.
func TestBridgeStamp_UpIsIdempotent(t *testing.T) {
	f := &fakeBridges{index: map[string]int{"docker0": 3}}
	b := newFakeStamp(f, &bytes.Buffer{})
	b.up("docker0")
	b.up("docker0")
	require.Len(t, f.links, 1)
	assert.Equal(t, []string{"docker0"}, f.live())
}

// A network removed and another created behind the same device is
// attached afresh, at a new index or at the same one, whether or not its
// destroy was seen; the dead device's attachment is closed. So is one that
// still answers attached, its index another device's now.
func TestBridgeStamp_RecreatedBridgeIsAttachedAfresh(t *testing.T) {
	for _, c := range []struct {
		name        string
		index       int
		destroySeen bool
		answering   bool
	}{
		{"new index", 9, false, false},
		{"reused index", 4, false, false},
		{"destroy seen", 4, true, false},
		{"new index, the old attachment answering", 9, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeBridges{index: map[string]int{"br-0123456789ab": 4}}
			b := newFakeStamp(f, &bytes.Buffer{})
			b.up("br-0123456789ab")
			f.remove("br-0123456789ab")
			f.links[0].attached = c.answering
			if c.destroySeen {
				b.gone("br-0123456789ab")
				assert.Empty(t, f.live())
			}
			f.index["br-0123456789ab"] = c.index
			b.up("br-0123456789ab")
			require.Len(t, f.links, 2)
			assert.Equal(t, 1, f.links[0].closed, "the dead device's attachment is closed once")
			assert.True(t, f.links[1].Attached())
		})
	}
}

// A bridge gone by the time it is reported is dropped, with a warning; so
// is one the program can't be attached to, and startup goes on.
func TestBridgeStamp_FailuresWarn(t *testing.T) {
	f := &fakeBridges{
		index: map[string]int{"br-a": 5, "br-b": 6},
		fail:  map[string]error{"br-b": errors.New("attach TCX ingress: permission denied")},
	}
	var log bytes.Buffer
	b := newFakeStamp(f, &log)
	b.up("br-a")
	f.remove("br-a")
	b.up("br-a")
	b.up("br-b")
	assert.Empty(t, f.live())
	assert.Contains(t, log.String(), "level=WARN msg=\"Docker bridge not found")
	assert.Contains(t, log.String(), "bridge=br-a")
	assert.Contains(t, log.String(), "level=WARN msg=\"Docker bridge left unstamped")
	assert.Contains(t, log.String(), "bridge=br-b")
}

// Close detaches every bridge, and none is attached after.
func TestBridgeStamp_CloseDetachesEverything(t *testing.T) {
	f := &fakeBridges{index: map[string]int{"docker0": 3, "br-a": 5}}
	b := newFakeStamp(f, &bytes.Buffer{})
	b.up("docker0")
	b.up("br-a")
	b.gone("br-unknown")
	b.Close()
	assert.Empty(t, f.live())
	b.up("docker0")
	assert.Len(t, f.links, 2)
}

// The tracker startUserspace starts is handed the stamp's callbacks, none
// with the stamp off, and the attribution's Close detaches the stamp's
// bridges.
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

	f := &fakeBridges{index: map[string]int{"docker0": 3, "br-a": 5}}
	a.stamp = newFakeStamp(f, &bytes.Buffer{})
	a.startUserspace(t.Context(), nil, false, nil, u)
	require.NotNil(t, handed.OnBridge)
	require.NotNil(t, handed.OnBridgeGone)
	handed.OnBridge("docker0")
	handed.OnBridge("br-a")
	handed.OnBridgeGone("br-a")
	assert.Equal(t, []string{"docker0"}, f.live())
	a.Close()
	assert.Empty(t, f.live())
}
