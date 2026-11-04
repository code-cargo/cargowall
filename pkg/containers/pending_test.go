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
	"context"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectCall is one Options.OnConnect call.
type connectCall struct {
	first  bool
	carved []netip.Prefix
}

// Start does not wait for a daemon whose socket accepts and does not answer
// yet: it returns at once, nothing connects meanwhile, and once the daemon
// answers its first session reports itself first, with every bridge
// network's subnet carved from the network list, the default bridge's
// included and a macvlan's not, and no network inspected for its driver.
// A container started after it answered is tracked.
func TestStartBeforeDaemonAnswers(t *testing.T) {
	ready := make(chan struct{})
	f := newFixture(t)
	f.daemon = newFakeDaemonAfter(t, ready)
	f.daemon.setNetwork("bridge", "bridge", "172.17.0.0/16")
	f.daemon.setNetwork("appnet", "bridge", "172.18.0.5/16")
	f.daemon.setNetwork("lan", "macvlan", "192.168.1.0/24")
	var mu sync.Mutex
	var allowed []netip.Prefix
	f.allowLocal = func(p netip.Prefix) error {
		mu.Lock()
		defer mu.Unlock()
		allowed = append(allowed, p)
		return nil
	}
	connects := make(chan connectCall, 4)
	f.onConnect = func(first bool, carved []netip.Prefix) { connects <- connectCall{first, carved} }

	began := time.Now()
	f.start(t)
	require.Less(t, time.Since(began), time.Second, "Start must not wait for the daemon")
	select {
	case c := <-connects:
		t.Fatalf("connected before the daemon answered: %+v", c)
	case <-time.After(300 * time.Millisecond):
	}

	close(ready)
	var c connectCall
	select {
	case c = <-connects:
	case <-time.After(waitFor):
		t.Fatal("no connect once the daemon answered")
	}
	assert.True(t, c.first)
	want := []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16"), netip.MustParsePrefix("172.18.0.0/16")}
	assert.ElementsMatch(t, want, c.carved)
	mu.Lock()
	assert.ElementsMatch(t, want, allowed)
	mu.Unlock()
	assert.Zero(t, f.daemon.networkInspectCount(), "the list gives each network's driver")

	id := strings.Repeat("b", 64)
	f.addContainer(t, id, 4343, "172.17.0.3", false)
	f.daemon.push(startEvent(id, time.Now().UnixNano()))
	f.waitAttribution(t, "start", id)
	assert.NotContains(t, f.logs.String(), "level=WARN")
}

// waitConnect is the next Options.OnConnect call.
func waitConnect(t *testing.T, connects <-chan connectCall) connectCall {
	t.Helper()
	select {
	case c := <-connects:
		return c
	case <-time.After(waitFor):
		t.Fatal("no connect")
	}
	return connectCall{}
}

// Once a session has connected, losing the daemon is a Warn, not the Debug
// of a daemon not up yet, and the session that follows is no first one.
// Its reconcile carves a bridge network created while the stream was down,
// whose create event it never delivered.
func TestReconnectAfterConnect(t *testing.T) {
	f := newFixture(t)
	f.daemon.setNetwork("bridge", "bridge", "172.17.0.0/16")
	var mu sync.Mutex
	var allowed []netip.Prefix
	f.allowLocal = func(p netip.Prefix) error {
		mu.Lock()
		defer mu.Unlock()
		allowed = append(allowed, p)
		return nil
	}
	connects := make(chan connectCall, 4)
	f.onConnect = func(first bool, carved []netip.Prefix) { connects <- connectCall{first, carved} }
	f.start(t)
	require.True(t, waitConnect(t, connects).first)

	f.daemon.endStream()
	gap := netip.MustParsePrefix("172.20.0.0/16")
	f.daemon.setNetwork("gapnet", "bridge", gap.String())
	c := waitConnect(t, connects)
	assert.False(t, c.first, "a reconnect is no first session")
	assert.Contains(t, c.carved, gap)
	mu.Lock()
	assert.Contains(t, allowed, gap)
	mu.Unlock()
	assert.Contains(t, f.logs.String(), `level=WARN msg="Docker event stream interrupted; reconnecting"`)
	assert.NotContains(t, f.logs.String(), "not answering yet")
}

// WaitAnswer returns once the daemon answers, holding its request on a
// socket that accepts and does not answer yet, and with ctx's error when
// there is no daemon at all.
func TestWaitAnswer(t *testing.T) {
	ready := make(chan struct{})
	d := newFakeDaemonAfter(t, ready)
	done := make(chan error, 1)
	go func() { done <- WaitAnswer(context.Background(), d.sock) }()
	select {
	case err := <-done:
		t.Fatalf("answered before the daemon did: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(ready)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(waitFor):
		t.Fatal("no answer once the daemon answered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, WaitAnswer(ctx, filepath.Join(t.TempDir(), "none.sock")), context.DeadlineExceeded)
}

// A socket left by a daemon that has gone refuses every connection: until a
// session has connected, the tracker retries quietly, at Debug.
func TestStaleSocketStaysQuiet(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "stale.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, ln.Close())

	logs := &lockedBuffer{}
	tr, err := Start(context.Background(), Options{Socket: sock}, &fakeTagger{}, nil, nil,
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return strings.Count(logs.String(), "not answering yet") >= 2 }, waitFor, tick)
	tr.Close()
	assert.Contains(t, logs.String(), "connection refused")
	assert.NotContains(t, logs.String(), "level=WARN")
}
