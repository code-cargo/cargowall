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
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/podenv"
)

// bindErrs stands in for the proxy's account of the listeners it did not
// bind, keyed by address.
type bindErrs map[string]error

func (b bindErrs) BindError(addr string) error { return b[addr] }

// The address container DNS may be sent to, and allowed at, is the bridge's
// only once the proxy holds its listener there. Without a bridge, or with
// the feature off, there is none, and the proxy is not asked about an
// address it was never given.
func TestDockerDNS_ListeningIP(t *testing.T) {
	held := listenErr("udp4", "172.17.0.1:53", unix.EADDRINUSE)
	for _, c := range []struct {
		name string
		d    *dockerDNS
		err  error
		ip   string
	}{
		{name: "bound", d: &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{}}, ip: "172.17.0.1"},
		{name: "unbound", d: &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{"172.17.0.1:53": held}}, err: held},
		{name: "no bridge", d: &dockerDNS{proxy: bindErrs{":53": held}}},
		{name: "interception off"},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.err, c.d.listenerErr())
			assert.Equal(t, c.ip, c.d.listeningIP())
		})
	}
}

// useListenerRun is one useListener call against stand-ins for daemon.json:
// what it rewrote, how many undos were registered when it did, and its log.
type useListenerRun struct {
	configured  []string
	undosBefore int
	restored    int
	undo        func()
	d           *dockerDNS
	teardowns   *teardownList
	log         string
}

func runUseListener(kind podenv.DockerdKind, errs bindErrs, redirect bool) *useListenerRun {
	run := &useListenerRun{teardowns: &teardownList{}}
	var buf bytes.Buffer
	run.d = &dockerDNS{
		bridgeIP: "172.17.0.1",
		dockerd:  podenv.Dockerd{Kind: kind},
		proxy:    errs,
		configure: func(dnsIP string, _ *slog.Logger) error {
			run.configured = append(run.configured, dnsIP)
			run.undosBefore = len(run.teardowns.fns)
			return nil
		},
		restore: func(*slog.Logger) error { run.restored++; return nil },
		logger:  slog.New(slog.NewTextHandler(&buf, nil)),
	}
	run.undo = run.d.useListener(run.teardowns, redirect)
	run.log = buf.String()
	return run
}

// Only a listener the proxy holds is put to use: for a local daemon,
// daemon.json is rewritten to point at it, with the undo registered first,
// and the restart that applies it is due. A foreign daemon is left alone.
func TestDockerDNS_UseListenerBound(t *testing.T) {
	run := runUseListener(podenv.DockerdLocal, bindErrs{}, true)
	assert.Equal(t, []string{"172.17.0.1"}, run.configured)
	assert.Equal(t, 1, run.undosBefore, "the undo must be registered before the rewrite")
	assert.True(t, run.d.restart)
	assert.Contains(t, run.log, "Docker DNS interception enabled")
	run.undo()
	assert.Equal(t, 1, run.restored)

	for _, redirect := range []bool{true, false} {
		run = runUseListener(podenv.DockerdForeign, bindErrs{}, redirect)
		assert.Empty(t, run.configured, "a foreign daemon's config is not ours")
		assert.Empty(t, run.teardowns.fns)
		assert.False(t, run.d.restart)
		if redirect {
			assert.Contains(t, run.log, "container DNS is redirected at the bridge")
		} else {
			assert.Contains(t, run.log, "only by naming the bridge listener", "without the redirect nothing catches it")
		}
	}
}

// A listener the proxy could not bind is pointed at by nothing: daemon.json
// is not rewritten, so there is nothing to undo and no restart. It warns,
// whatever the redirect, saying containers resolve around the proxy, and
// that this loses the dns-redirect posture only when the redirect is on.
func TestDockerDNS_UseListenerUnbound(t *testing.T) {
	held := bindErrs{"172.17.0.1:53": listenErr("tcp4", "172.17.0.1:53", unix.EADDRINUSE)}
	for _, kind := range []podenv.DockerdKind{podenv.DockerdLocal, podenv.DockerdForeign} {
		for _, redirect := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/redirect=%v", kind, redirect), func(t *testing.T) {
				run := runUseListener(kind, held, redirect)
				assert.Empty(t, run.configured, "nothing may point containers at an address the proxy does not hold")
				assert.Empty(t, run.teardowns.fns)
				assert.False(t, run.d.restart)
				require.Equal(t, 1, strings.Count(run.log, "level=WARN"), run.log)
				assert.Contains(t, run.log, "around the proxy")
				assert.Contains(t, run.log, "addr=172.17.0.1:53")
				assert.Equal(t, kind == podenv.DockerdLocal, strings.Contains(run.log, "daemon.json is left alone"))
				assert.Equal(t, redirect, strings.Contains(run.log, "a lost dns-redirect posture"))
				assert.NotContains(t, run.log, "interception enabled")
			})
		}
	}
}

// No bridge, or the feature off, has nothing to put to use or report.
func TestDockerDNS_UseListenerIdle(t *testing.T) {
	var buf bytes.Buffer
	d := &dockerDNS{dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal}, proxy: bindErrs{}, logger: slog.New(slog.NewTextHandler(&buf, nil))}
	assert.NotPanics(t, func() {
		d.useListener(&teardownList{}, true)()
		(*dockerDNS)(nil).useListener(&teardownList{}, true)()
		(*dockerDNS)(nil).restartDaemon()
	})
	assert.Empty(t, buf.String())
}
