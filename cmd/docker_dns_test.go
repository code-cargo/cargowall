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
// what it rewrote, how many undos were registered when it did, how often a
// previous run's leftover was looked for, and its log.
type useListenerRun struct {
	configured  []string
	undosBefore int
	restored    int
	recoveries  int
	undo        func()
	d           *dockerDNS
	teardowns   *teardownList
	log         string
}

// runUseListener runs useListener for a daemon of the given kind whose
// proxy failed to bind what errs names; leftover is whether daemon.json
// holds a rewrite a previous run left.
func runUseListener(kind podenv.DockerdKind, errs bindErrs, redirect, leftover bool) *useListenerRun {
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
		recover: func(*slog.Logger) (bool, error) {
			run.recoveries++
			return leftover, nil
		},
		logger: slog.New(slog.NewTextHandler(&buf, nil)),
	}
	run.undo = run.d.useListener(run.teardowns, redirect)
	run.log = buf.String()
	return run
}

// Only a listener the proxy holds is put to use: for a local daemon,
// daemon.json is rewritten to point at it, with the undo registered first,
// and the restart that applies it is due; the rewrite undoes a previous
// run's leftover itself. A foreign daemon is left alone, and its line claims
// no redirect: whether one is in place is the redirect's to say once it is.
func TestDockerDNS_UseListenerBound(t *testing.T) {
	run := runUseListener(podenv.DockerdLocal, bindErrs{}, true, true)
	assert.Equal(t, []string{"172.17.0.1"}, run.configured)
	assert.Equal(t, 1, run.undosBefore, "the undo must be registered before the rewrite")
	assert.Zero(t, run.recoveries, "the rewrite recovers a leftover on its way")
	assert.True(t, run.d.restart)
	assert.Contains(t, run.log, "Docker DNS interception enabled")
	run.undo()
	assert.Equal(t, 1, run.restored)

	for _, redirect := range []bool{true, false} {
		run = runUseListener(podenv.DockerdForeign, bindErrs{}, redirect, true)
		assert.Empty(t, run.configured, "a foreign daemon's config is not ours")
		assert.Zero(t, run.recoveries, "nor is a foreign daemon's leftover")
		assert.Empty(t, run.teardowns.fns)
		assert.False(t, run.d.restart)
		assert.Contains(t, run.log, "only through the DNS redirect or by naming it")
		assert.NotContains(t, run.log, "redirected at the bridge")
	}
}

// A listener the proxy could not bind is pointed at by nothing: daemon.json
// is not rewritten, so there is nothing to undo. It warns, whatever the
// redirect, saying containers resolve around the proxy, and that this loses
// the dns-redirect posture only when the redirect is requested. A local
// daemon's daemon.json is still rid of a rewrite a previous run left, which
// points containers at the address the proxy does not hold, and then the
// restart that applies the original is due; the warning says which.
func TestDockerDNS_UseListenerUnbound(t *testing.T) {
	held := bindErrs{"172.17.0.1:53": listenErr("tcp4", "172.17.0.1:53", unix.EADDRINUSE)}
	for _, kind := range []podenv.DockerdKind{podenv.DockerdLocal, podenv.DockerdForeign} {
		for _, redirect := range []bool{true, false} {
			for _, leftover := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/redirect=%v/leftover=%v", kind, redirect, leftover), func(t *testing.T) {
					run := runUseListener(kind, held, redirect, leftover)
					local := kind == podenv.DockerdLocal
					assert.Empty(t, run.configured, "nothing may point containers at an address the proxy does not hold")
					assert.Empty(t, run.teardowns.fns)
					assert.Equal(t, local, run.recoveries == 1, "a local daemon's leftover is looked for, and only a local one's")
					assert.Equal(t, local && leftover, run.d.restart, "a restart is due only to apply an undone leftover")
					require.Equal(t, 1, strings.Count(run.log, "level=WARN"), run.log)
					assert.Contains(t, run.log, "around the proxy")
					assert.Contains(t, run.log, "addr=172.17.0.1:53")
					assert.Equal(t, local && !leftover, strings.Contains(run.log, "daemon.json is left alone"))
					assert.Equal(t, local && leftover, strings.Contains(run.log, "the rewrite a previous run left there is undone"))
					assert.Equal(t, redirect, strings.Contains(run.log, "a lost dns-redirect posture"))
					assert.NotContains(t, run.log, "interception enabled")
				})
			}
		}
	}
}

// A leftover that cannot be undone is warned, and no restart is due for
// it.
func TestDockerDNS_RecoverLeftoverFails(t *testing.T) {
	var buf bytes.Buffer
	d := &dockerDNS{
		bridgeIP: "172.17.0.1", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal},
		proxy:   bindErrs{"172.17.0.1:53": listenErr("udp4", "172.17.0.1:53", unix.EADDRINUSE)},
		recover: func(*slog.Logger) (bool, error) { return false, fmt.Errorf("read-only /etc/docker") },
		logger:  slog.New(slog.NewTextHandler(&buf, nil)),
	}
	d.useListener(&teardownList{}, true)()
	assert.False(t, d.restart)
	assert.Contains(t, buf.String(), "Failed to undo the daemon.json rewrite a previous run left")
	assert.Contains(t, buf.String(), "daemon.json is left alone")
}

// Port 53 is allowed at the proxy, its upstream, and the docker bridge
// listener only once the proxy holds it: otherwise port 53 there is
// another process's.
func TestDNSInfraIPs(t *testing.T) {
	held := listenErr("udp4", "172.17.0.1:53", unix.EADDRINUSE)
	for _, c := range []struct {
		name string
		d    *dockerDNS
		want []string
	}{
		{"bound", &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{}}, []string{"127.0.0.1", "10.0.0.2", "172.17.0.1"}},
		{"unbound", &dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{"172.17.0.1:53": held}}, []string{"127.0.0.1", "10.0.0.2"}},
		{"interception off", nil, []string{"127.0.0.1", "10.0.0.2"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, dnsInfraIPs("10.0.0.2:53", c.d))
		})
	}
	assert.Equal(t, []string{"127.0.0.1"}, dnsInfraIPs("", nil), "an upstream that is no address adds none")
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
