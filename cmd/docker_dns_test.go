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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/network"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// bindErrs stands in for the proxy's account of the listeners it did not
// bind, keyed by address.
type bindErrs map[string]error

func (b bindErrs) BindError(addr string) error { return b[addr] }

// The container listeners' addresses as BindError keys them, and a refusal
// of one, as network.OwnedAddrs words it.
var (
	listen4     = "169.254.0.53:53"
	listen6     = "[fd97:d1fb:f215::53]:53"
	errRefused4 = errors.New("it is already assigned to eth0")
)

// The addresses container DNS may be sent to, and allowed at, are the
// container listeners' the proxy holds, each family on its own. With the
// feature off there are none.
func TestDockerDNS_Listening(t *testing.T) {
	refusal6 := errors.New("it is routed through tun0 by fd97:d1fb:f215::/48")
	for _, c := range []struct {
		name    string
		d       *dockerDNS
		ip, ip6 string
	}{
		{name: "both bound", d: &dockerDNS{proxy: bindErrs{}}, ip: "169.254.0.53", ip6: "fd97:d1fb:f215::53"},
		{name: "IPv4 refused", d: &dockerDNS{proxy: bindErrs{listen4: errRefused4}}, ip6: "fd97:d1fb:f215::53"},
		{name: "IPv6 refused", d: &dockerDNS{proxy: bindErrs{listen6: refusal6}}, ip: "169.254.0.53"},
		{name: "both refused", d: &dockerDNS{proxy: bindErrs{listen4: errRefused4, listen6: refusal6}}},
		{name: "interception off"},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.ip, c.d.listeningIP())
			assert.Equal(t, c.ip6, c.d.listeningIPv6())
			assert.Equal(t, c.ip != "" || c.ip6 != "", c.d.serving())
		})
	}
	assert.Equal(t, errRefused4, (&dockerDNS{proxy: bindErrs{listen4: errRefused4}}).listenerErr(network.ContainerDNSIPv4))
	assert.NoError(t, (*dockerDNS)(nil).listenerErr(network.ContainerDNSIPv4))
}

// Off, the feature adds nothing. On, it registers the addresses' removal
// before anything is added: the addresses go on lo only once the proxy holds
// its primary.
func TestStartDockerDNS(t *testing.T) {
	teardowns := &teardownList{}
	d, undo := startDockerDNS(&StartCmd{}, nil, podenv.Dockerd{}, teardowns, slog.New(slog.DiscardHandler))
	assert.Nil(t, d)
	assert.Empty(t, teardowns.fns)
	undo()
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

// runUseListener runs useListener for an answering daemon of the given kind
// whose proxy failed to bind what errs names; leftover is whether
// daemon.json holds a rewrite a previous run left.
func runUseListener(kind podenv.DockerdKind, errs bindErrs, redirect, leftover bool) *useListenerRun {
	return runUseListenerFor(podenv.Dockerd{Kind: kind, Answers: true}, errs, redirect, leftover)
}

// runUseListenerFor is runUseListener for the daemon dockerd describes.
func runUseListenerFor(dockerd podenv.Dockerd, errs bindErrs, redirect, leftover bool) *useListenerRun {
	run := &useListenerRun{teardowns: &teardownList{}}
	var buf bytes.Buffer
	run.d = &dockerDNS{
		dockerd: dockerd,
		proxy:   errs,
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
// daemon.json is rewritten to point at the IPv4 one, with the undo
// registered first, and the restart that applies it is due; the rewrite
// undoes a previous run's leftover itself. A foreign daemon is left alone,
// and its line claims no redirect: whether one is in place is the
// redirect's to say once it is.
func TestDockerDNS_UseListenerBound(t *testing.T) {
	run := runUseListener(podenv.DockerdLocal, bindErrs{}, true, true)
	assert.Equal(t, []string{"169.254.0.53"}, run.configured)
	assert.Equal(t, 1, run.undosBefore, "the undo must be registered before the rewrite")
	assert.Zero(t, run.recoveries, "the rewrite recovers a leftover on its way")
	assert.True(t, run.d.restart)
	assert.Contains(t, run.log, "Docker DNS interception enabled")
	assert.Contains(t, run.log, "listen=169.254.0.53:53")
	run.undo()
	assert.Equal(t, 1, run.restored)

	for _, redirect := range []bool{true, false} {
		run = runUseListener(podenv.DockerdForeign, bindErrs{}, redirect, true)
		assert.Empty(t, run.configured, "a foreign daemon's config is not ours")
		assert.Zero(t, run.recoveries, "nor is a foreign daemon's leftover")
		assert.Empty(t, run.teardowns.fns)
		assert.False(t, run.d.restart)
		assert.Contains(t, run.log, "only through the DNS redirect or by naming its listener")
		assert.NotContains(t, run.log, "redirected at the bridge")
	}
}

// An IPv4 listener the proxy could not bind is pointed at by nothing:
// daemon.json is not rewritten, so there is nothing to undo. It warns,
// whatever the redirect, saying containers resolve around the proxy, and
// that this loses the dns-redirect posture only when the redirect is
// requested. A local daemon's daemon.json is still rid of a rewrite a
// previous run left, which points containers at an address the proxy does
// not listen on, and then the restart that applies the original is due; the
// warning says which. With the IPv6 listener held, it says interception is
// off for IPv4 alone, and with the redirect, that IPv6 container DNS still
// reaches the proxy.
func TestDockerDNS_UseListenerUnbound(t *testing.T) {
	for _, kind := range []podenv.DockerdKind{podenv.DockerdLocal, podenv.DockerdForeign} {
		for _, redirect := range []bool{true, false} {
			for _, leftover := range []bool{false, true} {
				for _, ipv6 := range []bool{true, false} {
					name := fmt.Sprintf("%s/redirect=%v/leftover=%v/ipv6=%v", kind, redirect, leftover, ipv6)
					t.Run(name, func(t *testing.T) {
						refused := bindErrs{listen4: errRefused4}
						if !ipv6 {
							refused[listen6] = errors.New("it is routed through tun0 by fd97:d1fb:f215::/48")
						}
						run := runUseListener(kind, refused, redirect, leftover)
						local := kind == podenv.DockerdLocal
						assert.Empty(t, run.configured, "nothing may point containers at an address the proxy does not hold")
						assert.Empty(t, run.teardowns.fns)
						assert.Equal(t, local, run.recoveries == 1, "a local daemon's leftover is looked for, and only a local one's")
						assert.Equal(t, local && leftover, run.d.restart, "a restart is due only to apply an undone leftover")
						require.Equal(t, 1, strings.Count(run.log, "level=WARN"), run.log)
						assert.Contains(t, run.log, "around the proxy")
						assert.Contains(t, run.log, "addr=169.254.0.53:53")
						assert.Contains(t, run.log, "already assigned to eth0")
						assert.Equal(t, local && !leftover, strings.Contains(run.log, "daemon.json is left alone"))
						assert.Equal(t, local && leftover, strings.Contains(run.log, "the rewrite a previous run left there is undone"))
						assert.Equal(t, redirect, strings.Contains(run.log, "a lost dns-redirect posture"))
						assert.NotContains(t, run.log, "interception enabled")
						assert.Equal(t, ipv6, strings.Contains(run.log, "unavailable for IPv4"))
						assert.Equal(t, ipv6 && redirect, strings.Contains(run.log, "IPv6 DNS to the IPv6 listener"))
					})
				}
			}
		}
	}
}

// A local daemon still to come up is left alone, a previous run's
// leftover in its daemon.json included, whether its listener holds or
// not: nothing is rewritten or undone, and no restart is due.
func TestDockerDNS_UseListenerPending(t *testing.T) {
	pending := podenv.Dockerd{Kind: podenv.DockerdLocal}
	for _, errs := range []bindErrs{{}, {listen4: errRefused4}} {
		run := runUseListenerFor(pending, errs, true, true)
		assert.Empty(t, run.configured)
		assert.Zero(t, run.recoveries, "a pending daemon's leftover is left too")
		assert.False(t, run.d.restart)
		assert.Empty(t, run.teardowns.fns)
		assert.NotContains(t, run.log, "not proven local")
	}
}

// A leftover that cannot be undone is warned, and no restart is due for
// it.
func TestDockerDNS_RecoverLeftoverFails(t *testing.T) {
	var buf bytes.Buffer
	d := &dockerDNS{
		dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Answers: true},
		proxy:   bindErrs{listen4: errRefused4},
		recover: func(*slog.Logger) (bool, error) { return false, fmt.Errorf("read-only /etc/docker") },
		logger:  slog.New(slog.NewTextHandler(&buf, nil)),
	}
	d.useListener(&teardownList{}, true)()
	assert.False(t, d.restart)
	assert.Contains(t, buf.String(), "Failed to undo the daemon.json rewrite a previous run left")
	assert.Contains(t, buf.String(), "daemon.json is left alone")
}

// Port 53 is allowed at the proxy, its upstream, and each container
// listener the proxy holds: port 53 at one it does not is another process's,
// or no one's.
func TestDNSInfraIPs(t *testing.T) {
	for _, c := range []struct {
		name string
		d    *dockerDNS
		want []string
	}{
		{"both bound", &dockerDNS{proxy: bindErrs{}}, []string{"127.0.0.1", "10.0.0.2", "169.254.0.53", "fd97:d1fb:f215::53"}},
		{"IPv4 refused", &dockerDNS{proxy: bindErrs{listen4: errRefused4}}, []string{"127.0.0.1", "10.0.0.2", "fd97:d1fb:f215::53"}},
		{"interception off", nil, []string{"127.0.0.1", "10.0.0.2"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, dnsInfraIPs("10.0.0.2:53", c.d))
		})
	}
	assert.Equal(t, []string{"127.0.0.1"}, dnsInfraIPs("", nil), "an upstream that is no address adds none")
}

// The feature off has nothing to put to use or report.
func TestDockerDNS_UseListenerOff(t *testing.T) {
	assert.NotPanics(t, func() {
		(*dockerDNS)(nil).useListener(&teardownList{}, true)()
		(*dockerDNS)(nil).restartDaemon()
	})
}
