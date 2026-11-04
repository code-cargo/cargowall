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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/code-cargo/cargowall/pkg/origin"
	"github.com/code-cargo/cargowall/pkg/podenv"
)

// The mode ladder is the safety gate for phase 3b: enforcement must be
// opt-in, and merely turning the hook on must never start dropping traffic.
// The flag's "observe" is the kernel's SHADOW rung — the operator-facing
// question is whether anything drops, and shadow is the rung that answers no
// while still computing the verdict.
func TestResolveMode(t *testing.T) {
	tests := []struct {
		name   string
		egress string
		want   origin.Mode
	}{
		{"off", ContainerEgressOff, origin.ModeObserve},
		{"observe selects shadow, never enforce", ContainerEgressObserve, origin.ModeShadow},
		{"enforce opt-in", ContainerEgressEnforce, origin.ModeEnforce},
		{
			// Unspellable through the flag (AfterApply rejects it), so this
			// pins the fail-safe direction of the fallthrough itself: an
			// unrecognized posture must never resolve to enforcement.
			"unknown posture stays inert", "wat", origin.ModeObserve,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveMode(tt.egress))
		})
	}
}

// A nil *containerAttribution is the disabled feature; every method must be
// safe on it so startCargoWall can wire the subsystem unconditionally.
func TestContainerAttributionNilSafe(t *testing.T) {
	var a *containerAttribution
	assert.NotPanics(t, func() {
		a.enableMode()
		a.ensureLoopbackAllowed(nil)
		a.wireVerdicts(nil, nil, nil, nil, nil)
		a.preallowLocalNetworks(t.Context(), podenv.Dockerd{})
		assert.NoError(t, a.allowLocalNetwork(netip.Prefix{}))
		a.Close()
		assert.Nil(t, a.enricherArg())
		assert.Nil(t, a.observerProgram())
		a.startUserspace(t.Context(), nil, false, nil, nil)
	})
}

// preallowRun is what preallowNetworks did: what it carved, the bridges
// whose network it read, how often it asked the daemon, and its log.
type preallowRun struct {
	carved []netip.Prefix
	read   []string
	asked  int
	log    string
}

// runPreallow is preallowNetworks for dockerd, with each bridge's network
// from subnets (a bridge missing there has none to read), the daemon's
// networks one of their own, and every carve failing with carveErr.
func runPreallow(t *testing.T, dockerd podenv.Dockerd, subnets map[string]string, carveErr error) *preallowRun {
	t.Helper()
	run := &preallowRun{}
	oldBridge, oldDiscover := bridgeSubnet, discoverBridgeSubnets
	t.Cleanup(func() { bridgeSubnet, discoverBridgeSubnets = oldBridge, oldDiscover })
	bridgeSubnet = func(name string) (netip.Prefix, error) {
		run.read = append(run.read, name)
		if s, ok := subnets[name]; ok {
			return netip.MustParsePrefix(s), nil
		}
		return netip.Prefix{}, fmt.Errorf("%s interface not found", name)
	}
	discoverBridgeSubnets = func(context.Context, string) ([]netip.Prefix, error) {
		run.asked++
		return []netip.Prefix{netip.MustParsePrefix("172.30.0.0/16")}, nil
	}
	var buf bytes.Buffer
	preallowNetworks(t.Context(), dockerd, func(p netip.Prefix) error {
		run.carved = append(run.carved, p)
		return carveErr
	}, slog.New(slog.NewTextHandler(&buf, nil)))
	run.log = buf.String()
	return run
}

// Before the hook's mode is raised, a daemon that answered is asked for its
// networks, and its docker0 is carved from its address too, where it is up
// or the bridges could not be listed: one up with no docker0 (a renamed
// default bridge, --bridge=none, Podman) reads and warns of none. One that has
// not, still to come up or with no socket to ask, is never asked, which
// would cost startup the daemon's silence: each Docker bridge up is carved
// from its own address instead, a user network's included, since dockerd
// starts restart-policy containers on them before it serves the API, and
// docker0 alone when the bridges could not be listed. With no bridge,
// nothing is read or warned about; with no Docker, nothing at all.
func TestPreallowNetworks(t *testing.T) {
	subnets := map[string]string{"docker0": "172.17.0.0/16", "br-0123456789ab": "172.18.0.0/16"}
	docker0, user := netip.MustParsePrefix("172.17.0.0/16"), netip.MustParsePrefix("172.18.0.0/16")
	discovered := netip.MustParsePrefix("172.30.0.0/16")
	both := []string{"docker0", "br-0123456789ab"}
	for _, c := range []struct {
		name    string
		dockerd podenv.Dockerd
		read    []string
		carved  []netip.Prefix
		asked   int
		warn    string
	}{
		{name: "no Docker", dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent}},
		{name: "pending, no bridge", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal}},
		{
			name: "pending, bridges up", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: both},
			read: both, carved: []netip.Prefix{docker0, user},
		},
		{
			name:    "pending, bridges not listed",
			dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, BridgesErr: errors.New("netlink: permission denied")},
			read:    []string{"docker0"}, carved: []netip.Prefix{docker0},
		},
		{
			name:    "unreachable, a user network's bridge",
			dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent, Bridges: []string{"br-0123456789ab"}},
			read:    []string{"br-0123456789ab"}, carved: []netip.Prefix{user},
		},
		{
			name:    "unreachable, a bridge with no address",
			dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent, Bridges: []string{"br-ffffffffffff", "docker0"}},
			read:    []string{"br-ffffffffffff", "docker0"}, carved: []netip.Prefix{docker0},
			warn: "Docker bridge subnet not discovered; its traffic stays adjudicated\" bridge=br-ffffffffffff",
		},
		{
			name: "up", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: both, Answers: true},
			read: []string{"docker0"}, carved: []netip.Prefix{docker0, discovered}, asked: 1,
		},
		{
			name:    "up, no docker0",
			dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: []string{"br-0123456789ab"}, Answers: true},
			carved:  []netip.Prefix{discovered}, asked: 1,
		},
		{
			name: "up, no bridge", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Answers: true},
			carved: []netip.Prefix{discovered}, asked: 1,
		},
		{
			name: "up, bridges not listed", asked: 1,
			dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, BridgesErr: errors.New("netlink: denied"), Answers: true},
			read:    []string{"docker0"}, carved: []netip.Prefix{docker0, discovered},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := runPreallow(t, c.dockerd, subnets, nil)
			assert.Equal(t, c.read, run.read)
			assert.Equal(t, c.carved, run.carved)
			assert.Equal(t, c.asked, run.asked, "only a daemon that answered is asked for its networks")
			if c.warn == "" {
				assert.NotContains(t, run.log, "level=WARN")
			} else {
				assert.Contains(t, run.log, c.warn)
			}
		})
	}

	unlisted := podenv.Dockerd{Kind: podenv.DockerdLocal, BridgesErr: errors.New("netlink: denied"), Answers: true}
	missing := runPreallow(t, unlisted, nil, nil)
	assert.Contains(t, missing.log, "Docker bridge subnet not discovered", "with the bridges unknown, docker0 is looked for")
	assert.Equal(t, []netip.Prefix{discovered}, missing.carved, "and the networks carved without it")

	pending := podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: []string{"docker0"}}
	failed := runPreallow(t, pending, subnets, errors.New("map full"))
	assert.Contains(t, failed.log, "Docker bridge carve-out failed")
	assert.Contains(t, failed.log, "bridge=docker0")
	refused := runPreallow(t, pending, subnets, origin.ErrLocalNetworkRefused)
	assert.NotContains(t, refused.log, "level=WARN", "a refusal is the policy's, already logged by the write")
}
