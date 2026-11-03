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
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/podenv"
)

// dockerUpFor is newDockerUp for dockerd and cmd, logging into the
// returned buffer and recording into a dockerFile of the test's own.
func dockerUpFor(t *testing.T, dockerd podenv.Dockerd, cmd *StartCmd) (*dockerUp, *bytes.Buffer) {
	t.Helper()
	saved := dockerFile
	dockerFile = filepath.Join(t.TempDir(), "cargowall-docker")
	t.Cleanup(func() { dockerFile = saved })
	var buf bytes.Buffer
	return newDockerUp(podenv.Shape{Dockerd: dockerd}, cmd, slog.New(slog.NewTextHandler(&buf, nil))), &buf
}

// The startup line says what waits for a Docker still to come up, by what
// is on: attribution and carve-outs start when it answers, its containers'
// DNS goes to the container DNS addresses by the redirect, or around the
// proxy without one, and daemon.json is left alone. A host with no Docker
// gets one line, and an up one none of its own; only a pending one is
// recorded for the summary.
func TestDockerUp_StartupLines(t *testing.T) {
	pending := podenv.Dockerd{Kind: podenv.DockerdLocal}
	for _, c := range []struct {
		name    string
		dockerd podenv.Dockerd
		cmd     StartCmd
		want    []string
		absent  []string
		record  bool
	}{
		{
			name: "no Docker", dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent},
			want: []string{"No Docker on this host"}, absent: []string{"not answering"},
		},
		{
			name: "up", dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: []string{"docker0"}, Answers: true},
			absent: []string{"not answering", "No Docker"},
		},
		{
			name: "pending, everything on", dockerd: pending,
			cmd: StartCmd{ContainerEgress: ContainerEgressEnforce, DockerDNSInterception: true, DNSRedirect: true},
			want: []string{
				"Docker socket present, daemon not answering yet",
				"container attribution and bridge carve-outs start when it does",
				"goes to 169.254.0.53 and fd97:d1fb:f215::53 by the DNS redirect, and daemon.json is left alone",
			},
			record: true,
		},
		{
			name: "pending, interception without the redirect", dockerd: pending,
			cmd:    StartCmd{ContainerEgress: ContainerEgressOff, DockerDNSInterception: true},
			want:   []string{"without --dns-redirect its containers' DNS goes around the proxy"},
			absent: []string{"container attribution"},
			record: true,
		},
		{
			name:    "pending, bridges up but not answering",
			dockerd: podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: []string{"docker0"}},
			want:    []string{"not answering yet though its bridges are up"}, record: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, buf := dockerUpFor(t, c.dockerd, &c.cmd)
			for _, w := range c.want {
				assert.Contains(t, buf.String(), w)
			}
			for _, a := range c.absent {
				assert.NotContains(t, buf.String(), a)
			}
			assert.NotContains(t, buf.String(), "level=WARN")
			_, recorded := readDockerRecord()
			assert.Equal(t, c.record, recorded)
		})
	}
}

// The arrival of a Docker still to come up is logged and recorded once,
// whichever reports it first: the tracker's first connect, with the
// subnets it carved, or the watcher. Later connects, and anything after
// teardown, are not arrivals. Without the redirect it is a Warn, its
// containers' DNS going around the proxy.
func TestDockerUp_Arrival(t *testing.T) {
	cmd := &StartCmd{ContainerEgress: ContainerEgressObserve, DockerDNSInterception: true, DNSRedirect: true}
	u, buf := dockerUpFor(t, podenv.Dockerd{Kind: podenv.DockerdLocal}, cmd)
	carved := []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() { defer wg.Done(); u.connected(true, carved) }()
		go func() { defer wg.Done(); u.answered(false, nil) }()
	}
	wg.Wait()
	u.connected(false, nil)
	u.close()
	assert.Equal(t, 1, strings.Count(buf.String(), "Docker answered"), buf.String())
	assert.NotContains(t, buf.String(), "never answered")
	rec, ok := readDockerRecord()
	require.True(t, ok)
	assert.True(t, rec.Answered)
	assert.Positive(t, rec.AfterS)
	assert.Contains(t, dockerLine(), "answered")

	u, buf = dockerUpFor(t, podenv.Dockerd{Kind: podenv.DockerdLocal}, &StartCmd{DockerDNSInterception: true})
	u.answered(false, nil)
	assert.Contains(t, buf.String(), "level=WARN")
	assert.Contains(t, buf.String(), "goes around the proxy")

	// An up daemon's connects are no arrival.
	u, buf = dockerUpFor(t, podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: []string{"docker0"}, Answers: true}, cmd)
	u.connected(true, carved)
	u.close()
	assert.NotContains(t, buf.String(), "Docker answered")
}

// A Docker still to come up that never answers is said so at teardown, and
// in the summary: an Info with no bridge at startup, since no container of
// its can have run, and a Warn with its bridges up, whose containers went
// untracked. An arrival after teardown is none.
func TestDockerUp_NeverAnswered(t *testing.T) {
	u, buf := dockerUpFor(t, podenv.Dockerd{Kind: podenv.DockerdLocal}, &StartCmd{})
	u.close()
	u.answered(false, nil)
	assert.Contains(t, buf.String(), "level=INFO")
	assert.Contains(t, buf.String(), "Docker never answered while cargowall ran")
	assert.NotContains(t, buf.String(), "Docker answered")
	assert.Equal(t, "Docker: the daemon never answered while CargoWall ran; no containers observed.", dockerLine())

	u, buf = dockerUpFor(t, podenv.Dockerd{Kind: podenv.DockerdLocal, Bridges: []string{"docker0"}}, &StartCmd{})
	u.close()
	assert.Contains(t, buf.String(), "level=WARN")
	assert.Contains(t, buf.String(), "containers on them went untracked")

	(*dockerUp)(nil).close()
}

// startUserspace starts no tracker on a host with no Docker, quietly, and
// none for bridges with no socket, with a warning.
func TestStartUserspace_DockerClasses(t *testing.T) {
	for _, c := range []struct {
		name    string
		dockerd podenv.Dockerd
		warn    string
	}{
		{name: "no Docker", dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent}},
		{
			name: "bridges, no socket", dockerd: podenv.Dockerd{Kind: podenv.DockerdAbsent, Bridges: []string{"docker0"}},
			warn: "no Docker socket to ask about their containers",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			a := &containerAttribution{logger: logger}
			u, _ := dockerUpFor(t, c.dockerd, &StartCmd{})
			assert.False(t, a.startUserspace(t.Context(), nil, false, nil, u))
			if c.warn != "" {
				assert.Contains(t, buf.String(), c.warn)
			} else {
				assert.NotContains(t, buf.String(), "level=WARN")
			}
			assert.NotContains(t, buf.String(), "Container attribution enabled")
		})
	}
}

// The summary's line about a Docker still to come up at startup: nothing
// without a record, and through Run, above the dashboard link.
func TestSummary_DockerLine(t *testing.T) {
	var buf bytes.Buffer
	renderDocker(&buf, "")
	assert.Empty(t, buf.String())

	redirectStateFiles(t)
	u, _ := dockerUpFor(t, podenv.Dockerd{Kind: podenv.DockerdLocal}, &StartCmd{})
	u.answered(false, nil)
	var out bytes.Buffer
	c := &SummaryCmd{
		AuditLog: filepath.Join(t.TempDir(), "never-written.ndjson"),
		Steps:    "[]",
		Mode:     "enforce",
		output:   &out,
	}
	require.NoError(t, c.Run())
	assert.Contains(t, out.String(), "Docker: the daemon answered")
}
