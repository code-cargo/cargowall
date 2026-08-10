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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startUnixServer serves handler on a unix socket beneath t.TempDir and
// returns the socket path. The socket name is one short segment: sun_path
// is 104/108 bytes and the temp dir already spends most of that budget.
func startUnixServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestPingOK(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "OK")
	})
	c := newDockerClient(startUnixServer(t, mux))
	require.NoError(t, c.ping(context.Background()))
}

func TestPingNon200(t *testing.T) {
	c := newDockerClient(startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "starting", http.StatusInternalServerError)
	})))
	require.ErrorContains(t, c.ping(context.Background()), "500")
}

func TestEventsStreamDecodesDaemonFrames(t *testing.T) {
	id := strings.Repeat("ca", 32)
	execID := strings.Repeat("be", 32)
	// Two NDJSON frames as dockerd emits them, including fields the client
	// must ignore (status, from, scope, time) — tolerant decoding is the
	// contract with a moving daemon API.
	frames := fmt.Sprintf(`{"status":"start","Type":"container","Action":"start","Actor":{"ID":"%s","Attributes":{"image":"alpine:3","name":"c1"}},"scope":"local","time":1700000000,"timeNano":1700000000123456789}
{"Type":"container","Action":"exec_start: sh -c true","Actor":{"ID":"%s","Attributes":{"execID":"%s"}},"timeNano":1700000000223456789}
`, id, id, execID)

	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, frames)
		w.(http.Flusher).Flush()
		// Hold the stream open like the real daemon; the client ends it by
		// closing the body.
		<-r.Context().Done()
	})
	c := newDockerClient(startUnixServer(t, mux))

	body, err := c.events(context.Background(), 0)
	require.NoError(t, err)
	defer body.Close()

	dec := json.NewDecoder(body)
	var ev dockerEvent
	require.NoError(t, dec.Decode(&ev))
	assert.Equal(t, "container", ev.Type)
	assert.Equal(t, "start", ev.Action)
	assert.Equal(t, id, ev.Actor.ID)
	assert.Equal(t, "alpine:3", ev.Actor.Attributes["image"])
	assert.Equal(t, int64(1700000000123456789), ev.TimeNano)

	require.NoError(t, dec.Decode(&ev))
	assert.Equal(t, "exec_start: sh -c true", ev.Action)
	assert.Equal(t, execID, ev.Actor.Attributes["execID"])
	assert.Equal(t, int64(1700000000223456789), ev.TimeNano)
}

func TestEventsSinceParam(t *testing.T) {
	queries := make(chan url.Values, 2)
	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})
	c := newDockerClient(startUnixServer(t, mux))

	body, err := c.events(context.Background(), 0)
	require.NoError(t, err)
	body.Close()
	q := <-queries
	assert.False(t, q.Has("since"), "a fresh subscription must not constrain the stream")
	// The daemon-side filter is part of the request contract: container
	// events (tracking) and network events (bridge-subnet carve-outs).
	assert.JSONEq(t, `{"type":["container","network"]}`, q.Get("filters"))

	// 42ns past the epoch second: the fractional part must be zero-padded
	// to nine digits or the daemon would read .42 as 420ms and replay a
	// wider window than intended.
	body, err = c.events(context.Background(), 5_000_000_042)
	require.NoError(t, err)
	body.Close()
	q = <-queries
	assert.Equal(t, "5.000000042", q.Get("since"))
}

func TestEventsNon200(t *testing.T) {
	c := newDockerClient(startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"bad parameter"}`, http.StatusBadRequest)
	})))
	_, err := c.events(context.Background(), 0)
	require.ErrorContains(t, err, "400")
}

func TestInspectContainerDecodes(t *testing.T) {
	id := strings.Repeat("ab", 32)
	// Trimmed real inspect payload; unknown fields must be ignored and the
	// multi-network shape (compose/user-defined bridges) must decode.
	payload := fmt.Sprintf(`{
		"Id": %q,
		"Created": "2026-08-07T00:00:00Z",
		"State": {"Status": "running", "Running": true, "Pid": 4242},
		"HostConfig": {"Privileged": true, "NetworkMode": "bridge"},
		"NetworkSettings": {
			"IPAddress": "172.17.0.2",
			"Networks": {
				"bridge": {"Gateway": "172.17.0.1", "IPAddress": "172.17.0.2"},
				"internal": {"IPAddress": "10.9.8.7"}
			}
		},
		"ExecIDs": ["e1", "e2"]
	}`, id)
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != id {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, payload)
	})
	c := newDockerClient(startUnixServer(t, mux))

	insp, err := c.inspectContainer(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, id, insp.ID)
	assert.Equal(t, 4242, insp.State.Pid)
	assert.True(t, insp.State.Running)
	assert.True(t, insp.HostConfig.Privileged)
	assert.Equal(t, "172.17.0.2", insp.NetworkSettings.IPAddress)
	assert.Equal(t, "172.17.0.2", insp.NetworkSettings.Networks["bridge"].IPAddress)
	assert.Equal(t, "10.9.8.7", insp.NetworkSettings.Networks["internal"].IPAddress)
	assert.Equal(t, []string{"e1", "e2"}, insp.ExecIDs)
}

func TestInspectExecDecodes(t *testing.T) {
	execID := strings.Repeat("e1", 32)
	containerID := strings.Repeat("ab", 32)
	payload := fmt.Sprintf(`{
		"ID": %q,
		"Running": true,
		"Pid": 4343,
		"ContainerID": %q,
		"ProcessConfig": {"tty": false, "entrypoint": "sh"}
	}`, execID, containerID)
	mux := http.NewServeMux()
	mux.HandleFunc("/exec/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != execID {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, payload)
	})
	c := newDockerClient(startUnixServer(t, mux))

	insp, err := c.inspectExec(context.Background(), execID)
	require.NoError(t, err)
	assert.Equal(t, execID, insp.ID)
	assert.True(t, insp.Running)
	assert.Equal(t, 4343, insp.Pid)
	assert.Equal(t, containerID, insp.ContainerID)
}

func TestListContainersDecodes(t *testing.T) {
	idA := strings.Repeat("aa", 32)
	idB := strings.Repeat("bb", 32)
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `[{"Id":%q,"Names":["/c1"]},{"Id":%q}]`, idA, idB)
	})
	c := newDockerClient(startUnixServer(t, mux))

	list, err := c.listContainers(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, idA, list[0].ID)
	assert.Equal(t, idB, list[1].ID)
}

func TestUnaryNon200(t *testing.T) {
	// dockerd reports errors as JSON bodies on 4xx/5xx; every unary path
	// must surface the status as an error, never decode the error body as
	// a payload.
	c := newDockerClient(startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
	})))
	ctx := context.Background()
	tests := []struct {
		name string
		call func() error
	}{
		{"inspectContainer", func() error { _, err := c.inspectContainer(ctx, "x"); return err }},
		{"inspectExec", func() error { _, err := c.inspectExec(ctx, "x"); return err }},
		{"listContainers", func() error { _, err := c.listContainers(ctx); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, tt.call(), "404")
		})
	}
}
