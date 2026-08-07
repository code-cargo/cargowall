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
)

// dockerClient is a deliberately minimal Docker Engine API client over the
// unix socket: four GETs, decoded into local structs that name only the
// fields we read (encoding/json ignores the rest, which is the tolerant
// decoding a moving daemon API needs). Paths are unversioned on purpose —
// every field here predates API v1.24 and unversioned means "the daemon's
// current version", which survives both old daemons and Docker's periodic
// minimum-API raises, where a pinned /v1.xx/ can be rejected in either
// direction. A full docker client dependency would add nothing but a
// dependency tree.
type dockerClient struct {
	http *http.Client
}

func newDockerClient(sockPath string) *dockerClient {
	return &dockerClient{
		// No client-level timeout: the events stream is long-lived. Unary
		// calls bound themselves with request contexts.
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sockPath)
				},
			},
		},
	}
}

// dockerEvent is one message from GET /events (only container-type events
// are subscribed). Actor.ID is the container id; exec events additionally
// carry the exec id in Attributes["execID"].
type dockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	TimeNano int64 `json:"timeNano"`
}

type containerInspect struct {
	ID    string `json:"Id"`
	State struct {
		Pid     int  `json:"Pid"`
		Running bool `json:"Running"`
	} `json:"State"`
	HostConfig struct {
		Privileged  bool   `json:"Privileged"`
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		IPAddress string `json:"IPAddress"`
		Networks  map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	ExecIDs []string `json:"ExecIDs"`
}

type execInspect struct {
	ID          string `json:"ID"`
	Running     bool   `json:"Running"`
	Pid         int    `json:"Pid"`
	ContainerID string `json:"ContainerID"`
}

type containerSummary struct {
	ID string `json:"Id"`
}

// events opens the container-event stream. sinceNano > 0 resumes from that
// timestamp so events across a reconnect gap replay (handlers are idempotent
// and resolve ordinals by event time, so replay is safe). The returned body
// streams NDJSON until closed or the daemon goes away.
func (c *dockerClient) events(ctx context.Context, sinceNano int64) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("filters", `{"type":["container"]}`)
	if sinceNano > 0 {
		q.Set("since", fmt.Sprintf("%d.%09d", sinceNano/1e9, sinceNano%1e9))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/events?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("docker events: unexpected status %s", resp.Status)
	}
	return resp.Body, nil
}

func (c *dockerClient) inspectContainer(ctx context.Context, id string) (containerInspect, error) {
	var out containerInspect
	return out, c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &out)
}

func (c *dockerClient) inspectExec(ctx context.Context, id string) (execInspect, error) {
	var out execInspect
	return out, c.get(ctx, "/exec/"+url.PathEscape(id)+"/json", &out)
}

// listContainers returns running containers (the API default) for the
// reconciliation pass after (re)connecting.
func (c *dockerClient) listContainers(ctx context.Context) ([]containerSummary, error) {
	var out []containerSummary
	return out, c.get(ctx, "/containers/json", &out)
}

func (c *dockerClient) ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker ping: unexpected status %s", resp.Status)
	}
	return nil
}

func (c *dockerClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("docker GET %s: unexpected status %s", path, resp.Status)
	}
	// Inspect responses are small; the bound only guards against a
	// misbehaving endpoint streaming forever.
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}
