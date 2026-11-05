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
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeProxy answers WaitListening with err and records the address asked.
type fakeProxy struct {
	err   error
	asked []string
}

func (p *fakeProxy) WaitListening(_ context.Context, addr string) error {
	p.asked = append(p.asked, addr)
	return p.err
}

// TestRedirectContainerDNS_NoBridge: with no Docker bridge there is nothing
// to wait for and nothing installed.
func TestRedirectContainerDNS_NoBridge(t *testing.T) {
	proxy := &fakeProxy{}
	teardowns := &teardownList{}
	undo := redirectContainerDNS(context.Background(), proxy, "", teardowns, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.Nil(t, undo)
	require.Empty(t, proxy.asked)
	require.Empty(t, teardowns.fns)
}

// TestRedirectContainerDNS_ListenerNotHeld: when the proxy does not hold the
// bridge listener, no redirect is installed (and none is registered for
// teardown), so container DNS is never handed to whatever holds the address.
func TestRedirectContainerDNS_ListenerNotHeld(t *testing.T) {
	proxy := &fakeProxy{err: errors.New("address already in use")}
	teardowns := &teardownList{}
	undo := redirectContainerDNS(context.Background(), proxy, "172.17.0.1", teardowns, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.Nil(t, undo)
	require.Equal(t, []string{"172.17.0.1:53"}, proxy.asked, "the wait must name the address the proxy was asked to listen on")
	require.Empty(t, teardowns.fns)
}
