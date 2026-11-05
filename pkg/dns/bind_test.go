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

package dns

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
)

// startServer starts a proxy listening on 127.0.0.1:0 and on extra, and
// stops it when the test ends.
func startServer(t *testing.T, extra ...string) *Server {
	t.Helper()
	s := NewServer(config.NewConfigManager(), nil, "127.0.0.1:1", "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, addr := range extra {
		s.AddListenAddr(addr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return s
}

func waitListening(s *Server, addr string, wait time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return s.WaitListening(ctx, addr)
}

// TestWaitListening_Bound: an address the proxy binds over UDP and TCP
// settles without error, whether the wait begins before or after it does.
func TestWaitListening_Bound(t *testing.T) {
	s := startServer(t, "127.0.0.2:0")
	require.NoError(t, waitListening(s, "127.0.0.1:0", 2*time.Second))
	require.NoError(t, waitListening(s, "127.0.0.2:0", 2*time.Second))
	require.NoError(t, waitListening(s, "127.0.0.2:0", 2*time.Second), "a settled address stays settled")
}

// TestWaitListening_Held: an address something else holds settles with the
// bind failure, even though the other protocol bound.
func TestWaitListening_Held(t *testing.T) {
	holder, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer holder.Close()
	held := holder.LocalAddr().String()

	s := startServer(t, held)
	err = waitListening(s, held, 2*time.Second)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to listen on "+held)
}

// TestWaitListening_NeverStarted: an address the proxy was never asked to
// listen on does not settle; the wait ends with its context.
func TestWaitListening_NeverStarted(t *testing.T) {
	s := startServer(t)
	err := waitListening(s, "127.0.0.3:53", 100*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
