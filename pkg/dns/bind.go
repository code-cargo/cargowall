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
	"fmt"
	"sync"
)

// listenProtocols are the protocols the proxy serves on every listen address.
var listenProtocols = []string{"udp4", "tcp4"}

// listenerBinds records whether the proxy holds each of its listen addresses.
// Start binds every listener in its own goroutine and only logs a failure, so
// this is how a caller learns whether an address is really the proxy's
// before pointing traffic at it.
type listenerBinds struct {
	mu    sync.Mutex
	addrs map[string]*bindState
}

// bindState is one address's outcome: settled once every protocol is
// listening, or as soon as one fails to bind.
type bindState struct {
	pending int           // protocols not yet listening
	err     error         // the bind failure, if one settled it
	settled chan struct{} // closed when settled
}

// stateLocked returns addr's state, creating it on first use so a wait may
// begin before Start has run. Requires b.mu.
func (b *listenerBinds) stateLocked(addr string) *bindState {
	if b.addrs == nil {
		b.addrs = make(map[string]*bindState)
	}
	st, ok := b.addrs[addr]
	if !ok {
		st = &bindState{pending: len(listenProtocols), settled: make(chan struct{})}
		b.addrs[addr] = st
	}
	return st
}

// listening records that one protocol is listening on addr.
func (b *listenerBinds) listening(addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.stateLocked(addr)
	select {
	case <-st.settled:
		return
	default:
	}
	if st.pending--; st.pending == 0 {
		close(st.settled)
	}
}

// failed records that a protocol on addr stopped with err. Once the address
// has settled this changes nothing: a server returning after it was
// listening is shutting down, not failing to bind.
func (b *listenerBinds) failed(addr string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.stateLocked(addr)
	select {
	case <-st.settled:
		return
	default:
	}
	st.err = err
	close(st.settled)
}

// wait blocks until addr settles or ctx ends.
func (b *listenerBinds) wait(ctx context.Context, addr string) error {
	b.mu.Lock()
	st := b.stateLocked(addr)
	b.mu.Unlock()
	select {
	case <-st.settled:
		// st.err was written before settled was closed.
		if st.err != nil {
			return fmt.Errorf("DNS proxy failed to listen on %s: %w", addr, st.err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("DNS proxy not listening on %s: %w", addr, ctx.Err())
	}
}

// WaitListening blocks until the proxy is listening on addr, as passed to
// NewServer or AddListenAddr, over both UDP and TCP. It returns an error if
// either failed to bind (the address is held by something else, or is not
// on this host) or ctx ends first.
func (s *Server) WaitListening(ctx context.Context, addr string) error {
	return s.binds.wait(ctx, addr)
}
