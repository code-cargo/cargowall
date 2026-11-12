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

package events

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeHostAddrs is a hostAddrSet over a settable clock and listing.
type fakeHostAddrs struct {
	clock atomic.Int64 // unix nanoseconds
	mu    sync.Mutex
	addrs []string
	err   error
	lists int
}

func (f *fakeHostAddrs) set(t *testing.T) *hostAddrSet {
	t.Helper()
	f.clock.Store(time.Unix(1000, 0).UnixNano())
	h := &hostAddrSet{
		now: func() time.Time { return time.Unix(0, f.clock.Load()) },
		list: func() ([]net.Addr, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.lists++
			if f.err != nil {
				return nil, f.err
			}
			var out []net.Addr
			for _, a := range f.addrs {
				ip, ipn, _ := net.ParseCIDR(a)
				ipn.IP = ip
				out = append(out, ipn)
			}
			return out, nil
		},
	}
	saved := hostAddrs
	hostAddrs = h
	t.Cleanup(func() { hostAddrs = saved })
	return h
}

func (f *fakeHostAddrs) advance(d time.Duration) { f.clock.Add(int64(d)) }

// The namespace's addresses, listed at most every hostAddrsTTL: one added
// since reads as not the host's until the snapshot refreshes. A v4-mapped
// address is its v4 one, and a zone is ignored.
func TestHostAddrs_Snapshot(t *testing.T) {
	f := &fakeHostAddrs{addrs: []string{"10.1.0.11/24", "fe80::1/64"}}
	h := f.set(t)
	assert.True(t, h.has("10.1.0.11"))
	assert.True(t, h.has("::ffff:10.1.0.11"))
	assert.True(t, h.has("fe80::1%eth0"))
	assert.False(t, h.has("10.1.0.12"))
	assert.False(t, h.has("not an address"))

	f.mu.Lock()
	f.addrs = append(f.addrs, "10.1.0.12/24")
	f.mu.Unlock()
	assert.False(t, h.has("10.1.0.12"), "stale within the TTL")
	f.advance(hostAddrsTTL)
	assert.True(t, h.has("10.1.0.12"), "refreshed after it")
	assert.Equal(t, 2, f.lists)

	f.mu.Lock()
	f.err = errors.New("netlink busy")
	f.mu.Unlock()
	f.advance(hostAddrsTTL)
	assert.True(t, h.has("10.1.0.12"), "a failed listing keeps the last snapshot")
	assert.Equal(t, 3, f.lists)
	assert.True(t, h.has("10.1.0.11"))
	assert.Equal(t, 3, f.lists, "and is retried only after the TTL")
}

// Readers and refreshes race safely.
func TestHostAddrs_Concurrent(t *testing.T) {
	f := &fakeHostAddrs{addrs: []string{"10.1.0.11/24"}}
	h := f.set(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				f.advance(time.Second)
				assert.True(t, h.has("10.1.0.11"))
			}
		}()
	}
	wg.Wait()
}
