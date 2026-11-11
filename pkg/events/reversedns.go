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
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// addrResolver is the reverse-lookup surface resolveDestination uses: the
// system resolver in production, a scripted one in tests.
type addrResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// reverseDNSResolver uses the system default resolver for PTR lookups. The
// binary is built without cgo, so this is Go's own resolver, which reports
// NXDOMAIN and an answer with no PTR record as *net.DNSError IsNotFound, and
// timeouts, SERVFAIL and socket errors as IsTimeout or IsTemporary.
var reverseDNSResolver addrResolver = net.DefaultResolver

const (
	// reverseDNSCacheMax bounds the IPs tracked, so a flood of distinct
	// destinations can't grow memory without limit.
	reverseDNSCacheMax = 10000

	// reverseDNSTimeout bounds one lookup. It runs on the event-reporting
	// path, so it must stay short.
	reverseDNSTimeout = 500 * time.Millisecond

	// reverseDNSMaxAttempts caps the lookups one IP may cost in a run, and
	// reverseDNSBaseBackoff spaces them: the wait after the nth failure is
	// the base doubled n-1 times. Repeated denials of one destination must
	// not turn into repeated PTR queries.
	reverseDNSMaxAttempts = 6
	reverseDNSBaseBackoff = 2 * time.Second
)

// reverseDNS is the run's record of which destination IPs may still be
// looked up.
var reverseDNS = newReverseDNSTracker(reverseDNSCacheMax, time.Now)

// reverseLookupSettled reports whether a LookupAddr result is final for the
// run. Only an answer — names, or an authoritative "no such name" or empty
// answer — is. Anything else (a timeout, SERVFAIL, a network error) says
// nothing about the IP and must not stop a later lookup from finding the
// name a rule would match.
func reverseLookupSettled(err error) bool {
	if err == nil {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

type reverseDNSEntry struct {
	touched  time.Time // last change; the eviction order
	retryAt  time.Time // earliest next lookup after a failed one
	failures int       // failed lookups so far
	final    bool      // settled, or out of attempts: no further lookup
	inFlight bool      // a lookup is running; no second one may start
}

// reverseDNSTracker decides when a destination IP may be looked up. An IP is
// looked up at most once at a time, never again once a lookup settles, and
// after a failed lookup only once its backoff has passed, up to
// reverseDNSMaxAttempts lookups in all.
type reverseDNSTracker struct {
	mu      sync.Mutex
	entries map[string]*reverseDNSEntry
	max     int
	now     func() time.Time
}

func newReverseDNSTracker(maxEntries int, now func() time.Time) *reverseDNSTracker {
	return &reverseDNSTracker{entries: make(map[string]*reverseDNSEntry), max: maxEntries, now: now}
}

// begin reports whether a lookup of ip may run now and, when it may, claims
// it: concurrent callers get false until finish records the outcome.
func (t *reverseDNSTracker) begin(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e, ok := t.entries[ip]
	if !ok {
		e = t.insertLocked(ip, now)
	} else if e.final || e.inFlight || now.Before(e.retryAt) {
		return false
	}
	e.inFlight = true
	e.touched = now
	return true
}

// reverseDNSAttempt is what finish recorded about a lookup that did not
// settle: how many lookups have now failed, and either when the next may run
// or that none will.
type reverseDNSAttempt struct {
	failures  int
	retryIn   time.Duration
	exhausted bool
}

// finish records the outcome of a lookup begin claimed.
func (t *reverseDNSTracker) finish(ip string, settled bool) reverseDNSAttempt {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e, ok := t.entries[ip]
	if !ok {
		// Evicted while the lookup ran: record the outcome all the same.
		e = t.insertLocked(ip, now)
	}
	e.inFlight = false
	e.touched = now
	if settled {
		e.final = true
		return reverseDNSAttempt{}
	}
	e.failures++
	if e.failures >= reverseDNSMaxAttempts {
		e.final = true
		return reverseDNSAttempt{failures: e.failures, exhausted: true}
	}
	wait := reverseDNSBaseBackoff << (e.failures - 1)
	e.retryAt = now.Add(wait)
	return reverseDNSAttempt{failures: e.failures, retryIn: wait}
}

// insertLocked adds a fresh entry for ip, evicting the least recently
// touched one when the tracker is full. An evicted IP only loses its record:
// it may be looked up again, which costs a query, never a wrong answer.
func (t *reverseDNSTracker) insertLocked(ip string, now time.Time) *reverseDNSEntry {
	if len(t.entries) >= t.max {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, e := range t.entries {
			if first || e.touched.Before(oldest) {
				oldestKey, oldest, first = k, e.touched, false
			}
		}
		if !first {
			delete(t.entries, oldestKey)
		}
	}
	e := &reverseDNSEntry{touched: now}
	t.entries[ip] = e
	return e
}

// reset forgets every IP. Tests use it to keep runs independent.
func (t *reverseDNSTracker) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = make(map[string]*reverseDNSEntry)
}

// size reports how many IPs the tracker holds.
func (t *reverseDNSTracker) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
