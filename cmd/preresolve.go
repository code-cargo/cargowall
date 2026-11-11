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
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/network"
)

// Startup pre-resolution warms what the firewall knows before the TC program
// attaches: the names behind the job's existing connections, the addresses
// systemd-resolved has cached for the policy's names, and the policy's names
// resolved afresh through the proxy. It sits on the path to the ready
// sentinel, so its cost must not depend on how fast upstream DNS answers: a
// launcher waits a fixed time for ready (cargowall-action allows 30 s) and
// stops cargowall past it. Every lookup therefore runs under one total
// deadline, concurrently and with bounded concurrency. What the deadline cuts
// off is only what pre-resolution adds. A name not resolved in time is still
// resolved, and enforced, through the proxy when it's next queried, and
// existing connections whose peers stay unnamed are still allowed, on their
// observed ports, by gateExistingConnections.
const (
	// preResolveDeadline bounds all startup lookups together. A healthy
	// upstream needs a round trip or two; the deadline only binds when it is
	// slow, and must stay well inside a launcher's readiness wait alongside
	// the rest of startup.
	preResolveDeadline = 5 * time.Second

	// preResolveStubLookup bounds one lookup through systemd-resolved's
	// stub. What those lookups are for is its cache, which answers at once,
	// so a slow answer is a miss worth nothing.
	preResolveStubLookup = 1 * time.Second

	// preResolveProxyLookup bounds one lookup through the proxy, which goes
	// upstream and may be slow for a cold name.
	preResolveProxyLookup = 2 * time.Second

	// preResolveWorkers bounds the lookups in flight in each round, so a
	// large policy doesn't fire hundreds of queries at once at the stub, the
	// proxy and the upstream.
	preResolveWorkers = 16
)

// stubResolver is the startup lookup surface: systemd-resolved's stub in
// production (newStubResolver), a scripted resolver in tests. The deadline
// bounds pre-resolution only if every lookup returns once its ctx ends, so an
// implementation must honour ctx; Go's resolver does, but a cgo one, whose
// getaddrinfo can't be cancelled, would not.
type stubResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// hostResolver resolves a name; the proxy in production (newProxyResolver).
// Like stubResolver, it must honour ctx.
type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// cacheSink takes what the stub's cache says about the tracked names; the
// DNS server in production.
type cacheSink interface {
	RecordSystemCacheAnswer(hostname string, ips []string)
	ApplyRulesToTrackedHostnames()
}

// newStubResolver resolves through systemd-resolved's stub listener, for
// the cache it holds. Marked so the redirect's stub DNAT (installed before
// this runs) passes these peeks through to the real stub instead of looping
// them into the proxy.
func newStubResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &net.Dialer{Control: network.MarkDNSProxySocket}
			return d.DialContext(ctx, "udp", "127.0.0.53:53")
		},
	}
}

// newProxyResolver resolves through cargowall's own DNS proxy, which writes
// the answers it enforces to the firewall.
func newProxyResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", "127.0.0.1:53")
		},
	}
}

// preResolve runs startup pre-resolution under preResolveDeadline. The
// existing connections' reverse names and the stub-cache snapshot (phase 1)
// run side by side, both from the stub; the cache entries are applied to the
// firewall; then the tracked names are resolved through the proxy (phase 2).
//
// Phase 1's answers are recorded only once both stub rounds are done. An
// address both rounds name gets the name the last write gives it, and the
// cached forward answer, the policy's own name, must be that last word: a
// PTR name in its place matches no rule, so gateExistingConnections would
// allow an existing connection to a host the job denies on its observed
// ports. A cache hit answers at once while a PTR goes upstream, so recording
// as the answers arrive would let the PTR win.
// A slow upstream can spend the whole deadline in phase 1, leaving phase 2
// nothing: that costs only phase 2's head start, never enforcement. Derives
// from ctx, so a startup-window shutdown signal drains it promptly.
func preResolve(ctx context.Context, conns existingConns, configMgr *config.Manager, sink cacheSink,
	stub stubResolver, proxy hostResolver, logger *slog.Logger,
) {
	ctx, cancel := context.WithTimeout(ctx, preResolveDeadline)
	defer cancel()
	started := time.Now()
	hostnames := slices.Sorted(maps.Keys(configMgr.GetTrackedHostnames()))

	var wg sync.WaitGroup
	var cached, cacheCutOff int
	var answersMu sync.Mutex
	answers := make(map[string][]string)
	wg.Go(func() { reverseDNSExistingConnections(ctx, conns, configMgr, stub, logger) })
	wg.Go(func() {
		cached, cacheCutOff = lookupEach(ctx, hostnames, preResolveStubLookup, func(ctx context.Context, hostname string) bool {
			ips, err := stub.LookupHost(ctx, hostname)
			if err != nil {
				logger.Debug("System DNS cache miss", "hostname", hostname, "error", err)
				return false
			}
			answersMu.Lock()
			answers[hostname] = ips
			answersMu.Unlock()
			return true
		})
	})
	wg.Wait()

	// Local work, so it runs whatever the deadline left; the answers last,
	// over the reverse names (see above).
	for _, hostname := range hostnames {
		if ips, ok := answers[hostname]; ok {
			sink.RecordSystemCacheAnswer(hostname, ips)
		}
	}
	sink.ApplyRulesToTrackedHostnames()
	logger.Info("Applied system DNS cache entries to firewall",
		"hostnames", len(hostnames), "answered", cached, "cut_off", cacheCutOff)

	resolved, cutOff := lookupEach(ctx, hostnames, preResolveProxyLookup, func(ctx context.Context, hostname string) bool {
		if _, err := proxy.LookupHost(ctx, hostname); err != nil {
			logger.Debug("Failed to pre-resolve hostname", "hostname", hostname, "error", err)
			return false
		}
		return true
	})
	logger.Info("Pre-resolved tracked hostnames via DNS proxy",
		"hostnames", len(hostnames), "resolved", resolved, "cut_off", cutOff,
		"elapsed", time.Since(started).Round(time.Millisecond))
}

// reverseDNSExistingConnections looks up the reverse name of each scanned
// existing-connection IP through the stub, recording it as that IP's
// hostname for gateExistingConnections' attribution.
func reverseDNSExistingConnections(ctx context.Context, conns existingConns, configMgr *config.Manager, stub stubResolver, logger *slog.Logger) {
	if len(conns) == 0 {
		return
	}
	named, cutOff := lookupEach(ctx, slices.Sorted(maps.Keys(conns)), preResolveStubLookup, func(ctx context.Context, ip string) bool {
		names, err := stub.LookupAddr(ctx, ip)
		if err != nil || len(names) == 0 {
			return false
		}
		hostname := strings.TrimSuffix(names[0], ".")
		configMgr.UpdateDNSMapping(hostname, ip)
		logger.Debug("Reverse DNS for existing connection", "ip", ip, "hostname", hostname)
		return true
	})
	logger.Info("Populated reverse DNS cache from existing connections",
		"ips", len(conns), "named", named, "cut_off", cutOff)
}

// lookupEach runs lookup for every item from at most preResolveWorkers
// goroutines, each call bounded by perLookup and all of them by ctx. It
// returns how many lookups succeeded, and how many items ctx cut off: never
// started, or still running when it ended. A lookup that fails on its own,
// inside its bound, is neither.
func lookupEach(ctx context.Context, items []string, perLookup time.Duration, lookup func(ctx context.Context, item string) bool) (ok, cutOff int) {
	work := make(chan string)
	var succeeded, cut atomic.Int64
	var wg sync.WaitGroup
	for range min(preResolveWorkers, len(items)) {
		wg.Go(func() {
			for item := range work {
				if ctx.Err() != nil {
					cut.Add(1)
					continue
				}
				lookupCtx, cancel := context.WithTimeout(ctx, perLookup)
				done := lookup(lookupCtx, item)
				cancel()
				switch {
				case done:
					succeeded.Add(1)
				case ctx.Err() != nil:
					cut.Add(1)
				}
			}
		})
	}
	for _, item := range items {
		work <- item
	}
	close(work)
	wg.Wait()
	return int(succeeded.Load()), int(cut.Load())
}
