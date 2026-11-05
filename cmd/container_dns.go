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
	"net"
	"time"

	"github.com/code-cargo/cargowall/pkg/network"
)

// bridgeListenerWait bounds how long startup waits for the DNS proxy to
// bind its Docker bridge listener. Binding is immediate when it works; the
// bound only matters when it never settles.
const bridgeListenerWait = 2 * time.Second

// listeningProxy is the part of the DNS proxy that redirecting container DNS
// depends on.
type listeningProxy interface {
	WaitListening(ctx context.Context, addr string) error
}

// dockerBridgeNet reads docker0's prefix for an address it holds; a var so
// tests can stand in for docker0.
var dockerBridgeNet = network.DockerBridgeNet

// redirectContainerDNS sends DNS from containers on Docker bridges to the
// proxy's listener on the Docker bridge address, and returns the undo to
// defer, or nil when nothing was installed. upstream is the proxy's
// upstream resolver (host:port, or a bare host).
//
// It installs nothing unless the proxy holds bridgeIP:53 over both UDP and
// TCP: a DNAT to an address the proxy does not hold would hand container DNS
// to whatever does. Without the redirect containers resolve as they did
// before, through the proxy only if Docker points them at the bridge
// listener. ctx is startup's: a shutdown signal ends the wait quietly.
func redirectContainerDNS(ctx context.Context, proxy listeningProxy, bridgeIP, upstream string, teardowns *teardownList, logger *slog.Logger) func() {
	if bridgeIP == "" {
		return nil
	}
	listener := net.JoinHostPort(bridgeIP, "53")
	waitCtx, cancel := context.WithTimeout(ctx, bridgeListenerWait)
	defer cancel()
	if err := proxy.WaitListening(waitCtx, listener); err != nil {
		if ctx.Err() != nil {
			return nil // shutting down; startup unwinds at its next checkpoint
		}
		logger.Warn("Container DNS not redirected: the DNS proxy does not hold the Docker bridge listener",
			"listener", listener, "error", err)
		return nil
	}

	// The rules exempt docker0's own subnet; teardown deletes them by the
	// same prefix, so it is read once, here.
	bridge, err := dockerBridgeNet(bridgeIP)
	if err != nil {
		logger.Warn("Container DNS not redirected: cannot read the Docker bridge subnet", "error", err)
		return nil
	}
	c := network.ContainerDNS{Bridge: bridge, Upstreams: upstreamIPv4(upstream)}

	// Registered BEFORE the mutation, like the host redirect's undo: a
	// failure partway through leaves rules only the undo removes.
	undo := teardowns.add(func() {
		if err := network.TeardownContainerDNSRedirect(c, logger); err != nil {
			logger.Warn("Failed to tear down container DNS redirect", "error", err)
		}
	})
	if err := network.SetupContainerDNSRedirect(c, logger); err != nil {
		logger.Warn("Failed to set up container DNS redirect (iptables)", "error", err)
	}
	return undo
}

// upstreamIPv4 is the address of the proxy's upstream resolver, as the one
// element of a slice, when it is a non-loopback IPv4 address; otherwise
// nothing. A loopback upstream is no address a container could ask.
func upstreamIPv4(upstream string) []net.IP {
	host := upstream
	if h, _, err := net.SplitHostPort(upstream); err == nil {
		host = h
	}
	ip := net.ParseIP(host).To4()
	if ip == nil || ip.IsLoopback() {
		return nil
	}
	return []net.IP{ip}
}
