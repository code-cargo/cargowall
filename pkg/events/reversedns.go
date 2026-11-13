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
	"net/netip"
	"strings"

	"github.com/code-cargo/cargowall/pkg/config"
)

// HostResolver is the forward-lookup surface ConfirmReverseName uses.
type HostResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ConfirmReverseName returns the first of names, a reverse lookup's answer
// for ip, whose own forward lookup includes ip: lowercased, without its
// trailing dot. It returns "" when none does. settled reports whether that
// outcome is final. It is false when no name was confirmed and a forward
// lookup failed in a way that says nothing about the name (a timeout,
// SERVFAIL, a network error), so a later attempt may still confirm it.
//
// A PTR record is the destination's own claim. Whoever controls an address's
// reverse zone can make it name any host, including one a rule allows, so an
// unconfirmed reverse name must never decide which rule a connection is
// judged under. The forward answer is controlled by the owner of the name's
// domain, so a name whose forward answer leads back to ip is one that
// domain's owner vouches for.
//
// Each name gets one lookup in ip's own family, on the rooted name: one query
// has one error, so settled never depends on which of an A and an AAAA answer
// arrived first, and a rooted name skips the resolv.conf search list, which
// could otherwise confirm the name through a record under a search domain.
// err is the last forward lookup's error, for logging.
func ConfirmReverseName(ctx context.Context, r HostResolver, ip string, names []string) (
	name string, settled bool, err error,
) {
	want, parseErr := netip.ParseAddr(ip)
	if parseErr != nil {
		return "", true, nil
	}
	want = want.Unmap()
	family := "ip6"
	if want.Is4() {
		family = "ip4"
	}
	settled = true
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if n == "" {
			continue
		}
		addrs, lookupErr := r.LookupNetIP(ctx, family, n+".")
		if lookupErr != nil {
			err = lookupErr
			var dnsErr *net.DNSError
			if !errors.As(lookupErr, &dnsErr) || !dnsErr.IsNotFound {
				settled = false
			}
			continue
		}
		for _, a := range addrs {
			if a.Unmap() == want {
				return n, true, nil
			}
		}
	}
	return "", settled, err
}

// UsableReverseNames returns the names among a reverse lookup's answer that a
// rule allows, lowercased and without the trailing dot. Only those can change
// a verdict, so only those are worth confirming. Any other name is neither
// looked up nor used as a label, so no query goes to a zone the destination's
// owner chose, and the proxy, which forwards exactly these names, never sees
// one it would refuse and record as the job's query.
func UsableReverseNames(cm *config.Manager, names []string) []string {
	var usable []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if n != "" && cm.MatchHostnameRule(n).HasAllow() {
			usable = append(usable, n)
		}
	}
	return usable
}
