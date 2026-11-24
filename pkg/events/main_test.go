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
	"net/netip"
	"os"
	"testing"
)

// offlineResolver answers every lookup as a name that does not exist,
// without sending a query.
type offlineResolver struct{}

func (offlineResolver) LookupAddr(context.Context, string) ([]string, error) {
	return nil, errPTRNotFound
}

func (offlineResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errPTRNotFound
}

// TestMain keeps the package's tests off the network. A denial of an address
// with no name triggers a reverse lookup, which defaults to the system
// resolver, and the fixtures here are real addresses (8.8.8.8, 93.184.216.34,
// 2001:db8::2). So a test that fed one a blocked event sent a PTR query to
// whatever resolver the machine has. Its result then depended on the network,
// and on a runner behind cargowall each query was one the job's own firewall
// refused and reported. A test that needs answers scripts them
// (useScriptedReverseDNS), which swaps this resolver out and back.
func TestMain(m *testing.M) {
	reverseDNSResolver = offlineResolver{}
	reverseDNSRetries = newReverseDNSRetrier(reverseDNS, reverseDNSResolver, reverseDNSRetryQueue)
	os.Exit(m.Run())
}
