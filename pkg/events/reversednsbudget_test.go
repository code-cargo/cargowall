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
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	networkCapLog = "reached the cap for a network"
	runCapLog     = "reached the run's cap"
)

func infoLogger(buf *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(buf, nil)) }

// At most reverseDNSPerNetwork distinct addresses per IPv4 /24 and per IPv6
// /48 are let through; an address let through is let through again without
// counting, and a local address is never counted.
func TestReverseDNSBudget_PerNetworkAndLocal(t *testing.T) {
	var logs bytes.Buffer
	logger := infoLogger(&logs)
	b := newReverseDNSBudget(reverseDNSPerNetwork, reverseDNSRunMaxV4, reverseDNSRunMaxV6)

	assert.True(t, b.take("192.0.2.1", logger))
	assert.True(t, b.take("192.0.2.2", logger))
	assert.False(t, b.take("192.0.2.3", logger), "a third in the /24")
	assert.True(t, b.take("192.0.2.1", logger), "again: no new count")
	assert.True(t, b.take("192.0.3.1", logger), "another /24")

	assert.True(t, b.take("2001:db8:abcd:1::1", logger))
	assert.True(t, b.take("2001:db8:abcd:2::1", logger))
	assert.False(t, b.take("2001:db8:abcd:3::1", logger), "a third in the /48")

	// Local addresses are never counted, however many.
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "fd00::1", "100.64.0.1", "127.0.0.1"} {
		assert.True(t, b.take(ip, logger), ip)
	}

	assert.Equal(t, 2, strings.Count(logs.String(), networkCapLog), logs.String())
	assert.NotContains(t, logs.String(), runCapLog)
}

// At most reverseDNSRunMaxV4 IPv4 and reverseDNSRunMaxV6 IPv6 addresses are
// let through per run, the families apart; reset forgets what was spent.
func TestReverseDNSBudget_RunCapPerFamily(t *testing.T) {
	var logs bytes.Buffer
	logger := infoLogger(&logs)
	b := newReverseDNSBudget(reverseDNSPerNetwork, reverseDNSRunMaxV4, reverseDNSRunMaxV6)
	for i := range reverseDNSRunMaxV4 {
		require.True(t, b.take(fmt.Sprintf("203.%d.%d.1", i/256, i%256), logger), i)
	}
	assert.False(t, b.take("192.0.2.1", logger), "past the IPv4 cap")
	for i := range reverseDNSRunMaxV6 {
		require.True(t, b.take(fmt.Sprintf("2001:db8:%x::1", i), logger), "the IPv6 cap is its own: %d", i)
	}
	assert.False(t, b.take("2001:db9::1", logger), "past the IPv6 cap")
	assert.Equal(t, 2, strings.Count(logs.String(), runCapLog), "once per family: %s", logs.String())

	b.reset()
	assert.True(t, b.take("192.0.2.1", logger), "reset forgets what was spent")
}
