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
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// bindErrs stands in for the proxy's account of the optional listeners it
// did not bind, keyed by address.
type bindErrs map[string]error

func (b bindErrs) BindError(addr string) error { return b[addr] }

// The daemon is restarted onto the bridge listener only once the proxy holds
// it: otherwise the restart would point its containers at whatever holds the
// address, or at nothing. The rewrite is undone instead, and the daemon is
// left running as it was.
func TestDockerDNS_RestartsOntoABoundListenerOnly(t *testing.T) {
	for _, c := range []struct {
		name              string
		errs              bindErrs
		restarted, undone bool
	}{
		{"bound", bindErrs{}, true, false},
		{"held", bindErrs{"172.17.0.1:53": fmt.Errorf("tcp4: %w", unix.EADDRINUSE)}, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var restarted, undone bool
			d := &dockerDNS{
				bridgeIP: "172.17.0.1",
				proxy:    c.errs,
				restart:  func(*slog.Logger) error { restarted = true; return nil },
				undo:     func() { undone = true },
				logger:   slog.New(slog.DiscardHandler),
			}
			d.restartDaemon()
			assert.Equal(t, c.restarted, restarted, "restarted")
			assert.Equal(t, c.undone, undone, "daemon.json restored")
		})
	}
	assert.NotPanics(t, func() {
		(*dockerDNS)(nil).restartDaemon()
		(&dockerDNS{bridgeIP: "172.17.0.1", proxy: bindErrs{}}).restartDaemon() // not ours: nothing to restart
	})
}
