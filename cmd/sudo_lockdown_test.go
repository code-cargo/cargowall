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
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/lockdown"
)

// stubLockdown makes enableSudoLockdown's lockdown return err, and records
// whether it ran.
func stubLockdown(t *testing.T, err error) *bool {
	t.Helper()
	ran := false
	old := enableLockdown
	enableLockdown = func(*lockdown.SudoLockdownConfig, *slog.Logger) error {
		ran = true
		return err
	}
	t.Cleanup(func() { enableLockdown = old })
	return &ran
}

// A lockdown that does not come up has rolled itself back, so the job would
// run with the runner's sudo unchanged. Under an enforcing policy that fails
// startup and names the posture for the sentinel and the exit status; under
// an auditing policy it warns and the summary lists it; in policy lockdown
// it is an error that fails nothing, as for every other layer.
func TestEnableSudoLockdown_LossByPolicyMode(t *testing.T) {
	const reason = "sudo lockdown does not hold: sudo ran /usr/bin/id as root for a job step"
	for _, tc := range []struct {
		name                     string
		enforcing, policyLockout bool
		wantErr                  string
		wantLevel                string
	}{
		{
			name: "enforcing", enforcing: true,
			wantErr:   "--sudo-lockdown=true requested but could not be applied: " + reason,
			wantLevel: "level=ERROR",
		},
		{name: "auditing", wantLevel: "level=WARN"},
		{name: "policy lockdown", enforcing: true, policyLockout: true, wantLevel: "level=ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redirectStateFiles(t)
			ran := stubLockdown(t, errors.New(reason+"\nsudo output: root"))
			var buf bytes.Buffer
			cmd := &StartCmd{SudoLockdown: true, policyLockdown: tc.policyLockout}
			p := newPostures(cmd, "6.6.141", tc.enforcing, slog.New(slog.NewTextHandler(&buf, nil)))

			err := enableSudoLockdown(sudoLockdownConfig(cmd, p.logger), p, p.logger)
			require.True(t, *ran)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				assert.Equal(t, postureSudoLockdown, cmd.refusedPosture,
					"the failure sentinel and exit status name the refused posture")
			} else {
				require.NoError(t, err)
				assert.Empty(t, cmd.refusedPosture)
			}
			assert.Contains(t, buf.String(), tc.wantLevel)
			assert.Contains(t, buf.String(), `msg="--sudo-lockdown=true requested but could not be applied`,
				"the ledger owns the log line")

			want := []postureLine{{
				Posture: postureSudoLockdown, Requested: sudoLockdownOn, Applied: sudoLockdownOff,
				Reason: reason,
			}}
			assert.Equal(t, want, p.lines(), "the reason is the error's first line")
			p.write()
			assert.Equal(t, want, readPostures(), "the summary reads back what start wrote")
		})
	}
}

// A lockdown that comes up, warnings and all, loses nothing: the record
// shows it applied, and the summary has no row for it.
func TestEnableSudoLockdown_AppliedLosesNothing(t *testing.T) {
	stubLockdown(t, nil)
	var buf bytes.Buffer
	cmd := &StartCmd{SudoLockdown: true}
	p := newPostures(cmd, "6.6.141", true, slog.New(slog.NewTextHandler(&buf, nil)))

	require.NoError(t, enableSudoLockdown(sudoLockdownConfig(cmd, p.logger), p, p.logger))
	assert.Empty(t, cmd.refusedPosture)
	assert.Equal(t, []postureLine{{Posture: postureSudoLockdown, Requested: sudoLockdownOn, Applied: sudoLockdownOn}}, p.lines())
	var out bytes.Buffer
	renderPostures(&out, p.lines())
	assert.Empty(t, out.String())
}

// Without a request the ledger tracks no lockdown, so nothing can lose it.
func TestPostures_SudoLockdownNotRequested(t *testing.T) {
	cmd := &StartCmd{}
	p := newPostures(cmd, "6.6.141", true, slog.New(slog.DiscardHandler))
	assert.Nil(t, p.find(postureSudoLockdown))
	require.NoError(t, p.lose(postureSudoLockdown, "never asked for"))
	assert.Empty(t, cmd.refusedPosture)
}

// The policy's settings replace the flags', both ways, and only a policy
// that carries them does: the ledger registers whatever is on cmd once they
// are applied.
func TestPolicySudoLockdown_OverridesFlags(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flag      bool
		flagCmds  string
		policy    *config.SudoLockdownSettings
		wantOn    bool
		wantCmds  string
		wantTrack bool
	}{
		{name: "no policy settings keep the flag", flag: true, flagCmds: "/usr/bin/id", wantOn: true, wantCmds: "/usr/bin/id", wantTrack: true},
		{name: "no policy settings keep no request", wantOn: false},
		{
			name: "policy enables it", policy: &config.SudoLockdownSettings{Enabled: true, AllowCommands: []string{"/usr/bin/apt-get", "/usr/bin/id"}},
			wantOn: true, wantCmds: "/usr/bin/apt-get,/usr/bin/id", wantTrack: true,
		},
		{
			name: "policy disables a flagged one", flag: true, flagCmds: "/usr/bin/id",
			policy: &config.SudoLockdownSettings{Enabled: false}, wantOn: false, wantCmds: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &StartCmd{SudoLockdown: tc.flag, SudoAllowCommands: tc.flagCmds}
			policySudoLockdown(cmd, tc.policy)
			assert.Equal(t, tc.wantOn, cmd.SudoLockdown)
			assert.Equal(t, tc.wantCmds, cmd.SudoAllowCommands)
			p := newPostures(cmd, "6.6.141", true, slog.New(slog.DiscardHandler))
			assert.Equal(t, tc.wantTrack, p.find(postureSudoLockdown) != nil)
		})
	}
}

// A lost lockdown reaches the summary's table as its flag spells it.
func TestRenderPostures_SudoLockdown(t *testing.T) {
	var buf bytes.Buffer
	renderPostures(&buf, []postureLine{{
		Posture: postureSudoLockdown, Requested: sudoLockdownOn, Applied: sudoLockdownOff,
		Reason: "sudo lockdown incomplete, /etc/sudoers could not be amended",
	}})
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "### Postures not applied\n"), out)
	assert.Contains(t, out, "| `sudo-lockdown` | true | **false** | sudo lockdown incomplete, /etc/sudoers could not be amended |")
}
