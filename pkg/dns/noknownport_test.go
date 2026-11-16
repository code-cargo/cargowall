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
	"bytes"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// An answer whose rule the firewall refuses for naming no known port opens
// nothing, and isn't logged again for each answer: the firewall logs it once.
func TestApplyVerdictSide_NoKnownPortIsQuietAndNotOpened(t *testing.T) {
	cfg := config.NewConfigManager()
	require.NoError(t, cfg.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "web.example", Action: config.ActionAllow},
	}, config.ActionDeny))
	mockFw := firewall.NewMockFirewall(t)
	mockFw.On("AddIP", mock.Anything, config.ActionAllow, mock.Anything).Return(false, config.ErrNoKnownPort).Times(2)
	server := newTestServer(t, cfg, mockFw)
	var logs bytes.Buffer
	server.logger = slog.New(slog.NewTextHandler(&logs, nil))

	for range 2 {
		opened := server.applyVerdictSide(net.ParseIP("104.16.1.1"), "web.example", config.ActionAllow, nil, false)
		assert.False(t, opened, "refused, so not opened and nothing re-reported")
	}
	assert.NotContains(t, logs.String(), "Failed to add IP to BPF maps")
}

// A step install the firewall refuses for naming no known port records
// nothing and isn't warned about per answer.
func TestStepInstall_NoKnownPortIsQuietAndRecordsNothing(t *testing.T) {
	cfg := config.NewConfigManager()
	fw := newRecordingFirewall()
	fw.stepErr = config.ErrNoKnownPort
	var logs bytes.Buffer
	s := newStepTestServer(t, cfg, fw)
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	rec := &recordingRegistrar{}
	s.SetL7Registrar(rec)
	loadStepPolicy(t, cfg, stepWritersPolicy)
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.69"))
	answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.69"))
	assert.Empty(t, fw.stepIPs(policyFetch))
	assert.Empty(t, rec.scopes)
	assert.Empty(t, s.steps.l7.scoped)
	assert.NotContains(t, logs.String(), "Step rule install failed")
}
