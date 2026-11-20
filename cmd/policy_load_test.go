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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/events"
)

// A default-deny policy whose rules say nothing about DNS.
func noDNSPolicy() *cargowallv1pb.CargoWallPolicy {
	return &cargowallv1pb.CargoWallPolicy{
		Mode:          datapb.CargoWallMode_CARGO_WALL_MODE_ENFORCE,
		DefaultAction: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY,
		Rules: []*cargowallv1pb.CargoWallPolicy_Rule{
			{Type: datapb.CargoWallRuleType_CARGO_WALL_RULE_TYPE_HOSTNAME, Value: "github.com", Action: datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW},
		},
	}
}

func requireDNSAllowed(t *testing.T, cm *config.Manager, ips ...string) {
	t.Helper()
	for _, ip := range ips {
		assert.Equal(t, config.AutoAddedTypeDNS, cm.GetAutoAllowedType(ip, 53, config.ProtocolUDP, ""),
			"%s:53/udp must be allowed", ip)
	}
}

// The policy hook's policy carries only its own rules, so the DNS upstream
// must be allowed after it loads, as after every other source, or the proxy's
// forwarded queries meet the default deny at TC.
func TestLoadStartupPolicy_HookAllowsDNSUpstream(t *testing.T) {
	cleaned := false
	hooks := &StartHooks{
		LoadPolicy: func(context.Context, *StartCmd) (*cargowallv1pb.CargoWallPolicy, events.StateMachineClient, func(), error) {
			return noDNSPolicy(), nil, func() { cleaned = true }, nil
		},
	}
	cmd := &StartCmd{DNSUpstream: "10.0.0.2:53"}
	require.Equal(t, CIModeNone, cmd.CIMode())
	cm := config.NewConfigManager()

	loaded, client, cleanup, err := loadStartupPolicy(context.Background(), cmd, hooks, cm, nil, "172.17.0.1", quietLogger())
	require.NoError(t, err)

	assert.False(t, loaded, "a hook policy is not the CodeCargo API's")
	assert.Nil(t, client)
	require.NotNil(t, cleanup)
	cleanup()
	assert.True(t, cleaned, "the hook's cleanup is handed back to the caller")
	assert.Equal(t, config.ActionDeny, cm.GetDefaultAction())
	assert.True(t, cm.MatchHostnameRule("github.com").AllowRule != "", "the policy's own rules load")
	requireDNSAllowed(t, cm, "127.0.0.1", "10.0.0.2", "172.17.0.1")
}

// A failing hook still hands back its cleanup, and the error names the hook.
func TestLoadStartupPolicy_HookErrorKeepsCleanup(t *testing.T) {
	boom := errors.New("boom")
	hooks := &StartHooks{
		LoadPolicy: func(context.Context, *StartCmd) (*cargowallv1pb.CargoWallPolicy, events.StateMachineClient, func(), error) {
			return nil, nil, func() {}, boom
		},
	}
	_, _, cleanup, err := loadStartupPolicy(context.Background(), &StartCmd{DNSUpstream: "10.0.0.2:53"}, hooks,
		config.NewConfigManager(), nil, "", quietLogger())
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "via hook")
	assert.NotNil(t, cleanup)
}

// Outside CI mode and without a hook, the config file is the source, and it
// gets the same DNS allows.
func TestLoadStartupPolicy_FileAllowsDNSUpstream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
		"defaultAction": "deny",
		"rules": [{"type": "hostname", "value": "github.com", "action": "allow"}]
	}`), 0o600))
	cmd := &StartCmd{Config: path, DNSUpstream: "10.0.0.2:53"}
	require.Equal(t, CIModeNone, cmd.CIMode())
	cm := config.NewConfigManager()

	_, _, _, err := loadStartupPolicy(context.Background(), cmd, nil, cm, nil, "", quietLogger())
	require.NoError(t, err)
	assert.True(t, cm.MatchHostnameRule("github.com").AllowRule != "")
	requireDNSAllowed(t, cm, "127.0.0.1", "10.0.0.2")
}
