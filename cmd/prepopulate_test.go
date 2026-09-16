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
	"log/slog"
	"testing"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/dns"
)

// Pre-population must not turn a synthetic name into an L7 identity: the
// mapping is recorded for attribution, the evidence that would let
// RegisterL7Identity scope the address is not. A real rule name gets both.
func TestRecordSystemCacheAnswer_WithholdsEvidenceForLocalAliases(t *testing.T) {
	cfg := config.NewConfigManager()
	srv := dns.NewServer(cfg, nil, "192.0.2.53:53", "127.0.0.1:0", slog.Default())

	recordSystemCacheAnswer(cfg, srv, "_gateway", []string{"192.168.127.1"})
	if got := cfg.LookupHostnameByIP("192.168.127.1"); got != "_gateway" {
		t.Errorf("attribution: LookupHostnameByIP = %q, want _gateway", got)
	}
	if cfg.NameResolvedToIP("_gateway", "192.168.127.1") {
		t.Error("_gateway must not mint forward-resolution evidence")
	}

	recordSystemCacheAnswer(cfg, srv, "registry.example", []string{"192.0.2.10"})
	if got := cfg.LookupHostnameByIP("192.0.2.10"); got != "registry.example" {
		t.Errorf("attribution: LookupHostnameByIP = %q, want registry.example", got)
	}
	if !cfg.NameResolvedToIP("registry.example", "192.0.2.10") {
		t.Error("a wire name must mint forward-resolution evidence")
	}
}
