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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/code-cargo/cargowall/pkg/config"
)

// defaultConfigPath is the local config file read when --config names none.
// A var so tests can point it at a temporary path.
var defaultConfigPath = "/etc/cargowall/config.json"

// configFile is the local config file to read: the one --config (or
// CARGOWALL_CONFIG) names, or the default.
func (c *StartCmd) configFile() string {
	if c.Config != "" {
		return c.Config
	}
	return defaultConfigPath
}

// explicitConfigFile names the file --config or CARGOWALL_CONFIG names, and
// which, for a message: a CARGOWALL_CONFIG set in a runner's environment is
// easy to miss, as kong reads it in the flag's place.
func (c *StartCmd) explicitConfigFile() string {
	if c.Config != "" && os.Getenv("CARGOWALL_CONFIG") == c.Config {
		return c.Config + " (from CARGOWALL_CONFIG)"
	}
	return c.Config
}

// refusedConfig names a local configuration that didn't load, a file's or
// the environment's, in the failure sentinel's refused= line, after the
// --config flag, as a refused posture is named after its flag.
const refusedConfig = "config"

// loadConfigFile loads the local config file. A file that is there and
// doesn't load is a startup failure, whether --config named it or it sits
// at the default path: either way it is the configuration meant to apply,
// and running on without it would leave a caller waiting on a firewall that
// enforces something else. A file --config names must also be there. The
// failure is a refusal (refusedConfig, exitRefused), as a fail-closed
// posture's loss is: cargowall could run, just not with the configuration
// meant to apply, so a launcher must fail the job rather than run it with
// no firewall, as it may for a runner that can't run cargowall at all.
// Only a default path with no file at it leaves the deny-all default in
// place, as it always has; that load error is returned as unloaded for the
// caller to report.
func loadConfigFile(cmd *StartCmd, configMgr *config.Manager) (unloaded, fatal error) {
	path := cmd.configFile()
	err := configMgr.LoadConfig(path)
	switch {
	case err == nil:
		return nil, nil
	case cmd.Config == "" && errors.Is(err, fs.ErrNotExist):
		return err, nil
	default:
		cmd.refusedPosture = refusedConfig
		return nil, fmt.Errorf("config file %s did not load: %w", path, err)
	}
}

// loadLocalConfig loads CI mode's local configuration, read only when no
// CodeCargo policy loaded and the run isn't in policy lockdown: the
// environment's when any of its variables is set, the config file only
// when none is. The two never combine. An environment configuration that
// doesn't load is refused as a file that doesn't load is, rather than
// leaving the file to apply in its place; and one beside a file --config
// names is refused, since either could be the one meant to apply. A file
// at the default path, which the environment's leaves unread, is warned of.
func loadLocalConfig(cmd *StartCmd, configMgr *config.Manager, logger *slog.Logger) error {
	err := configMgr.LoadFromEnv()
	switch {
	case errors.Is(err, config.ErrNoEnvConfig):
	case cmd.Config != "":
		cmd.refusedPosture = refusedConfig
		return fmt.Errorf("the config file %s and the environment configuration (%s) are both set; set one",
			cmd.explicitConfigFile(), strings.Join(config.SetEnvConfigVars(), ", "))
	case err != nil:
		cmd.refusedPosture = refusedConfig
		return fmt.Errorf("environment configuration did not load: %w", err)
	default:
		if _, err := os.Stat(defaultConfigPath); err == nil {
			logger.Warn("Ignoring the config file at the default path: the environment configuration applies",
				"path", defaultConfigPath, "variables", config.SetEnvConfigVars())
		}
		return nil
	}
	logger.Debug("No environment config found, trying file")
	unloaded, fatal := loadConfigFile(cmd, configMgr)
	if fatal != nil {
		return fatal
	}
	if unloaded != nil {
		logger.Warn("No config loaded — defaulting to deny-all. Infrastructure hosts will be auto-allowed.",
			"error", unloaded, "path", cmd.configFile())
	}
	return nil
}

// loadPlainConfig loads the configuration outside CI mode and without a
// policy hook: the config file alone.
func loadPlainConfig(cmd *StartCmd, configMgr *config.Manager, logger *slog.Logger) error {
	unloaded, fatal := loadConfigFile(cmd, configMgr)
	if unloaded != nil {
		logger.Error("Failed to load config", "error", unloaded, "path", cmd.configFile())
	}
	return fatal
}
