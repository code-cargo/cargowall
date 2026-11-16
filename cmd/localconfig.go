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

// loadConfigFile loads the local config file. A file that is there and
// doesn't load is a startup failure, whether --config named it or it sits
// at the default path: either way it is the configuration meant to apply,
// and running on without it would leave a caller waiting on a firewall that
// enforces something else. A file --config names must also be there. Only
// a default path with no file at it leaves the deny-all default in place,
// as it always has; that load error is returned as unloaded for the caller
// to report.
func loadConfigFile(cmd *StartCmd, configMgr *config.Manager) (unloaded, fatal error) {
	path := cmd.configFile()
	err := configMgr.LoadConfig(path)
	switch {
	case err == nil:
		return nil, nil
	case cmd.Config == "" && errors.Is(err, fs.ErrNotExist):
		return err, nil
	default:
		return nil, fmt.Errorf("config file %s did not load: %w", path, err)
	}
}

// loadLocalConfig loads CI mode's local configuration, read only when no
// CodeCargo policy loaded and the run isn't in policy lockdown: the
// environment's, or failing that the config file.
func loadLocalConfig(cmd *StartCmd, configMgr *config.Manager, logger *slog.Logger) error {
	err := configMgr.LoadFromEnv()
	if err == nil {
		return nil
	}
	logger.Debug("No environment config found, trying file", "error", err)
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
