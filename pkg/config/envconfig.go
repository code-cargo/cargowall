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

package config

import (
	"errors"
	"os"
	"strings"
)

// envConfigVars are the variables LoadFromEnv reads. Any one of them set
// makes the environment the local configuration.
var envConfigVars = []string{
	"CARGOWALL_DEFAULT_ACTION",
	"CARGOWALL_ALLOWED_HOSTS",
	"CARGOWALL_ALLOWED_CIDRS",
	"CARGOWALL_BLOCKED_HOSTS",
	"CARGOWALL_BLOCKED_CIDRS",
	"CARGOWALL_SEARCH_DOMAINS",
}

// ErrNoEnvConfig is LoadFromEnv's error when none of its variables is set,
// the one error that leaves a caller free to read a config file instead.
// Any other means the environment configuration is there and didn't load.
var ErrNoEnvConfig = errors.New("no environment configuration found")

// SetEnvConfigVars returns the names of the variables LoadFromEnv reads
// that are set, in the order it reads them. A value of only whitespace
// sets nothing: a variable left blank shouldn't make the environment the
// local configuration, leaving a config file unread.
func SetEnvConfigVars() []string {
	var set []string
	for _, name := range envConfigVars {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			set = append(set, name)
		}
	}
	return set
}

// BlankEnvConfigVars returns the names of the variables LoadFromEnv reads
// that are set to only whitespace, which SetEnvConfigVars leaves out.
func BlankEnvConfigVars() []string {
	var blank []string
	for _, name := range envConfigVars {
		if v := os.Getenv(name); v != "" && strings.TrimSpace(v) == "" {
			blank = append(blank, name)
		}
	}
	return blank
}
