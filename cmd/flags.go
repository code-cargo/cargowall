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
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kong"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	"github.com/code-cargo/cargowall/pkg/events"
)

type Globals struct {
	Version VersionFlag `name:"version" help:"Print version information and quit"`
	Debug   bool        `name:"debug" help:"Enable debug mode"`
}

type VersionFlag string

func (v VersionFlag) Decode(ctx *kong.DecodeContext) error { return nil }

func (v VersionFlag) IsBool() bool { return true }

func (v VersionFlag) BeforeApply(app *kong.Kong, vars kong.Vars) error {
	fmt.Println(vars["version"])
	app.Exit(0)
	return nil
}

type StartHooks struct {
	Ready      func() error
	LoadPolicy func(ctx context.Context, cmd *StartCmd) (*cargowallv1pb.CargoWallPolicy, events.StateMachineClient, func(), error)
	InitLogger func(ctx context.Context, version string, debug bool) (slog.Handler, func(context.Context) error, error)
}

type ExecuteFn func(cmd *StartCmd, hooks *StartHooks) error

type StartCmd struct {
	Execute        ExecuteFn                   `kong:"-"`
	Logger         *slog.Logger                `kong:"-"`
	LoggerShutdown func(context.Context) error `kong:"-"`
	Version        string                      `kong:"-"` // Version passed from main
	Hooks          *StartHooks                 `kong:"-"`

	// Configuration
	Config    string `help:"Path to configuration file" default:"/etc/cargowall/config.json" env:"CARGOWALL_CONFIG"`
	Interface string `help:"Network interface to attach to (auto-detect if empty)" env:"CARGOWALL_INTERFACE"`

	Token  string `help:"codecargo token" env:"CODECARGO_AUTH_TOKEN"`
	ApiUrl string `help:"CodeCargo API URL to fetch policy from" name:"api-url" env:"CARGOWALL_API_URL"`
	JobKey string `help:"CI job key for job-level policy resolution" name:"job-key" env:"CARGOWALL_JOB_KEY"`

	// Runtime options
	DisableDNSTracking bool   `help:"Disable DNS tracking and hostname resolution" default:"false"`
	DNSUpstream        string `help:"Upstream DNS server to forward queries to" required:"" env:"CARGOWALL_DNS_UPSTREAM"`

	// CI presets — bundles the orthogonal flags below with sensible defaults
	// for the named CI environment.
	GithubAction bool `help:"Run in GitHub Actions mode (preset: enables DNS redirect, Docker DNS interception, query filtering, cache pre-population, cloud metadata auto-allow, GitHub hosts auto-allow)" default:"false" env:"CARGOWALL_GITHUB_ACTION"`
	GitlabCI     bool `help:"Run in GitLab CI mode (preset: enables DNS redirect, Docker DNS interception, query filtering, cache pre-population, cloud metadata auto-allow, GitLab hosts auto-allow)" name:"gitlab-ci" default:"false" env:"CARGOWALL_GITLAB_CI"`

	// Orthogonal CI plumbing flags — usable on any CI system (or standalone).
	// Each is also implied by a CI preset above.
	DNSRedirectIptables    bool `help:"Install iptables OUTPUT NAT rules redirecting outbound DNS (UDP+TCP/53) to the local proxy at 127.0.0.1:53" default:"false" env:"CARGOWALL_DNS_REDIRECT_IPTABLES"`
	DockerDNSInterception  bool `help:"Listen on the Docker bridge IP for DNS, rewrite /etc/docker/daemon.json so containers use the proxy, and restart the Docker daemon" default:"false" env:"CARGOWALL_DOCKER_DNS_INTERCEPTION"`
	DNSQueryFiltering      bool `help:"Filter DNS queries against the firewall policy (blocks DNS tunneling)" default:"false" env:"CARGOWALL_DNS_QUERY_FILTERING"`
	PrepopulateDNSCache    bool `help:"Pre-populate the BPF allowlist from the systemd-resolved cache and existing TCP connections at startup" default:"false" env:"CARGOWALL_PREPOPULATE_DNS_CACHE"`
	AutoAllowCloudMetadata bool `help:"Auto-allow cloud metadata endpoints (Azure wireserver/IMDS or GCP metadata server, auto-detected via systemd-resolved upstreams)" default:"false" env:"CARGOWALL_AUTO_ALLOW_CLOUD_METADATA"`
	AutoAllowGitHubHosts   bool `help:"Auto-allow GitHub service hostnames (github.com, *.githubusercontent.com, etc.) and discover ACTIONS_* runtime URLs" default:"false" env:"CARGOWALL_AUTO_ALLOW_GITHUB_HOSTS"`
	AutoAllowGitlabHosts   bool `help:"Auto-allow GitLab service hostnames (gitlab.com, registry.gitlab.com, etc.) and discover CI_* runtime URLs" default:"false" env:"CARGOWALL_AUTO_ALLOW_GITLAB_HOSTS"`

	// Sudo lockdown (CI security hardening)
	SudoLockdown      bool   `help:"Enable sudo lockdown to prevent firewall bypass" default:"false" env:"CARGOWALL_SUDO_LOCKDOWN"`
	SudoAllowCommands string `help:"Comma-separated list of command paths to allow via sudo when lockdown is enabled (e.g. /usr/bin/apt-get,/usr/bin/docker)" default:"" env:"CARGOWALL_SUDO_ALLOW_COMMANDS"`

	// Audit mode and logging
	AuditMode bool   `help:"Monitor and log connections without blocking (audit only)" default:"false" env:"CARGOWALL_AUDIT_MODE"`
	AuditLog  string `help:"Path to write JSON audit log for step correlation" env:"CARGOWALL_AUDIT_LOG"`

	// Pre-existing connection handling
	AllowExistingConnections bool `help:"Allow pre-existing TCP connections at startup (loads /proc/net/tcp{,6} IPs into allow maps)" default:"false" env:"CARGOWALL_ALLOW_EXISTING_CONNECTIONS"`

	// Pidfile pairs with the `cargowall stop` subcommand. Backgrounding is
	// delegated to the shell (`cargowall start --pidfile X &`) — true Unix
	// daemonization isn't worth the Go runtime complexity for CI use.
	Pidfile string `help:"Write the cargowall process pid to this file (used with 'cargowall stop')" default:"" env:"CARGOWALL_PIDFILE"`
}

// CIMode is the active CI integration mode, derived from which preset flag
// was passed. Drives log labels and which auto-allow defaults are applied.
type CIMode string

const (
	CIModeNone         CIMode = ""
	CIModeGithubAction CIMode = "github_action"
	CIModeGitlabCI     CIMode = "gitlab_ci"
)

// CIMode returns the active CI integration mode for this start invocation.
// GitHub Actions takes precedence if both presets are set (shouldn't happen).
func (c *StartCmd) CIMode() CIMode {
	if c.GithubAction {
		return CIModeGithubAction
	}
	if c.GitlabCI {
		return CIModeGitlabCI
	}
	return CIModeNone
}

// AfterApply expands the active CI preset into the orthogonal flags it
// implies. `--github-action` and `--gitlab-ci` are conveniences that turn
// on the underlying plumbing flags so users don't have to enumerate each
// one. The presets are mutually exclusive — if both are set, CIMode()'s
// precedence rule (GitHub wins) is the single source of truth.
func (c *StartCmd) AfterApply() error {
	switch c.CIMode() {
	case CIModeGithubAction:
		c.applyCIPreset(CIModeGithubAction)
	case CIModeGitlabCI:
		c.applyCIPreset(CIModeGitlabCI)
	}
	return nil
}

// applyCIPreset turns on the plumbing flags shared by both CI presets, then
// sets the host auto-allow flag specific to the named CI.
func (c *StartCmd) applyCIPreset(mode CIMode) {
	c.DNSRedirectIptables = true
	c.DockerDNSInterception = true
	c.DNSQueryFiltering = true
	c.PrepopulateDNSCache = true
	c.AutoAllowCloudMetadata = true
	switch mode {
	case CIModeGithubAction:
		c.AutoAllowGitHubHosts = true
	case CIModeGitlabCI:
		c.AutoAllowGitlabHosts = true
	}
}

func defaultLogger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func (c *StartCmd) Run(globals *Globals) error {
	// GithubAction-only by design: the handler emits GitHub-specific
	// `::error::` / `::warning::` workflow commands. GitLab CI has no
	// equivalent log-formatting protocol, so --gitlab-ci falls through to
	// the default JSON logger.
	if c.GithubAction {
		c.Logger = slog.New(NewGitHubActionsHandler(globals.Debug))
	} else {
		c.Logger = defaultLogger(globals.Debug)
	}
	slog.SetDefault(c.Logger)

	defaultLog := c.Logger
	if c.Hooks != nil && c.Hooks.InitLogger != nil {
		// Use a timeout context only for initialization to prevent hanging
		initCtx, initCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer initCancel()

		handler, shutdown, err := c.Hooks.InitLogger(initCtx, c.Version, globals.Debug)
		if err != nil {
			slog.Warn("failed to initialize logger via hook", "error", err)
		} else if handler == nil {
			slog.Warn("InitLogger hook returned nil handler")
		} else {
			inner := &atomic.Pointer[slog.Handler]{}
			inner.Store(&handler)
			sh := &swappableHandler{inner: inner}
			c.Logger = slog.New(sh)
			slog.SetDefault(c.Logger)
			defaultHandler := defaultLog.Handler()
			c.LoggerShutdown = func(ctx context.Context) error {
				// Swap first so concurrent goroutines log safely
				// while the old handler is being shutdown.
				sh.inner.Store(&defaultHandler)
				if shutdown != nil {
					return shutdown(ctx)
				}
				return nil
			}
		}
	}

	return c.Execute(c, c.Hooks)
}

type CLI struct {
	Globals
	Start     StartCmd     `cmd:"" help:"Start the Cargowall eBPF firewall"`
	Summary   SummaryCmd   `cmd:"" help:"Generate audit summary correlating events with GitHub Actions steps"`
	WaitReady WaitReadyCmd `cmd:"" name:"wait-ready" help:"Block until the cargowall ready sentinel appears"`
	Stop      StopCmd      `cmd:"" help:"Send SIGTERM to a backgrounded cargowall process and wait for it to exit"`
}
