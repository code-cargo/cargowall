//go:build linux

package cmd

import (
	"context"
	"log/slog"
	"fmt"
	"os"
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
	LoadPolicy func(ctx context.Context, cmd *StartCmd) (*cargowallv1pb.CargoWallPolicy, events.StateMachineClient, func(), error)
	InitLogger func(ctx context.Context, version string, debug bool) (*slog.Logger, func(context.Context) error, error)
}

type ExecuteFn func(cmd *StartCmd, hooks *StartHooks) error

type StartCmd struct {
	Execute ExecuteFn    `kong:"-"`
	Logger  *slog.Logger `kong:"-"`
	Version string       `kong:"-"` // Version passed from main
	Hooks   *StartHooks  `kong:"-"`

	// Configuration
	Config    string `help:"Path to configuration file" default:"/etc/cargowall/config.json" env:"CARGOWALL_CONFIG"`
	Interface string `help:"Network interface to attach to (auto-detect if empty)" env:"CARGOWALL_INTERFACE"`

	Token  string `help:"codecargo token" env:"CODECARGO_AUTH_TOKEN"`
	ApiUrl string `help:"CodeCargo API URL to fetch policy from" name:"api-url" env:"CARGOWALL_API_URL"`
	JobKey string `help:"GitHub Actions job key for job-level policy resolution" name:"job-key" env:"CARGOWALL_JOB_KEY"`

	// Runtime options
	DisableDNSTracking bool   `help:"Disable DNS tracking and hostname resolution" default:"false"`
	DNSUpstream        string `help:"Upstream DNS server to forward queries to" required:"" env:"CARGOWALL_DNS_UPSTREAM"`

	// GitHub Actions mode
	GithubAction bool `help:"Run in GitHub Actions mode" default:"false" env:"CARGOWALL_GITHUB_ACTION"`

	// Sudo lockdown (GitHub Actions security hardening)
	SudoLockdown      bool   `help:"Enable sudo lockdown to prevent firewall bypass" default:"false" env:"CARGOWALL_SUDO_LOCKDOWN"`
	SudoAllowCommands string `help:"Comma-separated list of command paths to allow via sudo when lockdown is enabled (e.g. /usr/bin/apt-get,/usr/bin/docker)" default:"" env:"CARGOWALL_SUDO_ALLOW_COMMANDS"`

	// Audit mode and logging
	AuditMode bool   `help:"Monitor and log connections without blocking (audit only)" default:"false" env:"CARGOWALL_AUDIT_MODE"`
	AuditLog  string `help:"Path to write JSON audit log for step correlation" env:"CARGOWALL_AUDIT_LOG"`

	// Pre-existing connection handling
	AllowExistingConnections bool `help:"Allow pre-existing TCP connections at startup (loads /proc/net/tcp{,6} IPs into allow maps)" default:"false" env:"CARGOWALL_ALLOW_EXISTING_CONNECTIONS"`
}

func (c *StartCmd) AfterApply() error {
	return nil
}

func (c *StartCmd) Run(globals *Globals) error {
	ctx := context.Background()

	// In GitHub Actions mode, use a simple logger with GH-compatible format
	if c.GithubAction {
		handler := NewGitHubActionsHandler(globals.Debug)
		logger := slog.New(handler)
		slog.SetDefault(logger)
		c.Logger = logger
		return c.Execute(c, c.Hooks)
	}

	// Initialize logger
	if c.Hooks != nil && c.Hooks.InitLogger != nil {
		// Use a timeout context only for initialization to prevent hanging
		initCtx, initCancel := context.WithTimeout(ctx, 5*time.Second)
		defer initCancel()

		logger, shutdown, err := c.Hooks.InitLogger(initCtx, c.Version, globals.Debug)
		if err != nil {
			slog.Warn("failed to initialize logger via hook", "error", err)
		} else {
			slog.SetDefault(logger)
			c.Logger = logger
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := shutdown(shutdownCtx); err != nil {
					slog.Warn("failed to shutdown logger", "error", err)
				}
			}()
		}
	} else {
		// Fall back to a simple JSON logger
		logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
		if globals.Debug {
			logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))
		}
		slog.SetDefault(logger)
		c.Logger = logger
	}

	return c.Execute(c, c.Hooks)
}

type CLI struct {
	Globals
	Start   StartCmd   `cmd:"" help:"Start the Cargowall eBPF firewall"`
	Summary SummaryCmd `cmd:"" help:"Generate audit summary correlating events with GitHub Actions steps"`
}
