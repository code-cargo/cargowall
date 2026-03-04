//go:build linux

package main

import (
	"github.com/alecthomas/kong"

	"github.com/code-cargo/cargowall/cmd"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -go-package bpf -cc clang -output-dir bpf TcBpf bpf/tcbpf.c

var version = "dev"

func main() {
	cli := cmd.CLI{}
	ctx := kong.Parse(&cli,
		kong.Name("cargowall"),
		kong.Description("Cargowall eBPF-based L4 firewall with DNS awareness"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{
			"version": version,
		})

	// Set up the execute function — standalone mode passes nil hooks
	cli.Start.Execute = func(c *cmd.StartCmd, hooks *cmd.StartHooks) error {
		return cmd.StartCargoWall(c, hooks)
	}
	cli.Start.Version = version

	err := ctx.Run(&cli.Globals)
	ctx.FatalIfErrorf(err)
}
