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
