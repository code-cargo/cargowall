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

package network

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// FindPodInterface finds the pod's primary network interface
func FindPodInterface() (string, error) {
	// In Kubernetes pods, eth0 is typically the primary interface
	// We could also look for interfaces with default routes
	interfaces := []string{"eth0", "ens3", "ens4", "enp0s3", "enp0s4"}

	for _, ifname := range interfaces {
		if _, err := net.InterfaceByName(ifname); err == nil {
			return ifname, nil
		}
	}

	// If none of the common names work, get the first non-loopback interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

// AttachTC attaches the TC BPF program to the network interface
func AttachTC(ifname string, prog *ebpf.Program, attachType ebpf.AttachType, logger *slog.Logger) (link.Link, error) {
	// Get the network interface index
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", ifname, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    attachType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach TC %s: %w", attachType, err)
	}

	logger.Info("Attached TC program", "direction", attachType, "interface", ifname)
	return l, nil
}
