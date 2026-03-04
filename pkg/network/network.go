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
