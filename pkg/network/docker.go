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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// daemonConfig is the daemon.json rewrite and its undo. The paths and the
// reload are fields so the crash and failure paths can be driven against a
// temp dir.
type daemonConfig struct {
	path   string // daemon.json
	backup string // the original, when there was one
	absent string // marker recording that there was no original
	reload func(*slog.Logger) error
}

var dockerDaemonConfig = daemonConfig{
	path:   "/etc/docker/daemon.json",
	backup: "/etc/docker/daemon.json.cargowall.bak",
	absent: "/etc/docker/daemon.json.cargowall.absent",
	reload: reloadDockerDaemon,
}

// GetDockerBridgeIP returns the IP address of the docker0 bridge interface.
// This is typically 172.17.0.1 and is used as the gateway for Docker containers.
func GetDockerBridgeIP() (string, error) {
	ipnet, err := dockerBridgeIPNet()
	if err != nil {
		return "", err
	}
	return ipnet.IP.String(), nil
}

// GetDockerBridgeSubnet returns the default bridge's IPv4 network in CIDR
// form (e.g. "172.17.0.0/16"). The cgroup egress hook adjudicates bridge
// traffic TC never saw — host→published-port via docker-proxy, container→
// container — and under shadow/enforce that local-only class is carved out
// by subnet (pkg/origin's local-nets map), not discovered one denial at a
// time.
func GetDockerBridgeSubnet() (string, error) {
	ipnet, err := dockerBridgeIPNet()
	if err != nil {
		return "", err
	}
	network := &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}
	return network.String(), nil
}

// dockerBridgeIPNet is the one walk of docker0's addresses — the bridge IP
// (DNS listener) and the bridge subnet (local-net carve-out) must always
// come from the same interface and address, or the two halves of docker
// integration could disagree about which bridge they serve.
func dockerBridgeIPNet() (*net.IPNet, error) {
	iface, err := net.InterfaceByName("docker0")
	if err != nil {
		return nil, fmt.Errorf("docker0 interface not found: %w", err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker0 addresses: %w", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return &net.IPNet{IP: ip4, Mask: ipnet.Mask}, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 address found on docker0")
}

// ConfigureDockerDNS configures Docker to use the specified DNS server.
// This modifies /etc/docker/daemon.json. A full Docker restart via
// RestartDockerDaemon is required for the changes to take effect.
func ConfigureDockerDNS(dnsIP string, logger *slog.Logger) error {
	return dockerDaemonConfig.configure(dnsIP, logger)
}

// RestoreDockerDNS restores the original Docker daemon configuration. It is
// safe whether or not ConfigureDockerDNS ran or got as far as the rewrite:
// with nothing recorded, daemon.json is left alone.
func RestoreDockerDNS(logger *slog.Logger) error {
	return dockerDaemonConfig.restore(logger)
}

// configure records the original before touching it — the backup, or the
// absent marker when there was no daemon.json — and refuses to rewrite
// without that record, since restore can put back only what was recorded.
// A record left by a run that never restored is undone first: it holds the
// real original, and recording over it would save that run's rewrite as
// the original instead.
func (c daemonConfig) configure(dnsIP string, logger *slog.Logger) error {
	logger.Info("Configuring Docker DNS", "dns", dnsIP)

	recovered, err := c.restoreFiles()
	if err != nil {
		return fmt.Errorf("undo the daemon.json rewrite a previous run left: %w", err)
	}
	if recovered {
		logger.Warn("Restored daemon.json left rewritten by a previous run that did not shut down cleanly")
	}

	existingConfig := make(map[string]any)
	data, err := os.ReadFile(c.path)
	switch {
	case err == nil:
		if err := writeFileReplace(c.backup, data); err != nil {
			return fmt.Errorf("failed to back up daemon.json: %w", err)
		}
		logger.Debug("Backed up existing daemon.json", "path", c.backup)
		// A body that parses to JSON null leaves the map nil.
		if err := json.Unmarshal(data, &existingConfig); err != nil || existingConfig == nil {
			logger.Warn("Failed to parse existing daemon.json, will overwrite", "error", err)
			existingConfig = make(map[string]any)
		}
	case errors.Is(err, os.ErrNotExist):
		if err := writeFileReplace(c.absent, nil); err != nil {
			return fmt.Errorf("failed to record that daemon.json did not exist: %w", err)
		}
	default:
		return fmt.Errorf("failed to read daemon.json: %w", err)
	}

	// Set DNS to point to cargowall
	existingConfig["dns"] = []string{dnsIP}

	data, err = json.MarshalIndent(existingConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal daemon.json: %w", err)
	}
	if err := writeFileReplace(c.path, data); err != nil {
		return fmt.Errorf("failed to write daemon.json: %w", err)
	}
	logger.Debug("Wrote Docker daemon config", "path", c.path)

	// NOTE: Docker's SIGHUP handler does NOT reload DNS settings.
	// A full Docker restart is required for DNS changes to take effect.
	// The caller (start.go) handles this via RestartDockerDaemon after
	// all services are ready.

	logger.Info("Docker DNS configured (restart required to take effect)", "dns", dnsIP)
	return nil
}

func (c daemonConfig) restore(logger *slog.Logger) error {
	logger.Info("Restoring Docker DNS configuration")
	restored, err := c.restoreFiles()
	if err != nil {
		return err
	}
	if !restored {
		logger.Debug("daemon.json was never rewritten; nothing to restore")
		return nil
	}
	if err := c.reload(logger); err != nil {
		logger.Warn("Failed to reload Docker daemon during restore", "error", err)
	}
	logger.Info("Docker DNS configuration restored")
	return nil
}

// restoreFiles puts back what configure recorded — the backup over
// daemon.json, or, when there was no original, removes the rewrite — and
// reports whether there was a record to act on. Each record is removed only
// after the restore it drives, so a crash partway leaves it for the next
// run to finish.
func (c daemonConfig) restoreFiles() (bool, error) {
	data, err := os.ReadFile(c.backup)
	if err == nil {
		if err := writeFileReplace(c.path, data); err != nil {
			return true, fmt.Errorf("failed to restore daemon.json: %w", err)
		}
		if err := os.Remove(c.backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, fmt.Errorf("failed to remove daemon.json backup: %w", err)
		}
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("failed to read daemon.json backup: %w", err)
	}

	if _, err := os.Stat(c.absent); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check daemon.json absent marker: %w", err)
	}
	if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return true, fmt.Errorf("failed to remove daemon.json: %w", err)
	}
	if err := os.Remove(c.absent); err != nil && !errors.Is(err, os.ErrNotExist) {
		return true, fmt.Errorf("failed to remove daemon.json absent marker: %w", err)
	}
	return true, nil
}

// writeFileReplace writes data to path through a rename, so a crash leaves
// the old file or the new one, never a torn daemon.json.
func writeFileReplace(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// RestartDockerDaemon performs a full Docker daemon restart and waits for it
// to become ready. This is required for DNS configuration changes — Docker's
// SIGHUP handler only reloads a subset of settings (debug, labels, registries,
// etc.) and does NOT reload DNS settings from daemon.json.
func RestartDockerDaemon(logger *slog.Logger) error {
	logger.Info("Restarting Docker daemon to apply DNS configuration")

	cmd := exec.Command("systemctl", "restart", "docker")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl restart docker failed: %w", err)
	}

	// Wait for Docker to be ready (up to 30 seconds)
	for i := range 30 {
		cmd := exec.Command("docker", "info")
		if err := cmd.Run(); err == nil {
			logger.Info("Docker daemon ready after restart", "seconds", i+1)
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for Docker daemon to be ready after restart")
}

// reloadDockerDaemon sends SIGHUP to the Docker daemon to reload configuration.
func reloadDockerDaemon(logger *slog.Logger) error {
	// Try to find dockerd PID
	pidBytes, err := os.ReadFile("/var/run/docker.pid")
	if err != nil {
		// Try using systemctl if available
		logger.Debug("Could not read docker.pid, trying systemctl")
		cmd := exec.Command("systemctl", "reload", "docker")
		if err := cmd.Run(); err != nil {
			// Last resort: try pkill
			logger.Debug("systemctl reload failed, trying SIGHUP via pkill")
			cmd = exec.Command("pkill", "-HUP", "dockerd")
			return cmd.Run()
		}
		return nil
	}

	var pid int
	if _, err := fmt.Sscanf(string(pidBytes), "%d", &pid); err != nil {
		return fmt.Errorf("failed to parse docker PID: %w", err)
	}

	// Send SIGHUP to reload config
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find docker process: %w", err)
	}

	if err := process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("failed to send SIGHUP to docker: %w", err)
	}

	logger.Debug("Sent SIGHUP to Docker daemon", "pid", pid)
	return nil
}
