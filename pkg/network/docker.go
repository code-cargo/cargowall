//go:build linux

package network

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	dockerDaemonConfigPath   = "/etc/docker/daemon.json"
	dockerDaemonConfigBackup = "/etc/docker/daemon.json.cargowall.bak"
)

// GetDockerBridgeIP returns the IP address of the docker0 bridge interface.
// This is typically 172.17.0.1 and is used as the gateway for Docker containers.
func GetDockerBridgeIP() (string, error) {
	iface, err := net.InterfaceByName("docker0")
	if err != nil {
		return "", fmt.Errorf("docker0 interface not found: %w", err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get docker0 addresses: %w", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no IPv4 address found on docker0")
}

// ConfigureDockerDNS configures Docker to use the specified DNS server.
// This modifies /etc/docker/daemon.json. A full Docker restart via
// RestartDockerDaemon is required for the changes to take effect.
func ConfigureDockerDNS(dnsIP string, logger *slog.Logger) error {
	logger.Info("Configuring Docker DNS", "dns", dnsIP)

	// Read existing config if it exists
	var existingConfig map[string]interface{}
	if data, err := os.ReadFile(dockerDaemonConfigPath); err == nil {
		if err := json.Unmarshal(data, &existingConfig); err != nil {
			logger.Warn("Failed to parse existing daemon.json, will overwrite", "error", err)
			existingConfig = make(map[string]interface{})
		}

		// Backup existing config
		if err := os.WriteFile(dockerDaemonConfigBackup, data, 0o644); err != nil {
			logger.Warn("Failed to backup daemon.json", "error", err)
		} else {
			logger.Debug("Backed up existing daemon.json", "path", dockerDaemonConfigBackup)
		}
	} else {
		existingConfig = make(map[string]interface{})
	}

	// Set DNS to point to cargowall
	existingConfig["dns"] = []string{dnsIP}

	// Write updated config
	data, err := json.MarshalIndent(existingConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal daemon.json: %w", err)
	}

	if err := os.WriteFile(dockerDaemonConfigPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write daemon.json: %w", err)
	}

	logger.Debug("Wrote Docker daemon config", "path", dockerDaemonConfigPath)

	// NOTE: Docker's SIGHUP handler does NOT reload DNS settings.
	// A full Docker restart is required for DNS changes to take effect.
	// The caller (start.go) handles this via RestartDockerDaemon after
	// all services are ready.

	logger.Info("Docker DNS configured (restart required to take effect)", "dns", dnsIP)
	return nil
}

// RestoreDockerDNS restores the original Docker daemon configuration.
func RestoreDockerDNS(logger *slog.Logger) error {
	logger.Info("Restoring Docker DNS configuration")

	// Check if backup exists
	if _, err := os.Stat(dockerDaemonConfigBackup); os.IsNotExist(err) {
		// No backup - remove our config
		if err := os.Remove(dockerDaemonConfigPath); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove daemon.json", "error", err)
		}
	} else {
		// Restore from backup
		data, err := os.ReadFile(dockerDaemonConfigBackup)
		if err != nil {
			return fmt.Errorf("failed to read backup: %w", err)
		}

		if err := os.WriteFile(dockerDaemonConfigPath, data, 0o644); err != nil {
			return fmt.Errorf("failed to restore daemon.json: %w", err)
		}

		// Remove backup
		os.Remove(dockerDaemonConfigBackup)
	}

	// Reload Docker daemon
	if err := reloadDockerDaemon(logger); err != nil {
		logger.Warn("Failed to reload Docker daemon during restore", "error", err)
	}

	logger.Info("Docker DNS configuration restored")
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
