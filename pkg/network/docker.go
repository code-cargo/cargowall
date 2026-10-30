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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// daemonConfig is the daemon.json rewrite and its undo. The paths and the
// reload are fields so the crash and failure paths can be driven against a
// temp dir.
//
// Three records sit beside daemon.json while it is rewritten: the original
// (backup) or the fact there was none (absent), and the exact bytes the
// rewrite wrote (rewrite). A record is acted on only while daemon.json still
// holds those bytes: anything else is the original (a crash before the
// rewrite landed) or a file someone has changed since, and is not ours to
// replace or delete.
type daemonConfig struct {
	path    string // daemon.json
	backup  string // the original, when there was one
	absent  string // marker recording that there was no original
	rewrite string // the bytes the rewrite wrote
	reload  func(*slog.Logger) error

	// mu serializes configure and restore: the undo is registered before
	// configure, and a second signal runs it on another goroutine.
	mu sync.Mutex
	// restored is set by the first restore, so a configure the undo has
	// already overtaken does not rewrite what nothing will then undo.
	restored bool
}

var dockerDaemonConfig = &daemonConfig{
	path:    "/etc/docker/daemon.json",
	backup:  "/etc/docker/daemon.json.cargowall.bak",
	absent:  "/etc/docker/daemon.json.cargowall.absent",
	rewrite: "/etc/docker/daemon.json.cargowall.rewrite",
	reload:  reloadDockerDaemon,
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
// absent marker when there was no daemon.json — then the bytes it is about
// to write, and refuses to rewrite without those records, since restore can
// put back only what was recorded. Records a run left without restoring are
// settled first: they hold the real original, and recording over them would
// save that run's rewrite as the original instead.
func (c *daemonConfig) configure(dnsIP string, logger *slog.Logger) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.restored {
		return errors.New("daemon.json already restored; teardown has begun")
	}
	logger.Info("Configuring Docker DNS", "dns", dnsIP)

	recovered, err := c.restoreFiles(logger)
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
		if err := writeFileReplace(c.backup, data, 0o600); err != nil {
			return fmt.Errorf("failed to back up daemon.json: %w", err)
		}
		logger.Debug("Backed up existing daemon.json", "path", c.backup)
		if err := json.Unmarshal(data, &existingConfig); err != nil {
			logger.Warn("Failed to parse existing daemon.json, will overwrite", "error", err)
			existingConfig = make(map[string]any)
		} else if existingConfig == nil {
			existingConfig = make(map[string]any) // the body was JSON null
		}
	case errors.Is(err, os.ErrNotExist):
		if err := writeFileReplace(c.absent, nil, 0o600); err != nil {
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
	if err := writeFileReplace(c.rewrite, data, 0o600); err != nil {
		return fmt.Errorf("failed to record the daemon.json rewrite: %w", err)
	}
	if err := writeFileReplace(c.path, data, 0o644); err != nil {
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

func (c *daemonConfig) restore(logger *slog.Logger) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restored = true
	logger.Info("Restoring Docker DNS configuration")
	restored, err := c.restoreFiles(logger)
	if err != nil {
		return err
	}
	if !restored {
		logger.Debug("daemon.json holds no rewrite of ours; nothing to restore")
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
// reports whether it did. It acts only while daemon.json still holds the
// recorded rewrite; otherwise it clears the records and leaves daemon.json
// alone, setting an unverifiable backup aside rather than deleting it. The
// rewrite record goes last, so a crash partway leaves the next run to finish.
func (c *daemonConfig) restoreFiles(logger *slog.Logger) (bool, error) {
	original, err := os.ReadFile(c.backup)
	hasBackup := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("failed to read daemon.json backup: %w", err)
	}
	hasAbsent, err := exists(c.absent)
	if err != nil {
		return false, fmt.Errorf("failed to check daemon.json absent marker: %w", err)
	}
	ours, err := os.ReadFile(c.rewrite)
	hasOurs := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("failed to read daemon.json rewrite record: %w", err)
	}
	if !hasBackup && !hasAbsent {
		return false, removeIfExists(c.rewrite)
	}

	current, err := os.ReadFile(c.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("failed to read daemon.json: %w", err)
	}
	present := err == nil
	if !present || !hasOurs || !bytes.Equal(current, ours) {
		// Not the rewrite: the original (the rewrite never landed) or a file
		// changed since. Either way it stays.
		if hasOurs {
			logger.Warn("daemon.json changed since cargowall rewrote it; leaving it as it is", "path", c.path)
		}
		if hasBackup && present && bytes.Equal(original, current) {
			if err := removeIfExists(c.backup); err != nil {
				return false, err
			}
		} else if hasBackup {
			aside := fmt.Sprintf("%s.unrestored-%d", c.backup, time.Now().Unix())
			if err := os.Rename(c.backup, aside); err != nil {
				return false, fmt.Errorf("failed to set aside daemon.json backup: %w", err)
			}
			logger.Warn("Kept a pre-cargowall daemon.json that no longer matches for manual recovery", "path", aside)
		}
		if err := removeIfExists(c.absent); err != nil {
			return false, err
		}
		return false, removeIfExists(c.rewrite)
	}

	if hasBackup {
		if err := writeFileReplace(c.path, original, 0o644); err != nil {
			return true, fmt.Errorf("failed to restore daemon.json: %w", err)
		}
		if err := removeIfExists(c.backup); err != nil {
			return true, err
		}
	} else if err := removeIfExists(c.path); err != nil {
		return true, err
	}
	if err := removeIfExists(c.absent); err != nil {
		return true, err
	}
	return true, removeIfExists(c.rewrite)
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove %s: %w", path, err)
	}
	return nil
}

// writeFileReplace writes data to path through a rename, so a crash leaves
// the old file or the new one, never a torn daemon.json. The rename lands on
// a symlink's target, and an existing file keeps its mode and owner: a
// daemon.json linked into managed config, or kept 0600, stays that way.
// perm applies only to a file that does not exist yet.
func writeFileReplace(path string, data []byte, perm os.FileMode) error {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		target = path
	}
	uid, gid := -1, -1
	if fi, err := os.Stat(target); err == nil {
		perm = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(perm)
	}
	if err == nil && uid >= 0 {
		err = f.Chown(uid, gid)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, target)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
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
