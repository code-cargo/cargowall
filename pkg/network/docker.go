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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// daemonConfig is the daemon.json rewrite and its undo. The paths and the
// daemon restarts are fields so the crash and failure paths can be driven
// against a temp dir.
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
	// restart restarts the daemon and waits for it; queueRestart only asks
	// systemd for a restart, which carries on after cargowall exits.
	restart      func(*slog.Logger) error
	queueRestart func(*slog.Logger) error

	// mu serializes configure, restore and the check before a restart: the
	// undo is registered before configure, and a second signal runs it on
	// another goroutine. A restart itself runs outside it, so a forced
	// teardown never waits on one.
	mu sync.Mutex
	// restored is set by the first restore, so a configure the undo has
	// already overtaken does not rewrite what nothing will then undo.
	restored bool
	// applied is set while the daemon may run a rewrite: once it is
	// restarted onto ours, or once a rewrite a previous run left is undone,
	// since a daemon started after that run's restart runs it. A restart onto
	// anything else clears it. restore restarts the daemon while it is set.
	applied bool
}

var dockerDaemonConfig = &daemonConfig{
	path:    "/etc/docker/daemon.json",
	backup:  "/etc/docker/daemon.json.cargowall.bak",
	absent:  "/etc/docker/daemon.json.cargowall.absent",
	rewrite: "/etc/docker/daemon.json.cargowall.rewrite",

	restart:      restartDockerDaemon,
	queueRestart: queueDockerRestart,
}

// DockerDNSServers is daemon.json's "dns": the servers the daemon gives
// its containers, nil when daemon.json sets none or there is none.
func DockerDNSServers() ([]string, error) { return dockerDaemonConfig.dnsServers() }

func (c *daemonConfig) dnsServers() ([]string, error) {
	data, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg struct {
		DNS []string `json:"dns"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", c.path, err)
	}
	return cfg.DNS, nil
}

// BridgeSubnet is the IPv4 network of the bridge called name, from its
// first IPv4 address (172.17.0.0/16 for a default docker0). The cgroup
// egress hook adjudicates bridge traffic TC never saw — host→published-port
// via docker-proxy, container→container — and under shadow/enforce that
// local-only class is carved out by subnet (pkg/origin's local-nets map),
// not discovered one denial at a time.
func BridgeSubnet(name string) (netip.Prefix, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s interface not found: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to get %s addresses: %w", name, err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				ones, _ := ipnet.Mask.Size()
				return netip.PrefixFrom(netip.AddrFrom4([4]byte(ip4)), ones).Masked(), nil
			}
		}
	}
	return netip.Prefix{}, fmt.Errorf("no IPv4 address found on %s", name)
}

// ConfigureDockerDNS configures Docker to use the specified DNS server.
// This modifies /etc/docker/daemon.json. A full Docker restart via
// RestartDockerDaemon is required for the changes to take effect.
func ConfigureDockerDNS(dnsIP string, logger *slog.Logger) error {
	return dockerDaemonConfig.configure(dnsIP, logger)
}

// RestoreDockerDNS restores the original Docker daemon configuration, and
// queues a daemon restart onto it when the daemon may run a rewrite: this
// run's, or one a previous run left. It is safe whether or not
// ConfigureDockerDNS ran or got as far as the rewrite: with nothing recorded,
// daemon.json is left alone.
func RestoreDockerDNS(logger *slog.Logger) error {
	return dockerDaemonConfig.restore(logger)
}

// RecoverDockerDNS undoes a daemon.json rewrite that a previous run left
// behind, as ConfigureDockerDNS does first, without rewriting it again, and
// reports whether there was one: a daemon started since reads it, so only a
// restart (RestartDockerDaemon) applies the original again. With nothing
// recorded, daemon.json is left alone.
func RecoverDockerDNS(logger *slog.Logger) (bool, error) {
	return dockerDaemonConfig.recover(logger)
}

// recover is RecoverDockerDNS.
func (c *daemonConfig) recover(logger *slog.Logger) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recoverLocked(logger)
}

// recoverLocked settles the records a run left without restoring, which
// hold the real original. Caller holds c.mu.
func (c *daemonConfig) recoverLocked(logger *slog.Logger) (bool, error) {
	recovered, err := c.restoreFiles(logger)
	if recovered {
		c.applied = true
	}
	if err != nil {
		return recovered, fmt.Errorf("undo the daemon.json rewrite a previous run left: %w", err)
	}
	if recovered {
		logger.Warn("Restored daemon.json left rewritten by a previous run that did not shut down cleanly")
	}
	return recovered, nil
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

	if _, err := c.recoverLocked(logger); err != nil {
		return err
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
	switch {
	case err != nil:
	case restored:
		logger.Info("Docker DNS configuration restored")
	default:
		logger.Debug("daemon.json holds no rewrite of ours; nothing to restore")
	}
	// A daemon that never ran a rewrite still runs its original settings,
	// and is left alone. One that may keeps pointing its containers at the
	// listener, which goes with cargowall, until it restarts: a reload does
	// not undo it, and with no "dns" in daemon.json leaves the daemon handing
	// its containers an empty nameserver. That holds when restoreFiles fails
	// after putting the original back, when a previous run's rewrite was
	// undone earlier in this run, so restore finds nothing of its own, and
	// when daemon.json was changed since the rewrite, which restoreFiles
	// leaves alone and the restart then applies. A daemon.json that still
	// holds the rewrite has nothing to restart onto.
	// The restart is only queued: a teardown, forced ones included, does not
	// wait on the daemon, and systemd finishes the restart after cargowall
	// has gone. One queued while startup's restart still runs makes systemd
	// run that one again, so the daemon comes up on the original either way.
	if c.applied && !c.holdsRewrite() {
		if err := c.queueRestart(logger); err != nil {
			logger.Warn("Failed to queue a Docker daemon restart off cargowall's daemon.json rewrite; "+
				"its containers resolve through an address cargowall no longer serves until it restarts", "error", err)
		} else {
			logger.Info("Queued a Docker daemon restart off cargowall's daemon.json rewrite")
		}
	}
	return err
}

// restartDaemon is RestartDockerDaemon. It records whether the daemon is
// about to run the rewrite before restarting it: a restart that fails or
// times out may have applied it all the same. A restore that gets in
// between has put the original back, and the restart applies that. Once
// teardown has begun, restore has seen to the daemon, and there is no
// restart.
func (c *daemonConfig) restartDaemon(logger *slog.Logger) error {
	c.mu.Lock()
	if c.restored {
		c.mu.Unlock()
		logger.Debug("Docker daemon restart skipped; teardown has begun")
		return nil
	}
	rewrite := c.holdsRewrite()
	if rewrite {
		c.applied = true
	}
	c.mu.Unlock()

	err := c.restart(logger)
	if err == nil && !rewrite {
		c.mu.Lock()
		c.applied = false
		c.mu.Unlock()
	}
	return err
}

// holdsRewrite reports whether daemon.json holds the rewrite recorded
// beside it.
func (c *daemonConfig) holdsRewrite() bool {
	ours, err := os.ReadFile(c.rewrite)
	if err != nil {
		return false
	}
	current, err := os.ReadFile(c.path)
	return err == nil && bytes.Equal(current, ours)
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
// etc.) and does NOT reload DNS settings from daemon.json. A restart onto the
// rewrite is recorded, so RestoreDockerDNS restarts the daemon onto the
// original too.
func RestartDockerDaemon(logger *slog.Logger) error { return dockerDaemonConfig.restartDaemon(logger) }

// dockerRestartTimeout bounds a daemon restart, teardown's included: systemctl
// waits on the start job, which docker.service gives no timeout of its own
// (TimeoutStartSec=0), and the daemon has then to answer.
const dockerRestartTimeout = 60 * time.Second

// restartDockerDaemon restarts the daemon through systemd and waits for it to
// answer, within dockerRestartTimeout. A start job systemctl stops waiting on
// carries on in systemd.
func restartDockerDaemon(logger *slog.Logger) error {
	logger.Info("Restarting Docker daemon to apply DNS configuration")
	ctx, cancel := context.WithTimeout(context.Background(), dockerRestartTimeout)
	defer cancel()
	started := time.Now()

	resetDockerStartLimit(ctx, logger)
	if err := exec.CommandContext(ctx, "systemctl", "restart", "docker").Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("systemctl restart docker did not finish within %s", dockerRestartTimeout)
		}
		return fmt.Errorf("systemctl restart docker failed: %w", err)
	}

	for {
		if exec.CommandContext(ctx, "docker", "info").Run() == nil {
			logger.Info("Docker daemon ready after restart", "seconds", int(time.Since(started).Seconds())+1)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Docker daemon to be ready after restart")
		case <-time.After(time.Second):
		}
	}
}

// queueDockerRestart asks systemd to restart the daemon and returns without
// waiting for it. Where the daemon is socket-activated, as the distribution
// and Docker packages set it up, a docker command meanwhile waits on
// docker.socket, which systemd holds open through the restart; elsewhere it
// fails until the daemon is back.
func queueDockerRestart(logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resetDockerStartLimit(ctx, logger)
	if err := exec.CommandContext(ctx, "systemctl", "restart", "--no-block", "docker").Run(); err != nil {
		return fmt.Errorf("systemctl restart --no-block docker failed: %w", err)
	}
	return nil
}

// resetDockerStartLimit flushes docker.service's start rate limit before a
// restart. The unit allows three starts a minute (StartLimitBurst=3), and the
// restart onto the rewrite, the one onto the original and any a job makes
// itself can go past it: systemd then refuses the start and leaves the
// daemon stopped.
func resetDockerStartLimit(ctx context.Context, logger *slog.Logger) {
	if err := exec.CommandContext(ctx, "systemctl", "reset-failed", "docker").Run(); err != nil {
		logger.Debug("systemctl reset-failed docker failed; restarting regardless", "error", err)
	}
}
