//go:build linux

package cmd

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/code-cargo/cargowall/bpf"
	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/dns"
	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/firewall"
	"github.com/code-cargo/cargowall/pkg/lockdown"
	"github.com/code-cargo/cargowall/pkg/network"
)

func StartCargoWall(cmd *StartCmd, hooks *StartHooks) error {
	logger := cmd.Logger

	// Check eBPF capabilities early to provide clear error messages
	caps := cargowallEbpf.Detect()
	if !caps.IsSupported() {
		logger.Error("eBPF capability check failed",
			"kernel", caps.KernelVersion,
			"kernel_supported", caps.KernelSupported,
			"bpf_syscall", caps.BPFSyscall,
			"can_create_programs", caps.CanCreatePrograms,
			"cap_bpf", caps.HasCAP_BPF,
			"cap_net_admin", caps.HasCAP_NET_ADMIN)

		if cmd.GithubAction {
			// In GitHub Actions mode, provide actionable guidance
			logger.Error("eBPF is not supported on this runner. " +
				"Self-hosted runners may need kernel 5.x+ and CAP_BPF/CAP_NET_ADMIN capabilities. " +
				"GitHub-hosted runners require sudo privileges.")
		}

		return cargowallEbpf.RequireCapabilities()
	}

	logger.Debug("eBPF capabilities verified",
		"kernel", caps.KernelVersion,
		"cap_bpf", caps.HasCAP_BPF,
		"cap_net_admin", caps.HasCAP_NET_ADMIN)

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warn("Failed to remove memlock limit (may require additional capabilities)", "error", err)
		// Try to continue anyway - it might work with current limits
	}

	// Create configuration manager
	configMgr := config.NewConfigManager()

	// Start DNS proxy server BEFORE loading config (since config resolution needs DNS)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dnsServer *dns.Server
	var dockerBridgeIP string
	var dnsRedirectEnabled bool
	if !cmd.DisableDNSTracking {
		// Get upstream DNS server (defaults to Kubernetes DNS)
		upstream := cmd.DNSUpstream

		// Listen on localhost port 53 for DNS interception
		listenAddr := "127.0.0.1:53"
		dnsServer = dns.NewServer(
			configMgr,
			nil, // Will be set later after firewall is created
			upstream,
			listenAddr,
			logger,
		)

		// In GitHub Actions mode, also listen on Docker bridge for container DNS
		if cmd.GithubAction {
			// Enable DNS query filtering to prevent DNS tunneling
			dnsServer.EnableQueryFiltering(true)
			logger.Info("DNS query filtering enabled (blocks DNS tunneling)")

			var err error
			dockerBridgeIP, err = network.GetDockerBridgeIP()
			if err != nil {
				logger.Debug("Docker bridge not found, container DNS filtering unavailable", "error", err)
			} else {
				// Add docker bridge IP as additional listen address
				dnsServer.AddListenAddr(dockerBridgeIP + ":53")
				logger.Info("Docker DNS interception enabled", "docker_bridge", dockerBridgeIP)

				// Configure Docker to use our DNS proxy
				if err := network.ConfigureDockerDNS(dockerBridgeIP, logger); err != nil {
					logger.Warn("Failed to configure Docker DNS", "error", err)
				}
			}
		}

		dnsErrCh := make(chan error, 1)
		go func() {
			if err := dnsServer.Start(ctx); err != nil {
				dnsErrCh <- err
			}
		}()

		// Check for early startup failure
		select {
		case err := <-dnsErrCh:
			return fmt.Errorf("DNS proxy server failed to start: %w", err)
		case <-time.After(100 * time.Millisecond):
			// OK, server likely started
		}

		logger.Debug("DNS proxy server started",
			"listen", listenAddr,
			"upstream", upstream)

		// Set up iptables DNAT to force all outbound DNS through the proxy.
		// This catches processes that bypass /etc/resolv.conf and query
		// upstream DNS directly (e.g., Go's pure resolver, Node.js).
		if cmd.GithubAction {
			if err := network.SetupDNSRedirect(logger); err != nil {
				logger.Warn("Failed to set up DNS redirect (iptables)", "error", err)
			} else {
				dnsRedirectEnabled = true
			}
		}
	}

	// Variable to hold the notification tracker
	var notificationTracker *events.NotificationTracker

	// Initialize audit logger if audit log path is specified
	var auditLogger *events.AuditLogger
	if cmd.AuditLog != "" {
		var err error
		auditLogger, err = events.NewAuditLogger(cmd.AuditLog, cmd.AuditMode)
		if err != nil {
			return fmt.Errorf("failed to create audit logger: %w", err)
		}
		defer auditLogger.Close()

		if cmd.AuditMode {
			logger.Info("Running in AUDIT MODE - connections will be logged but NOT blocked",
				"audit_log", cmd.AuditLog)
		} else {
			logger.Info("Audit logging enabled",
				"audit_log", cmd.AuditLog)
		}
	} else if cmd.AuditMode {
		logger.Warn("Audit mode enabled but no audit log path specified (--audit-log)")
	}

	// Now load configuration (DNS proxy is running so hostname resolution will work)
	var apiPolicyLoaded bool
	if cmd.GithubAction {
		// GitHub Actions mode: load from environment variables or file, no NATS
		logger.Info("Running in GitHub Actions mode")

		// Priority 1: SaaS API (when api-url + token are set)
		if cmd.ApiUrl != "" && cmd.Token != "" {
			// Bootstrap an empty config so EnsureHostnameAllowed can add rules
			// before the real policy is loaded. The API hostname must be
			// allowed through DNS filtering for the policy fetch to succeed.
			if u, err := url.Parse(cmd.ApiUrl); err == nil && u.Hostname() != "" {
				configMgr.LoadConfigFromRules(nil, config.ActionDeny)
				configMgr.EnsureHostnameAllowed(u.Hostname())
			}

			logger.Info("Fetching policy from CodeCargo API", "api_url", cmd.ApiUrl, "job_key", cmd.JobKey)
			policy, err := fetchPolicyFromAPI(ctx, cmd.ApiUrl, cmd.Token, cmd.JobKey)
			if err != nil {
				logger.Warn("API policy fetch failed, falling back to env/file config", "error", err)
			} else {
				if policyJSON, jsonErr := protojson.Marshal(policy); jsonErr == nil {
					logger.Info("Raw policy from API", "policy", string(policyJSON))
				}
				if err := configMgr.LoadConfigFromCargoWall(policy); err != nil {
					logger.Warn("Failed to load API policy into config, falling back to env/file config", "error", err)
				} else {
					// Override audit mode from the API response's mode field
					switch policy.Mode {
					case datapb.CargoWallMode_CARGO_WALL_MODE_AUDIT:
						cmd.AuditMode = true
					case datapb.CargoWallMode_CARGO_WALL_MODE_ENFORCE:
						cmd.AuditMode = false
					}
					// Update the audit logger with the mode from the SaaS policy,
					// since it was created before the policy was fetched.
					if auditLogger != nil {
						auditLogger.SetAuditMode(cmd.AuditMode)
					}
					// Write effective mode to a state file so the summary
					// step picks up the SaaS-overridden value.
					modeStr := "enforce"
					if cmd.AuditMode {
						modeStr = "audit"
					}
					_ = os.WriteFile("/tmp/cargowall-mode", []byte(modeStr), 0o644)

					apiPolicyLoaded = true
					logger.Info("Policy loaded from CodeCargo API",
						"mode", policy.Mode.String(),
						"default_action", policy.DefaultAction.String(),
						"rules", len(policy.Rules))
				}
			}
		}

		// Priority 2: env vars, Priority 3: config file
		if !apiPolicyLoaded {
			if err := configMgr.LoadFromEnv(); err != nil {
				logger.Debug("No environment config found, trying file", "error", err)
				if err := configMgr.LoadConfig(cmd.Config); err != nil {
					logger.Warn("No config loaded — defaulting to deny-all. Infrastructure hosts will be auto-allowed.",
						"error", err, "path", cmd.Config)
				}
			}
		}

		// Auto-allow DNS infrastructure IPs on port 53 so the DNS proxy
		// can reach the upstream and local processes/containers can resolve.
		dnsIPs := []string{"127.0.0.1"}
		if dnsUpstreamHost, _, err := net.SplitHostPort(cmd.DNSUpstream); err == nil {
			dnsIPs = append(dnsIPs, dnsUpstreamHost)
		}
		if dockerBridgeIP != "" {
			dnsIPs = append(dnsIPs, dockerBridgeIP)
		}
		configMgr.EnsureDNSAllowed(dnsIPs)
	} else if hooks != nil && hooks.LoadPolicy != nil {
		// Extension hook: load policy from external source (e.g., NATS state machine)
		policy, hookSmClient, cleanup, err := hooks.LoadPolicy(ctx, cmd)
		if err != nil {
			return fmt.Errorf("failed to load policy via hook: %w", err)
		}
		if cleanup != nil {
			defer cleanup()
		}

		if policy != nil {
			if err := configMgr.LoadConfigFromCargoWall(policy); err != nil {
				return fmt.Errorf("failed to load CargoWall config: %w", err)
			}
		}

		if hookSmClient != nil {
			notificationTracker = events.NewNotificationTracker(hookSmClient, logger)
			logger.Info("CargoWall block notifications enabled via hook")
		}
	} else {
		// Load from file (original behavior)
		if err := configMgr.LoadConfig(cmd.Config); err != nil {
			logger.Error("Failed to load config", "error", err, "path", cmd.Config)
			// Continue with default deny-all policy
		}
	}

	// Find network interface
	ifname := cmd.Interface
	if ifname == "" {
		var err error
		ifname, err = network.FindPodInterface()
		if err != nil {
			return err
		}
	}
	logger.Info("Using network interface", "interface", ifname)

	// Load TC eBPF objects
	var objs bpf.TcBpfObjects
	if err := bpf.LoadTcBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: nil,
			LogLevel:    ebpf.LogLevelBranch | ebpf.LogLevelStats,
		},
	}); err != nil {
		// Try to get the full verifier log
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			logger.Error("eBPF verifier error - Full log follows:")
			// Print the full log to stderr since it might be very long
			_, _ = fmt.Fprintf(os.Stderr, "\n=== VERIFIER LOG START ===\n%s\n=== VERIFIER LOG END ===\n", verr.Log)
		}
		return fmt.Errorf("failed to load TC eBPF objects: %w", err)
	}
	defer objs.Close()

	// Attach cgroup programs for PID tracking via socket cookie.
	// Best-effort: if attachment fails, TC filtering still works but PID will be 0.
	cgroupProgs := []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
		name   string
	}{
		{objs.CgConnect4, ebpf.AttachCGroupInet4Connect, "connect4"},
		{objs.CgConnect6, ebpf.AttachCGroupInet6Connect, "connect6"},
	}
	for _, cp := range cgroupProgs {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    "/sys/fs/cgroup",
			Attach:  cp.attach,
			Program: cp.prog,
		})
		if err != nil {
			logger.Warn("Failed to attach cgroup program (PID tracking disabled)", "program", cp.name, "error", err)
		} else {
			defer l.Close()
		}
	}

	// Create firewall instance that owns the BPF maps
	fw := firewall.NewFirewall(objs.MapCidrs, objs.MapPorts, objs.MapCidrsV6, objs.MapPortsV6, objs.MapDefaultAction, objs.MapAuditMode, logger)

	// Set up ring buffer readers
	rd, err := ringbuf.NewReader(objs.MapEvents)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	defer rd.Close()

	// Start processors before attaching programs
	go events.ProcessBlockedEvents(rd, configMgr, notificationTracker, auditLogger, fw, logger)

	// Attach TC programs
	egressLink, err := network.AttachTC(ifname, objs.TcEgress, ebpf.AttachTCXEgress, logger)
	if err != nil {
		return fmt.Errorf("failed to attach TC egress: %w", err)
	}
	defer egressLink.Close()

	// Set default action through firewall
	defaultAction := configMgr.GetDefaultAction()
	if err := fw.SetDefaultAction(defaultAction); err != nil {
		return fmt.Errorf("failed to set default action: %w", err)
	}

	// Set audit mode if enabled
	if cmd.AuditMode {
		if err := fw.SetAuditMode(true); err != nil {
			return fmt.Errorf("failed to set audit mode: %w", err)
		}
	}

	// Populate CIDR rules from configuration
	if err := fw.UpdateAllowlistTC(configMgr); err != nil {
		return fmt.Errorf("failed to update CIDR rules: %w", err)
	}

	// Update DNS server with firewall now that it's created
	if dnsServer != nil {
		dnsServer.SetFirewall(fw)
		logger.Debug("Updated DNS server with firewall")

		// Set audit logger on DNS server if configured
		if auditLogger != nil {
			dnsServer.SetAuditLogger(auditLogger)
			logger.Debug("Updated DNS server with audit logger")
		}

		// IMPORTANT: Apply rules to any hostnames we tracked before config was loaded
		// This is needed because we may have already resolved hostnames (like NATS)
		// before we had the rules to track them
		if (hooks != nil && hooks.LoadPolicy != nil) || cmd.GithubAction {
			dnsServer.ApplyRulesToTrackedHostnames()
			logger.Info("Applied firewall rules to tracked hostnames")
		}

		// Before querying systemd-resolved's cache, ensure its upstream DNS
		// servers are allowed through the firewall (needed for cache misses).
		if cmd.GithubAction {
			if resolvedUpstreams, err := detectSystemdResolvedUpstreams(); err == nil {
				if len(resolvedUpstreams) > 0 {
					configMgr.EnsureDNSAllowed(resolvedUpstreams)

					// Auto-allow Azure wireserver on ports 53 (DNS), 80 (HTTP),
					// and 32526 (health) for every Azure VM / GitHub-hosted runner.
					// The upstream IPs from systemd-resolved on Azure are
					// typically 168.63.129.16.
					configMgr.EnsureInfraAllowed(resolvedUpstreams, []uint16{53, 80, 32526})

					if err := fw.UpdateAllowlistTC(configMgr); err != nil {
						logger.Warn("Failed to update allowlist with resolved upstreams", "error", err)
					}
					logger.Info("Allowed systemd-resolved upstream DNS servers", "ips", resolvedUpstreams)
				}
			} else {
				logger.Debug("Could not detect systemd-resolved upstreams", "error", err)
			}

			// Also pre-allow Azure IMDS metadata endpoint (169.254.169.254).
			// This link-local IP serves instance metadata over HTTP on all
			// Azure VMs and GitHub-hosted runners and must not be blocked.
			configMgr.EnsureInfraAllowed([]string{"169.254.169.254"}, []uint16{80})

			// Auto-allow GitHub Actions infrastructure. The runner communicates
			// with *.actions.githubusercontent.com for job control, log upload,
			// and token refresh. Subdomain matching covers pipelines., vstoken.,
			// results-receiver., etc.
			configMgr.EnsureHostnameAllowed("actions.githubusercontent.com")

			// Auto-discover hostnames from GitHub Actions runtime environment
			// variables. The runner communicates with specific subdomains like
			// pipelines.actions.githubusercontent.com and results-receiver-service.
			// actions.githubusercontent.com whose IPs differ from the parent
			// domain's DNS resolution. Tracking them explicitly ensures Phase 1/2
			// resolves their IPs into the BPF allowlist.
			for _, envVar := range []string{
				"ACTIONS_RUNTIME_URL",
				"ACTIONS_RESULTS_URL",
				"ACTIONS_CACHE_URL",
				"ACTIONS_ID_TOKEN_REQUEST_URL",
			} {
				if val := os.Getenv(envVar); val != "" {
					if u, err := url.Parse(val); err == nil && u.Hostname() != "" {
						configMgr.EnsureHostnameAllowed(u.Hostname())
						logger.Info("Auto-allowed Actions runtime hostname", "env", envVar, "hostname", u.Hostname())
					}
				}
			}

			// Auto-allow the CodeCargo API hostname so the summary push
			// (which runs while the firewall is active) is not blocked.
			if cmd.ApiUrl != "" {
				if u, err := url.Parse(cmd.ApiUrl); err == nil && u.Hostname() != "" {
					configMgr.EnsureHostnameAllowed(u.Hostname())
					logger.Info("Auto-allowed CodeCargo API hostname", "hostname", u.Hostname())
				}
			}

			if err := fw.UpdateAllowlistTC(configMgr); err != nil {
				logger.Warn("Failed to update allowlist with infra rules", "error", err)
			}
		}

		// Shared resolver that uses the systemd-resolved stub listener for
		// looking up cached DNS entries. Used for existing-connection reverse
		// DNS and Phase 1 cache population.
		cacheResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", "127.0.0.53:53")
			},
		}

		// Scan existing TCP connections and do reverse DNS lookups so that
		// IPs like 140.82.112.22 (github.com) show hostnames in the audit
		// log instead of raw IPs. This covers connections established before
		// cargowall started that aren't in the tracked hostnames list.
		var existingIPs []string
		if cmd.GithubAction {
			if scannedIPs, err := scanExistingConnections(); err == nil && len(scannedIPs) > 0 {
				existingIPs = scannedIPs
				lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 10*time.Second)
				for _, ip := range existingIPs {
					rCtx, rCancel := context.WithTimeout(lookupCtx, 1*time.Second)
					if names, err := cacheResolver.LookupAddr(rCtx, ip); err == nil && len(names) > 0 {
						hostname := strings.TrimSuffix(names[0], ".")
						configMgr.UpdateDNSMapping(hostname, ip)
						logger.Debug("Reverse DNS for existing connection", "ip", ip, "hostname", hostname)
					}
					rCancel()
				}
				lookupCancel()
				logger.Info("Populated reverse DNS cache from existing connections", "ips", len(existingIPs))
			} else if err != nil {
				logger.Debug("Could not scan existing connections", "error", err)
			}
		}

		// In GitHub Actions mode, pre-populate the BPF allowlist and reverse
		// lookup cache so that connections established before cargowall started
		// (using cached DNS IPs) are not incorrectly blocked.
		//
		// Phase 1: Query systemd-resolved's stub listener (127.0.0.53) to get
		// the CACHED IPs — the exact IPs running processes are currently using.
		// This is loopback traffic so the BPF TC filter on eth0 doesn't touch it.
		if cmd.GithubAction {
			cacheCtx, cacheCancel := context.WithTimeout(context.Background(), 10*time.Second)
			for hostname := range configMgr.GetTrackedHostnames() {
				lookupCtx, lookupCancel := context.WithTimeout(cacheCtx, 2*time.Second)
				if ips, err := cacheResolver.LookupHost(lookupCtx, hostname); err == nil {
					for _, ip := range ips {
						configMgr.UpdateDNSMapping(hostname, ip)
					}
				} else {
					logger.Debug("System DNS cache miss", "hostname", hostname, "error", err)
				}
				lookupCancel()
			}
			cacheCancel()

			// Push cached IPs into BPF maps
			dnsServer.ApplyRulesToTrackedHostnames()
			logger.Info("Applied system DNS cache entries to firewall")

			// Phase 2: Also resolve through our DNS proxy to capture any fresh
			// round-robin IPs and ensure the reverse lookup cache is fully populated.
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{}
					return d.DialContext(ctx, "udp", "127.0.0.1:53")
				},
			}
			resolveCtx, resolveCancel := context.WithTimeout(context.Background(), 15*time.Second)
			for hostname := range configMgr.GetTrackedHostnames() {
				lookupCtx, lookupCancel := context.WithTimeout(resolveCtx, 3*time.Second)
				if _, err := resolver.LookupHost(lookupCtx, hostname); err != nil {
					logger.Debug("Failed to pre-resolve hostname", "hostname", hostname, "error", err)
				}
				lookupCancel()
			}
			resolveCancel()
			logger.Info("Pre-resolved tracked hostnames via DNS proxy")
		}

		// Now that Phase 1/2 DNS resolution has populated the full
		// hostname→IP cache, gate pre-existing connections on denied hostnames.
		// Block IPs that resolve to a denied tracked hostname; allow everything
		// else (allowed hostnames and unresolvable IPs) to avoid breaking
		// legitimate connections where PTR records are unavailable.
		if cmd.AllowExistingConnections && fw != nil && len(existingIPs) > 0 {
			for _, ipStr := range existingIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}

				hostname := configMgr.LookupHostnameByIP(ipStr)
				trackedHost := configMgr.FindTrackedHostname(hostname)
				action := configMgr.GetTrackedHostnameAction(hostname)

				if trackedHost != "" && action == config.ActionDeny {
					// Positively matches a denied hostname — do NOT allow
					logger.Info("Blocked pre-existing connection (denied hostname)", "ip", ipStr, "hostname", hostname, "trackedHost", trackedHost)
					if auditLogger != nil {
						auditLogger.LogExistingConnection(ipStr, hostname, trackedHost, false)
					}
				} else {
					// Either matches an allowed hostname, or unresolvable — allow it
					if wasAdded, err := fw.AddIP(ip, config.ActionAllow, nil); err != nil {
						logger.Debug("Failed to allow existing connection IP", "ip", ipStr, "error", err)
					} else if wasAdded {
						logger.Info("Auto-allowed pre-existing connection", "ip", ipStr, "hostname", hostname)
						if auditLogger != nil {
							auditLogger.LogExistingConnection(ipStr, hostname, trackedHost, true)
						}
					}
				}
			}
			logger.Info("Processed pre-existing connections against allowlist", "count", len(existingIPs))
		}
	}

	// Log appropriate config source
	if apiPolicyLoaded {
		logger.Info("CargoWall TC firewall started",
			"interface", ifname,
			"config_source", "saas_api",
			"api_url", cmd.ApiUrl,
			"default_action", configMgr.GetDefaultAction())
	} else if cmd.GithubAction {
		logger.Info("CargoWall TC firewall started",
			"interface", ifname,
			"config_source", "github_action",
			"default_action", configMgr.GetDefaultAction())
	} else if hooks != nil && hooks.LoadPolicy != nil {
		logger.Info("CargoWall TC firewall started",
			"interface", ifname,
			"config_source", "hook")
	} else {
		logger.Info("CargoWall TC firewall started",
			"interface", ifname,
			"config_source", "file",
			"config_path", cmd.Config)
	}

	// Enable sudo lockdown if requested (typically in GitHub Actions mode)
	var sudoLockdownEnabled bool
	var lockdownCfg *lockdown.SudoLockdownConfig
	if cmd.SudoLockdown {
		var allowCmds []string
		if cmd.SudoAllowCommands != "" {
			for _, c := range strings.Split(cmd.SudoAllowCommands, ",") {
				c = strings.TrimSpace(c)
				if c != "" {
					allowCmds = append(allowCmds, c)
				}
			}
		}
		lockdownCfg = &lockdown.SudoLockdownConfig{
			AllowCommands: allowCmds,
			Username:      "", // Auto-detect
		}
		if err := lockdown.EnableSudoLockdown(lockdownCfg, logger); err != nil {
			logger.Warn("Failed to enable sudo lockdown", "error", err)
			// Continue without lockdown - it's a hardening feature, not critical
		} else {
			sudoLockdownEnabled = true
		}
	}

	// Restart Docker daemon so containers pick up the DNS configuration
	// written to daemon.json by ConfigureDockerDNS. Docker's SIGHUP handler
	// does NOT reload DNS settings — a full restart is required.
	if cmd.GithubAction && dockerBridgeIP != "" {
		if err := network.RestartDockerDaemon(logger); err != nil {
			logger.Warn("Failed to restart Docker daemon for DNS config", "error", err)
		}
	}

	logger.Info("CargoWall ready")

	err = os.WriteFile("/tmp/cargowall-ready", nil, 0o660)
	if err != nil {
		return err
	}

	// Handle signals for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	logger.Info("Shutting down TC firewall")

	// Disable sudo lockdown if we enabled it
	if sudoLockdownEnabled {
		if err := lockdown.DisableSudoLockdown(lockdownCfg, logger); err != nil {
			logger.Warn("Failed to disable sudo lockdown", "error", err)
		}
	}

	// Remove iptables DNS redirect rules if we added them
	if dnsRedirectEnabled {
		if err := network.TeardownDNSRedirect(logger); err != nil {
			logger.Warn("Failed to tear down DNS redirect", "error", err)
		}
	}

	// Restore Docker DNS configuration if we modified it
	if cmd.GithubAction && dockerBridgeIP != "" {
		if err := network.RestoreDockerDNS(logger); err != nil {
			logger.Warn("Failed to restore Docker DNS", "error", err)
		}
	}

	return nil
}

// detectSystemdResolvedUpstreams reads /run/systemd/resolve/resolv.conf
// to find the actual upstream DNS servers used by systemd-resolved.
func detectSystemdResolvedUpstreams() ([]string, error) {
	data, err := os.ReadFile("/run/systemd/resolve/resolv.conf")
	if err != nil {
		return nil, err
	}
	var upstreams []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := fields[1]
				if ip != "127.0.0.1" && ip != "127.0.0.53" {
					upstreams = append(upstreams, ip)
				}
			}
		}
	}
	return upstreams, nil
}

// scanExistingConnections reads /proc/net/tcp and /proc/net/tcp6 to find all
// unique remote IPs from established TCP connections. This is used in GitHub
// Actions mode to discover connections that were set up before cargowall
// started, so we can reverse-lookup their hostnames and populate the DNS cache.
func scanExistingConnections() ([]string, error) {
	seen := make(map[string]bool)

	// Scan IPv4 connections
	if err := scanProcTCP("/proc/net/tcp", false, seen); err != nil {
		return nil, err
	}

	// Scan IPv6 connections (best-effort — file may not exist)
	if err := scanProcTCP("/proc/net/tcp6", true, seen); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	result := make([]string, 0, len(seen))
	for ip := range seen {
		result = append(result, ip)
	}
	return result, nil
}

// scanProcTCP reads a /proc/net/tcp or /proc/net/tcp6 file and adds unique
// remote IPs from ESTABLISHED connections to the seen map.
func scanProcTCP(path string, isIPv6 bool, seen map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		// Column 3 (0-indexed field 3) is the connection state.
		// "01" = ESTABLISHED.
		if fields[3] != "01" {
			continue
		}

		// Column 2 (0-indexed field 2) is the remote address in hex "IP:PORT" format.
		parts := strings.SplitN(fields[2], ":", 2)
		if len(parts) != 2 {
			continue
		}

		var ip net.IP
		if isIPv6 {
			ip, err = parseHexIPv6(parts[0])
		} else {
			ip, err = parseHexIP(parts[0])
		}
		if err != nil {
			continue
		}

		// Skip loopback and link-local addresses
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}

		seen[ip.String()] = true
	}

	return scanner.Err()
}

// parseHexIP converts a little-endian hex-encoded IPv4 address from /proc/net/tcp
// into a 4-byte IP. The kernel stores IPv4 addresses as 32-bit integers in host
// byte order (little-endian on x86), so "0100007F" is 127.0.0.1.
func parseHexIP(hexStr string) (net.IP, error) {
	if len(hexStr) != 8 {
		return nil, fmt.Errorf("invalid hex IP length: %d", len(hexStr))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	// Reverse byte order (little-endian to big-endian)
	return net.IPv4(b[3], b[2], b[1], b[0]).To4(), nil
}

// parseHexIPv6 converts a hex-encoded IPv6 address from /proc/net/tcp6 into a
// 16-byte IP. The kernel stores IPv6 addresses as four 32-bit words, each in
// host byte order (little-endian on x86). For example,
// "B80D01200000000067452301EFCDAB89" is decoded by reversing each 4-byte group.
func parseHexIPv6(hexStr string) (net.IP, error) {
	if len(hexStr) != 32 {
		return nil, fmt.Errorf("invalid hex IPv6 length: %d", len(hexStr))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	// Reverse each 4-byte group from little-endian to big-endian
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		off := i * 4
		ip[off+0] = b[off+3]
		ip[off+1] = b[off+2]
		ip[off+2] = b[off+1]
		ip[off+3] = b[off+0]
	}
	return ip, nil
}
