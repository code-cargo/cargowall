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

package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/code-cargo/cargowall/pkg/config"
)

// FirewallUpdater allows the event processor to dynamically add IPs to the firewall
// when lazy reverse DNS reveals a blocked IP belongs to an allowed hostname.
type FirewallUpdater interface {
	AddIP(ip net.IP, action config.Action, ports []uint16) (bool, error)
}

// lookupProcessName reads the process name from /proc/<pid>/comm.
// Returns empty string if the process no longer exists or can't be read.
func lookupProcessName(pid uint32) string {
	if pid == 0 {
		return ""
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// StateMachineClient interface for sending notifications to state machines
type StateMachineClient interface {
	SendCargoWallBlockNotification(ctx context.Context, hostname, ip string, port uint32) error
}

// NotificationTracker ensures we only send one notification per unique destination
type NotificationTracker struct {
	sentDestinations sync.Map // map[string]bool for tracking unique destinations
	smClient         StateMachineClient
	logger           *slog.Logger
}

// NewNotificationTracker creates a new notification tracker
func NewNotificationTracker(smClient StateMachineClient, logger *slog.Logger) *NotificationTracker {
	return &NotificationTracker{
		smClient: smClient,
		logger:   logger,
	}
}

// SendNotification sends a block notification for each unique destination
func (n *NotificationTracker) SendNotification(hostname, ip string, port uint16) {
	// Create a unique key for this destination
	// Use hostname if available, otherwise use IP
	destination := hostname
	if destination == "" {
		destination = ip
	}
	key := fmt.Sprintf("%s:%d", destination, port)

	// Check if we've already sent a notification for this destination
	if _, alreadySent := n.sentDestinations.LoadOrStore(key, true); !alreadySent {
		// This is the first time we're seeing this destination, send notification
		ctx := context.Background()
		if err := n.smClient.SendCargoWallBlockNotification(ctx, hostname, ip, uint32(port)); err != nil {
			n.logger.Error("Failed to send CargoWall block notification",
				"hostname", hostname,
				"ip", ip,
				"port", port,
				"error", err)
			// Remove from map on error so we can retry
			n.sentDestinations.Delete(key)
		} else {
			n.logger.Info("CargoWall block notification sent for unique destination",
				"hostname", hostname,
				"ip", ip,
				"port", port,
				"key", key)
		}
	} else {
		n.logger.Debug("Skipping notification (already sent for this destination)",
			"hostname", hostname,
			"ip", ip,
			"port", port,
			"key", key)
	}
}

// BpfBlockedEvent matches the struct in tcbpf.c
type BpfBlockedEvent struct {
	IpVersion uint8
	Allowed   uint8
	Pad1      [2]uint8
	SrcIp     uint32 // IPv4 (used when IpVersion == 4)
	DstIp     uint32 // IPv4 (used when IpVersion == 4)
	SrcPort   uint16
	DstPort   uint16
	SrcIp6    [16]byte // IPv6 (used when IpVersion == 6)
	DstIp6    [16]byte // IPv6 (used when IpVersion == 6)
	Timestamp uint64
	Pid       uint32
	Pad2      uint32
}

// getProtocolName returns the name of an IP protocol number
func getProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6-in-IPv4"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 103:
		return "PIM"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("Protocol-%d", proto)
	}
}

// reverseDNSCache is a bounded cache of IPs we've already attempted reverse
// DNS for, so each unique IP triggers at most one lookup. Limited to 10000
// entries to prevent unbounded memory growth.
var (
	reverseDNSMu    sync.Mutex
	reverseDNSCache = make(map[string]time.Time) // IP -> timestamp of attempt
)

const reverseDNSCacheMax = 10000

// reverseDNSAttempted checks if an IP has been looked up before and marks it if not.
// Returns true if the IP was already in the cache (i.e., already attempted).
func reverseDNSAttempted(ip string) bool {
	reverseDNSMu.Lock()
	defer reverseDNSMu.Unlock()

	if _, ok := reverseDNSCache[ip]; ok {
		return true
	}

	// Evict oldest entries if cache is full
	if len(reverseDNSCache) >= reverseDNSCacheMax {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, t := range reverseDNSCache {
			if first || t.Before(oldestTime) {
				oldestKey = k
				oldestTime = t
				first = false
			}
		}
		if !first {
			delete(reverseDNSCache, oldestKey)
		}
	}

	reverseDNSCache[ip] = time.Now()
	return false
}

// reverseDNSResolver uses the system default resolver for PTR lookups.
var reverseDNSResolver = net.DefaultResolver

// processEvent handles a single blocked/allowed event from the ring buffer.
func processEvent(raw []byte, configMgr *config.Manager, notificationTracker *NotificationTracker,
	auditLogger *AuditLogger, fw FirewallUpdater, logger *slog.Logger,
) {
	if len(raw) < int(unsafe.Sizeof(BpfBlockedEvent{})) {
		return
	}
	event := (*BpfBlockedEvent)(unsafe.Pointer(&raw[0]))

	var srcIP, dstIP string

	switch event.IpVersion {
	case 6:
		srcIP = net.IP(event.SrcIp6[:]).String()
		dstIP = net.IP(event.DstIp6[:]).String()
	default:
		// IPv4 (version 4 or legacy events without version field)
		srcIP = fmt.Sprintf("%d.%d.%d.%d",
			(event.SrcIp>>24)&0xFF, (event.SrcIp>>16)&0xFF,
			(event.SrcIp>>8)&0xFF, event.SrcIp&0xFF)
		dstIP = fmt.Sprintf("%d.%d.%d.%d",
			(event.DstIp>>24)&0xFF, (event.DstIp>>16)&0xFF,
			(event.DstIp>>8)&0xFF, event.DstIp&0xFF)
	}

	// Look up hostname from config manager
	hostname := configMgr.LookupHostnameByIP(dstIP)
	if hostname == "" {
		logger.Debug("DNS cache miss", "ip", dstIP)
	} else {
		logger.Debug("DNS cache hit", "hostname", hostname, "ip", dstIP)
	}

	// Lazy reverse DNS for IPs not in the cache.
	// Each unique IP is only looked up once.
	if hostname == "" {
		if !reverseDNSAttempted(dstIP) {
			// Step 1: Try PTR lookup
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			names, err := reverseDNSResolver.LookupAddr(ctx, dstIP)
			cancel()
			if err == nil && len(names) > 0 {
				ptrName := strings.TrimSuffix(names[0], ".")
				// Try to match PTR result to a tracked hostname
				if tracked := configMgr.FindTrackedHostname(ptrName); tracked != "" {
					hostname = tracked
				} else {
					hostname = ptrName
				}
				configMgr.UpdateDNSMapping(hostname, dstIP)
				logger.Debug("Lazy reverse DNS resolved", "ip", dstIP, "hostname", hostname)
			}

			// Step 2: If PTR failed, try forward-matching all tracked hostnames
			if hostname == "" {
				if match := configMgr.ForwardMatchIP(dstIP); match != "" {
					hostname = match
					configMgr.UpdateDNSMapping(hostname, dstIP)
					logger.Debug("Forward DNS match resolved", "ip", dstIP, "hostname", hostname)
				}
			}
		}
	}

	// If we resolved a hostname and this was a BLOCKED event, check if the
	// hostname is actually allowed. If so, add the IP to the firewall so
	// subsequent connection retries succeed. This handles the case where a
	// process resolved DNS outside CargoWall's proxy (cached/stale results).
	if hostname != "" && event.Allowed == 0 && fw != nil {
		action := configMgr.GetTrackedHostnameAction(hostname)
		if action == config.ActionAllow {
			ip := net.ParseIP(dstIP)
			if ip != nil {
				if added, err := fw.AddIP(ip, config.ActionAllow, nil); err == nil && added {
					logger.Info("Late-resolved IP added to firewall",
						"ip", dstIP, "hostname", hostname)
				}
			}
		}
	}

	displayHostname := hostname
	if displayHostname == "" {
		displayHostname = dstIP
	}

	// Extract process info (name looked up from /proc since bpf_get_current_comm is unavailable in TC programs)
	pid := event.Pid
	comm := lookupProcessName(pid)

	if event.Allowed == 1 {
		// Allowed TCP SYN connection
		logger.Info("Connection allowed",
			"src", fmt.Sprintf("%s:%d", srcIP, event.SrcPort),
			"dst", displayHostname,
			"dst_ip", dstIP,
			"dst_port", event.DstPort,
			"process", comm,
			"pid", pid)

		if auditLogger != nil {
			if err := auditLogger.LogConnectionAllowed(srcIP, dstIP, hostname, event.DstPort, comm, pid); err != nil {
				logger.Error("Failed to write audit log", "error", err)
			}
		}
	} else if event.SrcPort == 0 && event.DstPort < 256 {
		// Non-TCP/UDP protocol block — dst_port contains the protocol number
		protocolName := getProtocolName(uint8(event.DstPort))
		logger.Info("Protocol blocked",
			"src", srcIP,
			"dst", displayHostname,
			"dst_ip", dstIP,
			"protocol", protocolName,
			"protocol_num", event.DstPort,
			"process", comm,
			"pid", pid,
			"timestamp", time.Now().Format("2006-01-02 15:04:05"))

		// Log to audit file if configured
		if auditLogger != nil {
			if err := auditLogger.LogProtocolBlocked(srcIP, dstIP, hostname, protocolName, comm, pid); err != nil {
				logger.Error("Failed to write audit log", "error", err)
			}
		}

		// Send notification if we have a tracker
		if notificationTracker != nil {
			notificationTracker.SendNotification(hostname, dstIP, event.DstPort)
		}
	} else {
		// Blocked TCP SYN or UDP connection
		logger.Info("Connection blocked",
			"src", fmt.Sprintf("%s:%d", srcIP, event.SrcPort),
			"dst", displayHostname,
			"dst_ip", dstIP,
			"dst_port", event.DstPort,
			"process", comm,
			"pid", pid,
			"timestamp", time.Now().Format("2006-01-02 15:04:05"))

		// Log to audit file if configured
		if auditLogger != nil {
			if err := auditLogger.LogConnectionBlocked(srcIP, dstIP, hostname, event.DstPort, comm, pid); err != nil {
				logger.Error("Failed to write audit log", "error", err)
			}
		}

		// Send notification if we have a tracker
		if notificationTracker != nil {
			notificationTracker.SendNotification(hostname, dstIP, event.DstPort)
		}
	}
}

// ProcessBlockedEvents processes blocked connection events
func ProcessBlockedEvents(rd *ringbuf.Reader, configMgr *config.Manager, notificationTracker *NotificationTracker, auditLogger *AuditLogger, fw FirewallUpdater, logger *slog.Logger) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Error("Failed to read from ring buffer", "error", err)
			continue
		}

		processEvent(record.RawSample, configMgr, notificationTracker, auditLogger, fw, logger)
	}
}
