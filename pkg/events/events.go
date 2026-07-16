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
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

// FirewallUpdater allows the event processor to dynamically add IPs to the firewall
// when lazy reverse DNS reveals a blocked IP belongs to an allowed hostname.
type FirewallUpdater interface {
	AddIP(ip net.IP, action config.Action, ports []config.Port) (bool, error)
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
	IpProto   uint8 // L4 protocol (unix.IPPROTO_TCP, _UDP, _ICMP, …)
	Pad1      uint8
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

// ipProtoToConfigProtocol maps the L4 protocol byte from a BpfBlockedEvent to
// the corresponding config.ProtocolType. The bool reports whether the proto
// is one we recognize; unknown protocols fail closed in dstPortAllowedByRule
// rather than mapping to ProtocolAll, so a future guard-loosening upstream
// can't silently widen the match.
func ipProtoToConfigProtocol(proto uint8) (config.ProtocolType, bool) {
	switch proto {
	case unix.IPPROTO_TCP:
		return config.ProtocolTCP, true
	case unix.IPPROTO_UDP:
		return config.ProtocolUDP, true
	case unix.IPPROTO_ICMP:
		return config.ProtocolICMP, true
	default:
		return "", false
	}
}

// dstPortAllowedByRule reports whether a (dstPort, proto) tuple would be
// permitted by an allow rule whose port restrictions are `ports`. An empty
// `ports` means the rule allows all ports. An unknown L4 proto fails closed
// (no overlap, even with ProtocolAll rules) — see ipProtoToConfigProtocol.
//
// Shares rulePortCovered with the late-allow reconciliation path, which
// reaches the same question from an audit-log protocol name rather than an L4
// byte: both decide "does this rule side cover the connection?", and the
// reconciler's mixed-verdict handling is only correct if it matches this one.
func dstPortAllowedByRule(dstPort uint16, proto uint8, ports []config.Port) bool {
	if len(ports) == 0 {
		return true
	}
	eventProto, ok := ipProtoToConfigProtocol(proto)
	if !ok {
		return false
	}
	return rulePortCovered(ports, dstPort, eventProto)
}

// rulePortCovered reports whether a rule-side port list covers (port, proto).
// An empty list means the side applies to all ports, matching rule semantics.
func rulePortCovered(ports []config.Port, port uint16, proto config.ProtocolType) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p.Port == port && config.ProtocolsOverlap(p.Protocol, proto) {
			return true
		}
	}
	return false
}

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
				// Lowercased so an unmatched PTR name is reported in the same
				// canonical case as forward mappings and tracked-rule matches,
				// keeping connection-event output consistent (#65). PTR replies
				// can carry mixed/0x20-randomized case off the wire.
				ptrName := strings.ToLower(strings.TrimSuffix(names[0], "."))
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

	// CNAME attribution: if this IP was reached as a CNAME target of an allowed
	// host (derived-allow enforcement recorded the chain — see
	// Manager.RecordCNAMEChain), report the connection under the origin hostname
	// the user actually allowed (chain[0]) and surface the full chain as a
	// drill-down field. For an edge IP shared by several allowed origins,
	// LookupCNAMEChain returns the most recently-resolved one. Done before the
	// late-allow block so a blocked derived connection on a non-inherited port
	// also attributes to the origin and runs the late-allow check against the
	// origin's rule. Setting hostname = chain[0] is a no-op when the resolved
	// hostname already is the origin (e.g. the IP was later re-mapped in-band),
	// but we still attach the chain so the drill-down isn't dropped.
	var cnameChain []string
	if chain := configMgr.LookupCNAMEChain(dstIP); len(chain) > 0 && chain[0] != "" {
		cnameChain = chain
		hostname = chain[0]
	}

	// Late-add: if a blocked event resolves to a hostname that's actually
	// allowed (e.g. process bypassed our DNS proxy with a cached IP), open the
	// firewall so future retries succeed. Only treat the triggering connection
	// itself as late-allowed when its dst_port is in the rule's allow set —
	// otherwise the retry will still be blocked and we'd misreport.
	//
	// Restricted to TCP/UDP because fw.AddIP exists to open BPF state for TCP
	// SYN / UDP retries; non-TCP/UDP events can't benefit and we don't want to
	// pollute the firewall or misreport as late-allowed.
	var lateAllowed bool
	var matchedRule string
	if hostname != "" && event.Allowed == 0 && fw != nil &&
		(event.IpProto == unix.IPPROTO_TCP || event.IpProto == unix.IPPROTO_UDP) {
		verdict := configMgr.MatchHostnameRule(hostname)
		if verdict.HasAllow() {
			matchedRule = verdict.AllowRule
			ip := net.ParseIP(dstIP)
			if ip != nil {
				// Write the deny side first (if any) so a mixed verdict —
				// e.g. `*.compute.internal: deny 80` + `bastion: allow 22`
				// — preserves the deny on its ports even though we're
				// opening the firewall for the allow side. Order doesn't
				// matter for correctness (per-port entries are
				// independent), but writing deny first makes the resulting
				// BPF state self-consistent if the allow write later
				// fails.
				if verdict.HasDeny() {
					if _, denyErr := fw.AddIP(ip, config.ActionDeny, verdict.DenyPorts); denyErr != nil {
						logger.Error("Late-resolved deny add failed",
							"ip", dstIP, "hostname", hostname, "error", denyErr)
					}
				}

				changed, err := fw.AddIP(ip, config.ActionAllow, verdict.AllowPorts)
				if err != nil {
					// Surface the failure for triage — the event will fall
					// through to the blocked branch (lateAllowed stays false),
					// so absence of this log + a "Connection blocked" entry
					// means the firewall write is the proximate cause.
					logger.Error("Late-resolved IP add failed",
						"ip", dstIP, "hostname", hostname, "error", err)
				} else {
					if changed {
						// `changed` covers both "IP was new" and "IP was
						// present but new per-port entries were written"
						// (shared-IP-different-ports case) — see
						// Firewall.AddIP contract.
						logger.Info("Late-resolved IP firewall state updated",
							"ip", dstIP, "hostname", hostname, "ports", verdict.AllowPorts)
					} else {
						// IP already in the BPF map with matching state —
						// useful when triaging "why didn't this connection
						// succeed on retry?".
						logger.Debug("Late-resolved IP already in firewall",
							"ip", dstIP, "hostname", hostname, "ports", verdict.AllowPorts)
					}
					// Best-effort prediction of "will the retry succeed?" from
					// this rule's own ports: FirewallImpl reconciles per-port
					// entries before the LPM no-op check, so on err==nil the
					// current rule's `ports` are in map_ports even when the IP
					// was already in the LPM from a different rule with disjoint
					// ports.
					//
					// For a mixed verdict (e.g. `*.foo: deny 80` + `bar:
					// allow all` on `bar.foo`), AllowPorts may be empty (all
					// ports) while DenyPorts covers the event's port. The
					// retry on that port will still be blocked by the deny
					// side's per-port BPF entry, so it is NOT late-allowed.
					//
					// Caveat: this looks only at THIS hostname's verdict, not at
					// other rules that resolved to the same shared IP. If that IP
					// already carries a conflicting all-ports grant (e.g. a
					// different all-ports-deny host shares it), the firewall's
					// PortSpecific=0 stickiness makes this rule's per-port entry
					// inert, so the audited late-allow/blocked label can diverge
					// from the actual BPF verdict for that edge. Enforcement is
					// unaffected — this only governs the audit/notification.
					allowMatches := dstPortAllowedByRule(event.DstPort, event.IpProto, verdict.AllowPorts)
					denyMatches := verdict.HasDeny() &&
						dstPortAllowedByRule(event.DstPort, event.IpProto, verdict.DenyPorts)
					lateAllowed = allowMatches && !denyMatches
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
		// Check if this connection was allowed by an auto-added rule.
		// Pass the event's L4 protocol so the port match is protocol-aware
		// (TCP/443 and UDP/443 rules don't conflate). Unknown protocols
		// fall back to ProtocolAll so the attribution doesn't regress for
		// non-TCP/UDP/ICMP traffic — the firewall already gated the
		// connection by the time we get here, this is just audit tagging.
		eventProto, ok := ipProtoToConfigProtocol(event.IpProto)
		if !ok {
			eventProto = config.ProtocolAll
		}
		autoAllowedType := string(configMgr.GetAutoAllowedType(dstIP, event.DstPort, eventProto, hostname))

		// Allowed TCP SYN connection
		logConnEvent(logger, "Connection allowed", cnameChain,
			"src", fmt.Sprintf("%s:%d", srcIP, event.SrcPort),
			"dst", displayHostname,
			"dst_ip", dstIP,
			"dst_port", event.DstPort,
			"process", comm,
			"pid", pid)

		if auditLogger != nil {
			if err := auditLogger.LogConnectionAllowed(srcIP, dstIP, hostname, event.DstPort, comm, pid, autoAllowedType, getProtocolName(event.IpProto), cnameChain); err != nil {
				logger.Error("Failed to write audit log", "error", err)
			}
		}
	} else if event.SrcPort == 0 && event.DstPort < 256 {
		// Non-TCP/UDP protocol block — dst_port contains the protocol number
		protocolName := getProtocolName(uint8(event.DstPort))
		logConnEvent(logger, "Protocol blocked", cnameChain,
			"src", srcIP,
			"dst", displayHostname,
			"dst_ip", dstIP,
			"protocol", protocolName,
			"protocol_num", event.DstPort,
			"process", comm,
			"pid", pid)

		// Log to audit file if configured
		if auditLogger != nil {
			if err := auditLogger.LogProtocolBlocked(srcIP, dstIP, hostname, protocolName, comm, pid, cnameChain); err != nil {
				logger.Error("Failed to write audit log", "error", err)
			}
		}

		// Send notification if we have a tracker
		if notificationTracker != nil {
			notificationTracker.SendNotification(hostname, dstIP, event.DstPort)
		}
	} else if lateAllowed {
		// Policy outcome is allow (the retry will succeed), so log accordingly
		// and skip the block notification. matchedRule is the rule's Value
		// (pattern string for glob rules, configured hostname for plain rules) —
		// distinct from displayHostname, which is the reported destination: the
		// CNAME origin when this IP was reached via an allowed host's chain,
		// otherwise the resolved hostname.
		logConnEvent(logger, "Connection late-allowed", cnameChain,
			"src", fmt.Sprintf("%s:%d", srcIP, event.SrcPort),
			"dst", displayHostname,
			"dst_ip", dstIP,
			"dst_port", event.DstPort,
			"process", comm,
			"pid", pid,
			"matched_rule", matchedRule)

		if auditLogger != nil {
			if err := auditLogger.LogConnectionLateAllowed(srcIP, dstIP, hostname, matchedRule, event.DstPort, comm, pid, getProtocolName(event.IpProto), cnameChain); err != nil {
				logger.Error("Failed to write audit log", "error", err)
			}
		}
	} else {
		// Blocked TCP SYN or UDP connection
		logConnEvent(logger, "Connection blocked", cnameChain,
			"src", fmt.Sprintf("%s:%d", srcIP, event.SrcPort),
			"dst", displayHostname,
			"dst_ip", dstIP,
			"dst_port", event.DstPort,
			"process", comm,
			"pid", pid)

		// Log to audit file if configured
		if auditLogger != nil {
			if err := auditLogger.LogConnectionBlocked(srcIP, dstIP, hostname, event.DstPort, comm, pid, getProtocolName(event.IpProto), cnameChain); err != nil {
				logger.Error("Failed to write audit log", "error", err)
			}
		}

		// Send notification if we have a tracker
		if notificationTracker != nil {
			notificationTracker.SendNotification(hostname, dstIP, event.DstPort)
		}
	}
}

// cnameLogAttr returns the slog key/value pair surfacing the CNAME drill-down
// chain (origin..target) for a derived-allow connection, or nil when there is no
// chain so normal connection events aren't annotated. The chain is passed as a
// []string so the live log carries the same shape as the audit/proto field
// rather than a pre-joined string.
func cnameLogAttr(chain []string) []any {
	if len(chain) == 0 {
		return nil
	}
	return []any{"cname_chain", chain}
}

// logConnEvent emits a connection event at Info, appending the CNAME drill-down
// attribute when present. Centralizes the append/cnameLogAttr wiring so every
// event type surfaces cname_chain consistently.
func logConnEvent(logger *slog.Logger, msg string, cnameChain []string, attrs ...any) {
	logger.Info(msg, append(attrs, cnameLogAttr(cnameChain)...)...)
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
