# Design

Dual-stack (IPv4/IPv6) L4 firewall using TC eBPF egress filtering, cgroup socket hooks for PID tracking, an integrated DNS proxy for JIT hostname resolution, and an audit mode for log-only operation.

## Key Features

- **Dual-Stack L4 Firewall**: Filters TCP and UDP traffic on both IPv4 and IPv6
- **Protocol Handling**: Blocks non-TCP/UDP on IPv4; allows ICMPv6 and IPv6 multicast (`ff00::/8`); passes non-IP traffic (ARP)
- **DNS Proxy with JIT Resolution**: Intercepts DNS queries and updates firewall rules in real-time
- **DNS Query Filtering**: Blocks queries for non-allowed domains to prevent DNS tunneling
- **Port-Specific Rules**: Granular port-based filtering including wildcard CIDRs (`0.0.0.0/0`, `::/0`)
- **LPM Trie Optimization**: Separate IPv4 and IPv6 longest-prefix-match tries for efficient CIDR lookups
- **Process/PID Tracking**: Cgroup socket hooks map socket cookies to PIDs for per-process attribution
- **Audit Mode**: Log-only mode — events are emitted but traffic is never dropped
- **Audit Logging**: NDJSON log file with structured event records
- **Real-time Monitoring**: Ring buffer event stream with notification deduplication via state machine
- **DNS LRU Cache**: 10,000-entry cache with lazy TTL eviction
- **VLAN Support**: Handles 802.1Q and QinQ (802.1ad) tagged frames
- **Docker Integration**: Listens on bridge IP, configures daemon DNS
- **GitHub Actions Integration**: Auto-infrastructure discovery, iptables DNS redirect, sudo lockdown
- **Kubernetes Integration**: Search domain stripping, configurable upstream DNS

## Architecture Overview

```mermaid
flowchart TD
    APP[Application]
    UP[Upstream DNS]

    subgraph "User Space"
        DNS["DNS Proxy<br/>LRU Cache · Query Filter<br/>127.0.0.1:53"]
        UC[CargoWall Controller]
        CM[Config Manager]
        FW[Firewall Manager]
        EH[Event Handler]
        NT[Notification Tracker]
        AL[Audit Logger]
    end

    subgraph "Kernel Space"
        EG[tc_egress<br/>Egress Classifier]
        CG["Cgroup Hooks<br/>connect4/6, sendmsg4/6"]
    end

    subgraph "eBPF Maps"
        CIDRS["CIDR LPM Tries<br/>IPv4 + IPv6"]
        PORTS["Port Maps<br/>IPv4 + IPv6"]
        CFG["Config Maps<br/>default action, audit mode"]
        SP[map_sock_pid<br/>Socket→PID LRU]
        RB[map_events<br/>Ring Buffer]
    end

    SM[State Machine]

    APP -->|DNS Query| DNS
    DNS -->|Response| APP
    DNS -->|Cache Miss| UP
    UP -->|Response| DNS
    DNS -->|Check Domain| CM
    DNS -->|JIT Update| FW

    UC --> CM
    UC --> FW
    CM --> FW
    FW -.->|Update| CIDRS
    FW -.->|Update| PORTS
    UC -.->|Set| CFG

    CG -.->|Write| SP
    EG -->|Read| SP
    EG -->|Lookup| CIDRS
    EG -->|Lookup| PORTS
    EG -->|Lookup| CFG
    EG -->|Emit| RB

    EH <-.->|Read| RB
    EH --> AL
    EH --> NT
    NT -->|Notify| SM
```

## Packet Processing Flow (eBPF TC Egress)

### Main Dispatch

```mermaid
flowchart TD
    Start([Packet Arrives])
    ParseEth[Parse Ethernet Header]
    IsVLAN{802.1Q<br/>VLAN Tag?}
    StripVLAN[Read VLAN TCI<br/>Advance l3_offset +4]
    IsQinQ{QinQ<br/>Second Tag?}
    StripQinQ[Read Inner TCI<br/>Advance l3_offset +4]
    CheckProto{EtherType?}

    IPv4Path[Handle IPv4]
    IPv6Path[Handle IPv6]
    AllowOther([Allow Packet<br/>TC_ACT_OK])

    Start --> ParseEth
    ParseEth --> IsVLAN
    IsVLAN -->|Yes| StripVLAN
    StripVLAN --> IsQinQ
    IsQinQ -->|Yes| StripQinQ
    StripQinQ --> CheckProto
    IsQinQ -->|No| CheckProto
    IsVLAN -->|No| CheckProto
    CheckProto -->|ETH_P_IP| IPv4Path
    CheckProto -->|ETH_P_IPV6| IPv6Path
    CheckProto -->|Other<br/>ARP, etc.| AllowOther
```

### IPv4 Path

```mermaid
flowchart TD
    ParseIP[Parse IPv4 Header<br/>Validate IHL]
    IsFrag{Fragmented?<br/>Non-first frag}
    AllowFrag([Allow Fragment<br/>TC_ACT_OK])
    IsTCPUDP{Protocol?}
    BlockProto[Emit Protocol Block Event]
    BlockShot([Block<br/>TC_ACT_SHOT])
    ParsePorts[Extract src/dst Ports]

    LPMLookup["LPM Trie Lookup<br/>map_cidrs (dst_ip/32)"]
    HasRule{Found<br/>Matching<br/>CIDR?}

    IsPortSpecific{port_specific<br/>flag set?}
    CheckPort["Check Port Map<br/>map_ports (ip:port)"]
    HasPortRule{Found<br/>Port Rule?}

    CheckWildcard["Check Wildcard<br/>map_ports (0.0.0.0:port)"]
    HasWildcard{Found<br/>Wildcard?}

    CheckDefault["Check Default Action<br/>map_default_action"]
    IsAllowed{action == allow?}

    AuditCheck{Audit Mode?<br/>map_audit_mode}
    EmitAllow[Emit Allowed Event<br/>with PID from map_sock_pid]
    EmitBlock[Emit Blocked Event<br/>with PID from map_sock_pid]
    EmitAudit[Emit Blocked Event<br/>with PID from map_sock_pid]
    Allow([Allow Packet<br/>TC_ACT_OK])
    Block([Block Packet<br/>TC_ACT_SHOT])
    AuditAllow([Audit: Allow Packet<br/>TC_ACT_OK])

    ParseIP --> IsFrag
    IsFrag -->|Yes| AllowFrag
    IsFrag -->|No| IsTCPUDP
    IsTCPUDP -->|Other| BlockProto
    BlockProto --> BlockShot
    IsTCPUDP -->|TCP/UDP| ParsePorts

    ParsePorts --> LPMLookup
    LPMLookup --> HasRule
    HasRule -->|Yes| IsPortSpecific
    HasRule -->|No| CheckWildcard

    IsPortSpecific -->|No| IsAllowed
    IsPortSpecific -->|Yes| CheckPort
    CheckPort --> HasPortRule
    HasPortRule -->|Yes| IsAllowed
    HasPortRule -->|No| CheckWildcard

    CheckWildcard --> HasWildcard
    HasWildcard -->|Yes| IsAllowed
    HasWildcard -->|No| CheckDefault

    CheckDefault --> IsAllowed
    IsAllowed -->|Yes| EmitAllow --> Allow
    IsAllowed -->|No| AuditCheck
    AuditCheck -->|Enforce| EmitBlock --> Block
    AuditCheck -->|Audit| EmitAudit --> AuditAllow
```

### IPv6 Path

```mermaid
flowchart TD
    ParseIPv6[Parse IPv6 Header<br/>Fixed 40 bytes]
    IsMulticast{"Multicast?<br/>ff00::/8"}
    AllowMcast([Allow Multicast<br/>TC_ACT_OK])

    WalkExtHdr["Walk Extension Headers<br/>(max 6 iterations)<br/>Hop-by-Hop, Routing,<br/>Fragment, Dest Options,<br/>Mobility"]
    IsICMPv6{ICMPv6?}
    AllowICMP([Allow ICMPv6<br/>TC_ACT_OK])
    IsTCPUDP{TCP/UDP?}
    BlockProto[Emit Protocol Block Event]
    BlockShot([Block<br/>TC_ACT_SHOT])
    ParsePorts[Extract src/dst Ports]

    LPMLookup["LPM Trie Lookup<br/>map_cidrs_v6 (dst_ip6/128)"]
    HasRule{Found<br/>Matching<br/>CIDR?}

    IsPortSpecific{port_specific<br/>flag set?}
    CheckPort["Check Port Map<br/>map_ports_v6 (ip6:port)"]
    HasPortRule{Found<br/>Port Rule?}

    CheckWildcard["Check Wildcard<br/>map_ports_v6 (:::port)"]
    HasWildcard{Found<br/>Wildcard?}

    CheckDefault["Check Default Action<br/>map_default_action"]
    Decision["Same decision tree as IPv4<br/>(action → audit check → emit event)"]

    ParseIPv6 --> IsMulticast
    IsMulticast -->|Yes| AllowMcast
    IsMulticast -->|No| WalkExtHdr
    WalkExtHdr --> IsICMPv6
    IsICMPv6 -->|Yes| AllowICMP
    IsICMPv6 -->|No| IsTCPUDP
    IsTCPUDP -->|Other| BlockProto
    BlockProto --> BlockShot
    IsTCPUDP -->|TCP/UDP| ParsePorts

    ParsePorts --> LPMLookup
    LPMLookup --> HasRule
    HasRule -->|Yes| IsPortSpecific
    HasRule -->|No| CheckWildcard

    IsPortSpecific -->|No| Decision
    IsPortSpecific -->|Yes| CheckPort
    CheckPort --> HasPortRule
    HasPortRule -->|Yes| Decision
    HasPortRule -->|No| CheckWildcard

    CheckWildcard --> HasWildcard
    HasWildcard -->|Yes| Decision
    HasWildcard -->|No| CheckDefault
    CheckDefault --> Decision
```

## eBPF Map Data Structures

```mermaid
classDiagram
    class LPM_Key {
        +uint32 prefixlen
        +uint32 ip
    }

    class LPM_Key_V6 {
        +uint32 prefixlen
        +uint8 ip[16]
    }

    class LPM_Val {
        +uint8 action
        +uint8 port_specific
        +uint16 pad
    }

    class Port_Key {
        +uint32 ip
        +uint16 port
        +uint16 pad
    }

    class Port_Key_V6 {
        +uint8 ip[16]
        +uint16 port
        +uint16 pad
    }

    class Port_Val {
        +uint8 action
        +uint8 pad[3]
    }

    class Blocked_Event {
        +uint8 ip_version
        +uint8 allowed
        +uint8 pad1[2]
        +uint32 src_ip
        +uint32 dst_ip
        +uint16 src_port
        +uint16 dst_port
        +uint8 src_ip6[16]
        +uint8 dst_ip6[16]
        +uint64 timestamp
        +uint32 pid
        +uint32 _pad2
    }
    note for Blocked_Event "64 bytes total\nip_version: 4 or 6\nallowed: 0=blocked, 1=allowed\ntimestamp: bpf_ktime_get_ns()\npid: from map_sock_pid via socket cookie"

    class Default_Action {
        +uint8 action
    }
```

## DNS Proxy JIT Resolution Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant DNS as DNS Proxy<br/>(127.0.0.1:53)
    participant QF as Query Filter
    participant Cache as LRU Cache<br/>(10K entries)
    participant UP as Configurable<br/>Upstream DNS
    participant CM as Config Manager
    participant FW as Firewall Manager
    participant BPF as eBPF Maps

    App->>DNS: DNS Query<br/>(e.g., github.com)

    DNS->>QF: Check domain allowed?
    alt Domain blocked
        QF-->>DNS: REFUSED
        DNS->>App: REFUSED (or allowed in audit mode)
    end

    DNS->>Cache: Lookup cached response
    alt Cache hit (TTL valid)
        Cache-->>DNS: Cached response
    else Cache miss or expired
        DNS->>UP: Forward query
        UP->>DNS: DNS Response<br/>(IPs + TTL)
        DNS->>Cache: Store response<br/>(min TTL from answers)
    end

    DNS->>CM: Check if hostname<br/>is tracked
    CM-->>DNS: Action if tracked

    alt Hostname is tracked
        DNS->>CM: Check CIDR rule conflict
        CM-->>DNS: Resolved action

        DNS->>FW: AddIP(ip, action, ports)
        FW->>BPF: Update LPM Trie
        FW->>BPF: Update Port Map
    end

    DNS->>App: DNS Response

    Note over Cache: No cleanup timer.<br/>Lazy eviction on access<br/>and LRU capacity limit.
```

## Component Responsibilities

### Firewall Manager (`pkg/firewall`)
- Manages 8 eBPF maps: `map_cidrs`, `map_cidrs_v6`, `map_ports`, `map_ports_v6`, `map_default_action`, `map_audit_mode`, `map_events`, `map_sock_pid`
- Separate IPv4/IPv6 methods (`addCIDRv4`, `addCIDRv6`) with appropriate key types
- `SetDefaultAction(action)` — sets `map_default_action[0]` to 0 (deny) or 1 (allow)
- `SetAuditMode(enabled)` — sets `map_audit_mode[0]` to 0 (enforce) or 1 (audit)
- `AddIP(ip, action, ports)` — adds /32 or /128 entry with duplicate detection; returns whether entry was added
- `RemoveIP(ip)` — removes LPM entry and all associated port map entries
- Wildcard CIDR handling: `0.0.0.0/0` and `::/0` with specific ports add only port map entries (no LPM entry)
- Tracks IP-to-port associations (`ipPorts` map) for accurate cleanup on removal
- Thread-safe with `sync.RWMutex`

### DNS Proxy Server (`pkg/dns`)
- Primary listen address `127.0.0.1:53`, with additional addresses (e.g., Docker bridge IP) via `AddListenAddr()`
- Configurable upstream DNS (e.g., `10.96.0.10:53` for Kubernetes)
- LRU cache (10,000 entries) with per-entry TTL from DNS response minimum TTL
- DNS query filtering (`EnableQueryFiltering`) — blocks queries for non-allowed domains; always allows reverse DNS (`in-addr.arpa`, `ip6.arpa`)
- `ApplyRulesToTrackedHostnames()` — re-evaluates all accumulated IPs against current config after rule changes
- Rule conflict detection: checks CIDR vs hostname action conflicts via `CheckIPRuleConflict()`; deny wins
- Kubernetes search domain stripping (`.default.svc.cluster.local`, `.svc.cluster.local`, `.cluster.local`)
- Accumulates IPs per hostname across responses for round-robin DNS support
- Audit logging of blocked DNS queries

### Config Manager (`pkg/config`)
- Multiple config sources with priority: API > env vars > file > protobuf hook
  - Env vars: `CARGOWALL_DEFAULT_ACTION`, `CARGOWALL_ALLOWED_HOSTS`, `CARGOWALL_ALLOWED_CIDRS`, `CARGOWALL_BLOCKED_HOSTS`, `CARGOWALL_BLOCKED_CIDRS`
  - Port format in env: `host:port1;port2` (e.g., `github.com:443;80`)
- Subdomain matching: `lb-140-82-113-22-iad.github.com` matches a `github.com` rule
- Wildcard hostname normalization: `*.github.com` → `github.com` (parent domain matching handles subdomains)
- IP-to-hostname reverse mapping via `UpdateDNSMapping()` with bounded cache (10,000 entries, 24h TTL)
- Rule conflict detection: `CheckIPRuleConflict()` finds most specific CIDR by prefix length, checks port overlap, deny wins
- `EnsureDNSAllowed(ips)` — adds /32 allow rules on port 53 for upstream DNS IPs
- `EnsureInfraAllowed(ips, ports)` — adds allow rules for infrastructure (Azure IMDS, K8s API, etc.)
- `EnsureHostnameAllowed(hostname)` — adds hostname allow rule for auto-discovered infrastructure

### Event Handler (`pkg/events`)
- Processes both blocked and allowed events from ring buffer (`ip_version`, `allowed`, ports, IPs)
- PID tracking: reads `pid` field (populated by cgroup programs via `map_sock_pid`), resolves process name from `/proc/<pid>/comm`
- Lazy reverse DNS: bounded cache (10,000 entries), one PTR attempt per unique IP (500ms timeout), falls back to forward-matching tracked hostnames
- Late-resolved IP addition: if a blocked event resolves to an allowed hostname, adds the IP to the firewall on the fly
- Audit logging via `AuditLogger` — NDJSON with `would_deny`/`blocked` flags based on audit mode
- Notification deduplication: one notification per unique destination (`hostname:port` or `ip:port`) via `NotificationTracker`

## eBPF Programs

| Program | Attach Type | Purpose |
|---------|------------|---------|
| `tc_egress` | TC (classifier/egress) | Main egress filter — IPv4/IPv6 packet classification and filtering |
| `tc_ingress` | TC (classifier/ingress) | Defined but not attached; stub that allows all traffic |
| `cg_connect4` | cgroup/connect4 | Maps IPv4 TCP socket cookie → PID |
| `cg_connect6` | cgroup/connect6 | Maps IPv6 TCP socket cookie → PID |
| `cg_sendmsg4` | cgroup/sendmsg4 | Maps IPv4 UDP socket cookie → PID |
| `cg_sendmsg6` | cgroup/sendmsg6 | Maps IPv6 UDP socket cookie → PID |

## Audit Mode

Audit mode allows CargoWall to run in a log-only configuration — all traffic decisions are recorded but no packets are dropped.

**Activation:**
- CLI flag at startup
- Environment variable: `CARGOWALL_AUDIT_MODE=true`
- API policy configuration

**BPF behavior:**
- `map_audit_mode[0]` is set to `1` (audit) or `0` (enforce)
- In audit mode, `tc_egress` returns `TC_ACT_OK` instead of `TC_ACT_SHOT` for would-be-blocked traffic
- Events are still emitted to the ring buffer with the same `allowed` field semantics

**DNS behavior:**
- Blocked DNS queries are logged but still forwarded to upstream
- Query filter returns the upstream response instead of `REFUSED`

**Audit log:**
- NDJSON format, one JSON object per line
- Each event includes `would_deny` (true in audit mode) and `blocked` (true in enforce mode) flags
- Event types: `connection_blocked`, `connection_allowed`, `protocol_blocked`, `dns_blocked`, `existing_connection`

## Kubernetes Integration

```yaml
# Pod DNS Configuration
dnsPolicy: None
dnsConfig:
  nameservers: ["127.0.0.1"]  # Use CargoWall DNS proxy
  searches:
    - "default.svc.cluster.local"
    - "svc.cluster.local"
    - "cluster.local"
  options:
    - name: ndots
      value: "5"
```

The DNS proxy handles Kubernetes service discovery by:
1. Supporting search domains for short service names
2. Stripping common suffixes (`.default.svc.cluster.local`, `.svc.cluster.local`, `.cluster.local`) when checking rules
3. Allowing rules to match both short and FQDN formats
4. Upstream DNS is configurable (e.g., `10.96.0.10:53` for kube-dns)

## Docker Integration

- `GetDockerBridgeIP()` discovers the `docker0` bridge address (typically `172.17.0.1`)
- DNS proxy listens on the bridge IP in addition to `127.0.0.1:53` so containers can resolve through CargoWall
- `ConfigureDockerDNS(bridgeIP)` writes `{"dns": ["<bridgeIP>"]}` to `/etc/docker/daemon.json` (with backup)
- Docker daemon requires a full restart (`systemctl restart docker`) for DNS changes — SIGHUP is not sufficient
- `RestoreDockerDNS()` restores the original daemon.json from backup on shutdown

## GitHub Actions Integration

- **DNS redirect:** iptables DNAT rules redirect all outbound DNS (port 53) to `127.0.0.1:53`, exempting the proxy's own upstream queries via `SO_MARK` (`0xCA12`)
- **Sudo lockdown:** writes `/etc/sudoers.d/cargowall-lockdown` with a NOPASSWD allowlist; removes the runner user from the `docker` group
- **Auto-infrastructure:** `EnsureInfraAllowed()` and `EnsureHostnameAllowed()` add rules for platform services (Azure IMDS, GitHub API, etc.)
- **Logging:** `slog.Handler` that formats messages as GitHub workflow commands (`::error::`, `::warning::`, `::debug::`)
