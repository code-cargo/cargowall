# Design

Leverages TC (Traffic Control) eBPF programs for efficient packet processing and egress filtering with integrated DNS proxy for Just-In-Time (JIT) hostname resolution.

## Key Features

- **L4 Firewall**: Filters TCP and UDP traffic based on CIDR blocks and hostnames
- **Protocol Blocking**: Blocks all non-TCP/UDP protocols (ICMP, IGMP, GRE, etc.) for security
- **DNS Proxy with JIT Resolution**: Intercepts DNS queries and updates firewall rules in real-time
- **Port-Specific Rules**: Support for granular port-based filtering
- **LPM Trie Optimization**: Uses Longest Prefix Match for efficient CIDR lookups
- **Real-time Monitoring**: Tracks blocked connections and sends notifications
- **TTL-Based Cleanup**: Automatically removes expired IPs based on DNS TTL values
- **Kubernetes Integration**: Supports Kubernetes service discovery and search domains

## Architecture Overview

```mermaid
graph TB
    subgraph "User Space"
        UC[CargoWall Controller]
        CM[Config Manager]
        FW[Firewall Manager]
        DNS[DNS Proxy Server<br/>:53]
        EH[Event Handler]
        NT[Notification Tracker]
    end

    subgraph "Kernel Space"
        TC[TC eBPF Programs]
        EG[Egress Classifier]
        IG[Ingress Classifier]
    end

    subgraph "eBPF Maps"
        LPM[LPM Trie Map<br/>CIDR + Hostname IPs]
        PM[Port Map<br/>Port-Specific Rules]
        DA[Default Action Map]
        RB[Events Ring Buffer<br/>Blocked Connections]
    end

    subgraph "External"
        APP[Application]
        UP[Upstream DNS<br/>10.96.0.10:53]
        SM[State Machine]
    end

    APP -->|DNS Query| DNS
    DNS -->|Forward| UP
    UP -->|Response| DNS
    DNS -->|Response| APP
    DNS -->|JIT Update| FW

    UC --> CM
    UC --> FW
    CM --> FW
    FW -.->|Update| LPM
    FW -.->|Update| PM
    UC -.->|Set Default| DA

    TC --> EG
    TC --> IG

    EG -->|Lookup| LPM
    EG -->|Lookup| PM
    EG -->|Lookup| DA
    EG -->|Log| RB

    EH <-.->|Read| RB
    EH --> NT
    NT -->|Notify| SM
```

## Packet Processing Flow (eBPF TC Program)

```mermaid
flowchart TD
    Start([Packet Arrives])
    ParseEth[Parse Ethernet Header]
    IsIP{Is IPv4?}
    ParseIP[Parse IP Header]
    IsTCPUDP{Is TCP/UDP?}
    ParsePorts[Extract Ports]

    LPMLookup[LPM Trie Lookup<br/>for Destination IP]
    HasRule{Found<br/>Matching<br/>CIDR?}

    IsPortSpecific{Port<br/>Specific<br/>Rule?}
    CheckPort[Check Port Map<br/>IP:Port]
    HasPortRule{Found<br/>Port Rule?}

    CheckWildcard[Check Wildcard<br/>0.0.0.0:Port]
    HasWildcard{Found<br/>Wildcard?}

    CheckDefault[Check Default<br/>Action]
    IsAllowed{Allowed?}

    Allow([Allow Packet<br/>TC_ACT_OK])
    Block([Block Packet<br/>TC_ACT_SHOT])
    LogBlock[Log Blocked Event<br/>to Ring Buffer]

    Start --> ParseEth
    ParseEth --> IsIP
    IsIP -->|No| Allow
    IsIP -->|Yes| ParseIP
    ParseIP --> IsTCPUDP
    IsTCPUDP -->|No| BlockProtocol[Log Blocked Protocol<br/>to Ring Buffer]
    IsTCPUDP -->|Yes| ParsePorts
    BlockProtocol --> Block
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
    IsAllowed -->|Yes| Allow
    IsAllowed -->|No| LogBlock
    LogBlock --> Block
```

## eBPF Map Data Structures

```mermaid
classDiagram
    class LPM_Key {
        +uint32 prefixlen
        +uint32 ip
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

    class Port_Val {
        +uint8 action
        +uint8 pad[3]
    }

    class Blocked_Event {
        +uint32 src_ip
        +uint32 dst_ip
        +uint16 src_port
        +uint16 dst_port
        +uint32 pad
        +uint64 timestamp
    }

    class Default_Action {
        +uint8 action
    }
```

## DNS Proxy JIT Resolution Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant DNS as DNS Proxy<br/>(:53)
    participant UP as Upstream DNS
    participant CM as Config Manager
    participant FW as Firewall Manager
    participant BPF as eBPF Maps

    App->>DNS: DNS Query<br/>(e.g., github.com)
    DNS->>UP: Forward Query
    UP->>DNS: DNS Response<br/>(IPs + TTL)
    DNS->>CM: Check if hostname<br/>is tracked
    CM-->>DNS: Action if tracked

    alt Hostname is tracked
        DNS->>FW: AddIP(ip, action, ports)
        FW->>BPF: Update LPM Trie
        FW->>BPF: Update Port Map
        FW-->>DNS: Success
        DNS->>DNS: Track TTL<br/>for cleanup
    end

    DNS->>App: DNS Response

    Note over DNS: TTL Cleanup Timer
    DNS->>FW: RemoveIP(expired)
    FW->>BPF: Delete from LPM
```

## Component Responsibilities

### Firewall Manager (`pkg/firewall`)
- Owns and manages eBPF maps
- Thread-safe operations with mutex protection
- Provides AddIP/RemoveIP interface
- Handles duplicate detection
- Updates both LPM trie and port maps

### DNS Proxy Server (`pkg/dns`)
- Listens on 127.0.0.1:53
- Intercepts all DNS queries from pod
- Forwards to upstream (default: 10.96.0.10:53)
- JIT updates firewall for tracked hostnames
- Manages TTL-based cleanup
- Supports Kubernetes search domains

### Config Manager (`pkg/config`)
- Loads configuration from file or state machine
- Tracks hostname rules without pre-resolution
- Manages DNS cache for IP-to-hostname lookups
- Detects rule conflicts
- Provides resolved rules for initial setup

### Event Handler (`pkg/events`)
- Processes blocked connection events from ring buffer
- Logs protocol blocks (non-TCP/UDP)

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
2. Stripping common suffixes when checking rules
3. Allowing rules to match both short and FQDN formats
