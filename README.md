# CargoWall

[![build](https://github.com/code-cargo/cargowall/actions/workflows/ci.yml/badge.svg)](https://github.com/code-cargo/cargowall/actions/workflows/ci.yml)
[![release](https://github.com/code-cargo/cargowall/actions/workflows/release.yml/badge.svg)](https://github.com/code-cargo/cargowall/actions/workflows/release.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**The firewall for GitHub Actions.**

CargoWall is an **eBPF-based network firewall for GitHub Actions runners** that monitors and controls outbound connections during CI/CD runs.

It protects your pipelines from **malicious actions, dependency supply chain attacks, and secret exfiltration** — without requiring changes to your workflows.

CargoWall is open source and built by the team behind CodeCargo.

---

# Why This Exists

Modern CI/CD pipelines run **untrusted code** every day.

Your workflows execute:

* third-party GitHub Actions
* package installers
* build tools
* test frameworks
* deployment scripts

All with access to **sensitive credentials**:

* cloud keys
* registry tokens
* deploy keys
* signing secrets

If one dependency or action is compromised, attackers can silently:

* exfiltrate secrets
* tamper with build artifacts
* push malicious releases

This has already happened across the ecosystem.

CI/CD pipelines are now **one of the largest attack surfaces in software delivery**.

CargoWall exists to **put a firewall in front of your pipeline.**

---

# What CargoWall Does

CargoWall runs inside the GitHub runner and:

* monitors all outbound network connections
* blocks unauthorized destinations
* detects unexpected network activity
* prevents secret exfiltration
* logs all external connections made by the workflow

This is enforced using **kernel-level eBPF hooks** for minimal overhead and strong enforcement.

---

# What Makes CargoWall Different

Most CI/CD security tools are **static scanners**.

CargoWall protects the pipeline **while it is running**.

* **Runtime network firewall** — not a static scanner, enforces policy while your workflow runs
* **Kernel-level eBPF enforcement** — TC egress filters in kernel space, not userspace proxies
* **Process attribution** — every connection is traced back to the process and PID that initiated it
* **Dynamic DNS resolution** — hostname rules are resolved at runtime via a local DNS proxy
* **Audit and enforce modes** — start with visibility, then switch to blocking when ready
* **NDJSON audit logs** — machine-readable logs for compliance evidence and SIEM integration

---

# Quick Start

Add CargoWall to your workflow.

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Run CargoWall
    uses: code-cargo/cargowall-action@v1
    with:
      audit_mode: false
    env:
      CARGOWALL_DEFAULT_ACTION: deny
      CARGOWALL_ALLOWED_HOSTS: "github.com:443,registry.npmjs.org:443"
      CARGOWALL_ALLOWED_CIDRS: "8.8.8.8/32:53,8.8.4.4/32:53"

  - name: Build
    run: make build
```

CargoWall will immediately begin monitoring and enforcing network policy during the run.

---

# Example: Detecting Unexpected Network Access

CargoWall writes NDJSON audit logs with full connection details:

```json
{"timestamp":"2026-03-16T12:00:01Z","event_type":"connection_allowed","dst_ip":"104.16.3.35","dst_hostname":"registry.npmjs.org","dst_port":443,"protocol":"TCP","process":"node","pid":1234,"would_deny":false,"blocked":false}
{"timestamp":"2026-03-16T12:00:02Z","event_type":"connection_blocked","dst_ip":"203.0.113.50","dst_hostname":"evil-exfil.example.com","dst_port":443,"protocol":"TCP/UDP","process":"curl","pid":1337,"matched_rule":"","would_deny":false,"blocked":true}
```

If a dependency attempts to connect to an unexpected host, CargoWall will detect and block it.

In **audit mode**, denied connections are logged with `"would_deny": true` but not blocked — useful for building your allowlist before switching to enforce mode.

---

# How It Works

1. The CargoWall GitHub Action installs the CargoWall runtime on the runner.
2. CargoWall attaches **eBPF TC (Traffic Control) egress filters** to the runner's network interface using [cilium/ebpf](https://github.com/cilium/ebpf).
3. A **local DNS proxy** intercepts DNS queries, resolving hostnames to IPs and dynamically populating the firewall rules.
4. Outbound packets are matched against an **LPM trie** (longest-prefix match) in kernel space for CIDR and port-based rules.
5. **Cgroup socket hooks** (`connect4`/`connect6`/`sendmsg4`/`sendmsg6`) track which process (PID) initiated each connection.
6. Events are delivered to userspace via a **ring buffer** and written to an NDJSON audit log with full process attribution.

CargoWall supports both **audit mode** (log only, no blocking) and **enforce mode** (actively block denied traffic).

All enforcement happens **inside the runner at the kernel level** — no iptables, no sidecar proxy.

---

# Configuration

CargoWall can be configured via **environment variables** or a **JSON config file**.

## Environment Variables

| Variable | Description |
| --- | --- |
| `CARGOWALL_DEFAULT_ACTION` | `allow` or `deny` (default: `deny`) |
| `CARGOWALL_ALLOWED_HOSTS` | Comma-separated hostnames with optional ports (e.g. `github.com:443`) |
| `CARGOWALL_BLOCKED_HOSTS` | Comma-separated hostnames to block |
| `CARGOWALL_ALLOWED_CIDRS` | Comma-separated CIDR blocks with optional ports (e.g. `10.0.0.0/8:443`) |
| `CARGOWALL_BLOCKED_CIDRS` | Comma-separated CIDR blocks to block |
| `CARGOWALL_AUDIT_MODE` | Set to `true` for log-only mode (no blocking) |
| `CARGOWALL_AUDIT_LOG` | Path to the NDJSON audit log file |

Port syntax: `hostname:port1;port2` or `cidr:port1;port2`. Omit ports to allow all.

## JSON Config File

For more complex policies, use a JSON config file (see `config.example.json`):

```json
{
  "defaultAction": "deny",
  "rules": [
    { "type": "hostname", "value": "github.com", "ports": [443], "action": "allow" },
    { "type": "hostname", "value": "registry.npmjs.org", "ports": [443], "action": "allow" },
    { "type": "cidr", "value": "8.8.8.8/32", "ports": [53], "action": "allow" },
    { "type": "cidr", "value": "192.168.1.0/24", "action": "allow" }
  ]
}
```

---

# Centralized Policy Management

With the **CodeCargo Freemium or Paid** editions, you can create and assign CargoWall policies entirely from the CodeCargo SaaS — no workflow files or runner configuration needed. Just keep the CargoWall Action in your workflow and manage everything else from the dashboard.

Policies are resolved using a **hierarchical inheritance model**:

* **Organization** — set baseline network rules across all repos
* **Repository** — override or extend the org policy for specific repos
* **Workflow** — refine rules for individual workflows
* **Job** — apply the most specific policy at the job level

Each level can **extend** the parent policy (merge rules) or **replace** it entirely. The CargoWall Action automatically fetches the resolved policy from the CodeCargo API at runtime.

---

# CodeCargo Platform

Sign up for the [CodeCargo platform](https://www.codecargo.com) for enterprise features like:

* **Centralized policy management** — create, assign, and inherit CargoWall policies from a dashboard
* **Organization-wide policies** with repo, workflow, and job-level overrides
* Role-based access control
* CI/CD governance and workflow run retention
* AI-powered capabilities including Multi-repo AI Editor, Self-service, AI Service Catalog, and Actions Insights

---

# Documentation

Full documentation:

[https://docs.codecargo.com/concepts/cargowall](https://docs.codecargo.com/concepts/cargowall)

---

# When Should You Use CargoWall?

CargoWall is especially valuable if you:

* rely on **third-party GitHub Actions**
* run CI/CD in **regulated environments**
* need **SOC2 / FedRAMP evidence for pipeline controls**
* want to prevent **CI/CD supply chain attacks**
* want visibility into **network activity during builds**

---

# The Bigger Picture

CargoWall is the **runtime security layer** of the CodeCargo platform.

CodeCargo adds:

* CI/CD governance
* workflow policy enforcement
* service catalog visibility
* developer self-service workflows
* AI-powered pipeline automation

CargoWall provides the **network firewall protecting workflow execution**.

---

# Built With

* [Go](https://go.dev/)
* [cilium/ebpf](https://github.com/cilium/ebpf) — eBPF program loading and map management
* [miekg/dns](https://github.com/miekg/dns) — DNS proxy for runtime hostname resolution

---

# Security

If you discover a vulnerability, please report it responsibly.

See [`SECURITY.md`](SECURITY.md) for details.

---

# License

Apache 2.0

---

# Links

GitHub Action
[https://github.com/code-cargo/cargowall-action](https://github.com/code-cargo/cargowall-action)

Documentation
[https://docs.codecargo.com/concepts/cargowall](https://docs.codecargo.com/concepts/cargowall)

CodeCargo
[https://codecargo.com](https://codecargo.com)

---

