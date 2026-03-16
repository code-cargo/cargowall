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

• monitors all outbound network connections
• blocks unauthorized destinations
• detects unexpected network activity
• prevents secret exfiltration
• logs all external connections made by the workflow

This is enforced using **kernel-level eBPF hooks** for minimal overhead and strong enforcement.

---

# What Makes CargoWall Different

Most CI/CD security tools are **static scanners**.

CargoWall protects the pipeline **while it is running**.

| Capability                             | CargoWall |
| -------------------------------------- | --------- |
| Runtime network firewall               | ✅         |
| eBPF kernel enforcement                | ✅         |
| Detect unexpected outbound connections | ✅         |
| Block malicious network activity       | ✅         |
| Visibility into CI/CD network behavior | ✅         |

---

# Quick Start

Add CargoWall to your workflow.

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Run CargoWall
    uses: code-cargo/cargowall-action@v1

  - name: Build
    run: make build
```

CargoWall will immediately begin monitoring network activity during the run.

---

# Example: Detecting Unexpected Network Access

CargoWall logs outbound connections made during a workflow:

```
process: npm
destination: registry.npmjs.org
port: 443
status: allowed
```

If a dependency suddenly attempts to connect to an unexpected host, CargoWall will detect it.

Policies can be configured to **block unknown destinations automatically**.

---

# How It Works

1. The CargoWall GitHub Action installs the CargoWall runtime.
2. CargoWall attaches **eBPF probes** to the runner.
3. Network connections are intercepted and evaluated.
4. Connections are **logged, allowed, or blocked**.

All enforcement happens **inside the runner during execution**.

---

# Editions

CargoWall is available in three editions.

---

## Community (Open Source)

Free and open source.

* Works with **public repositories**
* Network monitoring
* Local enforcement
* GitHub Action integration

Perfect for:

* open source maintainers
* public projects
* security experimentation

---

## CodeCargo Freemium

Requires installing the CodeCargo GitHub App.

Includes:

* up to **10 repositories**
* **7 days** workflow run retention
* centralized CargoWall policy control
* all users are **admins**
* CodeCargo **non-AI features**

---

## CodeCargo Paid

Full platform access.

Includes:

* unlimited repositories
* unlimited retention
* role-based access control
* organization-wide policies
* CI/CD governance platform
* **AI-powered CodeCargo capabilities**

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

# Security

If you discover a vulnerability, please report it responsibly.

See `SECURITY.md` for details.

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

## One more thing (important)

If you're launching this on GitHub, **the README can do even more work for you**. The best security repos now include:

1. **attack demo GIF**
2. **network graph screenshot**
3. **“blocked exfiltration” example**
4. **benchmark showing near-zero overhead**

Those dramatically increase **stars and adoption**.

If you want, I can also show you the **exact README structure used by repos that reached 5k–20k stars**, and adapt it specifically for **CargoWall**.
