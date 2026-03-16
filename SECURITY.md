# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in CargoWall, please report it through [GitHub Security Advisories](https://github.com/code-cargo/cargowall/security/advisories/new).

Please include:

* A description of the vulnerability
* Steps to reproduce
* Any relevant logs or screenshots

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation plan within 7 business days.

## Scope

This policy applies to the CargoWall open source project and its components:

* eBPF programs (`bpf/`)
* Userspace daemon (`cmd/`, `pkg/`)
* DNS proxy (`pkg/dns/`)
* Configuration handling (`pkg/config/`)

For vulnerabilities in the CodeCargo platform or GitHub Action, please use the same email address.

## Supported Versions

Security fixes are applied to the latest release only.
