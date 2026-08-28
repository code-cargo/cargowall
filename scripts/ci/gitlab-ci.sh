#!/usr/bin/env bash
#   Copyright 2026 BoxBuild Inc DBA CodeCargo
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

# Body of the test-cargowall-gitlab-ci CI job. ci.yml stays wiring: one
# workflow step per subcommand (wait-ready and the log dump stay one-line
# steps in the YAML).
#
# Usage: gitlab-ci.sh <subcommand>

set -euo pipefail

policy() {
  sudo mkdir -p /etc/cargowall
  sudo tee /etc/cargowall/config.json > /dev/null <<'JSON'
{
  "defaultAction": "deny",
  "rules": [
    {
      "type": "hostname",
      "value": "github.com",
      "ports": [{"port": 443, "protocol": "tcp"}],
      "action": "allow"
    },
    {
      "type": "cidr",
      "value": "8.8.8.8/32",
      "ports": [{"port": 53, "protocol": "udp"}],
      "action": "allow"
    }
  ],
  "searchDomains": [".compute.internal"]
}
JSON
}

# nohup + & + disown lets cargowall outlive this step's shell. The
# privileged-Docker stand-in for GitLab SaaS doesn't exist on GitHub
# Actions runners, so we exercise the same code path on the Azure-backed
# Linux runner — eBPF + sudo + iptables work the same.
start() {
  sudo nohup ./bin/cargowall start \
    --gitlab-ci \
    --audit-mode \
    --audit-log /tmp/cargowall-audit.json \
    --pidfile /tmp/cargowall.pid \
    --dns-upstream "8.8.8.8:53" \
    --debug \
    > /tmp/cargowall.log 2>&1 &
  disown
}

# On the Azure runner the client resolver is systemd-resolved, whose warm
# stub cache used to serve pre-attach answers invisibly (#89). With the DNS
# redirect active (--gitlab-ci preset), cargowall flushes that cache at
# attach so future lookups traverse the proxy. Assert the
# FlushResolvedCache path executed — the flush itself on a resolved host,
# or the documented best-effort skip elsewhere.
verify_flush() {
  if sudo grep -q "Flushed systemd-resolved DNS cache" /tmp/cargowall.log; then
    echo "✅ resolved cache flushed at attach"
  elif sudo grep -qE "systemd-resolved not running|resolvectl not found" /tmp/cargowall.log; then
    echo "ℹ️ systemd-resolved not in use on this runner; flush correctly skipped"
  else
    echo "❌ neither flush nor skip logged — FlushResolvedCache path not reached"
    sudo grep -iE "resolv|flush|dns redirect" /tmp/cargowall.log || true
    exit 1
  fi
}

verify_pidfile() {
  if ! sudo test -s /tmp/cargowall.pid; then
    echo "❌ pidfile /tmp/cargowall.pid was not written"
    exit 1
  fi
  echo "✅ pidfile present, pid=$(sudo cat /tmp/cargowall.pid)"
}

allowed() {
  curl -sf --connect-timeout 10 --max-time 30 https://github.com > /dev/null
  echo "✅ github.com reachable"
}

disallowed() {
  curl -sf --connect-timeout 5 --max-time 10 https://example.com > /dev/null || true
  echo "✅ example.com fetch attempted (audit mode does not block)"
}

# `.compute.internal` is configured as a search domain (see policy). A
# query for a name under that suffix with no matching hostname rule should
# pass cargowall's filter via the bypass. In audit mode this means: no
# dns_blocked event is logged for it. The upstream will return NXDOMAIN for
# an ephemeral name like this, which is fine — we only care about
# cargowall's verdict.
dns_bypass() {
  dig +time=5 +tries=1 @127.0.0.1 ip-10-0-0-5.us-west-2.compute.internal A > /tmp/bypass-query.log 2>&1 || true
  cat /tmp/bypass-query.log
  echo "✅ search-domain query issued"
}

# No hostname rule, no search-domain match — cargowall should log this as
# dns_blocked-would (audit mode lets the query through but records the
# would-be-deny).
dns_control() {
  dig +time=5 +tries=1 @127.0.0.1 nonexistent.example.org A > /tmp/blocked-query.log 2>&1 || true
  cat /tmp/blocked-query.log
  echo "✅ control query issued"
}

verify_dns_verdicts() {
  AUDIT_LOG=/tmp/cargowall-audit.json
  if ! sudo test -s "$AUDIT_LOG"; then
    echo "❌ Audit log not written"
    exit 1
  fi

  # The bypassed query must NOT appear in dns_blocked events.
  BYPASSED_LOGGED=$(sudo jq -s '[
    .[] | select(.event_type == "dns_blocked")
        | select((.dst_hostname // "") | contains("compute.internal"))
  ] | length' "$AUDIT_LOG")
  if [ "$BYPASSED_LOGGED" -ne 0 ]; then
    echo "❌ search-domain query incorrectly logged as dns_blocked ($BYPASSED_LOGGED entries)"
    sudo jq -s '.[] | select(.event_type == "dns_blocked")' "$AUDIT_LOG"
    exit 1
  fi
  echo "✅ search-domain query not in dns_blocked log"

  # The control query MUST appear in dns_blocked.
  BLOCKED_LOGGED=$(sudo jq -s '[
    .[] | select(.event_type == "dns_blocked")
        | select((.dst_hostname // "") | contains("nonexistent.example.org"))
  ] | length' "$AUDIT_LOG")
  if [ "$BLOCKED_LOGGED" -eq 0 ]; then
    echo "❌ control query missing from dns_blocked log"
    sudo jq -s '.[] | select(.event_type == "dns_blocked")' "$AUDIT_LOG"
    exit 1
  fi
  echo "✅ control query correctly in dns_blocked log"
}

# --gitlab-ci enables --auto-allow-cloud-metadata, which triggers the
# detectCloudProvider path. GitHub-hosted runners are on Azure VMs, so
# detection should resolve to "azure" via the chassis_asset_tag or
# wireserver-upstream fallback.
verify_cloud_detect() {
  if ! sudo grep -q "Cloud provider detection" /tmp/cargowall.log; then
    echo "❌ 'Cloud provider detection' log line missing"
    sudo grep -i "cloud\|detect" /tmp/cargowall.log || true
    exit 1
  fi
  DETECTED=$(sudo grep "Cloud provider detection" /tmp/cargowall.log | head -1)
  echo "✅ Cloud provider detection ran: $DETECTED"
}

# Issue #119: the infrastructure auto-allows must be installed BEFORE the DNS
# proxy arms query filtering. When they landed after — behind the policy fetch
# — every infrastructure hostname queried inside that window was REFUSED under
# the pre-policy default-deny. One process writing one stream, so line order
# is decision order.
verify_startup_order() {
  LOG=/tmp/cargowall.log
  FILTER_LINE=$(sudo grep -n "DNS query filtering enabled" "$LOG" | head -1 | cut -d: -f1) || true
  INFRA_LINE=$(sudo grep -n "Auto-added infrastructure hostname allow rule" "$LOG" | tail -1 | cut -d: -f1) || true

  if [ -z "${FILTER_LINE:-}" ]; then
    echo "❌ 'DNS query filtering enabled' missing — the --gitlab-ci preset arms it"
    exit 1
  fi
  if [ -z "${INFRA_LINE:-}" ]; then
    echo "❌ no infrastructure hostname auto-allows logged — the auto-allow pass never ran"
    sudo grep -i "auto-a" "$LOG" || true
    exit 1
  fi
  if [ "$INFRA_LINE" -gt "$FILTER_LINE" ]; then
    echo "❌ auto-allow ran AFTER query filtering armed (line $INFRA_LINE > $FILTER_LINE) — #119 regression"
    sudo grep -nE "Auto-added infrastructure hostname allow rule|DNS query filtering enabled" "$LOG" || true
    exit 1
  fi
  echo "✅ infrastructure auto-allows installed before query filtering armed (line $INFRA_LINE < $FILTER_LINE)"
}

verify_audit() {
  AUDIT_LOG=/tmp/cargowall-audit.json
  if ! sudo test -s "$AUDIT_LOG"; then
    echo "❌ Audit log not written"
    exit 1
  fi
  BLOCKED=$(sudo jq -s '[.[] | select(.event_type == "connection_blocked" or .event_type == "dns_blocked")] | length' "$AUDIT_LOG")
  echo "would-deny events: $BLOCKED"
  if [ "$BLOCKED" -eq 0 ]; then
    echo "❌ Expected at least one would-deny event in audit log"
    sudo head -5 "$AUDIT_LOG" | jq .
    exit 1
  fi
  echo "✅ Audit log contains $BLOCKED would-deny events"
}

stop() {
  sudo ./bin/cargowall stop --pidfile /tmp/cargowall.pid --timeout 15s
  echo "✅ stop subcommand returned cleanly"
}

verify_pidfile_removed() {
  if sudo test -f /tmp/cargowall.pid; then
    echo "❌ pidfile still present after stop"
    sudo ls -la /tmp/cargowall.pid
    exit 1
  fi
  echo "✅ pidfile cleaned up"
}

emergency() {
  if sudo test -f /tmp/cargowall.pid; then
    sudo kill -TERM "$(sudo cat /tmp/cargowall.pid)" 2>/dev/null || true
  fi
}

case "${1:-}" in
  policy) policy ;;
  start) start ;;
  verify-flush) verify_flush ;;
  verify-pidfile) verify_pidfile ;;
  allowed) allowed ;;
  disallowed) disallowed ;;
  dns-bypass) dns_bypass ;;
  dns-control) dns_control ;;
  verify-dns-verdicts) verify_dns_verdicts ;;
  verify-cloud-detect) verify_cloud_detect ;;
  verify-startup-order) verify_startup_order ;;
  verify-audit) verify_audit ;;
  stop) stop ;;
  verify-pidfile-removed) verify_pidfile_removed ;;
  emergency) emergency ;;
  *) echo "usage: $0 <subcommand>" >&2; exit 2 ;;
esac
