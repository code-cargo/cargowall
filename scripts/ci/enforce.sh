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

# Traffic and summary assertions for the test-cargowall-enforce CI job.
# ci.yml stays wiring: one workflow step per subcommand. warm-resolver runs
# BEFORE the cargowall action step; everything else after. The container
# attribution scenarios for the same job live in container-attribution.sh.
#
# Usage: enforce.sh <subcommand>

set -euo pipefail

# GitHub's Azure runners resolve via systemd-resolved (127.0.0.53).
# Populate its stub cache with a wildcard-matched name BEFORE cargowall
# attaches. The concrete name can't be pre-tracked, so only the attach-time
# cache flush makes the later getaddrinfo miss the stub and re-resolve
# through the proxy — where **.githubusercontent.com matches and the IP is
# allowed with attribution. Without the flush the warm entry is served
# invisibly and the "hostname pattern" curl below is blocked as a bare IP.
# Best-effort so runners without systemd-resolved simply fall back to the
# cold-cache path.
warm_resolver() {
  resolvectl query raw.githubusercontent.com 2>/dev/null \
    || getent ahosts raw.githubusercontent.com \
    || true
  echo "Warmed resolver cache for raw.githubusercontent.com"
}

# Runs FIRST among the connection tests: it doubles as the #89 regression
# check for raw.githubusercontent.com, which was warmed into the
# systemd-resolved stub cache before attach (warm_resolver). Keeping it
# first minimizes the warm→request window so a short record TTL can't
# expire the entry and silently degrade this to the ordinary cold-cache
# path. If the attach-time cache flush regresses, this getaddrinfo is
# served invisibly from the warm stub, the proxy never sees the name, and
# the connection is blocked as a bare IP — failing here.
allowed_pattern() {
  curl -sf --connect-timeout 10 --max-time 30 https://raw.githubusercontent.com/github/gitignore/main/README.md > /dev/null
  echo "✅ raw.githubusercontent.com allowed via **.githubusercontent.com pattern (warm-cache re-resolved through proxy)"
}

allowed() {
  curl -sf --connect-timeout 10 --max-time 30 https://github.com > /dev/null
  echo "✅ github.com allowed"
}

blocked() {
  if curl -sf --connect-timeout 5 --max-time 10 https://example.com > /dev/null 2>&1; then
    echo "❌ example.com should be blocked"
    exit 1
  fi
  echo "✅ example.com blocked"
}

blocked_ip() {
  echo "Testing direct IP connection (bypassing DNS): 93.184.216.34 (example.com)"
  if curl -s --connect-timeout 5 --max-time 10 -o /dev/null http://93.184.216.34 2>&1; then
    echo "❌ Direct IP connection succeeded (should have been blocked)"
    exit 1
  fi
  echo "✅ Direct IP connection blocked"
}

docker_pull() {
  docker pull alpine:latest
  echo "✅ Docker pull succeeded through cargowall"
}

docker_filter() {
  # Test container can reach allowed host
  docker run --rm alpine:latest sh -c "
    wget -q --spider --timeout=15 https://github.com && echo 'CONNECTION_SUCCESS' || echo 'CONNECTION_FAILED'
  " 2>&1 | grep -q "CONNECTION_SUCCESS"
  echo "✅ Docker container reached github.com"

  # Test container is blocked from non-allowed host
  RESULT=$(docker run --rm alpine:latest sh -c "
    wget -q --spider --timeout=5 https://example.com && echo 'CONNECTION_SUCCESS' || echo 'CONNECTION_BLOCKED'
  " 2>&1) || true
  if echo "$RESULT" | grep -q "CONNECTION_SUCCESS"; then
    echo "❌ Docker container should not reach example.com"
    exit 1
  fi
  echo "✅ Docker container blocked from example.com"
}

# Gate for issue #110: the blocked() curl above ran in its own post-attach
# workflow step, so EVERY refused example.com query came from a step-tagged
# process and its dns_blocked event must carry that step's ordinal — the
# assertion is all-of-subset, not at-least-one, so a partially laundered or
# shed path cannot pass. Other domains (systemd units, background services)
# are printed as evidence but not asserted: unattributed is correct for
# clients outside the Runner.Worker subtree. On failure the per-event
# outcome taxonomy (step_attr_outcome says WHY: untagged / not_found /
# ambiguous_wildcard / dump_error / shed) and a socket-table snapshot make
# the run diagnosable from its log alone.
dns_attribution() {
  AUDIT_LOG=/tmp/cargowall-audit.json

  echo "Host-path dns_blocked events (domain / step_ordinal / outcome / process / pid):"
  jq -r -s '.[] | select(.event_type == "dns_blocked" and (.container_origin != true))
    | [.dst_hostname, (.step_ordinal // 0), (.step_attr_outcome // "-"), (.process // "-"), (.pid // 0)]
    | @tsv' "$AUDIT_LOG" || true

  # The blocked() probe's domain, restricted to host-path events. Real
  # ordinal: >0 and below events.MaxRealStepOrdinal — the same
  # StepOrdinalPreDaemon (0xFFFFFFFE) minus 2^16 arithmetic, derived here
  # from the named sentinel value rather than a pasted decimal.
  # step_attr_outcome must ALSO say "ok": an ordinal that did not come
  # through the sockdiag taxonomy must not pass the gate.
  MAX_REAL_ORDINAL=$((0xFFFFFFFE - 65536))
  TOTAL=$(jq -s '[.[] | select(.event_type == "dns_blocked" and (.container_origin != true))
    | select(.dst_hostname == "example.com")] | length' "$AUDIT_LOG")
  ATTRIBUTED=$(jq -s --argjson max "$MAX_REAL_ORDINAL" '[.[]
    | select(.event_type == "dns_blocked" and (.container_origin != true))
    | select(.dst_hostname == "example.com")
    | select(.step_attr_outcome == "ok")
    | select((.step_ordinal // 0) > 0 and (.step_ordinal // 0) < $max)] | length' "$AUDIT_LOG")
  echo "example.com dns_blocked events: $TOTAL, with real step ordinal: $ATTRIBUTED"

  if [ "$TOTAL" -eq 0 ]; then
    echo "❌ No example.com dns_blocked events — the blocked-connection step should have produced them"
    exit 1
  fi
  if [ "$ATTRIBUTED" -ne "$TOTAL" ]; then
    echo "❌ $((TOTAL - ATTRIBUTED))/$TOTAL example.com dns_blocked events lost their step ordinal (#110)"
    echo "UDP socket table at check time (diagnosis aid):"
    sudo ss -uapn | head -60 || true
    exit 1
  fi
  echo "✅ all $TOTAL example.com dns_blocked events carry a real step ordinal"
}

summary() {
  SUMMARY_OUTPUT=$(./bin/cargowall summary --audit-log /tmp/cargowall-audit.json --steps '[]' 2>&1)

  echo "Summary output:"
  echo "$SUMMARY_OUTPUT"

  SUMMARY_VALID=true

  if ! echo "$SUMMARY_OUTPUT" | grep -q "Enforce Mode"; then
    echo "❌ Missing 'Enforce Mode' header"
    SUMMARY_VALID=false
  fi

  if ! echo "$SUMMARY_OUTPUT" | grep -q "### Summary"; then
    echo "❌ Missing '### Summary' section"
    SUMMARY_VALID=false
  fi

  if ! echo "$SUMMARY_OUTPUT" | grep -q "Connections blocked"; then
    echo "❌ Missing 'Connections blocked' metric"
    SUMMARY_VALID=false
  fi

  if [ "$SUMMARY_VALID" = true ]; then
    echo "✅ Summary command produces valid markdown"
  else
    echo "❌ Summary command output missing expected content"
    exit 1
  fi
}

case "${1:-}" in
  warm-resolver) warm_resolver ;;
  allowed-pattern) allowed_pattern ;;
  allowed) allowed ;;
  blocked) blocked ;;
  blocked-ip) blocked_ip ;;
  docker-pull) docker_pull ;;
  docker-filter) docker_filter ;;
  dns-attribution) dns_attribution ;;
  summary) summary ;;
  *) echo "usage: $0 warm-resolver|allowed-pattern|allowed|blocked|blocked-ip|docker-pull|docker-filter|dns-attribution|summary" >&2; exit 2 ;;
esac
