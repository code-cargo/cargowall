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

# Body of the test-cargowall-cgroup-enforce CI job (issue #106 phase 3b).
# ci.yml stays wiring: it calls `pre` before starting cargowall via the
# action, and `verify` after. Each verify phase runs in a subshell with its
# own cleanup trap, mirroring the per-step traps this had as workflow YAML.
#
# Usage: cgroup-enforce.sh pre|verify

set -euo pipefail

step() { echo; echo "=== $* ==="; }

# Created BEFORE cargowall starts: its subnet must reach the cgroup hook's
# carve-out via the pre-enableMode pre-scan, because docker-event tracking
# begins only later. Asserted by verify_preexisting_bridge below.
# --restart unless-stopped: cargowall restarts dockerd to apply DNS config,
# and a daemon restart stops policy-less containers — the server must come
# back or the later assertion tests container lifecycle instead of
# enforcement.
pre() {
  step "Pre-create a user-defined bridge (service-container shape)"
  docker network create cw-pre > /dev/null
  docker run -d --name cw-pre-server --restart unless-stopped --network cw-pre alpine:latest \
    sh -c 'while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 8080; done'
}

# TC is attached to one interface and never saw `lo`; the cgroup hook does.
# If the loopback carve-out regresses, enforcement breaks every local
# service on the runner — this is the single highest-blast-radius behavior
# change in phase 3b.
verify_loopback() {
  step "Loopback must still work"
  python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
  local srv=$!
  sleep 2
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:18080/ || echo "000")
  kill "$srv" 2>/dev/null || true
  if [ "$code" != "200" ]; then
    echo "❌ Loopback blocked under cgroup enforcement (got HTTP '$code')"
    return 1
  fi
  echo "✅ Loopback reachable ($code)"
}

# The proxy's own upstream queries are SO_MARK-exempt in the hook; if that
# regresses, name resolution dies and everything else with it.
verify_dns_and_allowed() {
  step "DNS and allowed hosts must still work"
  getent hosts github.com > /dev/null || { echo "❌ DNS resolution broken"; return 1; }
  curl -sf --connect-timeout 10 --max-time 30 https://raw.githubusercontent.com/github/gitignore/main/README.md > /dev/null \
    || { echo "❌ Allowed host unreachable under cgroup enforcement"; return 1; }
  echo "✅ DNS + allowed host reachable"
}

# Now enforced by the cgroup hook rather than TC. For TCP the drop is NOT
# fast: the SYN dies in ip_finish_output and connect() only short-circuits
# on ECONNREFUSED, so curl runs into its own --connect-timeout — same UX as
# TC's blackhole, either way non-zero. (Fast EPERM is UDP-only; the probe
# phase below pins it.)
verify_blocked_host() {
  step "Blocked host is still blocked (host socket)"
  if curl -sf --connect-timeout 5 --max-time 10 https://example.com > /dev/null 2>&1; then
    echo "❌ example.com should be blocked"
    return 1
  fi
  echo "✅ example.com blocked"
}

# Prove an enforced drop end to end — deliberately, in THIS job, because
# its policy is supplied locally (offline mode): there is no SaaS push and
# no notification client, so the denial is asserted right here and reported
# nowhere else. The API-backed jobs must not run this probe — a deliberate
# block would land in the product's report for the run.
#
# 203.0.113.9:9999 is TEST-NET-3 (RFC 5737): reserved, unroutable, matches
# no allowlist, and recognizable in any audit log as a cargowall test
# artifact. (The BPF unit suite deliberately does NOT use an off-host
# address — its probe targets the host's own IP over lo so a production
# cargowall can never see it; this job is the one place a real off-host
# denial is exercised, because only here is the report guaranteed to stay
# local.)
# UDP, because only UDP surfaces the drop synchronously: sendto() returns
# EPERM from the cgroup hook. The audit record for this exact tuple is
# asserted in verify_events below.
verify_probe() {
  step "Deliberate direct-IP block probe (TEST-NET-3)"
  local got
  got=$(python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"cargowall-ci-probe", ("203.0.113.9", 9999))
    print("SENT")
except OSError as e:
    print(e.errno)')
  if [ "$got" != "1" ]; then
    echo "❌ expected EPERM (errno 1) sending to 203.0.113.9:9999, got: $got"
    return 1
  fi
  echo "✅ direct-IP probe denied with EPERM at the socket layer"
}

# Host→published-port and container→container ride the docker bridge —
# local-only surfaces TC never adjudicated, newly seen by the enforcing
# cgroup hook. The carve-outs (default bridge + pre-existing containers
# before enableMode, user-defined bridges via tracker discovery) are what
# keep them alive; before those existed, every shape below died with
# default-deny.
verify_bridge_local() (
  step "Bridge-local traffic must survive enforcement"
  cleanup() {
    docker rm -f cw-bridge-enforce cw-udn-server > /dev/null 2>&1 || true
    docker network rm cw-udn > /dev/null 2>&1 || true
  }
  trap cleanup EXIT
  # retry <label> <cmd...>: the servers, the tracker's async subnet
  # discovery, and busybox nc's between-connections gap all need a few
  # attempts — a single try here reads as an enforcement bug when it is
  # only a race.
  retry() {
    label="$1"; shift
    for i in 1 2 3 4 5 6 7 8; do
      sleep 1
      "$@" > /dev/null 2>&1 && return 0
    done
    echo "❌ $label"
    return 1
  }
  serve='while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 8080; done'
  docker run -d --name cw-bridge-enforce -p 18084:8080 alpine:latest sh -c "$serve"
  retry "published port dead under cgroup enforcement" \
    curl -sf --max-time 5 http://127.0.0.1:18084/
  SERVER_IP=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' cw-bridge-enforce)
  retry "container→container dead under cgroup enforcement" \
    docker run --rm alpine:latest wget -q -T 5 -O- "http://$SERVER_IP:8080/"

  # User-defined bridge created NOW: its subnet is carved out only via the
  # tracker's per-container discovery — the path with no startup-time
  # equivalent.
  docker network create cw-udn > /dev/null
  docker run -d --name cw-udn-server --network cw-udn alpine:latest sh -c "$serve"
  retry "user-defined bridge container→container dead under cgroup enforcement" \
    docker run --rm --network cw-udn alpine:latest wget -q -T 5 -O- "http://cw-udn-server:8080/"
  echo "✅ bridge-local traffic survives cgroup enforcement (default + user-defined bridge)"
)

# The network and server were created BEFORE cargowall started (the `pre`
# phase): the subnet reached the carve-out via the pre-enableMode pre-scan.
# This is the GitHub service-container / compose-stack shape. The probe
# dials the server's IP, not its name: the target is bridge-subnet
# ENFORCEMENT, and the name path drags in embedded-DNS resolution, which
# fails for unrelated reasons whenever the server is down (an unknown name
# gets forwarded upstream and correctly REFUSED by the query filter —
# exactly what a first version of this step misdiagnosed as an enforcement
# regression).
verify_preexisting_bridge() (
  step "Pre-existing user-defined bridge must survive enforcement"
  cleanup() {
    docker rm -f cw-pre-server > /dev/null 2>&1 || true
    docker network rm cw-pre > /dev/null 2>&1 || true
  }
  trap cleanup EXIT
  PRE_IP=""
  for i in 1 2 3 4 5 6 7 8; do
    sleep 1
    PRE_IP=$(docker inspect -f '{{with index .NetworkSettings.Networks "cw-pre"}}{{.IPAddress}}{{end}}' cw-pre-server 2>/dev/null)
    [ -n "$PRE_IP" ] && docker inspect -f '{{.State.Running}}' cw-pre-server 2>/dev/null | grep -q true && break
  done
  if [ -z "$PRE_IP" ]; then
    echo "❌ cw-pre-server not running (did the dockerd restart lose it despite --restart?)"
    docker ps -a | head -10
    exit 1
  fi
  for i in 1 2 3 4 5 6 7 8; do
    sleep 1
    docker run --rm --network cw-pre alpine:latest wget -q -T 5 -O- "http://$PRE_IP:8080/" > /dev/null 2>&1 && {
      echo "✅ pre-existing user-defined bridge survives enforcement"
      exit 0
    }
  done
  echo "❌ pre-existing user-defined bridge dead under cgroup enforcement (pre-scan regression)"
  exit 1
)

verify_container_enforced() {
  step "Container traffic is enforced and attributed"
  docker pull -q alpine:latest
  # Allowed destination still reachable from inside a container.
  docker run --rm alpine:latest sh -c \
    "wget -q --spider --timeout=15 https://github.com && echo OK || echo FAIL" 2>&1 | grep -q OK \
    || { echo "❌ Container cannot reach an allowed host under cgroup enforcement"; return 1; }
  echo "✅ Container reached github.com"

  # Denied destination: dropped in the container's own netns, before NAT —
  # so TC never sees the packet and the cgroup hook is the sole event
  # source for it.
  RESULT=$(docker run --rm alpine:latest sh -c \
    "sleep 1; wget -q --timeout=8 http://198.51.100.7/ && echo REACHED || echo BLOCKED" 2>&1) || true
  if echo "$RESULT" | grep -q REACHED; then
    echo "❌ Container reached a denied destination"
    return 1
  fi
  echo "✅ Container blocked from 198.51.100.7"
}

verify_events() {
  step "Validate enforcement events"
  local AUDIT_LOG=/tmp/cargowall-audit.json
  test -s "$AUDIT_LOG" || { echo "❌ Audit log missing"; return 1; }
  local VALID=true

  # In enforce mode a cgroup drop reports as a real connection_blocked
  # (same policy outcome as a TC drop), never as a would-block.
  WOULD=$(jq -s '[.[] | select(.event_type == "cgroup_would_block")] | length' "$AUDIT_LOG")
  echo "cgroup_would_block events (expected 0 in enforce): $WOULD"
  if [ "$WOULD" -ne 0 ]; then
    echo "❌ Enforce mode emitted would-block events"
    VALID=false
  fi

  # The container block must carry native attribution — a real step ordinal
  # AND a container id — with no TC event to join against, which is the
  # core phase-3b claim.
  ATTRIBUTED=$(jq -s '[.[] | select(.event_type == "connection_blocked" and .dst_ip == "198.51.100.7") | select(.container_origin == true) | select((.step_ordinal // 0) > 0 and (.step_ordinal // 0) < 4294901758) | select((.container_id // "") != "")] | length' "$AUDIT_LOG")
  echo "natively attributed container blocks: $ATTRIBUTED"
  if [ "$ATTRIBUTED" -eq 0 ]; then
    echo "❌ Container block lacks native step/container attribution"
    VALID=false
  fi

  # The deliberate TEST-NET-3 probe must have produced its audit record:
  # the drop already proved enforcement (EPERM), this proves the cgroup
  # hook is also the event source for what it drops — "every drop we cause
  # emits a record".
  PROBE=$(jq -s '[.[] | select(.event_type == "connection_blocked" and .dst_ip == "203.0.113.9" and .dst_port == 9999)] | length' "$AUDIT_LOG")
  echo "TEST-NET-3 probe blocked events: $PROBE"
  if [ "$PROBE" -eq 0 ]; then
    echo "❌ Probe was dropped but produced no connection_blocked audit event"
    VALID=false
  fi

  # Nothing on loopback or an allowed host may be blocked. (DNS to a
  # resolver the policy doesn't allow is a legitimate denial TC makes too,
  # so port 53 alone is not the signal — see the shadow job.)
  BAD=$(jq -s '[.[] | select(.event_type == "connection_blocked") | select(((.dst_ip // "") | startswith("127.")) or ((.dst_ip // "") | test("^172\\.(1[6-9]|2[0-9]|3[01])\\.")) or ((.dst_hostname // "") | test("github|githubusercontent")))] | length' "$AUDIT_LOG")
  if [ "$BAD" -ne 0 ]; then
    echo "❌ Enforcement blocked loopback/bridge/allowed traffic:"
    jq -c 'select(.event_type == "connection_blocked") | {dst_ip, dst_hostname, dst_port, process}' "$AUDIT_LOG" | head -20
    VALID=false
  fi

  echo "--- blocked events ---"
  jq -c 'select(.event_type == "connection_blocked") | {dst_ip, dst_port, process, step_ordinal, container_id, container_origin}' "$AUDIT_LOG" | head -20

  [ "$VALID" = true ] || return 1
  echo "✅ Cgroup enforcement events are correct"
}

verify() {
  verify_loopback
  verify_dns_and_allowed
  verify_blocked_host
  verify_probe
  verify_bridge_local
  verify_preexisting_bridge
  verify_container_enforced
  verify_events
}

case "${1:-}" in
  pre) pre ;;
  verify) verify ;;
  *) echo "usage: $0 pre|verify" >&2; exit 2 ;;
esac
