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

# Body of the test-cargowall-sidecar-shape CI job: cargowall as a sidecar
# container in a Kubernetes-style pod, the shape the CodeCargo SaaS runs it
# in. Every other e2e job runs the binary on the host, so this is the only
# coverage of an agent with its own pid and cgroup namespaces sharing a
# network namespace with the workload.
#
# The pod is built from plain docker containers:
#   cw-pod      owns the network namespace (the pause container); its
#               resolv.conf points at 127.0.0.1, as the pod dnsConfig does
#   cw-sidecar  privileged cargowall, private pid + cgroup namespace, joined
#               to cw-pod's netns; no CI preset, file policy (see start)
#   cw-client   the workload, joined to cw-pod's netns
# All three sit under one --cgroup-parent slice, the pod cgroup.
#
# ci.yml stays wiring: one workflow step per subcommand.
#
# Usage: sidecar-shape.sh <subcommand>

set -euo pipefail

POD_SLICE=cwpod.slice
STATE_DIR=/tmp/cw-sidecar
CLIENT_IMAGE=curlimages/curl:8.10.1
SIDECAR_IMAGE=alpine:3.20
# Overridable for local runs on networks that cannot reach 8.8.8.8.
DNS_UPSTREAM_IP=${DNS_UPSTREAM_IP:-8.8.8.8}

AUDIT_LOG="$STATE_DIR/audit.json"

client() { docker exec cw-client "$@"; }

# Pull before anything joins the pod: once cargowall enforces, the pod's
# DNS is the proxy and its policy does not allow a registry.
pod() {
  docker pull -q "$CLIENT_IMAGE"
  docker pull -q "$SIDECAR_IMAGE"
  sudo rm -rf "$STATE_DIR"
  mkdir -p "$STATE_DIR"
  # No rule for the upstream: start auto-allows the --dns-upstream host,
  # and the SaaS sidecar relies on exactly that.
  cat > "$STATE_DIR/config.json" <<'JSON'
{
  "defaultAction": "deny",
  "rules": [
    {
      "type": "hostname",
      "value": "github.com",
      "ports": [{"port": 443, "protocol": "tcp"}],
      "action": "allow"
    }
  ]
}
JSON
  docker run -d --name cw-pod --cgroup-parent "$POD_SLICE" --dns 127.0.0.1 \
    --entrypoint sleep "$CLIENT_IMAGE" infinity > /dev/null
  docker run -d --name cw-client --cgroup-parent "$POD_SLICE" \
    --network container:cw-pod \
    --entrypoint sleep "$CLIENT_IMAGE" infinity > /dev/null
  echo "✅ pod up: cw-pod (netns owner), cw-client (workload)"
}

# What this locks: no --github-action or --gitlab-ci, so no iptables DNS
# redirect and no Docker DNS rewrite; the workload reaches the proxy at
# 127.0.0.1:53 only through the pod resolv.conf. Query filtering stays off,
# as it is for the operator-injected sidecar, so a denied name still
# resolves and the block lands at TC. Policy comes from a file
# rather than an API fetch. The ready file sits on the bind mount so the
# host can see it; the operator's probe reads the default
# /tmp/cargowall-ready inside the container instead.
start() {
  docker run -d --name cw-sidecar --cgroup-parent "$POD_SLICE" \
    --privileged --cgroupns private \
    --network container:cw-pod \
    -v "$PWD/bin/cargowall:/usr/local/bin/cargowall:ro" \
    -v "$STATE_DIR:/state" \
    "$SIDECAR_IMAGE" \
    cargowall start \
      --config /state/config.json \
      --dns-upstream "$DNS_UPSTREAM_IP:53" \
      --audit-log /state/audit.json \
      --ready-file /state/ready \
      --failure-file /state/failed \
      --debug > /dev/null
  echo "✅ sidecar started"
}

# The waiter runs inside the sidecar's pid namespace, where the sentinels'
# pid stamp (1) is the live cargowall; a host-side wait-ready would see
# systemd at pid 1 and fall back to the mtime anchor, timing out on an
# early ready and ignoring an early failure. If the sidecar has already
# exited, exec fails at once and the failure sentinel on the bind mount is
# the reason.
wait_ready() {
  if docker exec cw-sidecar cargowall wait-ready \
      --ready-file /state/ready --failure-file /state/failed --timeout 30s; then
    echo "✅ sidecar ready"
    return
  fi
  echo "❌ sidecar not ready (running=$(docker inspect -f '{{.State.Running}}' cw-sidecar), exit=$(docker inspect -f '{{.State.ExitCode}}' cw-sidecar))"
  if [ -s "$STATE_DIR/failed" ]; then
    echo "failure sentinel: $(head -c 2048 "$STATE_DIR/failed")"
  fi
  exit 1
}

# Guards the harness itself: if a docker default ever changes, the job must
# fail here rather than go on passing against a shape the SaaS does not run.
verify_shape() {
  ns() { docker exec "$1" readlink "/proc/self/ns/$2"; }
  host_ns() { sudo readlink "/proc/1/ns/$1"; }

  for kind in pid cgroup; do
    if [ "$(ns cw-sidecar "$kind")" = "$(host_ns "$kind")" ]; then
      echo "❌ sidecar shares the host $kind namespace"
      exit 1
    fi
    if [ "$(ns cw-sidecar "$kind")" = "$(ns cw-client "$kind")" ]; then
      echo "❌ sidecar shares the workload's $kind namespace"
      exit 1
    fi
  done
  if [ "$(ns cw-sidecar net)" != "$(ns cw-client net)" ]; then
    echo "❌ sidecar and workload are in different network namespaces"
    exit 1
  fi
  if [ "$(ns cw-client net)" = "$(host_ns net)" ]; then
    echo "❌ the pod netns is the host's — TC would attach to the runner"
    exit 1
  fi
  # The pod dnsConfig: the workload's only resolver is the proxy.
  nameservers=$(docker exec cw-client grep '^nameserver' /etc/resolv.conf)
  if [ "$nameservers" != "nameserver 127.0.0.1" ]; then
    echo "❌ workload resolv.conf does not point only at 127.0.0.1"
    docker exec cw-client cat /etc/resolv.conf
    exit 1
  fi
  if [ "$(docker exec cw-sidecar cat /proc/self/cgroup)" != "0::/" ]; then
    echo "❌ sidecar is not at its cgroup namespace root"
    docker exec cw-sidecar cat /proc/self/cgroup
    exit 1
  fi
  for c in cw-sidecar cw-client; do
    if ! sudo grep -q "/$POD_SLICE/" "/proc/$(docker inspect -f '{{.State.Pid}}' "$c")/cgroup"; then
      echo "❌ $c is not under the pod slice $POD_SLICE"
      exit 1
    fi
  done
  echo "✅ shape: own pid + cgroup namespace, shared non-host netns, resolver 127.0.0.1, one pod cgroup"
}

# Resolution goes through the proxy at 127.0.0.1 (the pod resolv.conf); the
# allowed connection only succeeds because the proxy's answer seeded the
# allowlist.
allowed() {
  client curl -sf --connect-timeout 10 --max-time 30 -o /dev/null https://github.com
  echo "✅ github.com reachable from the workload"
}

blocked() {
  if client curl -sf --connect-timeout 5 --max-time 10 -o /dev/null https://example.com; then
    echo "❌ example.com reachable — enforcement is not applied to the workload"
    exit 1
  fi
  echo "✅ example.com blocked"
}

blocked_ip() {
  if client curl -sf --connect-timeout 5 --max-time 10 -o /dev/null http://1.1.1.1; then
    echo "❌ 1.1.1.1 reachable — enforcement is not applied to the workload"
    exit 1
  fi
  echo "✅ 1.1.1.1 blocked"
}

verify_audit() {
  if ! sudo test -s "$AUDIT_LOG"; then
    echo "❌ audit log not written"
    exit 1
  fi
  count() { sudo jq -s "[.[] | select(.event_type == \"connection_blocked\" and .blocked == true) | select($1)] | length" "$AUDIT_LOG"; }

  # By name: the proxy resolved it, so the blocked IP carries the hostname.
  if [ "$(count '(.dst_hostname // "") | contains("example.com")')" -eq 0 ]; then
    echo "❌ no enforced connection_blocked for example.com"
    sudo jq -s '.[] | select(.event_type == "connection_blocked")' "$AUDIT_LOG"
    exit 1
  fi
  if [ "$(count '.dst_ip == "1.1.1.1"')" -eq 0 ]; then
    echo "❌ no enforced connection_blocked for 1.1.1.1"
    sudo jq -s '.[] | select(.event_type == "connection_blocked")' "$AUDIT_LOG"
    exit 1
  fi
  if [ "$(count '(.dst_hostname // "") | contains("github.com")')" -ne 0 ]; then
    echo "❌ github.com was blocked"
    exit 1
  fi
  echo "✅ audit log records both blocks, nothing for the allowed host"
}

# SIGTERM, as kubelet sends it, with kubelet's default 30s grace period. A clean teardown exits 0 and detaches TC, so
# the workload's egress is unfiltered again.
stop() {
  docker stop -t 30 cw-sidecar > /dev/null
  code=$(docker inspect -f '{{.State.ExitCode}}' cw-sidecar)
  if [ "$code" -ne 0 ]; then
    echo "❌ sidecar exited $code on SIGTERM"
    exit 1
  fi
  if [ -f "$STATE_DIR/ready" ]; then
    echo "❌ ready sentinel left behind"
    exit 1
  fi
  # The inverse of blocked_ip: a bare IP needs no resolver, and the pod's
  # resolver died with the proxy.
  if ! client curl -sf --connect-timeout 10 --max-time 30 -o /dev/null http://1.1.1.1; then
    echo "❌ 1.1.1.1 still blocked after the sidecar stopped — teardown left a filter attached"
    exit 1
  fi
  echo "✅ clean SIGTERM teardown; workload egress unfiltered again"
}

logs() {
  docker logs cw-sidecar 2>&1 || true
}

cleanup() {
  docker rm -f cw-client cw-sidecar cw-pod > /dev/null 2>&1 || true
}

case "${1:-}" in
  pod) pod ;;
  start) start ;;
  wait-ready) wait_ready ;;
  verify-shape) verify_shape ;;
  allowed) allowed ;;
  blocked) blocked ;;
  blocked-ip) blocked_ip ;;
  verify-audit) verify_audit ;;
  stop) stop ;;
  logs) logs ;;
  cleanup) cleanup ;;
  *) echo "usage: $0 <subcommand>" >&2; exit 2 ;;
esac
