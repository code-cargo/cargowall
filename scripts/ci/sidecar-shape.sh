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
# coverage of an agent with its own pid namespace sharing a network
# namespace with the workload, on a host where other pods run beside it.
#
# The pod is built from plain docker containers:
#   cw-pod      owns the network namespace (the pause container); its
#               resolv.conf points at 127.0.0.1, as the pod dnsConfig does
#   cw-sidecar  privileged cargowall, private pid namespace, the HOST cgroup
#               namespace, joined to cw-pod's netns; no CI preset, file
#               policy (see start)
#   cw-client   the workload, joined to cw-pod's netns
# All three sit under one --cgroup-parent slice, the pod cgroup.
#
# The host cgroup namespace is what the SaaS sidecar gets: the operator sets
# privileged and nothing else, and on cgroup v2 containerd's CRI gives a
# container a cgroup namespace only when it is not privileged. Its
# /sys/fs/cgroup is therefore the node's whole tree.
#
#   cw-neighbour  a second pod (own netns, own slice) with no sidecar: a
#                 sidecar's enforcement must stay inside its own pod
#
# ci.yml stays wiring: one workflow step per subcommand.
#
# Usage: sidecar-shape.sh <subcommand>

set -euo pipefail

POD_SLICE=cwpod.slice
NEIGHBOUR_SLICE=cwneighbour.slice
STATE_DIR=/tmp/cw-sidecar
CLIENT_IMAGE=curlimages/curl:8.10.1
SIDECAR_IMAGE=alpine:3.20
# Overridable for local runs on networks that cannot reach 8.8.8.8.
DNS_UPSTREAM_IP=${DNS_UPSTREAM_IP:-8.8.8.8}

AUDIT_LOG="$STATE_DIR/audit.json"

client() { docker exec cw-client "$@"; }

# dockerd pulls from the host netns, which no filter touches; pulling here
# only keeps the pull output out of the timed steps.
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
  docker run -d --name cw-neighbour --cgroup-parent "$NEIGHBOUR_SLICE" \
    --entrypoint sleep "$CLIENT_IMAGE" infinity > /dev/null
  echo "✅ pod up: cw-pod (netns owner), cw-client (workload); neighbour pod cw-neighbour"
}

# What this locks: no --github-action or --gitlab-ci, so no iptables DNS
# redirect and no Docker DNS rewrite; the workload reaches the proxy at
# 127.0.0.1:53 only through the pod resolv.conf. Query filtering stays off,
# as it is for the operator-injected sidecar, so a denied name still
# resolves and the block lands at TC. Policy comes from a file
# rather than an API fetch. Readiness is probed inside the sidecar, as the
# operator's probe is (see wait_ready); the sentinels sit on the bind mount
# so the host can still read the failure file after an exit and watch the
# ready file disappear in stop.
start() {
  docker run -d --name cw-sidecar --cgroup-parent "$POD_SLICE" \
    --privileged --cgroupns host \
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
  running=$(docker inspect -f '{{.State.Running}}' cw-sidecar)
  echo "❌ sidecar not ready (running=$running, exit=$(docker inspect -f '{{.State.ExitCode}}' cw-sidecar))"
  # A live waiter has already printed the reason; only an exited sidecar
  # leaves the sentinel unread.
  if [ "$running" != true ] && [ -s "$STATE_DIR/failed" ]; then
    echo "failure sentinel: $(head -c 2048 "$STATE_DIR/failed")"
  fi
  exit 1
}

# Guards the harness itself: if a docker default ever changes, the job must
# fail here rather than go on passing against a shape the SaaS does not run.
verify_shape() {
  # Assignments, not inline substitutions, so a container that died after
  # wait-ready fails here under errexit instead of comparing empty strings.
  ns() { docker exec "$1" readlink "/proc/self/ns/$2"; }
  host_pid=$(sudo readlink /proc/1/ns/pid)
  host_cgroup=$(sudo readlink /proc/1/ns/cgroup)
  host_net=$(sudo readlink /proc/1/ns/net)
  sidecar_pid=$(ns cw-sidecar pid)
  sidecar_cgroup=$(ns cw-sidecar cgroup)
  sidecar_net=$(ns cw-sidecar net)
  client_pid=$(ns cw-client pid)
  client_net=$(ns cw-client net)
  neighbour_net=$(ns cw-neighbour net)

  if [ "$sidecar_pid" = "$host_pid" ]; then
    echo "❌ sidecar shares the host pid namespace"
    exit 1
  fi
  if [ "$sidecar_pid" = "$client_pid" ]; then
    echo "❌ sidecar shares the workload's pid namespace"
    exit 1
  fi
  if [ "$sidecar_cgroup" != "$host_cgroup" ]; then
    echo "❌ sidecar has its own cgroup namespace; a privileged pod container does not"
    exit 1
  fi
  if [ "$sidecar_net" != "$client_net" ]; then
    echo "❌ sidecar and workload are in different network namespaces"
    exit 1
  fi
  if [ "$client_net" = "$host_net" ]; then
    echo "❌ the pod netns is the host's — TC would attach to the runner"
    exit 1
  fi
  # The pod dnsConfig: the workload's only resolver is the proxy.
  nameservers=$(docker exec cw-client grep '^nameserver' /etc/resolv.conf || true)
  if [ "$nameservers" != "nameserver 127.0.0.1" ]; then
    echo "❌ workload resolv.conf does not point only at 127.0.0.1"
    docker exec cw-client cat /etc/resolv.conf
    exit 1
  fi
  # In the host cgroup namespace the sidecar sees its absolute path.
  if ! docker exec cw-sidecar grep -q "^0::/$POD_SLICE/" /proc/self/cgroup; then
    echo "❌ sidecar does not see its own absolute cgroup path under $POD_SLICE"
    docker exec cw-sidecar cat /proc/self/cgroup
    exit 1
  fi
  if [ "$neighbour_net" = "$client_net" ]; then
    echo "❌ neighbour pod shares the pod's netns"
    exit 1
  fi
  cgroup_of() { sudo cat "/proc/$(docker inspect -f '{{.State.Pid}}' "$1")/cgroup"; }
  for c in cw-sidecar cw-client; do
    if ! cgroup_of "$c" | grep -q "^0::/$POD_SLICE/"; then
      echo "❌ $c is not under the pod slice $POD_SLICE"
      exit 1
    fi
  done
  if ! cgroup_of cw-neighbour | grep -q "^0::/$NEIGHBOUR_SLICE/"; then
    echo "❌ cw-neighbour is not under its own slice $NEIGHBOUR_SLICE"
    exit 1
  fi
  echo "✅ shape: own pid ns, host cgroup ns, shared non-host netns, resolver 127.0.0.1, one pod cgroup, separate neighbour pod"
}

# Resolution goes through the proxy at 127.0.0.1 (the pod resolv.conf); the
# allowed connection only succeeds because the proxy's answer seeded the
# allowlist.
allowed() {
  client curl -sf --connect-timeout 10 --max-time 30 -o /dev/null https://github.com
  echo "✅ github.com reachable from the workload"
}

# A TC drop of the SYN is a connect timeout (curl exit 28). Any other
# failure, a resolve failure (6) above all, happened before TC and proves
# nothing about enforcement.
expect_blocked() {
  rc=0
  client curl -sf --connect-timeout 5 --max-time 10 -o /dev/null "$1" || rc=$?
  case $rc in
    0) echo "❌ $1 reachable — enforcement is not applied to the workload"; exit 1 ;;
    28) echo "✅ $1 blocked" ;;
    *) echo "❌ $1 failed with curl exit $rc, not a connect timeout — it never reached TC"; exit 1 ;;
  esac
}

blocked() { expect_blocked https://example.com; }

blocked_ip() { expect_blocked http://1.1.1.1; }

# 1.1.1.1 is blocked in the pod; from the neighbour pod it must not be.
# TC lives in the pod's own netns and cannot reach the neighbour, so this
# guards the cgroup side: the sidecar's cgroup programs attach at its
# /sys/fs/cgroup, which in the host cgroup namespace is the node root, and
# any of them that ever returns a verdict would drop this connection.
neighbour() {
  if ! docker exec cw-neighbour curl -sf --connect-timeout 10 --max-time 30 -o /dev/null http://1.1.1.1; then
    echo "❌ 1.1.1.1 blocked from the neighbour pod — enforcement leaked out of the sidecar's pod"
    exit 1
  fi
  echo "✅ neighbour pod unaffected"
}

verify_audit() {
  if ! test -s "$AUDIT_LOG"; then
    echo "❌ audit log not written"
    exit 1
  fi
  count() { jq -s "[.[] | select(.event_type == \"connection_blocked\" and .blocked == true) | select($1)] | length" "$AUDIT_LOG"; }

  # By name: the proxy resolved it, so the blocked IP carries the hostname.
  if [ "$(count '(.dst_hostname // "") | contains("example.com")')" -eq 0 ]; then
    echo "❌ no enforced connection_blocked for example.com"
    jq -s '.[] | select(.event_type == "connection_blocked")' "$AUDIT_LOG"
    exit 1
  fi
  if [ "$(count '.dst_ip == "1.1.1.1"')" -eq 0 ]; then
    echo "❌ no enforced connection_blocked for 1.1.1.1"
    jq -s '.[] | select(.event_type == "connection_blocked")' "$AUDIT_LOG"
    exit 1
  fi
  if [ "$(count '(.dst_hostname // "") | contains("github.com")')" -ne 0 ]; then
    echo "❌ github.com was blocked"
    exit 1
  fi
  neighbour_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cw-neighbour)
  if [ "$(jq -s --arg ip "$neighbour_ip" '[.[] | select(.src_ip == $ip)] | length' "$AUDIT_LOG")" -ne 0 ]; then
    echo "❌ audit log has events from the neighbour pod ($neighbour_ip)"
    exit 1
  fi
  echo "✅ audit log records both blocks, nothing for the allowed host or the neighbour pod"
}

# SIGTERM, as kubelet sends it, with kubelet's default 30s grace period. A
# clean teardown exits 0 and detaches TC, so the workload's egress is
# unfiltered again.
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
  docker rm -f cw-client cw-sidecar cw-pod cw-neighbour > /dev/null 2>&1 || true
}

case "${1:-}" in
  pod) pod ;;
  start) start ;;
  wait-ready) wait_ready ;;
  verify-shape) verify_shape ;;
  allowed) allowed ;;
  blocked) blocked ;;
  blocked-ip) blocked_ip ;;
  neighbour) neighbour ;;
  verify-audit) verify_audit ;;
  stop) stop ;;
  logs) logs ;;
  cleanup) cleanup ;;
  *) echo "usage: $0 <subcommand>" >&2; exit 2 ;;
esac
