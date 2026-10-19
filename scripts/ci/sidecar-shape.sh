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
# namespace with the workload.
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
  echo "✅ pod up: cw-pod (netns owner), cw-client (workload)"
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
  state=$(docker inspect -f 'running={{.State.Running}}, exit={{.State.ExitCode}}' cw-sidecar 2>&1 || true)
  echo "❌ sidecar not ready ($state)"
  # Printed even when the waiter already gave the reason: a sidecar that
  # dies mid-wait kills the waiter with it, and can still read as running.
  if [ -s "$STATE_DIR/failed" ]; then
    echo "failure sentinel: $(head -c 2048 "$STATE_DIR/failed")"
  fi
  exit 1
}

# A literal prefix match on a cgroup v2 /proc/<pid>/cgroup line.
under_pod_slice() {
  case "$1" in
    "0::/$POD_SLICE/"*) return 0 ;;
    *) return 1 ;;
  esac
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
  if ! under_pod_slice "$(docker exec cw-sidecar cat /proc/self/cgroup)"; then
    echo "❌ sidecar does not see its own absolute cgroup path under $POD_SLICE"
    docker exec cw-sidecar cat /proc/self/cgroup
    exit 1
  fi
  for c in cw-pod cw-sidecar cw-client; do
    if ! under_pod_slice "$(sudo cat "/proc/$(docker inspect -f '{{.State.Pid}}' "$c")/cgroup")"; then
      echo "❌ $c is not under the pod slice $POD_SLICE"
      exit 1
    fi
  done
  echo "✅ shape: own pid ns, host cgroup ns, shared non-host netns, resolver 127.0.0.1, one pod cgroup"
}

# Resolution goes through the proxy at 127.0.0.1 (the pod resolv.conf); the
# allowed connection only succeeds because the proxy's answer seeded the
# allowlist.
allowed() {
  client curl -sf --connect-timeout 10 --max-time 30 -o /dev/null https://github.com
  echo "✅ github.com reachable from the workload"
}

# Classifies one request from the workload by curl's timings, not its exit
# code alone: exit 28 is also a resolve that stalled past --connect-timeout,
# and a connection that got through can still fail on TLS or an HTTP error.
#   connected  the TCP handshake completed
#   dropped    the connect timed out after a completed resolve (http://1.1.1.1
#              has none to wait for): TC dropped the SYN
#   unreached  anything else, a failed resolve or exec above all
probe() {
  rc=0
  out=$(client curl -s -o /dev/null --connect-timeout "$2" --max-time "$3" \
    -w '%{time_namelookup} %{time_connect}' "$1") || rc=$?
  read -r lookup connect <<< "$out"
  if awk -v t="${connect:-0}" 'BEGIN { exit !(t > 0) }'; then
    echo connected
  elif [ "$rc" -eq 28 ] && { [ "$1" = http://1.1.1.1 ] || awk -v t="${lookup:-0}" 'BEGIN { exit !(t > 0) }'; }; then
    echo dropped
  else
    echo "unreached (curl exit $rc)"
  fi
}

expect_blocked() {
  result=$(probe "$1" 5 10)
  case "$result" in
    dropped) echo "✅ $1 blocked" ;;
    connected) echo "❌ $1 reachable — enforcement is not applied to the workload"; exit 1 ;;
    *) echo "❌ $1 $result — the request never reached TC"; exit 1 ;;
  esac
}

blocked() { expect_blocked https://example.com; }

blocked_ip() { expect_blocked http://1.1.1.1; }

# The pid check is the cgroup half of the shape: the connect hooks write the
# socket's pid and the TC event copies it. With no step tracker it is the
# node-global tgid, unresolvable in the sidecar's /proc, so process stays
# empty; but it is non-zero only if a hook attached here fired.
verify_audit() {
  if ! test -s "$AUDIT_LOG"; then
    echo "❌ audit log not written"
    exit 1
  fi
  # One pass, assigned: a torn line or a jq failure stops the step.
  summary=$(jq -s -c '
    [.[] | select(.event_type == "connection_blocked" and .blocked == true)]
    | [.[] | select(.dst_hostname == "example.com")] as $name
    | [.[] | select(.dst_ip == "1.1.1.1")] as $ip
    | {example_com: ($name | length), ip_1111: ($ip | length),
       github_com: ([.[] | select(.dst_hostname == "github.com")] | length),
       no_pid: ([$name[], $ip[] | select((.pid // 0) <= 0)] | length)}' "$AUDIT_LOG")
  if ! jq -e '.example_com > 0 and .ip_1111 > 0 and .github_com == 0 and .no_pid == 0' <<< "$summary" > /dev/null; then
    echo "❌ audit log: $summary (want example_com > 0, ip_1111 > 0, github_com 0, no_pid 0)"
    jq -s -c '.[] | select(.event_type == "connection_blocked")' "$AUDIT_LOG"
    exit 1
  fi
  echo "✅ audit log: both blocks recorded with a hook pid, nothing for the allowed host ($summary)"
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
  # resolver died with the proxy. On a tcx kernel (6.6+, as CI runs) the
  # kernel drops the link when the process's fd closes, so this proves
  # nothing outlived the process rather than that teardown detached it;
  # the clsact path, where a filter can outlive the process, is below 6.6.
  result=$(probe http://1.1.1.1 10 30)
  case "$result" in
    connected) echo "✅ clean SIGTERM teardown; workload egress unfiltered again" ;;
    dropped) echo "❌ 1.1.1.1 still blocked after the sidecar stopped — a filter outlived the sidecar"; exit 1 ;;
    *) echo "❌ teardown probe $result — it never reached TC"; exit 1 ;;
  esac
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
