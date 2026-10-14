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

# Body of the arc-probe workflow: records what an ARC runner pod looks like
# from inside the runner container, so pod-aware attribution is designed
# against observed facts rather than inferred ones. It asserts nothing; every
# subcommand reports, and the report lands in the job summary.
#
# The questions it answers:
#   shape        which namespaces the runner shares with the node and with
#                the dind sidecar, where its cgroup sits, and whether
#                dockerd's peer pid is visible from here
#   host-cgroup  with a host cgroup2 mount at $HOST_CGROUP: is the full node
#                hierarchy visible, which directory is ours (by inode), and
#                is its parent the pod cgroup
#   dns-probe    do queries from a dind container reach the proxy
#   report       how the probe traffic was attributed in the audit log
#
# Usage: arc-probe.sh <subcommand>

set -uo pipefail

HOST_CGROUP=${HOST_CGROUP:-/host/sys/fs/cgroup}
AUDIT_LOG=/tmp/cargowall-audit.json
PROBE_ID=${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}
SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/stdout}

# Every report is a fenced block in the job summary and in the step log.
section() {
  local title=$1
  shift
  {
    echo "### $title"
    echo '```'
    "$@" 2>&1
    echo '```'
  } | tee -a "$SUMMARY"
}

shape_body() {
  echo "kernel:      $(uname -r) $(uname -m)"
  echo "uid:         $(id -u)"
  for ns in pid cgroup net mnt; do
    printf '%-12s self=%s pid1=%s\n' "ns/$ns:" \
      "$(readlink /proc/self/ns/$ns)" "$(sudo readlink /proc/1/ns/$ns 2>/dev/null)"
  done
  echo "pid 1 comm:  $(cat /proc/1/comm)"
  echo "self cgroup: $(cat /proc/self/cgroup)"
  echo "cgroup root inode/dev: $(stat -c '%i %d' /sys/fs/cgroup)"
  echo "cgroup.procs at root: $(wc -l < /sys/fs/cgroup/cgroup.procs) entries"
  echo
  echo "-- cgroup2 mounts (mountinfo)"
  grep cgroup2 /proc/self/mountinfo
  echo
  echo "-- dockerd visible in this pid namespace?"
  pgrep -a dockerd || echo "no dockerd process visible"
  echo
  echo "-- docker socket peer (SO_PEERCRED; pid 0 = peer outside our pid namespace)"
  if command -v python3 > /dev/null; then
    sudo python3 - <<'PY'
import socket, struct
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/var/run/docker.sock")
pid, uid, gid = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
print(f"peer pid={pid} uid={uid} gid={gid}")
PY
  else
    echo "python3 not available"
  fi
  echo
  echo "-- docker info"
  docker info --format 'driver={{.CgroupDriver}} cgroup={{.CgroupVersion}} security={{.SecurityOptions}} kernel={{.KernelVersion}}'
  echo
  echo "-- a dind container's own view"
  docker run --rm alpine:3.20 sh -c 'echo "cgroup: $(cat /proc/self/cgroup)"; echo "resolv: $(grep nameserver /etc/resolv.conf | tr "\n" " ")"'
  echo
  echo "-- interfaces"
  ip -br addr
}

host_cgroup_body() {
  if [ ! -d "$HOST_CGROUP" ]; then
    echo "$HOST_CGROUP not mounted: this runner has no host cgroup mount"
    return
  fi
  echo "-- mountinfo for $HOST_CGROUP"
  grep " $HOST_CGROUP " /proc/self/mountinfo
  echo
  echo "top level: $(ls "$HOST_CGROUP" | grep -c '') entries"
  ls "$HOST_CGROUP" | grep -E 'slice|kubepods' || true
  echo
  read -r ino dev < <(stat -c '%i %d' /sys/fs/cgroup)
  echo "-- directories with our cgroup root's inode ($ino, dev $dev)"
  matches=$(sudo find "$HOST_CGROUP" -maxdepth 8 -type d -inum "$ino" 2>/dev/null)
  if [ -z "$matches" ]; then
    echo "none: the mount does not expose our cgroup"
    return
  fi
  while read -r m; do
    echo "$m (dev $(stat -c %d "$m"))"
  done <<< "$matches"
  self=$(head -1 <<< "$matches")
  parent=$(dirname "$self")
  echo
  echo "parent (pod cgroup candidate): $parent"
  echo "-- siblings of our cgroup"
  ls "$parent" | grep -vE '^(cgroup|cpu|io|memory|pids|hugetlb|rdma|misc)\.' || true
  echo
  echo "-- dind processes, read from this pid namespace"
  for pid in $(pgrep -x dockerd; pgrep -f containerd-shim | head -3); do
    echo "pid $pid ($(cat /proc/$pid/comm)): $(cat /proc/$pid/cgroup)"
  done
  echo
  echo "-- a dind container's process as seen from here"
  cid=$(docker run -d --rm alpine:3.20 sleep 30)
  cpid=$(docker inspect -f '{{.State.Pid}}' "$cid")
  echo "State.Pid=$cpid"
  if [ -r "/proc/$cpid/cgroup" ]; then
    echo "/proc/$cpid/cgroup: $(cat /proc/$cpid/cgroup)"
    echo "/proc/$cpid/comm:   $(cat /proc/$cpid/comm)"
  else
    echo "/proc/$cpid not visible (or not the container's task)"
  fi
  docker rm -f "$cid" > /dev/null
}

# One name per origin, so the audit log shows which queries the proxy saw.
# The names do not exist; only the proxy's record of the query matters.
dns_probe_body() {
  echo "-- host query: host-probe-$PROBE_ID.example.com"
  curl -sS --max-time 10 -o /dev/null "https://host-probe-$PROBE_ID.example.com" || true
  echo
  echo "-- dind container query: ctr-probe-$PROBE_ID.example.com"
  docker run --rm curlimages/curl:8.10.1 -sS --max-time 10 -o /dev/null \
    "https://ctr-probe-$PROBE_ID.example.com" || true
  echo
  echo "-- dind container connection: https://example.com"
  docker run --rm curlimages/curl:8.10.1 -sS --max-time 10 -o /dev/null \
    -w 'http=%{http_code} remote=%{remote_ip}\n' https://example.com || true
}

report_body() {
  if ! sudo test -s "$AUDIT_LOG"; then
    echo "audit log not written"
    return
  fi
  for origin in host ctr; do
    name="$origin-probe-$PROBE_ID.example.com"
    seen=$(sudo jq -s --arg n "$name" '[.[] | select((.dst_hostname // "") | startswith($n))] | length' "$AUDIT_LOG")
    echo "$origin query seen by the proxy: $([ "$seen" -gt 0 ] && echo yes || echo NO) ($seen events)"
  done
  echo
  echo "-- probe events"
  sudo jq -c -s --arg id "$PROBE_ID" '.[]
    | select(((.dst_hostname // "") | (contains($id) or . == "example.com")) or .event_type == "container_attribution")
    | {event_type, dst_hostname, dst_ip, dst_port, src_ip, pid, process, step_ordinal, step_attr_outcome, container_id, container_origin, attribution_kind}' "$AUDIT_LOG"
  echo
  echo "-- daemon log lines on namespaces, docker and attach points"
  sudo grep -iE 'namespace|docker|daemon\.json|cgroup|container attribution' /tmp/cargowall.log | cut -c1-400 | head -60
}

case "${1:-}" in
  shape) section "Runner pod shape" shape_body ;;
  host-cgroup) section "Host cgroup mount" host_cgroup_body ;;
  dns-probe) section "DNS probe" dns_probe_body ;;
  report) section "Attribution report" report_body ;;
  *) echo "usage: $0 <subcommand>" >&2; exit 2 ;;
esac
