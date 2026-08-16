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

# Container-attribution scenarios and audit-log validation for the
# test-cargowall-enforce CI job (issues #106 phase 3a/3b). ci.yml stays
# wiring: each subcommand backs exactly one workflow step, and that
# one-step-per-subcommand mapping is LOAD-BEARING — step ordinals come from
# workflow step boundaries, and the validate assertions test relations
# between them (the exec ordinal must be LATER than the start ordinal, the
# three concurrent containers must SHARE one). Folding two subcommands into
# one step would silently change what is being asserted.
#
# Usage: container-attribution.sh scenarios|exec|bridge|validate

set -euo pipefail

# The `sleep 1` inside each container puts the docker-events tagging window
# behind us before the workload opens sockets: the start→tag window is a
# documented 3a scope boundary (such traffic lands in the stricter
# container tier), not what these assertions measure.
scenarios() {
  # Concurrent containers hitting DISTINCT blocked destinations — proves
  # per-container attribution doesn't cross wires under concurrency.
  # TEST-NET-2 IPs skip DNS entirely (deterministic TC block, and SYN
  # retransmits give the origin-record join several shots) and can never
  # carry real traffic.
  : > /tmp/cargowall-concurrent-cids
  for ip in 198.51.100.7 198.51.100.8 198.51.100.9; do
    CID=$(docker run -d --rm alpine:latest sh -c "sleep 1; wget -q --timeout=6 http://$ip/ || true; sleep 2")
    echo "$ip ${CID:0:12}" >> /tmp/cargowall-concurrent-cids
  done

  # Attributed container DNS: blocked at the resolver, so the dns_blocked
  # record is where container DNS attribution shows up.
  docker run --rm alpine:latest sh -c 'sleep 1; wget -q --timeout=5 https://container-dns-probe.example.com || true'

  # Give the three detached containers time to finish their fetches.
  sleep 12
  cat /tmp/cargowall-concurrent-cids

  # Exec re-tag: container born in THIS step, exec'd from the NEXT step
  # (the `exec` subcommand, wired as its own workflow step) — the exec
  # traffic must attribute to the next step's ordinal, never this one's.
  CID=$(docker run -d --name cargowall-exec-test alpine:latest sleep 120)
  echo "${CID:0:12}" > /tmp/cargowall-exec-test-cid
}

exec_step() {
  docker exec cargowall-exec-test sh -c 'sleep 1; wget -q --timeout=6 http://198.51.100.44/ || true'
  docker rm -f cargowall-exec-test
}

# Generates the two bridge traffic shapes the cgroup hook newly
# adjudicates, so the shadow gate's zero-would-blocks-on-172.17.* assertion
# in validate has real traffic to assert on. Without this the assertion is
# vacuous: no other CI step publishes a port (host → docker-proxy →
# container address) or runs container→container.
bridge() {
  docker run -d --rm --name cw-bridge-server -p 18083:8080 alpine:latest \
    sh -c 'while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 8080; done'
  ok=false
  for i in 1 2 3 4 5; do
    sleep 1
    curl -sf --max-time 5 http://127.0.0.1:18083/ > /dev/null && { ok=true; break; }
  done
  $ok || { echo "❌ published container port unreachable"; docker logs cw-bridge-server; exit 1; }
  SERVER_IP=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' cw-bridge-server)
  c2c=false
  for i in 1 2 3 4 5; do
    docker run --rm alpine:latest wget -q -T 5 -O- "http://$SERVER_IP:8080/" > /dev/null 2>&1 && { c2c=true; break; }
    sleep 1
  done
  $c2c || { echo "❌ container→container bridge traffic failed"; exit 1; }
  docker stop cw-bridge-server > /dev/null
  echo "✅ bridge-local traffic flows (host→published port, container→container)"
}

validate() {
  AUDIT_LOG=/tmp/cargowall-audit.json

  if [ ! -f "$AUDIT_LOG" ] || [ ! -s "$AUDIT_LOG" ]; then
    echo "❌ Audit log file not found or empty"
    exit 1
  fi
  echo "✅ Audit log exists ($(wc -l < "$AUDIT_LOG") lines)"

  EVENTS_VALID=true

  BLOCKED_COUNT=$(jq -s '[.[] | select(.event_type == "connection_blocked" and .blocked == true)] | length' "$AUDIT_LOG")
  echo "connection_blocked events (blocked=true): $BLOCKED_COUNT"
  if [ "$BLOCKED_COUNT" -eq 0 ]; then
    echo "❌ No connection_blocked events found"
    EVENTS_VALID=false
  fi

  DNS_BLOCKED_COUNT=$(jq -s '[.[] | select(.event_type == "dns_blocked")] | length' "$AUDIT_LOG")
  echo "dns_blocked events: $DNS_BLOCKED_COUNT"
  if [ "$DNS_BLOCKED_COUNT" -eq 0 ]; then
    echo "❌ No dns_blocked events found"
    EVENTS_VALID=false
  fi

  # Step attribution runs against the real Runner.Worker on this job (the
  # action passes --github-action, which implies it). The daemon
  # deliberately degrades to a warning when attribution can't start, so
  # these are the only assertions that catch a silent degrade on the
  # environment that matters.
  STEP_BOUNDARY_COUNT=$(jq -s '[.[] | select(.event_type == "step_boundary")] | length' "$AUDIT_LOG")
  echo "step_boundary events: $STEP_BOUNDARY_COUNT"
  if [ "$STEP_BOUNDARY_COUNT" -eq 0 ]; then
    echo "❌ No step_boundary events found (step attribution silently degraded?)"
    EVENTS_VALID=false
  fi

  # Every curl in this job ran in a post-attach `run:` step, so its
  # connection events must carry a real (small) step ordinal — not 0
  # (untagged) and not the runner/pre-daemon sentinels. The upper bound is
  # pkg/steps maxOrdinalBase (0xFFFFFFFE minus the 2^16 sentinel margin =
  # 4294901758): no real ordinal can start there.
  STEP_TAGGED_COUNT=$(jq -s '[.[] | select(.event_type | test("^connection_")) | select((.step_ordinal // 0) > 0 and (.step_ordinal // 0) < 4294901758)] | length' "$AUDIT_LOG")
  echo "connection events with a real step_ordinal: $STEP_TAGGED_COUNT"
  if [ "$STEP_TAGGED_COUNT" -eq 0 ]; then
    echo "❌ No connection events carry a step ordinal"
    EVENTS_VALID=false
  fi

  # --- Container attribution (issue #106, phase 3a) ---
  # The daemon degrades to a warning when container attribution can't
  # start, so — as with step attribution above — these are the assertions
  # that catch a silent degrade on the environment that matters. Ordinal
  # bounds match the step assertions (real ordinal: >0, below the sentinel
  # margin).

  # Every container/exec tagging emits a container_attribution marker; at
  # least one must carry a real ordinal and a measured tag latency.
  CONTAINER_ATTR_COUNT=$(jq -s '[.[] | select(.event_type == "container_attribution") | select((.step_ordinal // 0) > 0 and (.step_ordinal // 0) < 4294901758) | select((.tag_latency_ms // -1) >= 0)] | length' "$AUDIT_LOG")
  echo "container_attribution events with real ordinal: $CONTAINER_ATTR_COUNT"
  if [ "$CONTAINER_ATTR_COUNT" -eq 0 ]; then
    echo "❌ No container_attribution events with a real step ordinal (container attribution silently degraded?)"
    EVENTS_VALID=false
  fi

  # Container DNS: the resolver-blocked probe must be attributed to its
  # container and step (this is the "map the forwarded queries"
  # deliverable — a container's blocked DNS is no longer ordinal 0).
  DNS_CONTAINER_COUNT=$(jq -s '[.[] | select(.event_type == "dns_blocked" and .container_origin == true) | select((.step_ordinal // 0) > 0 and (.step_ordinal // 0) < 4294901758) | select(.container_id != null and .container_id != "")] | length' "$AUDIT_LOG")
  echo "container-attributed dns_blocked events: $DNS_CONTAINER_COUNT"
  if [ "$DNS_CONTAINER_COUNT" -eq 0 ]; then
    echo "❌ No dns_blocked events carry container attribution"
    EVENTS_VALID=false
  fi

  # Concurrent-container correctness: each TEST-NET destination's blocked
  # connection events must carry exactly the container that fetched it
  # (captured at docker run time), with one shared real ordinal across all
  # three (same step launched them).
  while read -r ip cid; do
    MATCHED=$(jq -s --arg ip "$ip" --arg cid "$cid" '[.[] | select(.event_type | test("^connection_")) | select(.dst_ip == $ip and .container_origin == true and .container_id == $cid) | select((.step_ordinal // 0) > 0 and (.step_ordinal // 0) < 4294901758)] | length' "$AUDIT_LOG")
    CROSSED=$(jq -s --arg ip "$ip" --arg cid "$cid" '[.[] | select(.event_type | test("^connection_")) | select(.dst_ip == $ip and (.container_id // "") != "" and .container_id != $cid)] | length' "$AUDIT_LOG")
    echo "dst $ip: container $cid attributed=$MATCHED crossed=$CROSSED"
    if [ "$MATCHED" -eq 0 ]; then
      echo "❌ No attributed connection events for $ip / $cid"
      EVENTS_VALID=false
    fi
    if [ "$CROSSED" -ne 0 ]; then
      echo "❌ Events for $ip attributed to a DIFFERENT container — join keys crossed wires"
      EVENTS_VALID=false
    fi
  done < /tmp/cargowall-concurrent-cids
  # Real-ordinal guard like every sibling assertion: step_ordinal is
  # omitempty, so an unguarded unique-count would go red on a single null
  # (one event from the start-to-tag window) yet pass vacuously on [null]
  # alone (total attribution failure). Guarded, nulls and sentinels drop
  # out: one shared real ordinal passes, zero fails.
  SHARED_ORDS=$(jq -s '[.[] | select(.event_type | test("^connection_")) | select(.dst_ip == "198.51.100.7" or .dst_ip == "198.51.100.8" or .dst_ip == "198.51.100.9") | select(.container_origin == true) | select((.step_ordinal // 0) > 0 and (.step_ordinal // 0) < 4294901758) | .step_ordinal] | unique | length' "$AUDIT_LOG")
  echo "distinct real ordinals across the three concurrent containers: $SHARED_ORDS"
  if [ "$SHARED_ORDS" -ne 1 ]; then
    echo "❌ Concurrent containers launched by one step must share one real ordinal"
    EVENTS_VALID=false
  fi

  # Exec re-tag: the exec attribution for the long-lived container must
  # carry a LATER ordinal than its start attribution (the exec came from a
  # later step).
  EXEC_CID=$(cat /tmp/cargowall-exec-test-cid)
  START_ORD=$(jq -s --arg cid "$EXEC_CID" '[.[] | select(.event_type == "container_attribution" and .container_id == $cid and .attribution_kind == "start")][0].step_ordinal // 0' "$AUDIT_LOG")
  EXEC_ORD=$(jq -s --arg cid "$EXEC_CID" '[.[] | select(.event_type == "container_attribution" and .container_id == $cid and .attribution_kind == "exec")][0].step_ordinal // 0' "$AUDIT_LOG")
  echo "exec-test container $EXEC_CID: start_ordinal=$START_ORD exec_ordinal=$EXEC_ORD"
  if [ "$START_ORD" -eq 0 ] || [ "$EXEC_ORD" -eq 0 ] || [ "$EXEC_ORD" -le "$START_ORD" ]; then
    echo "❌ Exec re-tag failed: exec ordinal must be a later step than the start ordinal"
    EVENTS_VALID=false
  fi

  # --- Cgroup egress hook, shadow mode (issue #106, phase 3b) ---
  # --github-action implies container attribution, which puts the cgroup
  # hook in SHADOW: it computes the verdict and reports what it WOULD
  # block, while TC still governs every packet. These assertions are the
  # blast-radius gate that must hold before enforcement is turned on
  # anywhere.

  # It must see the denied destinations the job deliberately visits.
  WOULD_BLOCK=$(jq -s '[.[] | select(.event_type == "cgroup_would_block")] | length' "$AUDIT_LOG")
  echo "cgroup_would_block events: $WOULD_BLOCK"
  if [ "$WOULD_BLOCK" -eq 0 ]; then
    echo "❌ No cgroup_would_block events (shadow mode silently degraded?)"
    EVENTS_VALID=false
  fi

  # Nothing was actually blocked by it: shadow must never claim a block.
  BAD_FLAGS=$(jq -s '[.[] | select(.event_type == "cgroup_would_block" and .blocked == true)] | length' "$AUDIT_LOG")
  if [ "$BAD_FLAGS" -ne 0 ]; then
    echo "❌ cgroup_would_block events marked blocked=true — shadow mode must block nothing"
    EVENTS_VALID=false
  fi

  # The blast radius itself: the surfaces this hook adjudicates that TC
  # never saw — loopback (TC is attached to one interface) and the docker
  # bridge. A would-block there is a NEW denial that turning on
  # enforcement would introduce, and would break the runner.
  #
  # Deliberately not asserted here: DNS to a resolver the policy doesn't
  # allow. That is a legitimate denial TC makes too, not something this
  # hook introduces — asserting on port 53 would conflate "the cgroup hook
  # newly breaks DNS" with "policy denies this resolver anyway" and fail
  # spuriously.
  BLAST=$(jq -s '[.[] | select(.event_type == "cgroup_would_block") | select(((.dst_ip // "") | startswith("127.")) or ((.dst_ip // "") | startswith("172.17.")))] | length' "$AUDIT_LOG")
  echo "would-blocks on loopback/docker bridge (must be 0): $BLAST"
  if [ "$BLAST" -ne 0 ]; then
    echo "❌ Shadow mode would block loopback/bridge traffic — enforcement would break the runner"
    jq -c 'select(.event_type == "cgroup_would_block") | {dst_ip, dst_port, process, container_id}' "$AUDIT_LOG" | head -20
    EVENTS_VALID=false
  fi

  # Allowed destinations must never be would-blocked — that would mean the
  # cgroup hook and TC disagree about policy.
  BLAST_ALLOWED=$(jq -s '[.[] | select(.event_type == "cgroup_would_block") | select((.dst_hostname // "") | test("github|githubusercontent|docker"))] | length' "$AUDIT_LOG")
  if [ "$BLAST_ALLOWED" -ne 0 ]; then
    echo "❌ Shadow mode would block an ALLOWED host — hook/TC policy divergence"
    EVENTS_VALID=false
  fi

  echo "--- cgroup_would_block events ---"
  jq -c 'select(.event_type == "cgroup_would_block") | {dst_ip, dst_port, protocol, process, step_ordinal, container_id, container_origin}' "$AUDIT_LOG" | head -20

  # Evidence dump: the raw attribution rows, so a passing run shows
  # first-hand what was tagged (and a failing one shows what wasn't).
  echo "--- step_boundary events ---"
  jq -c 'select(.event_type == "step_boundary") | {step_ordinal, pid, process}' "$AUDIT_LOG"
  echo "--- container_attribution events ---"
  jq -c 'select(.event_type == "container_attribution") | {attribution_kind, container_id, step_ordinal, pid, tag_latency_ms, privileged}' "$AUDIT_LOG"
  echo "--- attributed connection events ---"
  jq -c 'select(.event_type | test("^connection_")) | {step_ordinal: (.step_ordinal // 0), event_type, dst_hostname, dst_ip, dst_port, process, container_id: (.container_id // ""), container_origin: (.container_origin // false)}' "$AUDIT_LOG"

  if [ "$EVENTS_VALID" = true ]; then
    echo "✅ Audit log contains expected event types"
  else
    echo "❌ Audit log missing expected event types"
    echo "Sample entries:"
    head -5 "$AUDIT_LOG" | jq .
    exit 1
  fi
}

case "${1:-}" in
  scenarios) scenarios ;;
  exec) exec_step ;;
  bridge) bridge ;;
  validate) validate ;;
  *) echo "usage: $0 scenarios|exec|bridge|validate" >&2; exit 2 ;;
esac
