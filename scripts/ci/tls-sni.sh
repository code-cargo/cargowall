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

# Body of the test-cargowall-tls-sni CI job: --tls-sni=enforce end to end.
# ci.yml stays wiring: it starts cargowall via the action, then calls
# `verify`.
#
# L7 enforcement governs an address a hostname rule opened: a flow there
# must present a name some rule allows on it, or it is dropped. The parsers,
# the oracle and the kernel drop have unit and BPF tests; this is the one
# place the wiring runs for real — the proxy scoping the address as it
# resolves, the mode gate raised, the drop, and the l7_blocked record naming
# what was refused.
#
# Each probe goes to an address the policy allows (a githubusercontent.com
# edge, resolved through the proxy so it is scoped) and differs from its
# control only in the NAME it presents, so a drop here is L7's, not L4's.
# Without L7 the edge answers a foreign SNI or Host with a status, so "no
# response" can only be the drop.
#
# Usage: tls-sni.sh verify

set -euo pipefail

step() { echo; echo "=== $* ==="; }

ALLOWED=raw.githubusercontent.com
ALLOWED_URL="https://$ALLOWED/github/gitignore/main/README.md"
# Only ever PRESENTED — as the SNI or Host of a flow to the allowed edge —
# never resolved or allowed.
DENIED=example.com
AUDIT_LOG=/tmp/cargowall-audit.json

# http_code prints the HTTP status a request got, 000 when none came back.
http_code() {
  curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 "$@" || true
}

# The allowed request's own connection: resolving through the proxy scopes
# the address, and completing proves the allowed name passes L7.
edge_ip() {
  curl -4 -sf --connect-timeout 10 --max-time 30 -o /dev/null -w '%{remote_ip}' "$ALLOWED_URL"
}

verify_tls() {
  step "TLS: an unlisted SNI to an allowed address is dropped"
  local ip code
  ip=$(edge_ip) || { echo "❌ $ALLOWED unreachable under --tls-sni=enforce"; return 1; }
  echo "✅ $ALLOWED reachable at $ip"
  # -k: a certificate mismatch is not what is being tested; with it out of
  # the way, only the L7 drop leaves no response.
  code=$(http_code -k --resolve "$DENIED:443:$ip" "https://$DENIED/")
  if [ "$code" != "000" ]; then
    echo "❌ SNI $DENIED reached $ip (HTTP $code)"
    return 1
  fi
  echo "✅ SNI $DENIED to $ip dropped"
}

verify_http() {
  step "HTTP: an unlisted Host to an allowed address is dropped"
  local ip code
  ip=$(edge_ip)
  code=$(http_code -H "Host: $ALLOWED" "http://$ip/")
  if [ "$code" = "000" ]; then
    echo "❌ Host $ALLOWED to $ip:80 got no response; the control must pass"
    return 1
  fi
  echo "✅ Host $ALLOWED to $ip:80 answered (HTTP $code)"
  code=$(http_code -H "Host: $DENIED" "http://$ip/")
  if [ "$code" != "000" ]; then
    echo "❌ Host $DENIED reached $ip:80 (HTTP $code)"
    return 1
  fi
  echo "✅ Host $DENIED to $ip:80 dropped"
}

# container_probe presents a name to the edge address from a container
# (--add-host, so no lookup of it) and prints REACHED when any HTTP response
# came back, BLOCKED when none did. wget exits non-zero on an error status
# too, so its exit code cannot tell a drop from a 4xx; -S prints the status
# line whenever there is one. The output goes to a file, never a pipe: when
# wget times out, its TLS helper (ssl_client) stays blocked in the dropped
# handshake holding whatever pipe it inherited, and a reader of that pipe
# waits until the server gives up — minutes. The container's exit kills it.
container_probe() {
  local name=$1 ip=$2
  docker run --rm --add-host "$name:$ip" alpine:latest sh -c \
    "timeout 20 wget -S -O /dev/null --timeout=8 --no-check-certificate https://$name/ > /tmp/probe 2>&1; if grep -q 'HTTP/' /tmp/probe; then echo REACHED; else echo BLOCKED; fi" 2>&1 || true
}

# Container traffic meets the same hook in its own netns, before NAT.
verify_container() {
  step "Container: an unlisted SNI to an allowed address is dropped"
  local ip
  ip=$(edge_ip)
  docker pull -q alpine:latest > /dev/null
  if ! container_probe "$ALLOWED" "$ip" | grep -q REACHED; then
    echo "❌ Container got no response from $ip presenting $ALLOWED; the control must pass"
    return 1
  fi
  echo "✅ Container's SNI $ALLOWED to $ip answered"
  if ! container_probe "$DENIED" "$ip" | grep -q BLOCKED; then
    echo "❌ Container reached $ip presenting $DENIED"
    return 1
  fi
  echo "✅ Container's SNI $DENIED to $ip dropped"
}

verify_events() {
  step "Validate L7 events"
  test -s "$AUDIT_LOG" || { echo "❌ Audit log missing"; return 1; }
  local valid=true n

  for proto in tls http; do
    n=$(jq -s --arg name "$DENIED" --arg proto "$proto" \
      '[.[] | select(.event_type == "l7_blocked" and .l7_name == $name and .l7_protocol == $proto)] | length' "$AUDIT_LOG")
    echo "l7_blocked $proto $DENIED: $n"
    if [ "$n" -eq 0 ]; then
      echo "❌ The $proto drop produced no l7_blocked record"
      valid=false
    fi
  done

  # The container's drop must be its own record, carrying its identity — the
  # host probe's record alone satisfies the count above.
  n=$(jq -s --arg name "$DENIED" \
    '[.[] | select(.event_type == "l7_blocked" and .l7_name == $name and .l7_protocol == "tls" and (.container_id // "") != "")] | length' "$AUDIT_LOG")
  echo "container-attributed l7_blocked tls $DENIED: $n"
  if [ "$n" -eq 0 ]; then
    echo "❌ The container's drop produced no container-attributed l7_blocked record"
    valid=false
  fi

  # The refused name is dropped, never merely reported. (Other would-blocks
  # are legitimate under enforce: an allowed name at an address it was not
  # seen resolving to passes and is reported as one.)
  n=$(jq -s --arg name "$DENIED" '[.[] | select(.event_type == "l7_would_block" and .l7_name == $name)] | length' "$AUDIT_LOG")
  echo "l7_would_block $DENIED (expected 0 in enforce): $n"
  [ "$n" -eq 0 ] || valid=false

  # Enforce never drops an allowed name.
  n=$(jq -s '[.[] | select((.event_type == "l7_blocked") and ((.l7_name // "") | test("githubusercontent|github\\.com")))] | length' "$AUDIT_LOG")
  echo "l7_blocked on allowed names (expected 0): $n"
  [ "$n" -eq 0 ] || valid=false

  echo "--- l7 events ---"
  jq -c 'select(.event_type | startswith("l7_")) | {event_type, dst_ip, dst_port, l7_protocol, l7_name, l7_reason, container_id}' "$AUDIT_LOG" | head -20

  [ "$valid" = true ] || return 1
  echo "✅ L7 enforcement events are correct"
}

verify() {
  verify_tls
  verify_http
  verify_container
  verify_events
}

case "${1:-}" in
  verify) verify ;;
  *) echo "usage: $0 verify" >&2; exit 2 ;;
esac
