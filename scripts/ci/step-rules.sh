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

# Body of the test-cargowall-step-rules CI job: a step's own allow rules,
# end to end. ci.yml stays wiring: one workflow step per subcommand, since
# a step's identity is the workflow step it runs in.
#
# The policy allows the job nothing of its own, and allows one step,
# Rules-Allowed, a host the job's rules don't: that step reaches it, and the
# step after it, which has no rules, is blocked from it. Step rules come
# only from a local --config, so cargowall runs straight from the binary
# rather than through the action, with the GitHub preset and L7 enforced,
# which step rules need.
#
# Usage: step-rules.sh policy|start|allowed|blocked|verify|stop|emergency

set -euo pipefail

HOST=example.com
URL="https://$HOST/"
# Only ever PRESENTED, as the SNI of a flow to $HOST's address: never
# resolved, and allowed by no rule.
DENIED_SNI=denied.example.net
AUDIT_LOG=/tmp/cargowall-audit.json
LOG=/tmp/cargowall.log

policy() {
  sudo mkdir -p /etc/cargowall
  sudo tee /etc/cargowall/config.json > /dev/null <<JSON
{
  "defaultAction": "deny",
  "rules": [],
  "steps": [
    {"id": "Rules-Allowed", "rules": [
      {"type": "hostname", "value": "$HOST", "ports": [{"port": 443, "protocol": "tcp"}]}
    ]}
  ]
}
JSON
}

# nohup + & + disown lets cargowall outlive this step's shell. The upstream
# is the one systemd-resolved forwards to, read before the redirect takes
# DNS over: a loopback upstream would loop under the redirect. The GitHub
# service hosts are the action's defaults, which the runner's own traffic
# needs under an enforcing policy.
start() {
  local upstream
  upstream=$(awk '/^nameserver/ {print $2; exit}' /run/systemd/resolve/resolv.conf)
  echo "DNS upstream: $upstream"
  sudo env CARGOWALL_GITHUB_SERVICE_HOSTS="github.com,api.github.com,githubapp.com,actions.githubusercontent.com,release-assets.githubusercontent.com,avatars.githubusercontent.com,github.githubassets.com" \
    nohup ./bin/cargowall start \
    --github-action \
    --config /etc/cargowall/config.json \
    --container-egress enforce \
    --tls-sni enforce \
    --dns-upstream "$upstream:53" \
    --allow-existing-connections \
    --audit-log "$AUDIT_LOG" \
    --pidfile /tmp/cargowall.pid \
    --debug \
    > "$LOG" 2>&1 &
  disown
}

# The step is bound to its policy once cargowall reads its first exec,
# which can trail the step's first connection: until then the step gets
# the job's rules. So the step retries, as any client would a refused
# connection, and must get through.
# The step's own allow is name-scoped like the job's: the same address, by
# a name no rule allows, is dropped at L7.
allowed() {
  local ip code
  if ! ip=$(curl -sf -o /dev/null -w '%{remote_ip}' --connect-timeout 5 --max-time 15 \
    --retry 10 --retry-all-errors --retry-delay 1 "$URL"); then
    echo "❌ Rules-Allowed could not reach $HOST, which its own rule allows"
    exit 1
  fi
  echo "✅ Rules-Allowed reached $HOST at $ip through its own rule"
  code=$(curl -s -k -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 \
    --resolve "$DENIED_SNI:443:$ip" "https://$DENIED_SNI/" || true)
  if [ "$code" != "000" ]; then
    echo "❌ SNI $DENIED_SNI reached $ip (HTTP $code): the step's allow is not name-scoped"
    exit 1
  fi
  echo "✅ SNI $DENIED_SNI to $ip dropped: the step's allow is name-scoped"
}

blocked() {
  if curl -sf -o /dev/null --connect-timeout 5 --max-time 10 "$URL"; then
    echo "❌ rules-blocked reached $HOST: only Rules-Allowed's rules allow it"
    exit 1
  fi
  echo "✅ rules-blocked was kept from $HOST"
}

verify() {
  local failed=false
  echo "step_boundary events (ordinal / step_id / step_class):"
  sudo jq -r -s '.[] | select(.event_type == "step_boundary")
    | [.step_ordinal, (.step_id // "-"), (.step_class // "-")] | @tsv' "$AUDIT_LOG"
  ordinal_of() {
    sudo jq -s --arg id "$1" '[.[] | select(.event_type == "step_boundary" and .step_id == $id)
      | .step_ordinal] | first // empty' "$AUDIT_LOG"
  }
  local allowed_ord blocked_ord
  allowed_ord=$(ordinal_of Rules-Allowed)
  blocked_ord=$(ordinal_of rules-blocked)
  # The runner hands a step its id as written, case and all: the policy
  # names it the same way, and binding compares ids exactly.
  if [ -z "$allowed_ord" ] || [ -z "$blocked_ord" ]; then
    echo "❌ a step's boundary is missing, or its id is not as written: Rules-Allowed=${allowed_ord:-none} rules-blocked=${blocked_ord:-none}"
    failed=true
  fi

  if sudo grep -q "Step bound to its policy.*step=Rules-Allowed" "$LOG"; then
    echo "✅ Rules-Allowed was bound to its policy"
  else
    echo "❌ Rules-Allowed was never bound"
    sudo grep -i "step bound\|step rules" "$LOG" || true
    failed=true
  fi
  if sudo grep -q "Step bound to its policy.*step=rules-blocked" "$LOG"; then
    echo "❌ rules-blocked, which has no rules, was bound"
    failed=true
  fi

  local n
  n=$(sudo jq -s --argjson o "${allowed_ord:-0}" '[.[] | select(.event_type == "l7_blocked"
    and .step_ordinal == $o and .l7_name == "'"$DENIED_SNI"'")] | length' "$AUDIT_LOG")
  if [ "$n" -ge 1 ]; then
    echo "✅ the foreign SNI was dropped at L7 under Rules-Allowed's ordinal"
  else
    echo "❌ no l7_blocked event for $DENIED_SNI under Rules-Allowed (ordinal ${allowed_ord:-none})"
    sudo jq -c 'select(.event_type | startswith("l7_"))' "$AUDIT_LOG" | head -5 || true
    failed=true
  fi

  n=$(sudo grep -cE "Connection allowed .*dst=$HOST .*step_ordinal=${allowed_ord:-none}\b" "$LOG" || true)
  if [ "$n" -ge 1 ]; then
    echo "✅ Rules-Allowed's connection was allowed under its own ordinal"
  else
    echo "❌ no allowed connection to $HOST under Rules-Allowed's ordinal ${allowed_ord:-none}"
    failed=true
  fi

  n=$(sudo jq -s --argjson o "${blocked_ord:-0}" '[.[] | select(.event_type == "connection_blocked"
    and .step_ordinal == $o and .dst_port == 443)] | length' "$AUDIT_LOG")
  if [ "$n" -ge 1 ]; then
    echo "✅ rules-blocked's connection was reported blocked, under its own step"
  else
    echo "❌ no connection_blocked event for rules-blocked (ordinal ${blocked_ord:-none})"
    failed=true
  fi

  if sudo jq -e '.[] | select(.posture == "step-rules" and .applied == "on")' /tmp/cargowall-postures > /dev/null; then
    echo "✅ the step-rules posture is on"
  else
    echo "❌ the step-rules posture is not on:"
    sudo cat /tmp/cargowall-postures || true
    failed=true
  fi
  $failed && exit 1
  echo "✅ step rules hold end to end"
}

stop() {
  sudo ./bin/cargowall stop --pidfile /tmp/cargowall.pid --timeout 15s
}

emergency() {
  if sudo test -f /tmp/cargowall.pid; then
    sudo kill -TERM "$(sudo cat /tmp/cargowall.pid)" 2>/dev/null || true
  fi
}

case "${1:-}" in
  policy) policy ;;
  start) start ;;
  allowed) allowed ;;
  blocked) blocked ;;
  verify) verify ;;
  stop) stop ;;
  emergency) emergency ;;
  *) echo "usage: $0 policy|start|allowed|blocked|verify|stop|emergency" >&2; exit 2 ;;
esac
