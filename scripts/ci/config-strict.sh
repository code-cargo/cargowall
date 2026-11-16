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

# A local --config that doesn't load fails startup. Each file below spells
# something cargowall would read loosely: a port with no protocol, which a
# loose read leaves on every port; a key cargowall doesn't read; a key in
# another case. For each, `cargowall start` must exit non-zero, and its
# failure sentinel must name the file. Then DNS must still resolve, since a
# failed start tears down what it set up. Runs from the binary, ahead of the
# step-rules job's own start.
#
# Usage: config-strict.sh

set -euo pipefail

FAILED=/tmp/cargowall-failed
dir=$(mktemp -d)
cat > "$dir/no-protocol.json" <<'JSON'
{"defaultAction": "deny", "rules": [{"type": "hostname", "value": "example.com", "action": "allow", "ports": [{"port": 443}]}]}
JSON
cat > "$dir/unknown-key.json" <<'JSON'
{"defaultAction": "deny", "rule": []}
JSON
cat > "$dir/case-variant.json" <<'JSON'
{"defaultAction": "deny", "Rules": [{"type": "hostname", "value": "example.com", "action": "allow"}]}
JSON

# The upstream systemd-resolved forwards to: a loopback upstream would loop
# under the redirect, which cargowall refuses.
upstream=$(awk '/^nameserver/ {print $2; exit}' /run/systemd/resolve/resolv.conf)

for f in "$dir"/*.json; do
  name=$(basename "$f")
  sudo rm -f "$FAILED"
  rc=0
  sudo timeout 120 ./bin/cargowall start \
    --github-action \
    --config "$f" \
    --dns-upstream "$upstream:53" \
    --failure-file "$FAILED" \
    --pidfile /tmp/cargowall-config-strict.pid \
    > "$dir/$name.log" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then
    echo "::error::cargowall start with $name didn't fail startup (exit $rc)"
    cat "$dir/$name.log"
    exit 1
  fi
  if ! sudo grep -F -- "config file $f did not load" "$FAILED"; then
    echo "::error::the failure sentinel for $name doesn't name the file"
    sudo cat "$FAILED" 2>/dev/null || true
    exit 1
  fi
  echo "$name: startup failed (exit $rc), as required"
done

getent hosts github.com > /dev/null || { echo "::error::DNS doesn't resolve after the failed starts"; exit 1; }
sudo rm -f "$FAILED"
