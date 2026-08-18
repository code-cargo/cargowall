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

# Body of BOTH sudo-lockdown CI jobs (allowlist and full-block). ci.yml
# stays wiring: one workflow step per subcommand invocation. The two jobs
# differ only in the `start` argument (the --sudo-allow-commands list, or
# none) and in which denial probes they run — the probe itself is one
# parametrized subcommand, `expect-denied <label> <cmd...>`.
#
# Usage:
#   sudo-lockdown.sh snapshot
#   sudo-lockdown.sh start [allow-commands]
#   sudo-lockdown.sh expect-allowed <label> <cmd...>
#   sudo-lockdown.sh expect-denied <label> <cmd...>
#   sudo-lockdown.sh stop-verify
#   sudo-lockdown.sh verify-restored
#   sudo-lockdown.sh verify-full-sudo
#   sudo-lockdown.sh emergency

set -euo pipefail

snapshot() {
  echo "--- Runner user info ---"
  id runner
  echo "--- Groups ---"
  groups runner
  echo "--- sudoers.d contents ---"
  sudo ls -la /etc/sudoers.d/
  echo "--- Verify runner has full sudo ---"
  sudo whoami
  echo "--- Save sudoers.d file list for later comparison ---"
  sudo ls /etc/sudoers.d/ | sort > /tmp/sudoers-before.txt
}

# Start cargowall inside a root wrapper that watches for a stop trigger.
# Once lockdown is active the runner user cannot sudo kill, so we need an
# already-root process that can send SIGTERM. An optional first argument is
# the --sudo-allow-commands list; absent, lockdown allows nothing.
start() {
  sudo bash -c '
    allow="$1"
    set --
    if [ -n "$allow" ]; then
      set -- --sudo-allow-commands "$allow"
    fi
    ./bin/cargowall start \
      --github-action \
      --audit-mode \
      --sudo-lockdown \
      "$@" \
      --dns-upstream "8.8.8.8:53" &
    CW_PID=$!
    echo $CW_PID > /tmp/cargowall-pid
    # Wait for stop trigger (created by a later step — no sudo needed)
    while [ ! -f /tmp/cargowall-stop ]; do sleep 1; done
    kill -TERM $CW_PID
    wait $CW_PID 2>/dev/null
  ' root-wrapper "${1:-}" &

  # Wait for cargowall to be ready
  for i in $(seq 1 30); do
    if [ -f /tmp/cargowall-ready ]; then
      echo "CargoWall ready after ${i}s"
      break
    fi
    sleep 1
  done
  if [ ! -f /tmp/cargowall-ready ]; then
    echo "CargoWall did not become ready"
    exit 1
  fi
}

expect_allowed() {
  local label="$1"; shift
  if sudo "$@" > /dev/null 2>&1; then
    echo "✅ Allowed command ($label) works via sudo"
  else
    echo "❌ Allowed command ($label) failed via sudo"
    exit 1
  fi
}

expect_denied() {
  local label="$1"; shift
  local output
  output=$(sudo -n "$@" 2>&1) && {
    echo "❌ $label should be blocked by sudo lockdown"
    exit 1
  }
  if echo "$output" | grep -qiE "not allowed|not in sudoers|may not run|a password is required"; then
    echo "✅ $label denied by sudo"
  else
    echo "❌ $label failed but not due to sudoers denial: $output"
    exit 1
  fi
}

stop_verify() {
  CW_PID=$(cat /tmp/cargowall-pid)

  # Signal the root wrapper to send SIGTERM — no sudo needed
  touch /tmp/cargowall-stop

  # Wait for cargowall to exit. Use /proc to check since kill -0 requires
  # permission on a root-owned process.
  for i in $(seq 1 15); do
    if [ ! -d "/proc/$CW_PID" ]; then
      echo "CargoWall stopped after ${i}s"
      break
    fi
    sleep 1
  done
  if [ -d "/proc/$CW_PID" ]; then
    echo "❌ CargoWall did not stop within 15s"
    exit 1
  fi
}

verify_restored() {
  echo "--- sudoers.d after cleanup ---"
  sudo ls -la /etc/sudoers.d/

  # Lockdown file should be removed
  if sudo test -f /etc/sudoers.d/zz-cargowall-lockdown; then
    echo "❌ Lockdown sudoers file still exists after cleanup"
    exit 1
  fi
  echo "✅ Lockdown sudoers file removed"

  # State file should be removed
  if sudo test -f /etc/sudoers.d/.cargowall-lockdown-state; then
    echo "❌ State file still exists after cleanup"
    exit 1
  fi
  echo "✅ State file removed"

  # Disabled files should be restored
  STILL_DISABLED=$(sudo ls /etc/sudoers.d/ | grep -c '\.cargowall-disabled$' || true)
  if [ "$STILL_DISABLED" -gt 0 ]; then
    echo "❌ $STILL_DISABLED sudoers files still disabled after cleanup"
    sudo ls -la /etc/sudoers.d/
    exit 1
  fi
  echo "✅ All disabled sudoers files restored"

  # sudoers.d should be back to original state
  sudo ls /etc/sudoers.d/ | sort > /tmp/sudoers-after.txt
  if ! diff /tmp/sudoers-before.txt /tmp/sudoers-after.txt; then
    echo "❌ sudoers.d contents differ from pre-lockdown state"
    exit 1
  fi
  echo "✅ sudoers.d contents match pre-lockdown state"
}

verify_full_sudo() {
  if sudo whoami > /dev/null 2>&1; then
    echo "✅ Full sudo access restored"
  else
    echo "❌ sudo access not restored after cleanup"
    exit 1
  fi

  # Verify unrestricted commands work again
  if sudo apt-get --version > /dev/null 2>&1; then
    echo "✅ Previously blocked commands now work"
  else
    echo "❌ apt-get still blocked after cleanup"
    exit 1
  fi
}

emergency() {
  # Signal the root wrapper to stop cargowall gracefully
  touch /tmp/cargowall-stop
  sleep 5
  # If we still have sudo, clean up any remnants
  if sudo -n true 2>/dev/null; then
    sudo rm -f /etc/sudoers.d/zz-cargowall-lockdown
    sudo rm -f /etc/sudoers.d/.cargowall-lockdown-state
    for f in /etc/sudoers.d/*.cargowall-disabled; do
      [ -f "$f" ] || continue
      sudo mv "$f" "${f%.cargowall-disabled}"
    done
    for group in sudo admin wheel; do
      sudo gpasswd -a runner "$group" 2>/dev/null || true
    done
  fi
  echo "Emergency cleanup complete"
}

cmd="${1:-}"
shift || true
case "$cmd" in
  snapshot) snapshot ;;
  start) start "$@" ;;
  expect-allowed) expect_allowed "$@" ;;
  expect-denied) expect_denied "$@" ;;
  stop-verify) stop_verify ;;
  verify-restored) verify_restored ;;
  verify-full-sudo) verify_full_sudo ;;
  emergency) emergency ;;
  *) echo "usage: $0 snapshot|start|expect-allowed|expect-denied|stop-verify|verify-restored|verify-full-sudo|emergency" >&2; exit 2 ;;
esac
