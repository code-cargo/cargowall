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

# Sudo lockdown against a group grant a running job keeps: the Actions
# Runner Controller image's shape, whose /etc/sudoers is the whole grant
# (`%sudo ALL=(ALL:ALL) NOPASSWD:ALL`) and includes no sudoers.d. Removing
# the user from the group reaches only later logins; every job step
# descends from a Runner.Worker started before the lockdown and keeps the
# group. So the lockdown's own rules must be read last, and hold.
#
# Runs in a throwaway privileged container, so the runner's own sudo is
# never touched. The image is the runner image itself (classic sudo), or
# Ubuntu 26.04 given the same user and sudoers (sudo-rs).
#
# Usage:
#   sudo-lockdown-group-grant.sh run <image>   (on the host, from the repo root)
#   sudo-lockdown-group-grant.sh inside        (in the container, as root)

set -euo pipefail

ALLOWED=/usr/bin/id

run() {
  local image="$1"
  docker run --rm --privileged --user root --entrypoint bash \
    -v "$PWD:/w:ro" "$image" /w/scripts/ci/sudo-lockdown-group-grant.sh inside
}

# runescalation is run for the rollback-on-escalation scenario.
runescalation() {
  local image="$1"
  docker run --rm --privileged --user root --entrypoint bash \
    -v "$PWD:/w:ro" "$image" /w/scripts/ci/sudo-lockdown-group-grant.sh escalation
}

# runlatefile is run for the later-sorting competing-grant scenario.
runlatefile() {
  local image="$1"
  docker run --rm --privileged --user root --entrypoint bash \
    -v "$PWD:/w:ro" "$image" /w/scripts/ci/sudo-lockdown-group-grant.sh latefile
}

fail() {
  echo "❌ $*"
  [ -f /tmp/cw.log ] && { echo "--- cargowall log"; tail -40 /tmp/cw.log; }
  exit 1
}

# prepare gives an image without the runner's user and sudoers both.
prepare() {
  if ! id runner >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq sudo python3 >/dev/null
    getent group docker >/dev/null || groupadd docker
    useradd -m -G sudo,users,docker runner
    printf '%%sudo   ALL=(ALL:ALL) NOPASSWD:ALL\n' > /etc/sudoers
    mkdir -p /etc/sudoers.d
    find /etc/sudoers.d -type f ! -name README -delete
  fi
  sudo --version | head -1
  echo "--- /etc/sudoers"
  cat /etc/sudoers
  if grep -qE '^[#@]includedir' /etc/sudoers; then
    fail "the image's sudoers includes sudoers.d; this test needs one that does not"
  fi
}

# held starts a stand-in for Runner.Worker as runner, before the lockdown,
# holding runner's login groups: on its signal it asks sudo what a job step
# would, and writes the answers.
held() {
  ln -sf /bin/bash /tmp/Runner.Worker
  su runner -c '/tmp/Runner.Worker -c "
    id -G > /tmp/held.groups
    while [ ! -f /tmp/held.go ]; do sleep 0.2; done
    sudo -n '"$ALLOWED"' -u > /tmp/held.allowed 2>&1; echo \$? > /tmp/held.allowed.rc
    sudo -n true > /tmp/held.true 2>&1; echo \$? > /tmp/held.true.rc
    sudo -n /bin/bash -c id > /tmp/held.bash 2>&1; echo \$? > /tmp/held.bash.rc
    touch /tmp/held.done
    while [ ! -f /tmp/held.again ]; do sleep 0.2; done
    sudo -n true > /dev/null 2>&1; echo \$? > /tmp/held.after.rc
    touch /tmp/held.after
    sleep 600"' &
  for _ in $(seq 1 50); do [ -f /tmp/held.groups ] && break; sleep 0.2; done
  local sudo_gid
  sudo_gid=$(getent group sudo | cut -d: -f3)
  grep -qw "$sudo_gid" /tmp/held.groups || fail "the held process does not hold the sudo group: $(cat /tmp/held.groups)"
  echo "✅ held process started before the lockdown, groups $(cat /tmp/held.groups)"
}

# dockersock makes a socket as dockerd does, root:docker 0660.
dockersock() {
  mkdir -p /var/run
  python3 -c 'import grp,os,socket,time
s = socket.socket(socket.AF_UNIX); s.bind("/var/run/docker.sock")
os.chown("/var/run/docker.sock", 0, grp.getgrnam("docker").gr_gid)
os.chmod("/var/run/docker.sock", 0o660); s.listen(1); time.sleep(600)' &
  for _ in $(seq 1 50); do [ -S /var/run/docker.sock ] && return; sleep 0.1; done
  fail "no docker socket"
}

inside() {
  prepare
  sha256sum /etc/sudoers > /tmp/sudoers.sha
  find /etc/sudoers.d | sort > /tmp/sudoersd.before
  dockersock
  held

  local upstream
  upstream="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)"
  echo '{"defaultAction":"allow","rules":[]}' > /tmp/policy.json
  /w/bin/cargowall start --config=/tmp/policy.json --dns-upstream="${upstream}:53" --audit-mode \
    --sudo-lockdown --sudo-allow-commands "$ALLOWED" \
    --ready-file=/tmp/cargowall-ready > /tmp/cw.log 2>&1 &
  local cw=$!
  for _ in $(seq 1 60); do [ -f /tmp/cargowall-ready ] && break; sleep 0.5; done
  [ -f /tmp/cargowall-ready ] || fail "cargowall did not become ready"
  echo "✅ lockdown up"

  touch /tmp/held.go
  for _ in $(seq 1 50); do [ -f /tmp/held.done ] && break; sleep 0.2; done
  [ -f /tmp/held.done ] || fail "the held process never answered"
  [ "$(cat /tmp/held.allowed.rc)" = 0 ] || fail "the allowed command was refused: $(cat /tmp/held.allowed)"
  echo "✅ allowed command runs for the held process"
  [ "$(cat /tmp/held.true.rc)" != 0 ] || fail "sudo true ran for a process that kept the sudo group"
  [ "$(cat /tmp/held.bash.rc)" != 0 ] || fail "sudo bash ran for a process that kept the sudo group: $(cat /tmp/held.bash)"
  echo "✅ held process is denied everything else"
  if su runner -c 'sudo -n true' >/dev/null 2>&1; then
    fail "sudo true ran for a login after the lockdown"
  fi
  echo "✅ a later login is denied"
  grep -q '"Verified sudo lockdown"' /tmp/cw.log || fail "the lockdown was not verified"
  echo "✅ cargowall verified the lockdown"
  grep -q 'Sudo lockdown leaves docker reachable' /tmp/cw.log || fail "docker access was not reported"
  echo "✅ docker access reported"

  kill -TERM "$cw"
  wait "$cw" 2>/dev/null || true
  touch /tmp/held.again
  for _ in $(seq 1 50); do [ -f /tmp/held.after ] && break; sleep 0.2; done
  [ "$(cat /tmp/held.after.rc)" = 0 ] || fail "sudo was not restored for the held process"
  echo "✅ sudo restored after stop"
  sha256sum -c --quiet /tmp/sudoers.sha || { cat /etc/sudoers; fail "/etc/sudoers differs after stop"; }
  echo "✅ /etc/sudoers restored byte for byte"
  find /etc/sudoers.d | sort | diff /tmp/sudoersd.before - || fail "sudoers.d differs after stop"
  echo "✅ sudoers.d restored"
  id -nG runner | grep -qw sudo || fail "runner is not back in the sudo group"
  echo "✅ runner back in the sudo group"
}

# latefile checks that grants read after the lockdown's own sudoers.d file
# are denied anyway — because the lockdown rules are appended to the end of
# /etc/sudoers, read after every sudoers.d file and every include. The Debian
# includedir shape, with three such grants, each of a command the
# verification probe never tests:
# - one in /etc/sudoers itself after the includedir, which no sudoers.d scan
#   can touch: only the appended block stops it, so this leg fails without it;
# - a later-sorting file with a quoted user name;
# - a later-sorting file with a tab-separated #include of another file.
latefile() {
  export DEBIAN_FRONTEND=noninteractive
  command -v sudo >/dev/null || { apt-get update -qq >/dev/null && apt-get install -y -qq sudo >/dev/null; }
  id runner >/dev/null 2>&1 || { getent group docker >/dev/null || groupadd docker; useradd -m -G sudo,users,docker runner; }
  printf 'root ALL=(ALL:ALL) ALL\n%%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\nrunner ALL=(ALL) NOPASSWD: /usr/bin/tail\n' > /etc/sudoers
  mkdir -p /etc/sudoers.d
  find /etc/sudoers.d -type f ! -name README -delete
  printf '"runner" ALL=(ALL) NOPASSWD: /bin/cat\n' > /etc/sudoers.d/zzz-quoted
  chmod 0440 /etc/sudoers.d/zzz-quoted
  printf '#include\t/etc/cargowall-extra-grant\n' > /etc/sudoers.d/zzz-tabinc
  chmod 0440 /etc/sudoers.d/zzz-tabinc
  printf 'runner ALL=(ALL) NOPASSWD: /usr/bin/head\n' > /etc/cargowall-extra-grant
  chmod 0440 /etc/cargowall-extra-grant
  sudo --version | head -1
  sha256sum /etc/sudoers > /tmp/sudoers.sha
  find /etc/sudoers.d | sort > /tmp/sudoersd.before

  ln -sf /bin/bash /tmp/Runner.Worker
  su runner -c '/tmp/Runner.Worker -c "
    while [ ! -f /tmp/go ]; do sleep 0.2; done
    sudo -n /bin/cat /etc/hostname >/dev/null 2>&1; echo \$? > /tmp/cat.rc
    sudo -n /usr/bin/head /etc/hostname >/dev/null 2>&1; echo \$? > /tmp/head.rc
    sudo -n /usr/bin/tail /etc/hostname >/dev/null 2>&1; echo \$? > /tmp/tail.rc
    touch /tmp/done; sleep 600"' &
  local upstream
  upstream="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)"
  echo '{"defaultAction":"allow","rules":[]}' > /tmp/policy.json
  /w/bin/cargowall start --config=/tmp/policy.json --dns-upstream="${upstream}:53" --audit-mode \
    --sudo-lockdown --sudo-allow-commands /usr/bin/id \
    --ready-file=/tmp/cargowall-ready > /tmp/cw.log 2>&1 &
  local cw=$!
  for _ in $(seq 1 60); do [ -f /tmp/cargowall-ready ] && break; sleep 0.5; done
  [ -f /tmp/cargowall-ready ] || fail "cargowall did not become ready"
  grep -q '"Verified sudo lockdown"' /tmp/cw.log || fail "the lockdown was not verified"
  echo "✅ lockdown up on the includedir shape"

  touch /tmp/go
  for _ in $(seq 1 50); do [ -f /tmp/done ] && break; sleep 0.2; done
  [ -f /tmp/done ] || fail "the held step never answered"
  [ "$(cat /tmp/cat.rc)" != 0 ] || fail "sudo cat ran: the quoted later-sorting grant applied"
  [ "$(cat /tmp/head.rc)" != 0 ] || fail "sudo head ran: the tab-include later-sorting grant applied"
  [ "$(cat /tmp/tail.rc)" != 0 ] || fail "sudo tail ran: the grant after the includedir applied, so the rules were not appended last"
  echo "✅ every grant read after the lockdown's sudoers.d file is denied by the appended block"

  kill -TERM "$cw" 2>/dev/null || true
  wait "$cw" 2>/dev/null || true
  sha256sum -c --quiet /tmp/sudoers.sha || { cat /etc/sudoers; fail "/etc/sudoers differs after stop"; }
  find /etc/sudoers.d | sort | diff /tmp/sudoersd.before - || fail "sudoers.d differs after stop"
  echo "✅ /etc/sudoers and sudoers.d restored after stop"
}

# escalation drives the rollback path: a stand-in `sudo` that always exits 0
# makes the step verification see an escalation, so EnableSudoLockdown must
# undo everything and report that it does not hold.
escalation() {
  prepare
  sha256sum /etc/sudoers > /tmp/sudoers.sha
  find /etc/sudoers.d | sort > /tmp/sudoersd.before
  id -nG runner | tr ' ' '\n' | sort > /tmp/groups.before

  # A fake sudo first on PATH for cargowall only; visudo and gpasswd still
  # resolve to the real ones further down PATH.
  mkdir -p /tmp/fakebin
  printf '#!/bin/sh\nexit 0\n' > /tmp/fakebin/sudo
  chmod 0755 /tmp/fakebin/sudo

  local upstream
  upstream="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)"
  echo '{"defaultAction":"allow","rules":[]}' > /tmp/policy.json
  PATH="/tmp/fakebin:$PATH" /w/bin/cargowall start --config=/tmp/policy.json \
    --dns-upstream="${upstream}:53" --audit-mode \
    --sudo-lockdown --sudo-allow-commands "$ALLOWED" \
    --ready-file=/tmp/cargowall-ready > /tmp/cw.log 2>&1 &
  local cw=$!
  for _ in $(seq 1 60); do [ -f /tmp/cargowall-ready ] && break; sleep 0.5; done
  [ -f /tmp/cargowall-ready ] || fail "cargowall did not become ready"

  grep -q 'sudo lockdown does not hold' /tmp/cw.log || fail "escalation was not detected"
  grep -q 'Failed to enable sudo lockdown' /tmp/cw.log || fail "the lockdown was not reported as failed"
  echo "✅ escalation detected and the lockdown reported as failed"

  # Everything the aborted enable touched must be undone, with cargowall
  # still running.
  [ -f /etc/sudoers.d/zz-cargowall-lockdown ] && fail "the lockdown sudoers file was left behind"
  [ -f /etc/sudoers.d/.cargowall-lockdown-state ] && fail "the state file was left behind"
  grep -q 'BEGIN cargowall sudo lockdown' /etc/sudoers && fail "the lockdown block was left in /etc/sudoers"
  sha256sum -c --quiet /tmp/sudoers.sha || { cat /etc/sudoers; fail "/etc/sudoers differs after rollback"; }
  find /etc/sudoers.d | sort | diff /tmp/sudoersd.before - || fail "sudoers.d differs after rollback"
  id -nG runner | tr ' ' '\n' | sort | diff /tmp/groups.before - || fail "runner's groups were not restored"
  echo "✅ rollback left the system pristine"

  kill -TERM "$cw" 2>/dev/null || true
  wait "$cw" 2>/dev/null || true
}

cmd="${1:-}"
shift || true
case "$cmd" in
  run) run "$@" ;;
  run-escalation) runescalation "$@" ;;
  run-latefile) runlatefile "$@" ;;
  inside) inside ;;
  escalation) escalation ;;
  latefile) latefile ;;
  *) echo "usage: $0 run <image> | run-escalation <image> | run-latefile <image> | inside | escalation | latefile" >&2; exit 2 ;;
esac
