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

# Asserts, once cargowall has exited, that it gave Docker its DNS back: no
# daemon.json records left beside it, a daemon restart queued at teardown for
# the one startup ran onto the rewrite, and a container started now gets a
# real nameserver. A daemon restarted onto cargowall's rewrite keeps pointing
# containers at cargowall's listener until it restarts again, and one only
# reloaded after the restore hands them "nameserver invalid IP". The image
# must be pulled beforehand: the container only reads its resolv.conf, so
# nothing here needs the network.
# usage: docker-dns-restored.sh <cargowall log> <when, for the error text> <image>
set -euo pipefail
log=$1
when=$2
image=$3

for record in /etc/docker/daemon.json.cargowall.{bak,absent,rewrite}; do
  if sudo test -e "$record"; then
    echo "::error::$record left behind $when"; exit 1
  fi
done

# A restart onto the rewrite at startup, and one queued onto the original at
# teardown.
for line in "Docker daemon ready after restart" "Queued a Docker daemon restart off cargowall's daemon.json rewrite"; do
  grep -q "$line" "$log" \
    || { echo "::error::cargowall never logged \"$line\" $when"; tail -30 "$log"; exit 1; }
done
if grep -qE "Failed to (restart|queue a) Docker daemon" "$log"; then
  echo "::error::a Docker daemon restart failed $when"
  grep -E "Failed to (restart|queue a) Docker daemon" "$log"; exit 1
fi
# The queued restart may not have run yet, and until it has, the old daemon
# still answers: wait until systemd has no job left for the daemon and the
# daemon answers.
for _ in $(seq 1 60); do
  if [ -z "$(systemctl list-jobs --no-legend docker.service)" ] && docker info > /dev/null 2>&1; then
    break
  fi
  sleep 1
done

servers=$(docker run --rm --pull=never "$image" sed -n 's/^nameserver[[:space:]]*//p' /etc/resolv.conf) \
  || { echo "::error::a container failed to start $when"; exit 1; }
echo "Container nameservers $when: $servers"
[ -n "$servers" ] || { echo "::error::a container got no nameserver $when"; exit 1; }
for server in $servers; do
  case $server in
    169.254.0.53 | fd97:d1fb:f215::53)
      echo "::error::a container still resolves through cargowall's listener $server $when"; exit 1 ;;
  esac
  # An address is hex digits, dots and colons; "invalid IP" is not.
  if ! [[ $server =~ ^[0-9a-fA-F.:]+$ ]]; then
    echo "::error::a container got nameserver \"$servers\" $when"; exit 1
  fi
done
echo "Docker DNS restored $when"
