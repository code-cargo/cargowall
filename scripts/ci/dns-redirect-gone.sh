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

# Asserts, once cargowall has exited, that its DNS redirect was torn down.
# The kernel deletes the redirect's table when cargowall's process exits,
# however it exits, so the table being gone proves nothing about the
# teardown, which also flushes the DNS flows still DNAT'd to the proxy. The
# teardown's own log line is the proof. The table is checked as well, so a
# redirect that stopped dying with its process shows up here too.
# usage: dns-redirect-gone.sh <cargowall log> <when, for the error text>
set -euo pipefail
log=$1
when=$2

grep -q "DNS redirect removed" "$log" \
  || { echo "::error::DNS redirect teardown did not run $when"; tail -30 "$log"; exit 1; }
# Listed into a variable first: an nft or sudo failure must fail the check,
# not read as an empty ruleset.
tables=$(sudo nft list tables) \
  || { echo "::error::nft list tables failed $when"; exit 1; }
if grep -qE "^table ip cargowall( |$)" <<< "$tables"; then
  echo "::error::DNS redirect table still present $when"
  exit 1
fi
echo "DNS redirect torn down $when"
