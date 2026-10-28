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

# Runs a command under sudo with the caller's whole environment, which is
# what `sudo -E` did before sudo-rs, Ubuntu 26.04's default sudo, began
# ignoring -E. Classic sudo and sudo-rs both honor --preserve-env=<list>, and
# both still strip LD_PRELOAD and the rest of their deny list. Every variable
# already set is named, as cargowall-action's sudoPreserveEnvArgs does, so a
# variable added to a step's env: cannot go missing under sudo.
#
# usage: bash scripts/ci/sudo-env.sh <command> [args...]
set -euo pipefail

# Only identifier-shaped names: a comma would split the list, and exported
# bash functions (BASH_FUNC_name%%) are not variables.
names=$(env -0 | awk -v RS='\0' -F= '
  $1 ~ /^[A-Za-z_][A-Za-z0-9_]*$/ { n = n ? n "," $1 : $1 }
  END { print n }')
[ -n "$names" ] || { echo "sudo-env: no environment to carry through sudo" >&2; exit 1; }
exec sudo --preserve-env="$names" "$@"
