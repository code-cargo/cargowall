//   Copyright 2026 BoxBuild Inc DBA CodeCargo
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

// Package testenv holds what the privileged tests of several packages
// share about the environment they run in. Only tests import it.
package testenv

import (
	"os"
	"testing"
)

// StrictEnv is set to 1 in CI's privileged lanes, where what those tests
// need (a bridge, veth, br_netfilter) must be there.
const StrictEnv = "CARGOWALL_TEST_STRICT"

// SkipUnlessStrict skips t for what the environment lacks, or fails it
// where StrictEnv says the environment must not lack it.
func SkipUnlessStrict(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv(StrictEnv) == "1" {
		t.Fatalf(format+" ("+StrictEnv+"=1)", args...)
	}
	t.Skipf(format, args...)
}
