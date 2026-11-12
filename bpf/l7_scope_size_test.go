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

//go:build linux

package bpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// L7ScopeEntries is each scope map's size, and room for the job's
// reservation and then some for the steps.
func TestL7ScopeEntriesMatchSpec(t *testing.T) {
	spec, err := LoadOriginBpf()
	require.NoError(t, err)
	for _, name := range []string{OriginBpfMapMapL7Scope, OriginBpfMapMapL7ScopeV6} {
		require.Equal(t, L7ScopeEntries, spec.Maps[name].MaxEntries, name)
	}
	require.Greater(t, L7ScopeEntries, RuleMapEntriesJobOnly)
}
