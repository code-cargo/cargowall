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

package steps

import (
	"bytes"

	"github.com/code-cargo/cargowall/pkg/events"
)

// stepIDVar is the variable Runner.Worker names each step process's step
// in: the step's contextName in the job plan, which is its YAML id: or a
// name the runner generates (__run, __run_2, __actions_checkout, __self).
// The runner sets it for every step process, after the job's and the
// step's env: and $GITHUB_ENV, none of which can override it. A
// composite's inner steps carry the outer step's name, and an action's
// pre and post steps their main step's.
var stepIDVar = []byte("GITHUB_ACTION=")

// maxStepIDLen bounds a step name; anything longer is not one the runner
// wrote.
const maxStepIDLen = 256

// Identity is what a step root's environment says it is.
type Identity struct {
	StepID string           // the runner's name for the step; set only for events.StepClassStep
	Class  events.StepClass // see events.StepClass
}

// identify reads a step root's identity from the start of its environment
// as the kernel captured it at the root's first exec, before any of the
// root's code ran: env holds the first bytes of the NUL-separated area,
// envLen the whole area's length (0 when it could not be read).
//
// The kernel copy is the only source: /proc/<pid>/environ reads the
// process's memory as it is now, which the step can have rewritten. The
// environment carries the step's secrets, so nothing but the step's name
// leaves here.
//
// An entry the cut went through is never read, so a name the cut shortened
// can't pass for another. More than one entry for the name, which execve
// would allow but Runner.Worker never writes, identifies nothing.
func identify(env []byte, envLen int) Identity {
	if envLen <= 0 {
		return Identity{Class: events.StepClassUnknown}
	}
	cut := envLen > len(env)
	if !cut {
		env = env[:envLen]
	}
	var (
		id    []byte
		found int
	)
	for len(env) > 0 {
		entry, rest, whole := bytes.Cut(env, []byte{0})
		if !whole && cut {
			break
		}
		if v, ok := bytes.CutPrefix(entry, stepIDVar); ok {
			id = v
			found++
		}
		env = rest
	}
	switch {
	case found == 1 && validStepID(id):
		return Identity{StepID: string(id), Class: events.StepClassStep}
	case found == 0 && !cut:
		return Identity{Class: events.StepClassRunner}
	default:
		return Identity{Class: events.StepClassUnknown}
	}
}

// validStepID reports whether id can be a step name the runner wrote: YAML
// ids and the generated names are short runs of printable, unspaced ASCII.
// Holding to that also keeps the name safe in logs and the summary.
func validStepID(id []byte) bool {
	if len(id) == 0 || len(id) > maxStepIDLen {
		return false
	}
	for _, c := range id {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}
