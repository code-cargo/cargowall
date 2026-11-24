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

package config

import (
	"log/slog"
	"slices"
	"strings"
)

// A CodeCargo policy's search domains are merged down the org, repository,
// workflow and job chain, so one entry set at the org reaches every run
// below it. Refusing the whole policy over that entry would drop every run
// to the policy-fetch failure posture (audit by default), turning
// enforcement off for all of them. So the policy loader keeps the entries
// validateSearchDomain accepts and drops the rest. The local config file
// and CARGOWALL_SEARCH_DOMAINS are written by the operator of this one run,
// where a typo should stop the run instead; they keep validateSearchDomains.

// filterPolicySearchDomains returns the normalized domains that
// validateSearchDomain accepts, in order. An always-active Kubernetes
// suffix is dropped at Info, since stripping it happens anyway; every other
// refused entry is dropped, and all of them are named with their reasons on
// one Warn line (Warn lines become job annotations, so one per entry would
// flood the job).
func filterPolicySearchDomains(domains []string) []string {
	var kept, alwaysActive, dropped []string
	for _, d := range domains {
		// Tested first: validateSearchDomain refuses this class with the
		// same error type as a real misconfiguration.
		if slices.Contains(kubernetesSearchDomains, d) {
			alwaysActive = append(alwaysActive, d)
			continue
		}
		if err := validateSearchDomain(d); err != nil {
			dropped = append(dropped, err.Error())
			continue
		}
		kept = append(kept, d)
	}
	if len(alwaysActive) > 0 {
		slog.Info("Search domains in the CodeCargo policy are dropped: they are always active for stripping",
			"domains", alwaysActive)
	}
	if len(dropped) > 0 {
		slog.Warn("Search domains in the CodeCargo policy are dropped; the rest of the policy applies",
			"count", len(dropped), "dropped", strings.Join(dropped, "; "))
	}
	return kept
}
