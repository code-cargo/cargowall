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
	"errors"
	"fmt"
	"log/slog"
	"strconv"
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

// maxReportedSearchDomains caps the entries one report line names, so a
// policy merged across levels with dozens of refused entries still makes a
// readable annotation; the rest are counted.
const maxReportedSearchDomains = 10

// filterPolicySearchDomains normalizes a CodeCargo policy's search domains
// and returns those validateSearchDomain accepts, in order, with report,
// which logs what was dropped. The caller calls report only once the policy
// has loaded, so a line never says a policy applies that then fails to.
//
// An always-active Kubernetes suffix is reported at Info, since stripping it
// happens anyway. Every other drop, an entry under a reverse-lookup zone
// included, shares one Warn line, each entry with a short reason: Warn lines
// become job annotations, so one per entry would flood the job.
func filterPolicySearchDomains(raw []string) (kept []string, report func()) {
	var alwaysActive, dropped []string
	for _, d := range normalizeSearchDomainsKeepingReverse(raw) {
		if ReverseLookupName(d) {
			dropped = append(dropped, strconv.Quote(d)+": under a reverse-lookup zone, which no search domain decides")
			continue
		}
		err := validateSearchDomain(d)
		switch {
		case err == nil:
			kept = append(kept, d)
		case errors.Is(err, errSearchDomainAlwaysActive):
			alwaysActive = append(alwaysActive, d)
		default:
			dropped = append(dropped, strconv.Quote(d)+": "+searchDomainClass(err))
		}
	}
	return kept, func() {
		if len(alwaysActive) > 0 {
			slog.Info("Search domains in the CodeCargo policy are dropped: they are always active for stripping",
				"domains", alwaysActive)
		}
		if len(dropped) > 0 {
			slog.Warn("Search domains in the CodeCargo policy are dropped; the rest of the policy loaded",
				"count", len(dropped), "dropped", cappedList(dropped))
		}
	}
}

// searchDomainClass is err's short reason: its class, or the whole message
// for an error validateSearchDomain did not classify.
func searchDomainClass(err error) string {
	var sd *searchDomainError
	if errors.As(err, &sd) {
		return sd.class.Error()
	}
	return err.Error()
}

// cappedList joins entries, naming at most maxReportedSearchDomains.
func cappedList(entries []string) string {
	if len(entries) <= maxReportedSearchDomains {
		return strings.Join(entries, "; ")
	}
	return strings.Join(entries[:maxReportedSearchDomains], "; ") +
		fmt.Sprintf("; and %d more", len(entries)-maxReportedSearchDomains)
}
