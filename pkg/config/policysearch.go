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
	"fmt"
	"log/slog"
	"slices"
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

// maxReportedSearchDomains caps the entries one report line names, and
// maxReportedSearchDomainLen the length each is named with, so a policy
// merged across levels with dozens of refused entries, or one carrying an
// oversized entry, still makes a readable annotation.
const (
	maxReportedSearchDomains   = 10
	maxReportedSearchDomainLen = 64
)

// filterPolicySearchDomains returns the CodeCargo policy's search domains
// classifySearchDomain accepts, normalized and deduplicated, in order, with
// report, which logs what was dropped. The caller calls report only once
// the policy has loaded, so a line never says a policy applies that then
// fails to.
//
// An always-active Kubernetes suffix is reported at Info, since stripping it
// happens anyway. Every other drop, an entry under a reverse-lookup zone
// included, shares one Warn line, each entry as the operator wrote it with
// a short reason: Warn lines become job annotations, so one per entry would
// flood the job, and the normalized form is not what the operator can
// search the policy for.
func filterPolicySearchDomains(raw []string) (kept []string, report func()) {
	var alwaysActive, dropped []string
	for _, r := range raw {
		d := normalizeSearchDomain(r)
		switch c, _ := classifySearchDomain(d); c {
		case searchDomainOK:
			kept = append(kept, d)
		case searchDomainAlwaysActive:
			alwaysActive = append(alwaysActive, reportedSearchDomain(r))
		default:
			dropped = append(dropped, reportedSearchDomain(r)+": "+c.String())
		}
	}
	kept = mergeNormalizedSearchDomains(nil, kept)
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

// reportedSearchDomain is an entry as the operator wrote it, shortened to
// maxReportedSearchDomainLen bytes, and `""` for an empty one.
func reportedSearchDomain(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return strconv.Quote(raw)
	}
	if len(raw) > maxReportedSearchDomainLen {
		return raw[:maxReportedSearchDomainLen] + "…"
	}
	return raw
}

// cappedList is entries with at most maxReportedSearchDomains named and the
// rest counted.
func cappedList(entries []string) []string {
	if len(entries) <= maxReportedSearchDomains {
		return entries
	}
	return append(slices.Clone(entries[:maxReportedSearchDomains]),
		fmt.Sprintf("and %d more", len(entries)-maxReportedSearchDomains))
}
