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
	"unicode/utf8"
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
			alwaysActive = appendNew(alwaysActive, reportedSearchDomain(r))
		default:
			// An entry repeated down the merge chain is named once, so
			// repeats don't use up the cap.
			dropped = appendNew(dropped, reportedSearchDomain(r)+": "+c.String())
		}
	}
	kept = mergeNormalizedSearchDomains(nil, kept)
	return kept, func() {
		if len(alwaysActive) > 0 {
			slog.Info("Search domains in the CodeCargo policy are dropped: they are always active for stripping",
				"domains", cappedList(alwaysActive))
		}
		if len(dropped) > 0 {
			slog.Warn("Search domains in the CodeCargo policy are dropped; the rest of the policy loaded",
				"count", len(dropped), "dropped", cappedList(dropped))
		}
	}
}

// appendNew appends s unless entries already holds it.
func appendNew(entries []string, s string) []string {
	if slices.Contains(entries, s) {
		return entries
	}
	return append(entries, s)
}

// reportedSearchDomain is an entry as the operator wrote it, quoted so its
// bounds and any whitespace show: at most maxReportedSearchDomainLen bytes of
// it, cut at a rune boundary, which strconv.Quote then escapes to at most
// four bytes each (\xNN), so a reported entry is at most
// 4*maxReportedSearchDomainLen+5 bytes, the quotes and "…" included.
func reportedSearchDomain(raw string) string {
	if len(raw) <= maxReportedSearchDomainLen {
		return strconv.Quote(raw)
	}
	n := maxReportedSearchDomainLen
	for n > 0 && !utf8.RuneStart(raw[n]) {
		n-- // never cut a rune in two
	}
	return strconv.Quote(raw[:n]) + "…"
}

// cappedList joins entries with "; ", naming at most
// maxReportedSearchDomains and counting the rest. One string, not a list:
// the GitHub Actions handler prints a list with %v, space-separated, which
// can't be told from the spaces inside an entry.
func cappedList(entries []string) string {
	if len(entries) <= maxReportedSearchDomains {
		return strings.Join(entries, "; ")
	}
	return strings.Join(entries[:maxReportedSearchDomains], "; ") +
		fmt.Sprintf("; and %d more", len(entries)-maxReportedSearchDomains)
}
